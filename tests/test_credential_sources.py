import json

import httpx
import pytest

from conftest import AT, HUDSON_ROUTE, fake_http, hudson_body, when_params
from farpoint.credential_import import build_batch
from farpoint.credential_sources import build_credential_providers
from farpoint.credential_sources.base import collect_credentials
from farpoint.credential_sources.hibp import HibpPublic
from farpoint.sources.hudsonrock import HudsonRock

D = "example.com"
HIBP_ROUTE = "haveibeenpwned.com/api/v3/breaches"


def _collect(provider, kinds=("email",)):
    rows = collect_credentials([provider], [D], kinds, AT)
    return build_batch([(rows, "live")], [D], kinds, AT)


def _hudson(body=None, handler=None):
    route = handler or when_params({"domain": D}, httpx.Response(200, json=body))
    source = HudsonRock(fake_http({HUDSON_ROUTE: route}), backoff=0)
    return build_credential_providers(fake_http({}), [source])["hudsonrock-osint"]


def _checks(built):
    return {(c["query_kind"], c["operation"]): (c["status"], c["error"]) for c in built.checks}


def test_reset_token_urls_keep_only_the_host():
    url = "https://auth.example.com/user/password/reset/1e7c/SENTINEL-TOKEN?next=SENTINEL-QUERY#SENTINEL-FRAG"
    built, _ = _collect(_hudson(hudson_body(employee_urls=[(url, 2)], employees=1)))
    text = json.dumps(built.to_json())
    assert "SENTINEL" not in text and "/user/" not in text
    (row,) = built.exposures
    assert row["service_host"] == "auth.example.com" and row["service_port"] is None


def test_employee_urls_become_one_workforce_row_per_host_with_summed_occurrences():
    body = hudson_body(employee_urls=[("https://vpn.example.com/a", 3), ("https://vpn.example.com/b?x=1", 4)])
    built, rejected = _collect(_hudson(body))
    (row,) = built.exposures
    assert rejected == 0 and row["occurrences"] == 7 and row["relationship"] == "workforce-associated"
    assert (row["exposure_type"], row["secret_evidence"], row["secret_types"]) == ("infostealer", "dataset", ["password"])
    assert row["event_at"] is None  # no per-URL date: never a theft date


def test_an_explicit_port_is_kept_apart_from_the_default():
    body = hudson_body(employee_urls=[("https://vpn.example.com:8443/x", 2), ("https://vpn.example.com/y", 5)])
    built, _ = _collect(_hudson(body))
    assert {(r["service_host"], r["service_port"], r["occurrences"]) for r in built.exposures} == {
        ("vpn.example.com", 8443, 2), ("vpn.example.com", None, 5)}


def test_unparseable_and_off_scope_urls_are_skipped():
    junk = [("not a url", 1), ("https://", 1), ("https://192.0.2.7/login", 1), ("http://localhost/", 1),
            ("https://login.microsoftonline.com/common", 1), ("https://example.com.evil.net/", 1), (None, 1)]
    built, rejected = _collect(_hudson(hudson_body(employee_urls=[*junk, ("https://sso.example.com/", 1)])))
    assert [r["service_host"] for r in built.exposures] == ["sso.example.com"] and rejected == 0


def test_user_urls_and_infected_users_need_the_website_kind():
    body = hudson_body(user_urls=[("https://shop.example.com/login", 9)], users=40,
                       last_user_compromised="2026-10-30T10:00:00.000Z")
    email, _ = _collect(_hudson(body), kinds=("email",))
    assert email.exposures == () and email.summaries == ()
    both, _ = _collect(_hudson(body), kinds=("email", "website"))
    (row,) = both.exposures
    assert row["relationship"] == "customer-reported" and row["query_kind"] == "website"
    (summary,) = both.summaries
    assert (summary["metric"], summary["count"], summary["window_end"]) == ("infected-users", 40, "2026-10-30T10:00:00Z")


def test_domain_summaries_skip_zero_counts():
    body = hudson_body(employees=12, third_parties=0, totalUrls=300, last_employee_compromised="2026-10-18T00:00:00.000Z",
                       stealerFamilies={"total": 12, "RedLine": 8, "Lumma": 4, "Vidar": 0})
    built, _ = _collect(_hudson(body))
    assert {(s["metric"], s["count"]) for s in built.summaries} == {
        ("infected-employees", 12), ("urls-held", 300), ("stealer-family:RedLine", 8), ("stealer-family:Lumma", 4)}
    (employees,) = [s for s in built.summaries if s["metric"] == "infected-employees"]
    assert employees["window_end"] == "2026-10-18T00:00:00Z"


def test_an_all_zero_response_writes_only_complete_checks():
    built, _ = _collect(_hudson(hudson_body()), kinds=("email", "website"))
    assert built.exposures == () and built.summaries == ()
    assert _checks(built) == {("email", "employee-urls"): ("complete", None), ("email", "domain-summary"): ("complete", None),
                              ("website", "user-urls"): ("complete", None), ("website", "domain-summary"): ("complete", None)}


def test_a_non_json_answer_is_a_failed_schema_check():
    page = httpx.Response(200, text="<html>Just a moment...</html>", headers={"content-type": "text/html"})
    built, _ = _collect(_hudson(handler=when_params({"domain": D}, page)))
    assert set(_checks(built).values()) == {("failed", "schema")} and built.exposures == ()


def test_a_429_after_retries_is_a_quota_failure(sleeps):
    built, _ = _collect(_hudson(handler=lambda request: httpx.Response(429)))
    assert set(_checks(built).values()) == {("failed", "quota")}


def test_hibp_skips_fabricated_and_spam_breaches_and_keeps_dataset_secret_types():
    def breach(name, **flags):
        return {"Name": name, "Domain": D, "BreachDate": "2019-05-24", "PwnCount": 1000,
                "DataClasses": ["Email addresses", "Passwords", "Auth tokens", "Physical addresses"],
                "IsVerified": True, "IsFabricated": False, "IsSpamList": False} | flags

    body = [breach("Example"), breach("Fake", IsFabricated=True), breach("Spam", IsSpamList=True)]
    hibp = HibpPublic(fake_http({HIBP_ROUTE: when_params({"domain": D}, httpx.Response(200, json=body))}))
    built, _ = _collect(hibp, kinds=("email", "website"))
    (row,) = built.exposures
    assert (row["source_name"], row["event_at"], row["event_date_basis"]) == ("Example", "2019-05-24", "breach")
    assert (row["exposure_type"], row["secret_evidence"]) == ("breach", "dataset")
    assert sorted(row["secret_types"]) == ["access-token", "password"]
    assert row["service_host"] == D and row["query_kind"] == "website"


def test_hibp_with_no_breaches_is_a_complete_check_and_no_rows():
    hibp = HibpPublic(fake_http({HIBP_ROUTE: httpx.Response(200, json=[])}))
    built, _ = _collect(hibp, kinds=("website",))
    assert built.exposures == () and _checks(built) == {("website", "breaches"): ("complete", None)}


def _live_http():
    return httpx.Client(timeout=60, headers={"User-Agent": "farpoint-tests"}, follow_redirects=True)


@pytest.mark.network
def test_hudsonrock_live_shape():
    provider = build_credential_providers(_live_http(), [HudsonRock(_live_http())])["hudsonrock-osint"]
    # Not example.com: Hudson Rock never answers for it (seen 2026-11-06), though it answers others in about a second.
    rows = collect_credentials([provider], ["tesla.com"], ("email", "website"), AT)
    built, _ = build_batch([(rows, "live")], ["tesla.com"], ("email", "website"), AT)
    assert {c["status"] for c in built.checks} == {"complete"}
    assert built.exposures and built.summaries


@pytest.mark.network
def test_hibp_live_shape():
    rows = collect_credentials([HibpPublic(_live_http())], ["adobe.com"], ("website",), AT)
    built, _ = build_batch([(rows, "live")], ["adobe.com"], ("website",), AT)
    assert [(r["source_name"], r["event_at"]) for r in built.exposures] == [("Adobe", "2013-10-04")]
