"""Ransomware leak-site claims against the organisation (--ransomware, from ransomware.live): kept only when
the claim names an in-scope domain, recorded without the links to the stolen data, and judged by age."""

import csv
from datetime import date

import httpx
import pytest

from conftest import fake_http
from farpoint.assess import derive
from farpoint.models import Observation
from farpoint.output import ReportError, load_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.sources.base import UnexpectedResponse
from farpoint.sources.ransomwarelive import RansomwareLive

from test_pipeline import StaticSource
from test_related import SUFFIXES, FakeNet

D = "example.com"
FREE = "api.ransomware.live/v2/searchvictims/"
PRO = "api-pro.ransomware.live/victims/search"
LEAK = "http://leaksiteabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop.onion/Thread-Example"


def free_victim(victim, domain, group="Akira", discovered="2026-10-02T08:00:00+00:00", ident="RXhhbXBsZUBBa2lyYQ=="):
    return {"victim": victim, "domain": domain, "group": group, "attackdate": "2026-10-01T00:00:00+00:00", "discovered": discovered,
            "country": "GB", "activity": "Manufacturing", "url": f"https://www.ransomware.live/id/{ident}", "claim_url": LEAK,
            "description": "Example Ltd makes widgets.\nLeak: https://gofile.io/d/AbCdEf", "screenshot": "https://images.ransomware.live/victims/x.png",
            "press": None, "ransom": None, "data_size": "120GB"}


def pro_victim(victim, website, ident="RXhhbXBsZUBBa2lyYQ"):
    return {"id": ident, "post_title": victim, "group_name": "Akira", "discovered": "2026-10-02T08:00:00+00:00",
            "published": "2026-10-01T00:00:00+00:00", "website": website, "country": "GB", "activity": "Manufacturing",
            "post_url": LEAK, "ransom": None, "data_size": "120GB", "screenshot": "https://images.ransomware.live/victims/x.png",
            "infostealer": "", "press": None, "permalink": f"https://www.ransomware.live/id/{ident}"}


def test_only_claims_naming_an_in_scope_domain_are_kept_and_never_their_leak_links():
    http = fake_http({FREE + D: httpx.Response(200, json=[
        free_victim("Example Ltd", "example.com"),
        free_victim("Example Shop", "WWW.Example.com", ident="c2hvcA=="),
        free_victim("Not Example", "notexample.com", ident="bm90"),  # the keyword is a substring of someone else's domain
        free_victim("Example Australia", "example.com.au", ident="YXU="),
        free_victim("Example Holdings", "", ident="aG9sZA=="),  # a name alone: company names collide
    ])})

    claims = RansomwareLive(http).claims(D)

    assert {(c["victim"], c["domain"]) for c in claims} == {("Example Ltd", "example.com"), ("Example Shop", "www.example.com")}
    ltd = next(c for c in claims if c["victim"] == "Example Ltd")
    assert ltd["group"] == "Akira" and ltd["discovered"].startswith("2026-10-02") and ltd["reference"].startswith("https://www.ransomware.live/id/")
    assert ".onion" not in repr(claims) and "gofile" not in repr(claims) and "images.ransomware.live" not in repr(claims)


def test_a_domain_nobody_claimed_is_an_empty_answer_but_a_page_that_isnt_one_fails():
    nothing = httpx.Response(404, json={"error": f"No victims found for keyword '{D}'."})
    assert RansomwareLive(fake_http({FREE + D: nothing})).claims(D) == []

    with pytest.raises(UnexpectedResponse):
        RansomwareLive(fake_http({FREE + D: httpx.Response(200, text="<html>Just a moment...</html>")})).claims(D)
    with pytest.raises(httpx.HTTPStatusError):  # a 404 that isn't the "no victims" answer is not "no claims"
        RansomwareLive(fake_http({FREE + D: httpx.Response(404, text="Not Found")})).claims(D)


def test_with_a_key_the_pro_api_gives_the_same_claim_under_the_same_id():
    seen = []

    def pro(request):
        seen.append(request)
        return httpx.Response(200, json={"client": "someone@example.org", "query": D, "count": 2,
                                         "victims": [pro_victim("Example Ltd", "example.com"), pro_victim("Other", "other.org", ident="b3RoZXI")]})

    free = RansomwareLive(fake_http({FREE + D: httpx.Response(200, json=[free_victim("Example Ltd", "example.com")])})).claims(D)
    paid = RansomwareLive(fake_http({PRO: pro}), "k3y").claims(D)

    assert seen[0].headers["x-api-key"] == "k3y" and seen[0].url.params["q"] == D
    assert paid == free  # same fields, and the id without base64 padding, so the two merge as one claim
    assert ".onion" not in repr(paid) and "someone@example.org" not in repr(paid)


def test_the_free_api_is_asked_once_a_minute(sleeps):
    http = fake_http({FREE + D: httpx.Response(200, json=[free_victim("Example Ltd", "example.com")]),
                      FREE + "example.org": httpx.Response(404, json={"error": "No victims found for keyword 'example.org'."})})

    inv = Pipeline(sources=[], ransomware=RansomwareLive(http)).run([D, "example.org"])

    assert [c["victim"] for c in inv.ransomware_claims.values()] == ["Example Ltd"]
    assert len(sleeps) == 1 and sleeps[0] >= 60


class FakeClaims:
    def __init__(self, by_domain, failing=()):
        self.by_domain, self.failing, self.asked = by_domain, set(failing), []

    def claims(self, domain):
        self.asked.append(domain)
        if domain in self.failing:
            raise httpx.ConnectError("refused")
        return [dict(c) for c in self.by_domain.get(domain, [])]


def claim(domain, ident, discovered="2026-10-02T08:00:00+00:00", victim="Example Ltd"):
    return {"id": ident, "victim": victim, "domain": domain, "group": "Akira", "attackdate": "2026-10-01T00:00:00+00:00",
            "discovered": discovered, "country": "GB", "activity": "Manufacturing", "reference": f"https://www.ransomware.live/id/{ident}"}


def test_a_failed_search_is_an_error_not_an_all_clear(tmp_path):
    inv = Pipeline(sources=[], ransomware=FakeClaims({}, failing={D})).run([D])

    report = write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")

    assert any(e.source == "ransomware" and e.target == D for e in inv.errors)
    assert not inv.ransomware_claims and not (tmp_path / "ransomware.csv").exists()
    assert not [f for f in derive(report) if f["kind"] == "ransomware-claim"]


def test_strongly_tied_sister_domains_are_searched_too_and_say_so(monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    net = FakeNet(zones={"example.com": {"NS": ["ns1.example.com"]}, "example.de": {"NS": ["ns1.example.com"]}},
                  tenants={"example.com": ["example.com", "examplebrand.com"]})
    claims = FakeClaims({"examplebrand.com": [claim("examplebrand.com", "YnJhbmQ")]})

    inv = Pipeline(sources=[StaticSource("crtsh", [Observation("crtsh", "www.example.com")])], related=net, ransomware=claims).run([D])

    assert {d: r.tie for d, r in inv.related.items()} == {"examplebrand.com": "strong", "example.de": "medium"}
    assert claims.asked == [D, "examplebrand.com"]  # not the medium tie
    assert inv.ransomware_claims["YnJhbmQ"]["scope_domain"] == "examplebrand.com"
    assert inv.ransomware_claims["YnJhbmQ"]["related_to"] == D


def test_claims_accumulate_across_scans_and_are_listed(tmp_path):
    first = Pipeline(sources=[], ransomware=FakeClaims({D: [claim(D, "b2xk", "2024-03-01T00:00:00+00:00")]})).run([D])
    write_outputs(first, tmp_path, "2026-10-01T00:00:00Z")
    second = Pipeline(sources=[], ransomware=FakeClaims({D: [claim(D, "bmV3")]})).run([D])  # the old post has gone from the search

    report = write_outputs(second, tmp_path, "2026-11-01T00:00:00Z")

    assert {(c["id"], c["first_seen"], c["last_seen"]) for c in report["ransomware"]} == {
        ("b2xk", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"), ("bmV3", "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z")}
    with open(tmp_path / "ransomware.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["id"] for r in rows} == {"b2xk", "bmV3"} and set(rows[0]) >= {"victim", "domain", "group", "discovered", "reference", "scope_domain", "first_seen"}


def test_an_inventory_with_a_claim_it_cant_merge_is_refused_before_the_scan(tmp_path):
    (tmp_path / "assets.json").write_text('{"domains": ["example.com"], "ransomware": [{"victim": "Example Ltd"}]}', encoding="utf-8")

    with pytest.raises(ReportError, match=r"ransomware\[0\] has no 'id'"):
        load_report(tmp_path)


def test_a_recent_claim_is_high_an_old_one_medium_and_a_sister_domains_one_level_lower():
    recent, old = "2026-06-01T00:00:00+00:00", "2024-06-01T00:00:00+00:00"
    report = {"domains": [D], "ransomware": [
        {**claim(D, "cmVjZW50", recent), "scope_domain": D, "related_to": "", "last_seen": "2026-11-01T00:00:00Z"},
        {**claim(D, "b2xk", old), "scope_domain": D, "related_to": ""},
        {**claim("examplebrand.com", "YnJhbmQ", recent), "scope_domain": "examplebrand.com", "related_to": D},
        {**claim("examplebrand.com", "b2xkYnJhbmQ", old), "scope_domain": "examplebrand.com", "related_to": D},
        {**claim(D, "bm9kYXRl", ""), "attackdate": "", "scope_domain": D, "related_to": ""},  # no date: can't call it recent
    ]}

    findings = {f["id"].rsplit("|", 1)[1]: f for f in derive(report, today=date(2026, 11, 19)) if f["kind"] == "ransomware-claim"}

    assert {i: f["level"] for i, f in findings.items()} == {"cmVjZW50": "high", "b2xk": "medium", "YnJhbmQ": "medium", "b2xkYnJhbmQ": "low", "bm9kYXRl": "medium"}
    assert "Akira" in findings["cmVjZW50"]["detail"] and "2026-06-01" in findings["cmVjZW50"]["detail"]
    assert findings["cmVjZW50"]["evidence"] == ["https://www.ransomware.live/id/cmVjZW50"] and findings["cmVjZW50"]["seen"] == "2026-11-01T00:00:00Z"
    assert "examplebrand.com" in findings["YnJhbmQ"]["detail"] and D in findings["YnJhbmQ"]["detail"]


@pytest.mark.network
def test_a_victim_ransomware_live_lists_is_found_by_its_domain():
    with httpx.Client(timeout=60, follow_redirects=True) as http:
        recent = http.get("https://api.ransomware.live/v2/recentvictims").json()
        victim = next(v for v in recent if v.get("domain") and "." in v["domain"] and "/" not in v["domain"])
        domain = victim["domain"].lower().removeprefix("www.")

        claims = RansomwareLive(http).claims(domain)

    assert any(c["victim"] == victim["victim"] and c["group"] == victim["group"] for c in claims)
