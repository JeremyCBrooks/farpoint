from datetime import date, timedelta

import httpx
import pytest

from conftest import fake_http, when_params
from farpoint.enrich import NoRdapService, Rdap
from farpoint.lookalikes import LookalikeConfig, NetworkLookalikeLookups, fresh_registrations
from farpoint.models import Observation
from farpoint.output import merge_reports, run_report
from farpoint.pipeline import WILDCARD_PROBES, Pipeline
from farpoint.resolve import Resolution
from farpoint.sources.web import CrtSh

from test_pipeline import StaticSource

RECENT = (date.today() - timedelta(days=50)).isoformat()
OLD = "2001-01-01"


class FakeLookups:
    def __init__(self, created=None, certificates=None, failing=(), unknown=()):
        self.created, self.certificates, self.failing, self.unknown = created or {}, certificates or {}, set(failing), set(unknown)
        self.registrations, self.certificate_calls = [], []

    def registration(self, domain):
        self.registrations.append(domain)
        if domain in self.failing:
            raise httpx.ConnectError("registry unreachable")
        if domain in self.unknown:
            raise NoRdapService(domain.rsplit(".", 1)[-1])
        created = self.created.get(domain)
        return None if created is None else {"registrar": "Example Registrar", "created": created, "expires": None, "status": []}

    def last_certificate(self, domain):
        self.certificate_calls.append(domain)
        return self.certificates.get(domain)


def lookalike(domain, ip=None, mx=()):
    return Observation("dnstwist", domain, ip, lookalike=True, mx=mx, ns=("ns1.host.net",))


def scan(lookups, *observations, fresh=frozenset(), lookup=None):
    source = StaticSource("dnstwist", list(observations))
    source.collect = lambda domain: list(observations)
    return Pipeline(sources=[source], lookalikes=LookalikeConfig(lookups, fresh), lookup=lookup).run(["example.com"])


def test_only_lookalikes_that_can_mail_or_serve_are_looked_up():
    lookups = FakeLookups()
    scan(lookups, lookalike("mail.com", mx=("mx.mail.com",)), lookalike("web.com", "192.0.2.1"), lookalike("idle.com"))

    assert sorted(lookups.registrations) == ["mail.com", "web.com"]


def test_a_certificate_is_looked_up_only_for_a_recent_registration():
    lookups = FakeLookups(created={"new.com": RECENT, "old.com": OLD}, certificates={"new.com": "2026-09-02"})
    inv = scan(lookups, lookalike("new.com", "192.0.2.1"), lookalike("old.com", "192.0.2.2"))

    assert lookups.certificate_calls == ["new.com"]
    rows = {r["domain"]: r for r in run_report(inv)["lookalikes"]}
    assert (rows["new.com"]["registered_on"], rows["new.com"]["last_certificate"]) == (RECENT, "2026-09-02")
    assert (rows["old.com"]["registered_on"], rows["old.com"]["last_certificate"]) == (OLD, None)


def test_a_recently_checked_registration_is_not_asked_again():
    lookups = FakeLookups()
    scan(lookups, lookalike("known.com", "192.0.2.1"), fresh=frozenset({"known.com"}))
    assert lookups.registrations == []

    report = {"lookalikes": [
        {"domain": "fresh.com", "registered_on": "2026-01-01", "registration_checked": "2026-10-21T00:00:00Z"},
        {"domain": "stale.com", "registered_on": "2026-01-01", "registration_checked": "2026-09-21T00:00:00Z"},
        {"domain": "unknown.com", "registered_on": None, "registration_checked": "2026-10-21T00:00:00Z"},
    ]}
    assert fresh_registrations(report, "2026-10-31T00:00:00Z") == {"fresh.com"}
    assert fresh_registrations(None, "2026-10-31T00:00:00Z") == frozenset()


def test_a_failed_lookup_is_an_error_and_leaves_the_date_unknown():
    lookups = FakeLookups(created={"ok.com": OLD}, failing={"down.com"})
    inv = scan(lookups, lookalike("down.com", "192.0.2.1"), lookalike("ok.com", "192.0.2.2"))

    assert [(e.source, e.target) for e in inv.errors] == [("rdap-domain", "down.com")]
    rows = {r["domain"]: r for r in run_report(inv)["lookalikes"]}
    assert rows["down.com"]["registered_on"] is None and not rows["down.com"]["registration_checked"]
    assert rows["ok.com"]["registered_on"] == OLD and rows["ok.com"]["registration_checked"]


def test_network_lookups_read_rdap_and_crtsh():
    http = fake_http({
        "data.iana.org/rdap/dns.json": httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]}),
        "rdap.example/domain/a.com": httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2026-09-01T10:00:00Z"}]}),
        "crt.sh/": when_params({"q": "a.com", "output": "json"}, httpx.Response(200, json=[
            {"not_before": "2025-01-01T00:00:00"}, {"not_before": "2026-09-02T08:00:00"},
        ])),
    })
    lookups = NetworkLookalikeLookups(Rdap(http, retries=0), CrtSh(http, retries=0))

    assert lookups.registration("a.com")["created"] == "2026-09-01"
    assert lookups.registration("gone.com") is None  # the registry has no record
    assert lookups.last_certificate("a.com") == "2026-09-02"


def test_a_tld_without_an_rdap_service_is_unknown_not_unregistered():
    asked = []
    http = fake_http({
        "data.iana.org/rdap/dns.json": httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]}),
        "rdap.org/domain/example.io": lambda request: asked.append(request.url) or httpx.Response(404),
    })
    lookups = NetworkLookalikeLookups(Rdap(http, retries=0), CrtSh(http, retries=0))

    with pytest.raises(NoRdapService) as caught:
        lookups.registration("example.io")
    assert caught.value.tld == "io"
    assert asked == []  # rdap.org has nothing the IANA registry lacks: don't ask it


def test_rdap_orgs_own_404_is_unknown_but_a_registrys_404_means_no_record():
    http = fake_http({
        "data.iana.org/rdap/dns.json": httpx.Response(503),  # the bootstrap is down: everything goes to rdap.org
        "rdap.org/domain/example.io": httpx.Response(404),  # rdap.org knows no registry for .io
        "rdap.org/domain/gone.com": httpx.Response(302, headers={"location": "https://rdap.example/domain/gone.com"}),
        "rdap.example/domain/gone.com": httpx.Response(404),  # the registry has no such domain
    })
    lookups = NetworkLookalikeLookups(Rdap(http, retries=0), CrtSh(http, retries=0))

    with pytest.raises(NoRdapService):
        lookups.registration("example.io")
    assert lookups.registration("gone.com") is None


def test_a_name_under_someone_elses_domain_is_looked_up_by_that_registered_domain():
    http = fake_http({
        "data.iana.org/rdap/dns.json": httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]}),
        "rdap.example/domain/ample.com": httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2026-09-01T10:00:00Z"}]}),
    })
    lookups = NetworkLookalikeLookups(Rdap(http, retries=0), CrtSh(http, retries=0))

    assert lookups.registration("ex.ample.com")["created"] == "2026-09-01"  # dnstwist's dot insertion of example.com


def test_lookalikes_under_tlds_without_rdap_get_one_error_and_stay_unknown():
    lookups = FakeLookups(created={"ok.com": OLD}, unknown={"examp1e.io", "exampel.io", "example.de"})
    inv = scan(lookups, *(lookalike(d, "192.0.2.1") for d in ("examp1e.io", "exampel.io", "example.de", "ok.com")))

    assert [(e.source, e.target) for e in inv.errors] == [("rdap-domain", ".de .io")]
    assert "3 lookalikes" in inv.errors[0].message
    rows = {r["domain"]: r for r in run_report(inv)["lookalikes"]}
    assert rows["examp1e.io"]["registered_on"] is None and not rows["examp1e.io"]["registration_checked"]  # asked again next run
    assert rows["ok.com"]["registration_checked"]


def test_a_name_under_someone_elses_wildcard_is_not_dated_by_that_domain():
    asked = []

    def lookup(host):  # ample.com answers every name; ampel.com only its own
        asked.append(host)
        if host.endswith(".ample.com"):
            return Resolution(ips=("192.0.2.5",))
        return Resolution(ips=("192.0.2.6",)) if host == "ex.ampel.com" else Resolution()

    lookups = FakeLookups(created={"ex.ampel.com": RECENT, "examp1e.com": RECENT})
    inv = scan(lookups, lookalike("ex.ample.com", "192.0.2.5"), lookalike("ex.ampel.com", "192.0.2.6"), lookalike("examp1e.com", "192.0.2.7"), lookup=lookup)

    assert sorted(lookups.registrations) == ["ex.ampel.com", "examp1e.com"]  # not ex.ample.com: any name there answers the same
    rows = {r["domain"]: r for r in run_report(inv)["lookalikes"]}
    assert rows["ex.ample.com"]["registered_on"] is None and inv.errors == []
    wildcard_checks = [h for h in asked if h.count(".") == 2 and h.endswith((".ample.com", ".ampel.com")) and not h.startswith("ex.")]
    assert sorted(h.split(".", 1)[1] for h in wildcard_checks) == ["ampel.com"] * WILDCARD_PROBES + ["ample.com"] * WILDCARD_PROBES  # none for examp1e.com


def test_a_split_name_with_mail_servers_and_no_address_is_dated_despite_an_address_wildcard():
    # The wildcard check looks at addresses only, so it says nothing about a name set up to receive mail.
    lookups = FakeLookups(created={"ex.ample.com": RECENT})
    inv = scan(lookups, lookalike("ex.ample.com", mx=("mx.ex.ample.com",)), lookup=lambda host: Resolution(ips=("192.0.2.5",)))

    assert lookups.registrations == ["ex.ample.com"]


def test_a_split_name_whose_wildcard_check_gets_no_answer_stays_undated():
    lookups = FakeLookups(created={"ex.ample.com": RECENT})
    inv = scan(lookups, lookalike("ex.ample.com", "192.0.2.5"), lookup=lambda host: Resolution(timed_out=True))

    assert lookups.registrations == []
    assert [(e.source, e.target) for e in inv.errors] == [("lookalikes", "ample.com")]


def test_split_names_left_undated_without_dns_lookups_are_reported():
    lookups = FakeLookups(created={"ex.ample.com": RECENT, "examp1e.com": RECENT})
    inv = scan(lookups, lookalike("ex.ample.com", "192.0.2.5"), lookalike("examp1e.com", "192.0.2.7"))  # no lookup: --no-resolve

    assert lookups.registrations == ["examp1e.com"]
    assert [(e.source, e.target) for e in inv.errors] == [("lookalikes", "ex.ample.com")]


def test_merge_keeps_the_last_known_registration():
    def row(**fields):
        return {"domains": ["example.com"], "hosts": [], "ips": [], "errors": [], "skipped_sources": [], "lookalikes": [
            {"domain": "a.com", "ips": [], "current_ips": [], "mx": [], "ns": [], "sources": ["dnstwist"], **fields}
        ]}

    first = merge_reports(None, row(registered_on="2026-09-01", registrar="R", registration_checked=True, last_certificate="2026-09-02"), "2026-10-01T00:00:00Z")
    assert first["lookalikes"][0]["registration_checked"] == "2026-10-01T00:00:00Z"

    second = merge_reports(first, row(registered_on=None, registrar=None, registration_checked=False, last_certificate=None), "2026-10-02T00:00:00Z")
    kept = second["lookalikes"][0]
    assert (kept["registered_on"], kept["registration_checked"], kept["last_certificate"]) == ("2026-09-01", "2026-10-01T00:00:00Z", "2026-09-02")

    third = merge_reports(second, row(registered_on="2026-10-02", registrar="R2", registration_checked=True, last_certificate=None), "2026-10-03T00:00:00Z")
    assert (third["lookalikes"][0]["registered_on"], third["lookalikes"][0]["registration_checked"]) == ("2026-10-02", "2026-10-03T00:00:00Z")


def test_a_defensive_typo_on_the_organisations_own_nameservers_is_not_flagged_without_fingerprinting():
    from farpoint.assess import derive

    class Dns:
        def records(self, name, rdtype, strict=False):
            return {("example.com", "NS"): ["kate.ns.cloudflare.com", "rob.ns.cloudflare.com"], ("example.com", "MX"): ["mx.example.com"]}.get((name, rdtype), [])

        def txt(self, name):
            return []

    own = Observation("dnstwist", "examp1e.com", "192.0.2.1", lookalike=True, ns=("rob.ns.cloudflare.com", "kate.ns.cloudflare.com"))
    source = StaticSource("dnstwist", [own])
    source.collect = lambda domain: [own]
    inv = Pipeline(sources=[source], dns=Dns(), lookalikes=LookalikeConfig(FakeLookups(created={"examp1e.com": RECENT}))).run(["example.com"])
    report = merge_reports(None, run_report(inv), "2026-10-31T00:00:00Z")

    assert not [f for f in derive(report) if f["kind"].startswith("lookalike-")]
