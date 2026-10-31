from datetime import date, timedelta

import httpx

from conftest import fake_http, when_params
from farpoint.enrich import Rdap
from farpoint.lookalikes import LookalikeConfig, NetworkLookalikeLookups, fresh_registrations
from farpoint.models import Observation
from farpoint.output import merge_reports, run_report
from farpoint.pipeline import Pipeline
from farpoint.sources.web import CrtSh

from test_pipeline import StaticSource

RECENT = (date.today() - timedelta(days=50)).isoformat()
OLD = "2001-01-01"


class FakeLookups:
    def __init__(self, created=None, certificates=None, failing=()):
        self.created, self.certificates, self.failing = created or {}, certificates or {}, set(failing)
        self.registrations, self.certificate_calls = [], []

    def registration(self, domain):
        self.registrations.append(domain)
        if domain in self.failing:
            raise httpx.ConnectError("registry unreachable")
        created = self.created.get(domain)
        return None if created is None else {"registrar": "Example Registrar", "created": created, "expires": None, "status": []}

    def last_certificate(self, domain):
        self.certificate_calls.append(domain)
        return self.certificates.get(domain)


def lookalike(domain, ip=None, mx=()):
    return Observation("dnstwist", domain, ip, lookalike=True, mx=mx, ns=("ns1.host.net",))


def scan(lookups, *observations, fresh=frozenset()):
    source = StaticSource("dnstwist", list(observations))
    source.collect = lambda domain: list(observations)
    return Pipeline(sources=[source], lookalikes=LookalikeConfig(lookups, fresh)).run(["example.com"])


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
