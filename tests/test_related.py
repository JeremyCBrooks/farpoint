from easm.models import Observation
from easm.output import write_outputs
from easm.pipeline import Pipeline
from easm.related import Profile, bundled_suffixes, registered, split, tie, variants

from test_pipeline import StaticSource

SUFFIXES = ("com", "net", "org", "de", "com.au", "co.uk", "io")


def test_names_split_on_the_longest_known_suffix():
    assert split("example.com.au", SUFFIXES) == ("example", "com.au")
    assert split("www.example.com", SUFFIXES) is None  # not a registered domain
    assert registered("www.example.co.uk", SUFFIXES) == "example.co.uk"
    assert variants("example.com", SUFFIXES) == ["example.net", "example.org", "example.de", "example.com.au", "example.co.uk", "example.io"]


def test_bundled_suffixes_are_iana_tlds_and_common_second_levels():
    suffixes = bundled_suffixes()
    assert {"com", "de", "com.au", "co.uk"} <= set(suffixes) and len(suffixes) > 1500
    assert not any(s.startswith("xn--") for s in suffixes)


def profile(ns=(), mx=(), a=()):
    return Profile(frozenset(ns), frozenset(mx), frozenset(a))


def test_tie_tiers():
    own = {"example.com", "example-group.com"}
    profiles = {
        "example.com": profile(ns=["ns1.example.com", "ns2.example.com"], mx=["mx.mailhost.net"], a=["192.0.2.1"]),
        "example.org": profile(ns=["ns1.example.com", "ns2.example.com"]),  # its own nameservers
        "example.net": profile(ns=["ns1.example.com", "ns2.example.com"], mx=["mx.mailhost.net"]),
        "example.de": profile(ns=["a.dnshost.net", "b.dnshost.net"]),
        "example.io": profile(a=["192.0.2.1"]),
        "example.co.uk": profile(ns=["ns.parking.net"]),
    }
    t = lambda v, landing=None, tenant=(): tie(v, "example.com", profiles, own, set(tenant), landing, {"192.0.2.1": "example corp"}, SUFFIXES)
    assert t("example.co.uk", tenant=["example.co.uk"]) == ("strong", "in the Microsoft 365 tenant of example.com")
    assert t("example.co.uk", landing="www.example-group.com") == ("strong", "redirects to www.example-group.com")
    assert t("example.co.uk", landing="www.example.co.uk") is None  # landing on itself is no tie
    assert t("example.net")[0] == "strong"  # same nameservers and mail host
    assert t("example.org")[0] == "medium"
    assert t("example.io") == ("weak", "shares 192.0.2.1 with example.com (network: example corp)")
    profiles["example.com"] = profile(ns=["a.dnshost.net", "b.dnshost.net"])
    assert t("example.de")[0] == "weak"  # the same outside DNS provider's nameservers: not enough alone


class FakeNet:
    """A tiny internet: names -> {rdtype: records}, landings, tenants."""

    def __init__(self, zones, landings=None, tenants=None):
        self.zones, self.landings, self.tenants = zones, landings or {}, tenants or {}
        self.asked = []

    def tenant_domains(self, domain):
        return self.tenants.get(domain, [])

    def records(self, name, rdtype):
        self.asked.append(name)
        zone = self.zones.get(name)
        return None if zone is None else zone.get(rdtype, [])

    def landing(self, name):
        return self.landings.get(name)

    def network_owner(self, ip):
        return None


def run(net, tmp_path=None):
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com")])
    inv = Pipeline(sources=[src], related=net).run(["example.com"])
    return inv, (write_outputs(inv, tmp_path) if tmp_path else None)


def test_related_domains_are_found_tied_and_reported_but_never_scanned(tmp_path, monkeypatch):
    from easm import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    net = FakeNet(
        zones={
            "example.com": {"NS": ["ns1.example.com"], "MX": ["mx.example.com"]},
            "example.de": {"NS": ["ns1.example.com"]},  # served by the organisation's own nameservers
            "example.io": {"NS": ["ns.parking.net"], "A": ["198.51.100.9"]},  # someone else's
            "example.co.uk": {"NS": ["ns.other.net"]},
        },
        landings={"example.co.uk": "www.example.com"},
        tenants={"example.com": ["example.com", "mail.example.com", "examplebrand.com", "example.onmicrosoft.com", "x.smtp.vendor.cloud"]},
    )
    inv, report = run(net, tmp_path)
    assert {d: r.tie for d, r in inv.related.items()} == {"examplebrand.com": "strong", "example.co.uk": "strong", "example.de": "medium"}
    assert "mail.example.com" in inv.hosts and "m365" in inv.hosts["mail.example.com"].sources  # in scope: a host
    assert "vendor.cloud" not in inv.related  # a vendor's host in the tenant is not the organisation's domain
    assert "example.io" in inv.lookalikes  # registered, no tie
    assert not any(h.endswith((".de", ".co.uk", ".io")) or h == "examplebrand.com" for h in inv.hosts)  # never added to scope
    assert report["related"][0]["tie"] == "strong"
    assert "examplebrand.com,example.com,strong" in (tmp_path / "related.csv").read_text()


def test_a_suffix_that_answers_any_name_is_skipped(monkeypatch):
    from easm import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    monkeypatch.setattr(pipeline, "random_under", lambda s: f"random.{s}")
    net = FakeNet(zones={"example.com": {"NS": ["ns1.example.com"]}, "example.io": {"NS": ["ns1.example.com"]}, "random.io": {"NS": ["ns.wild"]}})
    inv, _ = run(net)
    assert "example.io" not in inv.related and "example.io" not in inv.lookalikes


def test_no_related_lookups_unless_asked():
    inv = Pipeline(sources=[StaticSource("crtsh", [])]).run(["example.com"])
    assert inv.related == {}
