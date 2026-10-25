from farpoint.models import Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.related import Profile, bundled_suffixes, split, tie, variants
from farpoint.suffixes import registered

from test_pipeline import StaticSource

SUFFIXES = ("com", "net", "org", "de", "com.au", "co.uk", "io")


def test_names_split_on_their_public_suffix():
    assert split("example.com.au") == ("example", "com.au")
    assert split("brand.ac.uk") == ("brand", "ac.uk")  # not just com/co/net/org second levels
    assert split("www.example.com") is None  # not a registered domain
    assert variants("example.com", SUFFIXES) == ["example.net", "example.org", "example.de", "example.com.au", "example.co.uk", "example.io"]


def test_registered_domains_follow_the_public_suffix_list():
    assert registered("www.example.co.uk") == "example.co.uk"
    assert registered("x.example.or.jp") == "example.or.jp"
    assert registered("co.uk") is None


def test_bundled_suffixes_are_iana_tlds_and_common_second_levels():
    suffixes = bundled_suffixes()
    assert {"com", "de", "com.au", "co.uk"} <= set(suffixes) and len(suffixes) > 1500
    assert not any(s.startswith("xn--") for s in suffixes)


def profile(ns=(), mx=(), a=()):
    return Profile(frozenset(ns), frozenset(mx), frozenset(a))


OWN_NS = ["ns1.example.com", "ns2.example.com"]
HOSTED_NS = ["ns01.dnshost.net", "ns02.dnshost.net"]


def tier(variant_profile, original_profile, redirects=()):
    profiles = {"example.com": original_profile, "example.de": variant_profile}
    result = tie("example.de", "example.com", profiles, {"example.com", "example-group.com"}, list(redirects), {})
    return result[0] if result else None


def test_one_signal_alone_is_at_most_medium():
    original = profile(ns=OWN_NS, mx=["mx.example.com"], a=["192.0.2.1"])
    assert tier(profile(ns=OWN_NS[:1]), original) == "medium"  # its own nameservers, not the same set
    assert tier(profile(), original, ["example.de", "www.example-group.com"]) == "medium"  # a direct redirect home
    assert tier(profile(mx=["mx.example.com"]), original) == "medium"  # the organisation's own mail host


def test_signals_that_agree_make_a_strong_tie():
    original = profile(ns=OWN_NS, mx=["mx.example.com"], a=["192.0.2.1"])
    assert tier(profile(ns=OWN_NS, a=["192.0.2.1"]), original) == "strong"
    assert tier(profile(ns=OWN_NS), original, ["example.de", "www.example.com"]) == "strong"
    hosted = profile(ns=HOSTED_NS, mx=["example-com.mail.protection.outlook.com"])
    assert tier(profile(ns=HOSTED_NS, mx=["example-com.mail.protection.outlook.com"]), hosted) == "strong"  # mail named after it


def test_what_unrelated_customers_of_one_provider_share_is_weak():
    hosted = profile(ns=HOSTED_NS, mx=["aspmx.l.mailhost.com"], a=["198.51.100.7"])
    assert tier(profile(ns=HOSTED_NS, mx=["aspmx.l.mailhost.com"], a=["198.51.100.7"]), hosted) == "weak"
    assert tier(profile(ns=HOSTED_NS), hosted) == "weak"
    assert tier(profile(ns=["ns.other.net"]), hosted) is None


def test_a_redirect_home_through_someone_elses_host_is_weak():
    original = profile(ns=OWN_NS)
    assert tier(profile(), original, ["example.de", "track.affiliates.net", "www.example.com"]) == "weak"
    assert tier(profile(), original, ["example.de", "www.example.de"]) is None  # landing on itself is no tie


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

    def redirects(self, name):
        return self.landings.get(name, [])

    def network_owner(self, ip):
        return None


def run(net, tmp_path=None):
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com")])
    inv = Pipeline(sources=[src], related=net).run(["example.com"])
    return inv, (write_outputs(inv, tmp_path) if tmp_path else None)


def test_related_domains_are_found_tied_and_reported_but_never_scanned(tmp_path, monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    net = FakeNet(
        zones={
            "example.com": {"NS": ["ns1.example.com"], "MX": ["mx.example.com"]},
            "example.de": {"NS": ["ns1.example.com"]},  # served by the organisation's own nameservers
            "example.io": {"NS": ["ns.parking.net"], "A": ["198.51.100.9"]},  # someone else's
            "example.co.uk": {"NS": ["ns.other.net"]},
        },
        landings={"example.co.uk": ["example.co.uk", "www.example.com"]},
        tenants={"example.com": ["example.com", "mail.example.com", "examplebrand.com", "example.onmicrosoft.com", "x.smtp.vendor.cloud"]},
    )
    inv, report = run(net, tmp_path)
    assert {d: r.tie for d, r in inv.related.items()} == {"examplebrand.com": "strong", "example.co.uk": "medium", "example.de": "medium"}
    assert "mail.example.com" in inv.hosts and "m365" in inv.hosts["mail.example.com"].sources  # in scope: a host
    assert "vendor.cloud" not in inv.related  # a vendor's host in the tenant is not the organisation's domain
    assert "example.io" in inv.lookalikes  # registered, no tie
    assert not any(h.endswith((".de", ".co.uk", ".io")) or h == "examplebrand.com" for h in inv.hosts)  # never added to scope
    assert report["related"][0]["tie"] == "strong"
    assert report["related"][0]["domain"] == "examplebrand.com"
    assert "examplebrand.com,example.com,strong" in (tmp_path / "related.csv").read_text()


def test_a_suffix_that_answers_any_name_is_skipped(monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    monkeypatch.setattr(pipeline, "random_under", lambda s: f"random.{s}")
    net = FakeNet(zones={"example.com": {"NS": ["ns1.example.com"]}, "example.io": {"NS": ["ns1.example.com"]}, "random.io": {"NS": ["ns.wild"]}})
    inv, _ = run(net)
    assert "example.io" not in inv.related and "example.io" not in inv.lookalikes


def test_no_related_lookups_unless_asked():
    inv = Pipeline(sources=[StaticSource("crtsh", [])]).run(["example.com"])
    assert inv.related == {}


def test_every_scan_domain_with_the_name_is_compared(monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    net = FakeNet(zones={
        "example.com": {"NS": ["ns1.example.com"]},
        "example.io": {"NS": ["ns9.unrelated.net"]},
        "example.de": {"NS": ["ns1.example.com"]},  # tied to example.com only
    })
    inv = Pipeline(sources=[], related=net).run(["example.com", "example.io"])
    assert inv.related["example.de"].related_to == "example.com"


def test_a_domain_no_longer_tied_leaves_related(tmp_path, monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)
    zones = {"example.com": {"NS": ["ns1.example.com"]}, "example.de": {"NS": ["ns1.example.com"]}}
    write_outputs(run(FakeNet(zones))[0], tmp_path, "2026-01-01T00:00:00Z")
    zones["example.de"] = {"NS": ["ns.squatter.net"]}  # lapsed and re-registered by someone else
    report = write_outputs(run(FakeNet(zones))[0], tmp_path, "2026-01-02T00:00:00Z")
    assert report["related"] == []
    assert "example.de" in {r["domain"] for r in report["lookalikes"]}


def test_a_lookup_that_times_out_is_an_error_not_unregistered(monkeypatch):
    from farpoint import pipeline

    monkeypatch.setattr(pipeline, "bundled_suffixes", lambda: SUFFIXES)

    class Flaky(FakeNet):
        def records(self, name, rdtype):
            if name == "example.de":
                raise TimeoutError("lifetime exceeded")
            return super().records(name, rdtype)

    inv, _ = run(Flaky(zones={"example.com": {"NS": ["ns1.example.com"]}}))
    assert ("related-ns", "example.de") in {(e.source, e.target) for e in inv.errors}
    assert "example.de" not in inv.related_checked


def test_a_null_mx_is_no_shared_mail_host():
    class NullMx(FakeNet):
        pass

    net = NullMx(zones={"example.de": {"NS": ["ns.parking.net"], "MX": [""]}, "example.com": {"NS": ["ns1.example.com"], "MX": [""]}})
    profiles = {n: Profile.of(net, n) for n in ("example.de", "example.com")}
    assert profiles["example.de"].mx == frozenset()
    assert tie("example.de", "example.com", profiles, {"example.com"}) is None
