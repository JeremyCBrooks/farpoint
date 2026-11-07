"""--out-of-scope: names and addresses the authorisation carves out are recorded, never contacted."""

import pytest

from farpoint import cli
from farpoint.fingerprint import FingerprintConfig
from farpoint.guess import GuessConfig
from farpoint.models import Observation
from farpoint.names import Exclusions
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution

from test_fingerprint import FakeProber
from test_pipeline import StaticSource, dns_table
from test_posture import FakeDns

D = "example.com"
OURS, THEIRS, NS_IP = "93.184.216.34", "151.101.1.1", "199.43.135.53"  # public: private and documentation addresses are never probed anyway


def test_exclusions_cover_a_name_and_everything_under_it_and_whole_address_ranges():
    ex = Exclusions.parse(["shop.example.com", "198.51.100.0/24", "2001:db8::1"])

    assert ex.host("shop.example.com") and ex.host("eu.shop.example.com")
    assert not ex.host("myshop.example.com") and not ex.host("example.com")
    assert ex.ip("198.51.100.200") and ex.ip("2001:db8::1") and not ex.ip(OURS)
    with pytest.raises(ValueError, match="not a hostname or address range"):
        Exclusions.parse(["not a host!"])


def scenario(exclusions):
    hosts = ("www.example.com", "shop.example.com", "pay.shop.example.com", "partner.example.com", "mx.example.com")
    lookup = dns_table({
        "www.example.com": Resolution(ips=(OURS,)),
        "shop.example.com": Resolution(ips=(OURS,)),  # excluded by name, though it shares our address
        "pay.shop.example.com": Resolution(ips=(OURS,)),
        "partner.example.com": Resolution(ips=(THEIRS,)),  # excluded by address
        "mx.example.com": Resolution(ips=(THEIRS,)),
        "ns1.example.com": Resolution(ips=(NS_IP,)),
    })
    dns = FakeDns({
        D: {"MX": ["mx.example.com"], "NS": ["ns1.example.com"], "TXT": ["v=spf1 -all"]},
        "_mta-sts.example.com": {"TXT": ["v=STSv1; id=1"]},
        "ns1.example.com": {"A": [NS_IP]},
    })
    prober = FakeProber(ports={(OURS, 443): "open", (THEIRS, 443): "open"})
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", h) for h in hosts])],
        lookup=lookup, dns=dns, prober=prober,
        fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False),
        exclusions=Exclusions.parse(exclusions),
    )
    return pipeline, prober


def test_excluded_names_and_addresses_are_kept_in_the_inventory_but_never_contacted():
    pipeline, prober = scenario(["shop.example.com", f"{THEIRS}/32", "mta-sts.example.com", NS_IP])

    inv = pipeline.run([D])

    assert {"shop.example.com", "pay.shop.example.com", "partner.example.com"} <= set(inv.hosts)  # still discovered
    contacted_hosts = {c[2] for c in prober.calls if c[0] == "http"} | {c[1] for c in prober.calls if c[0] == "tls"}
    contacted_ips = {c[1] for c in prober.calls if c[0] in ("connect", "banner", "axfr")}
    assert contacted_hosts == {"www.example.com"}
    assert THEIRS not in contacted_ips and NS_IP not in contacted_ips
    assert not [c for c in prober.calls if c[0] == "smtp"]  # the MX is at an excluded address
    assert set(inv.services) == {"www.example.com:443"}
    assert inv.excluded == {"shop.example.com", "pay.shop.example.com", "partner.example.com", "mx.example.com"}


def test_an_excluded_policy_host_or_nameserver_leaves_its_answer_unknown_not_missing():
    control, prober = scenario([])
    assert control.run([D]).posture[D]["mta_sts"] == "broken" and ("axfr", NS_IP, D) in prober.calls  # asked when allowed
    pipeline, _ = scenario(["mta-sts.example.com", NS_IP])

    posture = pipeline.run([D]).posture[D]

    assert posture["mta_sts"] == "unknown"  # never "broken": nobody asked
    assert posture["axfr"] is None and posture["ns"] == ["ns1.example.com"]


def test_guessing_never_tests_names_under_an_excluded_one():
    lookup_calls = []

    def lookup(host):
        lookup_calls.append(host)
        return Resolution(ips=(OURS,)) if host in ("app-dev.example.com", "shop-dev.example.com") else Resolution()

    hosts = ["app.example.com", "app-prod.example.com", "shop.example.com", "api-dev.example.com", "api-prod.example.com"]
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", h, OURS) for h in hosts])],
        lookup=lookup, guess=GuessConfig(budget=60), exclusions=Exclusions.parse(["shop.example.com", "shop-dev.example.com"]),
    )

    inv = pipeline.run([D])

    assert "app-dev.example.com" in lookup_calls and "app-dev.example.com" in inv.hosts  # the same pattern, in scope
    assert not [h for h in lookup_calls if h == "shop-dev.example.com" or h.endswith(".shop.example.com")]


def test_cli_rejects_a_bad_exclusion_and_reads_them_from_a_file(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--out-of-scope", "bad entry!", "-o", str(tmp_path)])
    assert "--out-of-scope" in capsys.readouterr().err

    listed = tmp_path / "carve-outs.txt"
    listed.write_text("# agreed with the client\nshop.example.com\n198.51.100.0/24\n", encoding="utf-8")
    assert cli.parse_exclusions([f"@{listed}", "partner.example.com"]).host("partner.example.com")
    assert cli.parse_exclusions([f"@{listed}"]).ip("198.51.100.9")


def test_a_nameserver_excluded_by_name_is_never_asked_for_a_zone_transfer():
    pipeline, prober = scenario(["ns1.example.com"])

    posture = pipeline.run([D]).posture[D]

    assert not [c for c in prober.calls if c[0] == "axfr"] and posture["axfr"] is None  # not asked: unknown


def test_a_host_excluded_by_name_is_not_probed_by_address_through_its_range():
    import ipaddress

    pipeline, prober = scenario(["shop.example.com", "pay.shop.example.com", "www.example.com"])  # every name at OURS
    pipeline.ranges = (ipaddress.ip_network(f"{OURS}/32"),)

    pipeline.run([D])

    assert not [c for c in prober.calls if c[0] == "connect" and c[1] == OURS]


def test_fetch_tries_a_hosts_other_addresses_when_one_is_excluded(monkeypatch):
    import socket

    from farpoint import probe
    from farpoint.probe import NetworkProber, OutOfScope

    tried = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kw: [(None, None, None, "", (ip, port)) for ip in (THEIRS, OURS)])
    monkeypatch.setattr(NetworkProber, "_guard", lambda self, ip, fn: tried.append(ip) or None)
    assert NetworkProber(exclusions=Exclusions.parse([THEIRS])).fetch("https://mta-sts.example.com/x") is None
    assert tried == [OURS]
    with pytest.raises(OutOfScope):
        NetworkProber(exclusions=Exclusions.parse([THEIRS, OURS])).fetch("https://mta-sts.example.com/x")
