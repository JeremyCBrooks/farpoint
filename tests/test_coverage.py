"""Hosts no source reported this run still get looked at: names InternetDB reports during enrichment,
and the inventory's earlier hosts."""

from farpoint.fingerprint import FingerprintConfig
from farpoint.models import IpDetails, Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution

from test_fingerprint import FakeProber
from test_pipeline import StaticSource, TableEnricher, dns_table
from test_posture import FakeDns

D = "example.com"
WWW, LEGACY, NEW = "93.184.216.34", "93.184.216.40", "93.184.216.50"


def pipeline(known=(), resolved=None):
    lookup = dns_table(resolved or {
        "www.example.com": Resolution(ips=(WWW,)),
        "legacy.example.com": Resolution(ips=(LEGACY,)),
        "vpn.example.com": Resolution(ips=(NEW,)),
    })
    enricher = TableEnricher({WWW: IpDetails(org="Example", hostnames={"vpn.example.com", "elsewhere.org"})})
    prober = FakeProber(ports={(ip, 443): "open" for ip in (WWW, LEGACY, NEW)})
    return Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", "www.example.com")])],
        lookup=lookup, enrichers=[enricher], dns=FakeDns({}), prober=prober,
        fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False),
        known=known,
    ), prober, enricher


def test_a_name_internetdb_reports_is_resolved_enriched_and_fingerprinted_in_the_same_run():
    run, prober, enricher = pipeline()

    inv = run.run([D])

    assert inv.hosts["vpn.example.com"].resolves is True and "elsewhere.org" not in inv.hosts
    assert NEW in enricher.seen  # its address is enriched too, so the sweep knows whose machine it is
    assert "vpn.example.com:443" in inv.services


def test_the_inventorys_earlier_hosts_are_resolved_again_and_fingerprinted_while_live(tmp_path):
    first, _, _ = pipeline(resolved={"www.example.com": Resolution(ips=(WWW,)), "legacy.example.com": Resolution(ips=(LEGACY,)), "gone.example.com": Resolution(ips=(LEGACY,))})
    first.sources = [StaticSource("otx", [Observation("otx", h) for h in ("www.example.com", "legacy.example.com", "gone.example.com")])]
    write_outputs(first.run([D]), tmp_path, "2026-10-01T00:00:00Z")

    second, prober, _ = pipeline(known=["legacy.example.com", "gone.example.com", "other.org"])  # gone.example.com no longer resolves
    report = write_outputs(second.run([D]), tmp_path, "2026-11-01T00:00:00Z")

    assert ("connect", LEGACY, 443) in prober.calls
    rows = {h["hostname"]: h for h in report["hosts"]}
    assert rows["legacy.example.com"]["last_seen"] == "2026-11-01T00:00:00Z" and rows["legacy.example.com"]["sources"] == ["dns", "otx"]
    # nothing vouched for it this run: its row is left as the last scan that saw it recorded it
    assert (rows["gone.example.com"]["last_seen"], rows["gone.example.com"]["resolves"]) == ("2026-10-01T00:00:00Z", True)
    assert "other.org" not in rows
