"""--udp: DNS, NTP and IKE on the organisation's own addresses, one ordinary question each."""

import struct

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from farpoint.assess import derive
from farpoint.fingerprint import FingerprintConfig
from farpoint.models import IpDetails, Observation
from farpoint.output import run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.probe import UdpResult
from farpoint.resolve import Resolution
from farpoint.udp import UDP_PORTS

from test_fingerprint import FakeProber
from test_pipeline import StaticSource, TableEnricher, dns_table
from test_posture import FakeDns

D = "example.com"
OURS, CDN = "93.184.216.34", "151.101.1.1"
CISCO_UNITY = bytes.fromhex("12f5f28c457168a9702d9fe274cc0100")


def resolver_answer(query: bytes, recursive=True) -> bytes:
    q = dns.message.from_wire(query)
    r = dns.message.make_response(q)
    if q.question[0].rdclass == dns.rdataclass.CH:
        r.answer.append(dns.rrset.from_text("version.bind.", 0, "CH", "TXT", '"9.18.24"'))
    elif recursive:
        r.flags |= dns.flags.RA
        r.answer.append(dns.rrset.from_text(q.question[0].name, 300, "IN", "A", "192.0.2.1"))
    else:
        r.set_rcode(dns.rcode.REFUSED)
    return r.to_wire()


def ike_answer(request: bytes, cookie: bytes | None = None, vendor_ids=(CISCO_UNITY,)) -> bytes:
    payloads, next_type = b"", 0
    for vid in reversed(vendor_ids):
        payloads = struct.pack("!BBH", next_type, 0, 4 + len(vid)) + vid + payloads
        next_type = 13
    header = (cookie or request[:8]) + b"\x11" * 8 + struct.pack("!BBBBII", next_type, 0x10, 2, 0, 0, 28 + len(payloads))
    return header + payloads


def ntp_answer(request: bytes) -> bytes:
    assert request[0] & 0x07 == 3  # a client asking the time, nothing else
    return bytes([0x1C, 2]) + b"\x00" * 46  # version 3, mode 4 (server), stratum 2


def scenario(udp, recursive=True, ike_cookie=None):
    prober = FakeProber(ports={(OURS, 443): "open", (CDN, 443): "open"})
    prober.udp_ = {
        (OURS, 53): lambda payload: UdpResult("open", resolver_answer(payload, recursive)),
        (OURS, 123): lambda payload: UdpResult("open", ntp_answer(payload)),
        (OURS, 500): lambda payload: UdpResult("open", ike_answer(payload, ike_cookie)),
        (CDN, 53): lambda payload: UdpResult("open", resolver_answer(payload)),
    }
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", h) for h in ("vpn.example.com", "gw.example.com", "www.example.com")])],
        lookup=dns_table({"vpn.example.com": Resolution(ips=(OURS,)), "gw.example.com": Resolution(ips=(OURS,)),
                          "www.example.com": Resolution(ips=(CDN,))}),
        enrichers=[TableEnricher({CDN: IpDetails(org="Fastly, Inc.")})], dns=FakeDns({}), prober=prober,
        fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False, udp=udp),
    )
    return pipeline, prober


def test_udp_services_are_asked_once_per_own_address_and_judged_once_per_address():
    pipeline, prober = scenario(UDP_PORTS)

    inv = pipeline.run([D])

    sent = [(c[1], c[2]) for c in prober.calls if c[0] == "udp"]
    assert sorted(set(sent)) == [(OURS, 53), (OURS, 123), (OURS, 500)]  # never the CDN's address
    dns_svc, ike = inv.services["gw.example.com:53/udp"], inv.services["vpn.example.com:500/udp"]
    assert dns_svc.service == "dns" and "open-resolver" in dns_svc.signals and dns_svc.banner == "version.bind: 9.18.24"
    assert ike.service == "ike" and "Cisco Unity" in ike.banner
    assert inv.services["gw.example.com:123/udp"].banner == "NTP version 3, stratum 2"
    findings = {(f["kind"], f["target"]): f for f in derive(run_report(inv))}
    assert findings[("open-resolver", f"{OURS}:53/udp")]["level"] == "medium"
    assert findings[("exposed-service", f"{OURS}:500/udp")]["level"] == "medium"
    assert findings[("exposed-service", f"{OURS}:123/udp")]["level"] == "low"
    assert not [k for k in findings if k[1].startswith("gw.example.com:53")]  # judged per address, not per name


def test_an_authoritative_only_server_and_a_stray_ike_answer_make_no_finding():
    pipeline, _ = scenario(UDP_PORTS, recursive=False, ike_cookie=b"\x99" * 8)

    inv = pipeline.run([D])

    assert "open-resolver" not in inv.services["gw.example.com:53/udp"].signals
    assert "gw.example.com:500/udp" not in inv.services  # its cookie isn't ours: not an answer to us
    kinds = {f["kind"] for f in derive(run_report(inv))}
    assert "open-resolver" not in kinds


def test_without_udp_nothing_is_sent_and_a_refused_port_drops_its_old_row(tmp_path):
    pipeline, prober = scenario(())
    pipeline.run([D])
    assert not [c for c in prober.calls if c[0] == "udp"]

    pipeline, prober = scenario(UDP_PORTS)
    write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")
    pipeline, prober = scenario(UDP_PORTS)
    prober.udp_[(OURS, 123)] = lambda payload: UdpResult("closed", b"")  # ICMP port unreachable
    prober.udp_[(OURS, 500)] = lambda payload: UdpResult("filtered", b"")  # no answer: unknown, keep the row
    report = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z")

    endpoints = {r["endpoint"] for r in report["fingerprints"]}
    assert "gw.example.com:123/udp" not in endpoints and "gw.example.com:500/udp" in endpoints
    assert {r["transport"] for r in report["fingerprints"] if r["endpoint"].endswith("/udp")} == {"udp"}
