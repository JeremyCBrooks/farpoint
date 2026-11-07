"""Opt-in UDP checks (--udp): what DNS, NTP and IKE say on the organisation's own addresses.

Each port gets the most ordinary question its protocol has, and nothing that amplifies, authenticates
or negotiates further:

- DNS (53): one recursive query for a name outside the organisation's domains, to see whether the
  server resolves for anyone (an open resolver), and `version.bind` in the CHAOS class, which many
  servers answer with their software and version.
- NTP (123): one client time request (mode 3). Never the mode 6/7 queries (`monlist`) that amplify.
- IKE (500): the first message of an IKEv1 Main Mode exchange with one common proposal. A gateway's
  answer, accepting or refusing, carries its vendor IDs. Never Aggressive Mode, whose answer includes a
  hash of the pre-shared key that can be cracked offline.

This module decides what to send and what an answer means; farpoint.probe sends it.
"""

from __future__ import annotations

import json
import secrets
import struct
from functools import cache
from importlib import resources

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from farpoint.models import ServiceRecord
from farpoint.probe import Prober

UDP_PORTS = (53, 123, 500)
RECURSION_TEST_NAME = "www.iana.org"  # anyone's resolver can answer it; an authoritative-only server refuses it
NTP_CLIENT_REQUEST = bytes([0x1B]) + bytes(47)  # LI 0, version 3, mode 3 (client)
_IKE_VENDOR_ID, _IKE_NOTIFY = 13, 11


@cache
def bundled_ike_vendors() -> tuple[tuple[str, str], ...]:
    data = json.loads(resources.files("farpoint.data").joinpath("ike_vendors.json").read_text(encoding="utf-8"))
    return tuple((v["prefix"].lower(), v["name"]) for v in data["vendors"])


def ike_main_mode(cookie: bytes) -> bytes:
    """An IKEv1 Main Mode SA proposal: AES-128, SHA-1, pre-shared key, DH group 2, 8 hours."""
    attributes = ((1, 7), (14, 128), (2, 2), (3, 1), (4, 2), (11, 1), (12, 28800))
    attrs = b"".join(struct.pack("!HH", 0x8000 | t, v) for t, v in attributes)
    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack("!BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    return cookie + bytes(8) + struct.pack("!BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa)) + sa


def parse_ike(data: bytes, cookie: bytes) -> dict | None:
    """The version, vendor IDs and any notification in an answer to our proposal; None if it isn't one."""
    if len(data) < 28 or data[:8] != cookie:
        return None
    next_type, version = data[16], data[17]
    vendor_ids, notify, pos = [], None, 28
    while next_type and pos + 4 <= len(data):
        following, _, length = struct.unpack("!BBH", data[pos : pos + 4])
        if length < 4:
            break
        body = data[pos + 4 : pos + length]
        if next_type == _IKE_VENDOR_ID:
            vendor_ids.append(body.hex())
        elif next_type == _IKE_NOTIFY and len(body) >= 8:
            notify = struct.unpack("!H", body[6:8])[0]
        next_type, pos = following, pos + length
    return {"version": f"{version >> 4}.{version & 0x0F}", "vendor_ids": vendor_ids, "notify": notify}


def vendor_names(vendor_ids: list[str]) -> list[str]:
    names = []
    for vid in vendor_ids:
        name = next((n for prefix, n in bundled_ike_vendors() if vid.lower().startswith(prefix)), None)
        names.append(name or f"unknown {vid[:16]}")
    return names


def _dns(prober: Prober, ip: str, name: str, rdtype: str, rdclass: str = "IN", recursive: bool = True):
    query = dns.message.make_query(name, rdtype, rdclass)
    if not recursive:
        query.flags &= ~dns.flags.RD
    answer = prober.udp(ip, 53, query.to_wire())
    if answer.state != "open":
        return answer.state, None
    try:
        reply = dns.message.from_wire(answer.data)
    except dns.exception.DNSException:
        return "open", None
    return "open", reply if reply.id == query.id else None


def check(prober: Prober, host: str, ip: str, port: int) -> tuple[str, ServiceRecord | None]:
    """(state, what answered). state is closed only on ICMP port unreachable; a silence is filtered."""
    rec = ServiceRecord(host, ip, port, service="udp", transport="udp")
    if port == 53:
        state, reply = _dns(prober, ip, RECURSION_TEST_NAME, "A")
        if reply is None:
            return state if state != "open" else "filtered", None
        rec.service = "dns"
        if reply.rcode() == dns.rcode.NOERROR and reply.flags & dns.flags.RA and reply.answer:
            rec.signals.append("open-resolver")
        _, version = _dns(prober, ip, "version.bind", "TXT", "CH", recursive=False)
        texts = [b.decode("utf-8", "replace") for rrset in (version.answer if version else []) for r in rrset if r.rdtype == dns.rdatatype.TXT for b in r.strings]
        if texts:
            rec.banner = f"version.bind: {texts[0][:120]}"
        return "open", rec
    if port == 123:
        answer = prober.udp(ip, port, NTP_CLIENT_REQUEST)
        if answer.state != "open" or len(answer.data) < 48 or answer.data[0] & 0x07 not in (4, 5):
            return answer.state if answer.state != "open" else "filtered", None
        rec.service = "ntp"
        rec.banner = f"NTP version {(answer.data[0] >> 3) & 0x07}, stratum {answer.data[1]}"
        return "open", rec
    if port == 500:
        cookie = secrets.token_bytes(8)
        answer = prober.udp(ip, port, ike_main_mode(cookie))
        parsed = parse_ike(answer.data, cookie) if answer.state == "open" else None
        if parsed is None:
            return answer.state if answer.state != "open" else "filtered", None
        rec.service = "ike"
        vendors = vendor_names(parsed["vendor_ids"])
        rec.banner = f"IKE {parsed['version']}" + (f"; vendor IDs: {', '.join(vendors)}" if vendors else "")
        return "open", rec
    raise ValueError(f"no UDP check for port {port}")
