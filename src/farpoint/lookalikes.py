"""Lookalike triage: which registered lookalikes look set up to impersonate the organisation.

A lookalike that can handle mail (MX) or serve a website (an address) is looked up at its registry
(RDAP: when it was registered) and, if that was recent, in certificate transparency (crt.sh: its
newest certificate). Both are third parties: nothing is sent to the lookalike's own servers.
assess.derive turns the facts into findings.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import cache
from importlib import resources
from typing import Protocol

import httpx

from farpoint.enrich import Rdap
from farpoint.posture import registration
from farpoint.sources.base import HttpSource
from farpoint.names import normalize_ip
from farpoint.suffixes import registered

RECENT_DAYS = 365  # registered within this many days: new enough to be someone's set-up
RECHECK_DAYS = 30  # a known registration date is looked up again after this (a dropped domain can be re-registered)


class LookalikeLookups(Protocol):
    def registration(self, domain: str) -> dict | None: ...  # posture.registration() shape; None: no record at the registry

    def last_certificate(self, domain: str) -> str | None: ...  # YYYY-MM-DD the newest certificate starts


class NetworkLookalikeLookups:
    def __init__(self, rdap: Rdap, crtsh: HttpSource) -> None:
        self.rdap, self.crtsh = rdap, crtsh

    def registration(self, domain: str) -> dict | None:
        try:
            return registration(self.rdap.domain(domain))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    def last_certificate(self, domain: str) -> str | None:
        rows = self.crtsh.get("https://crt.sh/", params={"q": domain, "output": "json"}).json()
        starts = [r["not_before"][:10] for r in rows if isinstance(r, dict) and r.get("not_before")]
        return max(starts, default=None)


@dataclass
class LookalikeConfig:
    lookups: LookalikeLookups
    fresh: frozenset[str] = field(default_factory=frozenset)  # registration dates known and checked within RECHECK_DAYS


def fresh_registrations(report: Mapping | None, stamp: str) -> frozenset[str]:
    """Lookalikes whose registration date an earlier run found within RECHECK_DAYS of `stamp`."""
    when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    cutoff = (when - timedelta(days=RECHECK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return frozenset(
        r["domain"] for r in (report or {}).get("lookalikes", [])
        if r.get("registered_on") and isinstance(r.get("registration_checked"), str) and r["registration_checked"] >= cutoff
    )


def capable(row: Mapping) -> list[str]:
    """What a lookalike can be used for now: "mail" (it has MX), "web" (it has an address)."""
    return [what for what, has in (("mail", row.get("mx")), ("web", row.get("current_ips"))) if has]


@cache
def _parking_data() -> dict:
    return json.loads(resources.files("farpoint.data").joinpath("parking.json").read_text(encoding="utf-8"))


def _service_of(host: str, kind: str) -> str | None:
    domain = registered(host) or host
    return next((s["name"] for s in _parking_data()["services"] if domain in s.get(kind, [])), None)


def shared_nameservers(hosts: Iterable[str]) -> bool:
    """Whether `hosts` are nameservers a registrar, parking service or DNS host gives every customer."""
    shared = {d for s in _parking_data()["services"] for d in s.get("nameservers", [])} | set(_parking_data().get("shared_nameservers", []))
    return any((registered(h) or h) in shared for h in hosts)


@cache
def _parking_networks() -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    return [(ipaddress.ip_network(a), s["name"]) for s in _parking_data()["services"] for a in s.get("addresses", [])]


def _one(names: set[str | None]) -> str | None:
    return next(iter(names)) if len(names) == 1 and None not in names else None


def parked_at(mx: Iterable[str], ns: Iterable[str], ips: Iterable[str]) -> str | None:
    """The parking service a lookalike shows and nothing else: all its nameservers are the service's
    parking nameservers, or all its addresses are its parked-page addresses; and any mail host is the
    service's too (data/parking.json)."""
    ns_service = _one({_service_of(h, "nameservers") for h in ns}) if ns else None
    ip_service = _one({next((name for net, name in _parking_networks() if (a := normalize_ip(ip)) and ipaddress.ip_address(a) in net), None) for ip in ips}) if ips else None
    service = ns_service or ip_service
    if service and all(_service_of(m, "mail") == service or _service_of(m, "nameservers") == service for m in mx):
        return service
    return None
