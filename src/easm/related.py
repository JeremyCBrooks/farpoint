"""Opt-in discovery of related domains: other registered domains the same organisation owns.

Two methods, both starting from nothing but the scan domains:
  - Microsoft 365: the domains verified in the tenant a scan domain belongs to (Exchange autodiscover's
    federation information). Only an owner can verify a domain, so these are the organisation's.
    Subdomains of the scan domains it lists are in scope and join the inventory.
  - TLD swap: the scan domain's name under every other suffix (example.com -> example.de,
    example.com.au), from a bundled list of all IANA top-level domains and common second levels.
    Registered ones are tied to the organisation by evidence:
      strong  listed in its Microsoft 365 tenant; redirects to one of its domains; or the same
              nameservers plus a shared mail host or address
      medium  served by the organisation's own nameservers (hosts under its own domains)
      weak    the same nameservers at an outside DNS provider, or a shared address (the evidence
              names the address's network owner: a company's own network or a hosting provider's)
    Registered variants with no tie are lookalikes: maybe someone else's, maybe a squatter's.

A related domain is never added to the scan: owning a domain is not permission to scan it.
Lookups go to the registries' and the variants' nameservers, plus one HTTP request to each
registered variant (to see where it redirects) and one to Microsoft per scan domain.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Protocol

import httpx

TIERS = ("weak", "medium", "strong")
AUTODISCOVER = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
_FEDERATION = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">{url}</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>"""


class Probes(Protocol):
    """What related-domain discovery asks the network."""

    def tenant_domains(self, domain: str) -> list[str]: ...  # Microsoft 365 tenant's verified domains

    def records(self, name: str, rdtype: str) -> list[str] | None: ...  # None: the name doesn't exist

    def landing(self, name: str) -> str | None: ...  # the host a browser ends up on

    def network_owner(self, ip: str) -> str | None: ...  # who the address's network is registered to


class NetworkProbes:
    def __init__(self, http: httpx.Client, records, network_owner) -> None:
        self.http = http
        self.records = records
        self._owner = network_owner

    def tenant_domains(self, domain: str) -> list[str]:
        body = _FEDERATION.format(url=AUTODISCOVER, domain=domain)
        action = "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"
        response = self.http.post(AUTODISCOVER, content=body, headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action}"'})
        response.raise_for_status()
        return sorted({d.lower() for d in re.findall(r"<Domain>([^<]+)</Domain>", response.text)})

    def landing(self, name: str) -> str | None:
        for scheme in ("https", "http"):
            try:
                return self.http.get(f"{scheme}://{name}/", timeout=15, follow_redirects=True).url.host.lower()
            except httpx.HTTPError:
                continue
        return None

    def network_owner(self, ip: str) -> str | None:
        owner = self._owner(ip)
        return owner.strip().lower() if owner else None


@cache
def bundled_suffixes() -> tuple[str, ...]:
    text = resources.files("easm.data").joinpath("suffixes.txt").read_text(encoding="utf-8")
    return tuple(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def split(domain: str, suffixes: Iterable[str]) -> tuple[str, str] | None:
    """(name, suffix) of a registered domain: example.com.au -> (example, com.au). None if `domain` is
    not one label directly under a known suffix."""
    known = set(suffixes)
    labels = domain.split(".")
    for i in range(1, len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in known:
            return (labels[i - 1], suffix) if i == 1 else None
    return None


def registered(host: str, suffixes: Iterable[str]) -> str | None:
    """The registered domain a host is under (www.example.com.au -> example.com.au), longest suffix first."""
    known = set(suffixes)
    labels = host.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in known:
            return ".".join(labels[i - 1 :])
    return None


def variants(domain: str, suffixes: Sequence[str]) -> list[str]:
    parts = split(domain, suffixes)
    if parts is None:
        return []
    name, own = parts
    return [f"{name}.{s}" for s in suffixes if s != own]


def random_under(suffix: str) -> str:
    return f"{secrets.token_hex(8)}.{suffix}"


@dataclass(frozen=True)
class Profile:
    ns: frozenset[str]
    mx: frozenset[str]
    a: frozenset[str]

    @staticmethod
    def of(probes: Probes, name: str, ns: Sequence[str] | None = None) -> Profile:
        get = lambda rdtype: frozenset(probes.records(name, rdtype) or ())
        return Profile(frozenset(ns) if ns is not None else get("NS"), get("MX"), get("A"))


def tie(
    variant: str,
    original: str,
    profiles: Mapping[str, Profile],
    own: set[str],
    tenant: set[str],
    landing: str | None,
    owners: Mapping[str, str | None],
    suffixes: Iterable[str],
) -> tuple[str, str] | None:
    """(tier, evidence) linking `variant` to the organisation that owns `original`, or None.
    `own`: the organisation's registered domains (scan domains and its tenant's); `owners`: network
    owner per address the two share."""
    v, o = profiles[variant], profiles[original]
    if variant in tenant:
        return "strong", f"in the Microsoft 365 tenant of {original}"
    if landing and registered(landing, suffixes) in own and registered(landing, suffixes) != variant:
        return "strong", f"redirects to {landing}"
    same_ns = bool(v.ns) and v.ns == o.ns
    if same_ns and (v.mx & o.mx or v.a & o.a):
        shared = "mail host" if v.mx & o.mx else "address"
        return "strong", f"same nameservers as {original} and a shared {shared}"
    if same_ns and all(registered(ns, suffixes) in own for ns in v.ns):
        return "medium", f"served by {original}'s own nameservers ({', '.join(sorted(v.ns))})"
    if same_ns:
        return "weak", f"same nameservers as {original} ({', '.join(sorted(v.ns))})"
    if shared := sorted(v.a & o.a):
        owner = owners.get(shared[0])
        return "weak", f"shares {shared[0]} with {original}" + (f" (network: {owner})" if owner else "")
    return None
