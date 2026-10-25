"""Opt-in discovery of related domains: other registered domains the same organisation owns.

Two methods, both starting from nothing but the scan domains:
  - Microsoft 365: the domains verified in the tenant a scan domain belongs to (Exchange autodiscover's
    federation information). Only an owner can verify a domain, so these are the organisation's.
    Subdomains of the scan domains it lists are in scope and join the inventory.
  - TLD swap: the scan domain's name under every other suffix (example.com -> example.de,
    example.com.au), from a bundled list of all IANA top-level domains and common second levels.
    Registered ones are tied to the organisation by evidence, each signal on its own being at most
    medium, because providers, parking services and squatters can each fake one:
      strong  served by the organisation's own nameservers plus a shared mail host, address or a
              redirect home; or the same nameservers plus a redirect home or a mail host of the
              organisation's own (named after it or under its domains)
      medium  one of those alone: its own nameservers; a direct redirect home; its own mail host
      weak    the same nameservers at an outside provider, a shared address or generic mail host,
              or a redirect home through someone else's host (as affiliate schemes do)
    Registered variants with no tie are lookalikes: maybe someone else's, maybe a squatter's.

A related domain is never added to the scan: owning a domain is not permission to scan it.
Lookups go to the registries' and the variants' nameservers, plus one HTTP request to each
registered variant (to see where it redirects) and one to Microsoft per scan domain.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Protocol

import httpx

from farpoint.suffixes import registered

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

    def redirects(self, name: str) -> list[str]: ...  # hosts a browser passes through, last the one it ends on

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

    def redirects(self, name: str) -> list[str]:
        for scheme in ("https", "http"):
            try:
                response = self.http.get(f"{scheme}://{name}/", timeout=15, follow_redirects=True)
            except httpx.HTTPError:
                continue
            return [r.url.host.lower() for r in [*response.history, response]]
        return []

    def network_owner(self, ip: str) -> str | None:
        owner = self._owner(ip)
        return owner.strip().lower() if owner else None


@cache
def bundled_suffixes() -> tuple[str, ...]:
    """Suffixes the TLD swap tries (not a public suffix list: see farpoint.suffixes for that)."""
    text = resources.files("farpoint.data").joinpath("suffixes.txt").read_text(encoding="utf-8")
    return tuple(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def split(domain: str) -> tuple[str, str] | None:
    """(name, suffix) of a registered domain: example.com.au -> (example, com.au); None otherwise."""
    if registered(domain) != domain:
        return None
    name, _, suffix = domain.partition(".")
    return name, suffix


def variants(domain: str, suffixes: Sequence[str]) -> list[str]:
    parts = split(domain)
    if parts is None:
        return []
    name, own = parts
    # a suffix the PSL doesn't list (co.de) or lists only by wildcard (*.za) gives no registered domain
    return [v for s in suffixes if s != own and split(v := f"{name}.{s}")]


def random_under(suffix: str) -> str:
    return f"{secrets.token_hex(8)}.{suffix}"


@dataclass(frozen=True)
class Profile:
    ns: frozenset[str]
    mx: frozenset[str]
    a: frozenset[str]

    @staticmethod
    def of(probes: Probes, name: str, ns: Sequence[str] | None = None) -> Profile:
        get = lambda rdtype: frozenset(r for r in probes.records(name, rdtype) or () if r)  # never an empty name
        return Profile(frozenset(ns) if ns is not None else get("NS"), get("MX"), get("A"))


def tie(
    variant: str,
    original: str,
    profiles: Mapping[str, Profile],
    own: set[str],
    redirects: Sequence[str] = (),
    owners: Mapping[str, str | None] | None = None,
) -> tuple[str, str] | None:
    """(tier, evidence) linking `variant` to the organisation that owns `original`, or None.
    `own`: the organisation's registered domains (scan domains and its tenant's); `redirects`: the
    hosts loading `variant` in a browser passes through, last the one it ends on; `owners`: network
    owner per address the two share."""
    v, o = profiles[variant], profiles[original]
    names = {d.split(".")[0] for d in own}
    ours = lambda host: registered(host) in own
    named_ours = lambda host: ours(host) or bool(names & set(re.split(r"[.-]", host)))
    signals: dict[str, str] = {}
    if v.ns and all(ours(ns) for ns in v.ns):
        signals["own-ns"] = f"served by the organisation's own nameservers ({', '.join(sorted(v.ns))})"
    elif v.ns and v.ns == o.ns:
        signals["same-ns"] = f"the same nameservers as {original} ({', '.join(sorted(v.ns))})"
    if redirects and ours(redirects[-1]) and registered(redirects[-1]) != variant:
        others = sorted({registered(h) or h for h in redirects[:-1]} - own - {variant})
        if others:
            signals["redirect-via"] = f"redirects to {redirects[-1]} through {', '.join(others)}"
        else:
            signals["redirect"] = f"redirects to {redirects[-1]}"
    if mail := sorted(m for m in v.mx & o.mx if named_ours(m)):
        signals["own-mx"] = f"shares the organisation's mail host {mail[0]}"
    elif mail := sorted(v.mx & o.mx):
        signals["shared-mx"] = f"shares the mail host {mail[0]} with {original}"
    if shared := sorted(v.a & o.a):
        owner = (owners or {}).get(shared[0])
        signals["shared-a"] = f"shares {shared[0]} with {original}" + (f" (network: {owner})" if owner else "")
    if not signals:
        return None
    has = signals.keys()
    if ("own-ns" in has and has & {"own-mx", "shared-mx", "shared-a", "redirect"}) or ("same-ns" in has and has & {"redirect", "own-mx"}):
        tier = "strong"
    elif has & {"own-ns", "redirect", "own-mx"}:
        tier = "medium"
    else:
        tier = "weak"
    return tier, "; ".join(signals.values())
