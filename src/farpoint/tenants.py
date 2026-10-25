"""Opt-in third-party tenant discovery: where else an organisation exists, on SaaS and cloud platforms.

Tenants are named after their customer (example.sharepoint.com, example-dev.appiancloud.com), and a
domain's own DNS says which platforms it uses: verification strings in its TXT records, the senders its
SPF record includes. Candidates come, in order, from:
  - tenant names a scan domain's TXT records give outright (example.onmicrosoft.com)
  - platforms the scan domains' own records point to (tied to the organisation by its records); for
    these the organisation's most used modifiers are tried too (example-dev)
  - zones this organisation's CNAMEs point into (tied by the CNAME)
  - every platform in a bundled table of generic tenant name patterns (a name match only)

Each candidate is looked up in DNS: the queries go to the platform's nameservers, not the
organisation's. Many platforms answer any name (wildcard DNS), so each pattern is first checked with
random names; there, a tenant counts only if it answers differently. One that can't be told apart is
kept only where the organisation's records point to the platform, as unverified.
"""

from __future__ import annotations

import json
import re
import secrets
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

from farpoint.guess import BARE, Taxonomy, parent_of
from farpoint.names import in_scope, normalize_hostname
from farpoint.suffixes import registered as _registered

TIES = ("name", "cname", "records")  # weakest first: what links a tenant to the organisation
MODIFIERS = 8  # the organisation's most used modifiers, tried on platforms its records point to
CNAME_ZONES = 15  # most common zones the organisation's CNAMEs point into
_SPF_RE = re.compile(r"(?:^|\s)(?:include:|redirect=)([^\s]+)", re.I)


@dataclass(frozen=True)
class Vendor:
    name: str
    patterns: tuple[str, ...]  # tenant names, {org} for the customer's name
    txt: tuple[str, ...] = ()  # a TXT string starting with one of these says the domain uses it
    spf: tuple[str, ...] = ()  # so does an SPF include ending in one of these


@dataclass(frozen=True)
class TenantConfig:
    budget: int = 800  # DNS lookups in all, random-name checks included
    known: Mapping[str, Sequence[str]] = field(default_factory=dict)  # earlier runs' hosts -> CNAMEs: modifiers and platforms
    vendors: Sequence[Vendor] | None = None  # None: the bundled table


@dataclass(frozen=True)
class Probe:
    """One tenant name pattern to try."""

    pattern: str
    vendor: str
    tie: str
    evidence: str
    expand: bool  # also try the organisation's modifiers
    records: tuple[tuple[str, str], ...] = ()  # for a "records" tie: (scan domain, evidence) per domain naming the platform

    def tie_for(self, domain: str) -> tuple[str, str]:
        """(tie, evidence) for a tenant named after `domain`: a domain's records tie only its own tenants."""
        if self.tie != "records":
            return self.tie, self.evidence
        why = next((why for d, why in self.records if d == domain), None)
        return ("records", why) if why else ("name", f"{self.vendor} tenant name pattern")

    def name(self, org: str) -> str:
        return self.pattern.format(org=org)

    @property
    def literal(self) -> bool:
        """A tenant name given outright (in a TXT record), not a pattern."""
        return "{org}" not in self.pattern


@cache
def bundled_vendors() -> tuple[Vendor, ...]:
    data = json.loads(resources.files("farpoint.data").joinpath("tenants.json").read_text(encoding="utf-8"))
    return tuple(
        Vendor(v["name"], tuple(v["patterns"]), tuple(v.get("txt", ())), tuple(v.get("spf", ()))) for v in data["vendors"]
    )


def org_tokens(domains: Iterable[str]) -> dict[str, str]:
    """What tenants are named after: each scan domain's first label (example.com -> example) -> the domain."""
    tokens: dict[str, str] = {}
    for d in domains:
        if "." in d:
            tokens.setdefault(d.split(".")[0], d)
    return tokens


def named_after(hostname: str, tokens: Mapping[str, str]) -> str | None:
    """The scan domain whose name a hostname's first label carries as a word (example-mft.vendor.co ->
    example.com), longest name first, so examplecorp-x is not taken for example-x."""
    parts = hostname.split(".")[0].split("-")
    for token in sorted(tokens, key=len, reverse=True):
        if token in parts:
            return tokens[token]
    return None


def spf_includes(txt: Iterable[str]) -> list[str]:
    return [m.lower().rstrip(".") for s in txt if s.lower().startswith("v=spf1") for m in _SPF_RE.findall(s)]


def registered(hostname: str) -> str:
    """A hostname's registered domain, or the name itself if it is a public suffix (naming a platform)."""
    return _registered(hostname) or hostname


def plan(
    domains: Sequence[str],
    txt: Mapping[str, Sequence[str]],
    cname_targets: Iterable[str],
    vendors: Sequence[Vendor],
) -> list[Probe]:
    """Tenant patterns to try, strongest tie first."""
    probes: dict[str, Probe] = {}

    def offer(probe: Probe) -> None:
        old = probes.get(probe.pattern)
        if old is None or TIES.index(probe.tie) > TIES.index(old.tie):
            probes[probe.pattern] = probe

    includes = {domain: spf_includes(txt.get(domain, ())) for domain in domains}
    claimed: set[str] = set()  # includes a table vendor explains
    for vendor in vendors:
        evidence = [(d, f"TXT '{s.split('=')[0][:40]}' on {d}") for d in domains for s in txt.get(d, ()) if vendor.txt and s.startswith(vendor.txt)]
        for d, incs in includes.items():
            for inc in incs:
                if vendor.spf and inc.endswith(vendor.spf):
                    evidence.append((d, f"SPF include:{inc} on {d}"))
                    claimed.add(inc)
        for pattern in vendor.patterns:
            if evidence:
                offer(Probe(pattern, vendor.name, "records", evidence[0][1], True, tuple(evidence)))
            else:
                offer(Probe(pattern, vendor.name, "name", f"{vendor.name} tenant name pattern", expand=False))
    senders: dict[str, list[tuple[str, str]]] = {}  # SPF senders no table entry explains: zone -> (domain, include)
    for d, incs in includes.items():
        for inc in incs:
            zone = registered(inc)
            if inc not in claimed and not any(in_scope(zone, own) for own in domains):
                senders.setdefault(zone, []).append((d, inc))
    for zone, seen in senders.items():
        records = tuple((d, f"SPF include:{inc} on {d}") for d, inc in seen)
        offer(Probe("{org}." + zone, zone, "records", records[0][1], True, records))
    for d in domains:  # a TXT string that is a hostname elsewhere names a tenant outright (example.onmicrosoft.com)
        for string in txt.get(d, ()):
            host = normalize_hostname(string) if "." in string and "=" not in string and " " not in string.strip() else None
            if host and "." in parent_of(host) and not any(in_scope(host, own) for own in domains):
                vendor = next((v.name for v in vendors for p in v.patterns if host.endswith(p.split("}", 1)[1])), registered(host))
                offer(Probe(host, vendor, "records", f"TXT '{host}' on {d}", False, ((d, f"TXT '{host}' on {d}"),)))
    zones = Counter(parent_of(t) for t in cname_targets if "." in parent_of(t) and not any(in_scope(t, own) for own in domains))
    for zone, n in zones.most_common(CNAME_ZONES):
        offer(Probe("{org}." + zone, zone, "cname", f"{n} CNAME target{'s' if n != 1 else ''} under {zone}", expand=False))
    return sorted(probes.values(), key=lambda p: -TIES.index(p.tie))


def org_modifiers(hosts: Mapping[str, Iterable[str]], domains: Sequence[str]) -> tuple[list[str], str]:
    """The organisation's most used modifiers and how it joins them ('-' or nothing)."""
    model = Taxonomy(hosts, domains)
    mods = [m for m, _ in model.mod_stems.most_common() if m != BARE and m.isalpha() and len(m) > 1][:MODIFIERS]
    sep = "-" if model.seps["-"] >= model.seps[""] else ""
    return mods, sep


def candidate_names(probe: Probe, tokens: Mapping[str, str], modifiers: Sequence[str], sep: str) -> list[tuple[str, str, bool]]:
    """(tenant name, scan domain it is named after, whether it is the bare name), bare names first."""
    if probe.literal:
        return [(probe.pattern, probe.records[0][0], True)]
    names = [(probe.name(t), d, True) for t, d in tokens.items()]
    if probe.expand:
        names += [(probe.name(f"{t}{sep}{m}"), d, False) for t, d in tokens.items() for m in modifiers]
    return names


def random_name(probe: Probe) -> str:
    if probe.literal:
        return f"{secrets.token_hex(8)}.{parent_of(probe.pattern)}"
    return probe.name(secrets.token_hex(8))
