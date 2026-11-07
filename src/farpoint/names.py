"""Hostname / IP normalization and scoping. Every source's raw output passes through here."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z][a-z0-9-]{{1,62}}$")


def normalize_hostname(raw: str) -> str | None:
    """Lowercase, strip wildcard/trailing dot; None if not a plausible public FQDN."""
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not _HOSTNAME_RE.match(name):
        return None
    return name


# Answers a filtering resolver gives in place of a blocked name's real address (Cisco Umbrella /
# OpenDNS block pages): they say the resolver refused the name, not where the name points.
BLOCK_PAGES = (ipaddress.ip_network("146.112.61.104/29"),)


def normalize_ip(raw: str | None) -> str | None:
    """Canonical form of an address (an IPv4-mapped IPv6 one as IPv4); None if it isn't one, or is a
    filtering resolver's block page."""
    if raw is None:
        return None
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in BLOCK_PAGES):
        return None
    return str(ip)


def is_public_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def in_scope(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


@dataclass(frozen=True)
class Exclusions:
    """What the authorisation carves out of the scan domains (--out-of-scope): a name excludes itself and
    every name under it, an address or range every address in it. Excluded hosts are still recorded
    from public data; farpoint never contacts them."""

    names: frozenset[str] = frozenset()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def parse(cls, entries: Iterable[str]) -> Exclusions:
        names, networks = set(), []
        for raw in entries:
            entry = raw.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            name = normalize_hostname(entry)
            if name is None or entry.startswith("*"):
                raise ValueError(f"{entry!r} is not a hostname or address range")
            names.add(name)
        return cls(frozenset(names), tuple(networks))

    def __bool__(self) -> bool:
        return bool(self.names or self.networks)

    def host(self, hostname: str) -> bool:
        return any(in_scope(hostname, n) for n in self.names)

    def ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.networks if net.version == addr.version)


def extract_hostnames(text: str, domain: str) -> set[str]:
    """Pull every in-scope hostname out of arbitrary text (HTML, CLI output, URLs)."""
    pattern = re.compile(
        rf"(?<![a-z0-9_.-])((?:[a-z0-9_-]+\.)*{re.escape(domain)})(?!\.?[a-z0-9_-])",
        re.IGNORECASE,
    )
    found = (normalize_hostname(m) for m in pattern.findall(text))
    return {h for h in found if h and in_scope(h, domain)}


def parse_domains(lines: Iterable[str]) -> list[str]:
    """Turn user input (bare domains, URLs, comments) into a de-duplicated, ordered domain list."""
    domains: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = urlsplit(line).hostname if "://" in line else line
        name = normalize_hostname(host or "")
        if name and name not in domains:
            domains.append(name)
    return domains
