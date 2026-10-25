"""Hostname / IP normalization and scoping. Every source's raw output passes through here."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
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


def normalize_ip(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def is_public_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def in_scope(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


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
