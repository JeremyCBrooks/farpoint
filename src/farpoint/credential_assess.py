"""Judging stored credential evidence (`credentials.json`) against the merged infrastructure inventory.

Pure: nothing here makes a request. Correlations are derived on every assessment, never stored, so a later
scan can confirm or retire the service a credential was for. Findings group exposures and count them; they
never carry an identity or anything derived from one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib import resources

from farpoint.credential_store import CredentialState
from farpoint.credentials import THEFT_BASES, identity_domain
from farpoint.names import in_scope
from farpoint.suffixes import registered

RECENT_DAYS = 90  # policy: theft this recent, on a currently observed service, is high; not a claim about password lifetime
STRONG = frozenset({"endpoint", "host", "sign-in", "tenant"})
THEFT = frozenset({"infostealer", "phishing"})
_STRONG_TIES = frozenset({"records", "cname"})
_NO_ASSET = frozenset({"provider-context"})
_NAMED_SOURCES = frozenset({"breach", "combolist", "unknown"})  # a stealer or phishing log's name can embed a victim's user or machine
# Providers whose answer is a capped sample of the moment: only rows from their latest complete check are current.
SNAPSHOT_PROVIDERS = frozenset({"hudsonrock-osint", "hibp-public"})


def _check_key(row: Mapping) -> tuple:
    return (row["provider"], row["scope_domain"], row["query_kind"], row["operation"])


def in_latest_snapshot(row: Mapping, checks: Mapping[tuple, Mapping]) -> bool | None:
    """None for a provider whose evidence accumulates; else whether the row was in its latest complete check."""
    if row["provider"] not in SNAPSHOT_PROVIDERS:
        return None
    complete = (checks.get(_check_key(row)) or {}).get("last_complete_at")
    return bool(complete) and row["last_seen"] >= complete


def no_data(check: Mapping, data: Mapping) -> bool:
    """A complete check that returned nothing: no data, which is not the same as no exposure."""
    if check.get("status") != "complete" or not check.get("last_complete_at"):
        return False
    key, since = _check_key(check), check["last_complete_at"]
    return not any(_check_key(r) == key and r["last_seen"] >= since
                   for r in [*data.get("exposures", []), *data.get("summaries", [])])


def _identity_key(row: Mapping) -> tuple | str:
    """One identity however its domain is spelt: (local part as supplied, normalised domain); else the raw string."""
    domain = identity_domain(row["identity"])
    return (row["identity"].rpartition("@")[0], domain) if domain else row["identity"]


@dataclass(frozen=True)
class Match:
    kind: str  # "endpoint" | "host" | "sign-in" | "tenant" | "host-port-unobserved" | "tentative-tenant" | "dns-only" | "lead" | "provider-context"
    asset: str  # "vpn.example.com:443", "vpn.example.com", "sts.example.com", "example.okta.com", or "" for provider-context
    seen: str | None  # last_seen of the positive supporting observation (fingerprint, identity or tenant row)
    current: bool  # seen is within recent_days of today and not after it


@cache
def _shared_sign_in() -> frozenset[str]:
    data = json.loads(resources.files("farpoint.data").joinpath("identity_providers.json").read_text(encoding="utf-8"))
    return frozenset(data.get("shared_sign_in", ()))


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value[:10]) if value else None
    except ValueError:
        return None


class Correlator:
    """The inventory's evidence for the service an exposure names, strongest first."""

    def __init__(self, report: Mapping, today: date, recent_days: int = RECENT_DAYS) -> None:
        self.today, self.recent_days = today, recent_days
        self.endpoints = {r["endpoint"]: r for r in report.get("fingerprints", []) if r.get("endpoint")}
        self.by_host: dict[str, list[Mapping]] = {}
        for r in report.get("fingerprints", []):
            if r.get("hostname"):
                self.by_host.setdefault(r["hostname"], []).append(r)
        self.sign_in: dict[str, list[Mapping]] = {}
        for r in report.get("identity", []):
            if r.get("sign_in_host"):
                self.sign_in.setdefault(r["sign_in_host"], []).append(r)
        self.tenants = {r["tenant"]: r for r in report.get("tenants", []) if r.get("tenant")}
        self.hosts = {h["hostname"] for h in report.get("hosts", []) if h.get("hostname")}
        self.domains = list(report.get("domains", []))

    def _positive(self, kind: str, asset: str, rows: list[Mapping]) -> Match:
        seen = max((r.get("last_seen") or "" for r in rows), default="") or None
        when = _date(seen)
        current = when is not None and 0 <= (self.today - when).days <= self.recent_days
        return Match(kind, asset, seen, current)

    def match(self, exposure: Mapping) -> Match | None:
        host, port = exposure.get("service_host"), exposure.get("service_port")
        if not host:
            return None
        endpoint = f"{host}:{port}"
        if port is not None and endpoint in self.endpoints:
            return self._positive("endpoint", endpoint, [self.endpoints[endpoint]])
        if host in self.by_host:  # a reported port that wasn't seen open may be closed, filtered or never probed
            if port is None:
                return self._positive("host", host, self.by_host[host])
            return self._positive("host-port-unobserved", endpoint, self.by_host[host])
        shared = registered(host) in _shared_sign_in()  # a provider's own sign-in page is context, even when federated to
        if host in self.sign_in and not shared:
            if port is not None:
                return self._positive("host-port-unobserved", endpoint, self.sign_in[host])
            return self._positive("sign-in", host, self.sign_in[host])
        if host in self.tenants:
            row = self.tenants[host]
            if port is not None:
                return self._positive("host-port-unobserved", endpoint, [row])
            return self._positive("tenant" if row.get("tie") in _STRONG_TIES else "tentative-tenant", host, [row])
        if shared:
            return Match("provider-context", "", None, False)
        if host in self.hosts:
            return Match("dns-only", host, None, False)
        if any(in_scope(host, d) for d in self.domains):
            return Match("lead", host, None, False)
        return None


def _theft_age(row: Mapping, today: date) -> int | None:
    """Days since the theft, or None when the date is missing, invalid, in the future or not a theft date."""
    when = _date(row.get("event_at")) if row.get("event_date_basis") in THEFT_BASES else None
    if when is None or when > today:
        return None
    return (today - when).days


def _level(row: Mapping, match: Match | None, today: date, recent_days: int) -> str:
    if row.get("exposure_type") in THEFT:
        age = _theft_age(row, today)
        fresh = age is not None and age <= recent_days
        return "high" if match and match.kind in STRONG and match.current and fresh else "medium"
    secrets = set(row.get("secret_types") or ())
    return "medium" if row.get("secret_evidence") == "record" and secrets & {"password", "password-hash"} else "low"


def credential_findings(report: Mapping, credentials: Mapping, today: date, recent_days: int = RECENT_DAYS) -> list[dict]:
    """Grouped findings for the sidecar's exposures and summaries; no identities, only counts."""
    from farpoint.assess import LEVELS, _finding, _seen

    correlator = Correlator(report, today, recent_days)
    checks = {_check_key(c): c for c in credentials.get("checks", [])}
    groups: dict[tuple, list[tuple[Mapping, Match | None]]] = {}
    for row in credentials.get("exposures", []):
        if in_latest_snapshot(row, checks) is False:
            continue
        match = correlator.match(row)
        kind = "credential-theft" if row.get("exposure_type") in THEFT else "credential-breach"
        asset = match.asset if match and match.kind not in _NO_ASSET else ""
        groups.setdefault((kind, row["scope_domain"], row["relationship"], asset), []).append((row, match))
    order = {level: i for i, level in enumerate(LEVELS)}
    out: list[dict] = []
    for (kind, scope, relationship, asset), members in sorted(groups.items()):
        rows = [row for row, _ in members]
        match = members[0][1]  # one asset, one correlation
        level = min((_level(row, m, today, recent_days) for row, m in members), key=order.__getitem__)
        n = len({_identity_key(row) for row in rows if row.get("identity")})
        m = len(rows)
        if any(row.get("identity") for row in rows):
            detail = f"{n} {relationship} identit{'y' if n == 1 else 'ies'} ({m} record{'s'[:m != 1]}) for {scope}"
        else:
            detail = f"{relationship}; identities not reported by provider ({m} record{'s'[:m != 1]}) for {scope}"
        if any(row.get("occurrences") is not None for row in rows):
            detail += f"; seen {sum(row.get('occurrences') or 0 for row in rows)} times"
        if match and match.kind == "host-port-unobserved":
            detail += "; reported port not observed (host-only evidence)"
        if match and match.kind == "dns-only":
            detail += "; --fingerprint could confirm the service"
        if kind == "credential-theft":
            ages = [_theft_age(row, today) for row in rows]
            if any(age is None for age in ages):
                detail += "; theft date unknown"
            if any(age is not None and age > recent_days for age in ages):
                detail += f"; theft older than {recent_days} days"
        if match and match.kind in STRONG and not match.current:
            detail += f"; service last observed {match.seen[:10]}, historical" if match.seen else "; service observation undated, historical"
        if match and match.kind == "tentative-tenant":
            detail += "; tenant tied by name only, tentative"
        if match and match.kind == "lead":
            detail += "; host not in the inventory"
        gaps = set()
        for row in rows:
            check = checks.get((row["provider"], row["scope_domain"], row["query_kind"], row["operation"]))
            if check and check.get("status") != "complete":
                gaps.add(f"; latest {check['provider']}/{check['query_kind']}/{check['operation']} check: {check['status']}")
        detail += "".join(sorted(gaps))
        names = {row["source_name"] for row in rows if row.get("source_name") and row.get("exposure_type") in _NAMED_SOURCES}
        evidence = sorted({f"{row['provider']}:{row['operation']}" for row in rows}) + sorted(names)
        out.extend(_seen([_finding(level, kind, asset or scope, detail, evidence, about=f"{scope}|{relationship}")], *rows))
    for s in credentials.get("summaries", []):
        if in_latest_snapshot(s, checks) is False:
            continue
        population = s.get("population")
        detail = (f"{s['provider']} reports {s['count']} for {s['metric']}" + (f" ({population})" if population else "")
                  + "; an aggregate, not a list of confirmed accounts")
        about = f"{s['provider']}/{s['query_kind']}/{s['operation']}/{s['metric']}"
        out.extend(_seen([_finding("low", "credential-summary", s["scope_domain"], detail, [f"{s['provider']}:{s['operation']}"], about=about)], s))
    return out


def credential_status(report: Mapping, state: CredentialState) -> str:
    """Whether the report's credential findings judge the sidecar as it is now: current, stale, unavailable or none."""
    if state.error:
        return "unavailable"
    stored = report.get("credential_assessment")
    if not stored and state.data is None:
        return "none"
    stored = stored or {}
    if stored.get("status") == "current" and stored.get("revision") == state.revision:
        return "current"
    if stored.get("status") == "none" and state.data is None:
        return "none"
    return "stale"


def current_findings(report: Mapping, state: CredentialState) -> list[dict]:
    """The report's findings, without credential findings unless they judge the sidecar as it is now."""
    keep = credential_status(report, state) == "current"
    return [f for f in report.get("findings", []) if keep or not f["kind"].startswith("credential-")]
