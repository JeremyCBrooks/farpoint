"""Credential-exposure evidence: vocabularies, the batch container and row validators.

Rows are allowlisted: a field that is not named here is rejected, so a secret value cannot ride along in
an unexpected key. Validation messages name a collection, row and field, never a value.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

from .names import in_scope, normalize_hostname

SCHEMA_VERSION = 1

QUERY_KINDS = ("email", "website")
EXPOSURE_TYPES = ("breach", "infostealer", "phishing", "combolist", "unknown")
SECRET_TYPES = ("password", "password-hash", "session-cookie", "access-token", "security-question", "other")
SECRET_EVIDENCE = ("record", "dataset")
DATE_BASES = ("breach", "compromised", "captured", "published", "uploaded", "unknown")
THEFT_BASES = frozenset({"compromised", "captured"})
RELATIONSHIPS = ("workforce-associated", "customer-reported", "service-account-unknown")
CUSTOMER_LABELS = frozenset({"customer", "user"})
CHECK_STATUSES = ("complete", "partial", "unavailable", "unsupported", "failed", "interrupted")
ERROR_CATEGORIES = ("no-key", "denied", "quota", "transport", "server", "schema")
LIMIT_HITS = ("pages", "records")

IMPORT_EXPOSURE_FIELDS = frozenset({
    "provider", "provider_record_id", "reference", "scope_domain", "query_kind", "operation", "identity",
    "provider_relationship", "service_host", "service_port", "exposure_type", "source_name", "source_event_id",
    "malware_family", "secret_types", "secret_evidence", "event_at", "event_date_basis",
    "provider_discovered_at", "source_observed_at",
})
IMPORT_SUMMARY_FIELDS = frozenset({
    "provider", "scope_domain", "query_kind", "operation", "metric", "population", "count",
    "window_start", "window_end", "reference",
})
IMPORT_CHECK_FIELDS = frozenset({"provider", "scope_domain", "query_kind", "operation", "status", "error", "checked_at"})

# What a stored row holds, in the order its keys are written (so equal rows serialise identically). A stored
# check keeps started_at/completed_at, not the import's raw checked_at.
STORED_EXPOSURE_ORDER = (
    "id", "provider", "provider_record_id", "reference", "scope_domain", "query_kind", "operation", "identity",
    "identity_domain", "provider_relationship", "relationship", "service_host", "service_port", "exposure_type",
    "source_name", "source_event_id", "malware_family", "secret_types", "secret_evidence", "event_at",
    "event_date_basis", "provider_discovered_at", "source_observed_at", "first_seen", "last_seen",
)
STORED_SUMMARY_ORDER = (
    "provider", "scope_domain", "query_kind", "operation", "metric", "population", "count", "window_start",
    "window_end", "reference", "retrieved_at", "first_seen", "last_seen",
)
STORED_CHECK_ORDER = (
    "provider", "scope_domain", "query_kind", "operation", "status", "error", "started_at", "completed_at",
    "last_complete_at", "pages", "records", "limit_hit", "origin",
)
STORED_EXPOSURE_FIELDS = frozenset(STORED_EXPOSURE_ORDER)
STORED_SUMMARY_FIELDS = frozenset(STORED_SUMMARY_ORDER)
STORED_CHECK_FIELDS = frozenset(STORED_CHECK_ORDER)

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]")
_FIELD_NAME = re.compile(r"[a-z_]{1,40}")


def has_schema_version(data: Any) -> bool:
    """True when `data` is an object whose schema_version is the integer 1 (not true, not 1.0)."""
    if not isinstance(data, dict):
        return False
    version = data.get("schema_version")
    return type(version) is int and version == SCHEMA_VERSION


def normalise_time(value: Any) -> str | None:
    """A date stays `YYYY-MM-DD`; an aware time becomes UTC `...Z`; a naive time keeps its precision with no
    zone invented. Anything else is None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if _DATE.match(text):
            return date.fromisoformat(text).isoformat()
        if not _DATETIME.match(text):
            return None
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return moment.strftime("%Y-%m-%dT%H:%M:%S")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_service(value: str | None, port: int | None = None) -> tuple[str | None, int | None]:
    """A service given as a URL or `host[:port]` becomes (hostname, port). Userinfo, path, query and fragment
    are dropped; a port is kept only when one was written (in the value or as `port`)."""
    if not isinstance(value, str) or not value.strip():
        return None, None
    text = value.strip()
    try:
        parts = urlsplit(text if "://" in text else "//" + text)
        host = normalize_hostname(parts.hostname or "")
        explicit = parts.port
    except ValueError:
        return None, None
    if host is None:
        return None, None
    return host, explicit if explicit is not None else port


_USERINFO = re.compile(r"(?<=//)[^/?#]*@")


def safe_reference(value: str) -> str:
    """A URL loses userinfo, query and fragment. A string without a scheme loses any `?...`/`#...` suffix and
    any `userinfo@` before its first `/`, so a secret is never stored."""
    if "://" not in value:
        head = value.split("?")[0].split("#")[0]
        first, slash, rest = head.partition("/")
        return first.rpartition("@")[2] + slash + rest
    try:
        parts = urlsplit(value)
        host = parts.netloc.rpartition("@")[2]
        return f"{parts.scheme}://{host}{parts.path}"
    except ValueError:
        return _USERINFO.sub("", value).split("?")[0].split("#")[0]


def identity_domain(identity: str | None) -> str | None:
    """The normalised domain after the last `@`; None for an identity with no `@` or no valid domain."""
    if not isinstance(identity, str) or "@" not in identity:
        return None
    return normalize_hostname(identity.rpartition("@")[2])


def exposure_id(row: Mapping) -> str:
    """`provider:record` when the provider gave a record id, else a versioned hash of what identifies the
    exposure: not when it was retrieved, nor anything a provider may later correct."""
    provider = row["provider"]
    if row.get("provider_record_id"):
        return f"{provider}:{row['provider_record_id']}"
    identity = row.get("identity")
    if isinstance(identity, str) and "@" in identity:
        local, _, domain = identity.rpartition("@")
        identity = f"{local}@{domain.lower()}"
    key = [provider, row.get("operation"), row.get("query_kind"), row.get("scope_domain"), identity,
           row.get("service_host"), row.get("service_port"), row.get("source_event_id")]
    digest = hashlib.sha256(json.dumps(key).encode("utf-8")).hexdigest()[:32]
    return f"{provider}:v{SCHEMA_VERSION}:{digest}"


def normalise_exposure(raw: Mapping, *, domains: Sequence[str], kinds: Collection[str]) -> dict | None:
    """The stored form of a validated import row, or None when no enabled scope predicate holds."""
    kind = raw["query_kind"]
    scope = normalize_hostname(raw["scope_domain"])
    if kind not in kinds or scope is None or scope not in domains:
        return None
    row = dict.fromkeys(STORED_EXPOSURE_ORDER) | raw  # every model field, in a fixed order; None where the import had none
    row["scope_domain"] = scope
    host, port = normalise_service(raw.get("service_host"), raw.get("service_port"))
    for name, value in (("service_host", host), ("service_port", port)):
        row[name] = value
    row["reference"] = safe_reference(raw["reference"])
    domain = identity_domain(raw.get("identity"))
    row["identity_domain"] = domain
    if kind == "email":
        in_play = domain is not None and in_scope(domain, scope)
    else:
        in_play = host is not None and in_scope(host, scope)
    if not in_play:
        return None
    if domain is not None and any(in_scope(domain, d) for d in domains):
        row["relationship"] = "workforce-associated"
    elif str(raw.get("provider_relationship") or "").lower() in CUSTOMER_LABELS:
        row["relationship"] = "customer-reported"
    else:
        row["relationship"] = "service-account-unknown"
    row["id"] = exposure_id(row)
    return row


class RowProblem(ValueError):
    """A row failed validation. `field` is None for a problem with the row as a whole; never holds a value."""

    def __init__(self, field: str | None, problem: str):
        super().__init__(problem)
        self.field = field
        self.problem = problem


class CollectionProblem(ValueError):
    """Where in an envelope a row failed: `<collection>[<row>].<field>: <problem>`. Value-free by construction."""

    def __init__(self, collection: str, row: int | None, field: str | None, problem: str):
        spot = collection if row is None else f"{collection}[{row}]"
        if field:
            spot += f".{field}"
        super().__init__(f"{spot}: {problem}")


# --- field checks: each returns the cleaned value or raises ValueError(problem) -------------------------

def _text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("must be a non-empty string")
    return value.strip()


def _enum(allowed: Collection[str]) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str) or value not in allowed:
            raise ValueError("is not an allowed value")
        return value
    return check


def _time(value: Any) -> str:
    stamp = normalise_time(value)
    if stamp is None:
        raise ValueError("must be an ISO 8601 date or time")
    return stamp


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("must be a non-negative integer")
    return value


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("must be a port number from 1 to 65535")
    return value


def _secret_types(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("must be a list")
    check = _enum(SECRET_TYPES)
    return [check(item) for item in value]


_IMPORT_EXPOSURE = {
    "provider": _text, "provider_record_id": _text, "reference": _text, "scope_domain": _text,
    "query_kind": _enum(QUERY_KINDS), "operation": _text, "identity": _text, "provider_relationship": _text,
    "service_host": _text, "service_port": _port, "exposure_type": _enum(EXPOSURE_TYPES), "source_name": _text,
    "source_event_id": _text, "malware_family": _text, "secret_types": _secret_types,
    "secret_evidence": _enum(SECRET_EVIDENCE), "event_at": _time, "event_date_basis": _enum(DATE_BASES),
    "provider_discovered_at": _time, "source_observed_at": _time,
}
_IMPORT_SUMMARY = {
    "provider": _text, "scope_domain": _text, "query_kind": _enum(QUERY_KINDS), "operation": _text,
    "metric": _text, "population": _text, "count": _count, "window_start": _time, "window_end": _time,
    "reference": _text,
}
_IMPORT_CHECK = {
    "provider": _text, "scope_domain": _text, "query_kind": _enum(QUERY_KINDS), "operation": _text,
    "status": _enum(CHECK_STATUSES), "error": _enum(ERROR_CATEGORIES), "checked_at": _time,
}
_STORED_EXPOSURE = _IMPORT_EXPOSURE | {
    "id": _text, "identity_domain": _text, "relationship": _enum(RELATIONSHIPS),
    "first_seen": _time, "last_seen": _time,
}
_STORED_SUMMARY = _IMPORT_SUMMARY | {"retrieved_at": _time, "first_seen": _time, "last_seen": _time}
_STORED_CHECK = {k: v for k, v in _IMPORT_CHECK.items() if k != "checked_at"} | {
    "started_at": _time, "completed_at": _time, "last_complete_at": _time, "pages": _count, "records": _count,
    "limit_hit": _enum(LIMIT_HITS), "origin": _text,
}

_EXPOSURE_REQUIRED = frozenset({"provider", "operation", "reference", "scope_domain", "query_kind"})
_SUMMARY_REQUIRED = frozenset({"provider", "operation", "metric", "count", "scope_domain", "query_kind"})
_CHECK_REQUIRED = frozenset({"provider", "operation", "status", "scope_domain", "query_kind"})


@dataclass(frozen=True)
class RowSpec:
    """Allowed fields (name -> check) and required names for one kind of row."""

    fields: Mapping[str, Callable[[Any], Any]]
    required: frozenset[str]

    def validate(self, row: Any) -> dict:
        """The cleaned row; raises RowProblem. A None value counts as absent."""
        if not isinstance(row, dict):
            raise RowProblem(None, "must be an object")
        for name in row:
            if name not in self.fields:
                known = isinstance(name, str) and _FIELD_NAME.fullmatch(name)
                raise RowProblem(name if known else None, "an unknown field")
        clean = {}
        for name, check in self.fields.items():
            value = row.get(name)
            if value is None:
                if name in self.required:
                    raise RowProblem(name, "is required")
                continue
            try:
                clean[name] = check(value)
            except ValueError as exc:
                raise RowProblem(name, str(exc)) from None
        return clean


IMPORT_SPECS = {
    "exposures": RowSpec(_IMPORT_EXPOSURE, _EXPOSURE_REQUIRED),
    "summaries": RowSpec(_IMPORT_SUMMARY, _SUMMARY_REQUIRED),
    "checks": RowSpec(_IMPORT_CHECK, _CHECK_REQUIRED),
}
STORED_SPECS = {
    "exposures": RowSpec(_STORED_EXPOSURE, _EXPOSURE_REQUIRED | {"id", "relationship", "first_seen", "last_seen"}),
    "summaries": RowSpec(_STORED_SUMMARY, _SUMMARY_REQUIRED | {"retrieved_at", "first_seen", "last_seen"}),
    "checks": RowSpec(_STORED_CHECK, _CHECK_REQUIRED | {"started_at"}),
}
COLLECTIONS = tuple(IMPORT_SPECS)


def validate_collections(doc: Mapping, specs: Mapping[str, RowSpec]) -> dict[str, list[dict]]:
    """Validate each collection of an envelope; raises CollectionProblem naming the first bad row."""
    out: dict[str, list[dict]] = {}
    for name in COLLECTIONS:
        rows = doc.get(name, [])
        if not isinstance(rows, list):
            raise CollectionProblem(name, None, None, "must be a list")
        out[name] = []
        for index, row in enumerate(rows):
            try:
                out[name].append(specs[name].validate(row))
            except RowProblem as exc:
                raise CollectionProblem(name, index, exc.field, exc.problem) from None
    return out


@dataclass(frozen=True)
class CredentialBatch:
    retrieved_at: str
    exposures: tuple[dict, ...] = ()
    summaries: tuple[dict, ...] = ()
    checks: tuple[dict, ...] = ()

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION, "retrieved_at": self.retrieved_at,
            "exposures": [dict(r) for r in self.exposures], "summaries": [dict(r) for r in self.summaries],
            "checks": [dict(r) for r in self.checks],
        }

    @classmethod
    def from_json(cls, data: Any) -> CredentialBatch:
        """Read stored (normalised) rows back; ValueError with a value-free message on anything malformed."""
        if not has_schema_version(data):
            raise ValueError("credential data is not a version 1 object")
        retrieved_at = normalise_time(data.get("retrieved_at"))
        if retrieved_at is None:
            raise ValueError("retrieved_at: must be an ISO 8601 date or time")
        rows = validate_collections(data, STORED_SPECS)  # CollectionProblem is a ValueError
        return cls(retrieved_at, tuple(rows["exposures"]), tuple(rows["summaries"]), tuple(rows["checks"]))
