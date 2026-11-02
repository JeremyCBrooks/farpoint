"""The credential sidecar: owner-only `credentials.json`, with its own merge rules.

Credential evidence is kept apart from `assets.json` so that the inventory's outputs never carry it and so
that a re-run can never regress newer evidence. The caller holds `files.locked(out_dir)` across a save.
Errors say what is structurally wrong and never repeat a value.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .credentials import (
    COLLECTIONS,
    SCHEMA_VERSION,
    STORED_SPECS,
    CollectionProblem,
    CredentialBatch,
    has_schema_version,
    merge_check,
    normalise_time,
    validate_collections,
)
from .files import OWNER_MODE, csv_text, write_atomic

SIDECAR = "credentials.json"
_ENVELOPE = frozenset({"schema_version", "revision", "updated_at", *COLLECTIONS})
_KEYS = {
    "exposures": ("id",),
    "summaries": ("provider", "scope_domain", "query_kind", "operation", "metric"),
    "checks": ("provider", "scope_domain", "query_kind", "operation"),
}


@dataclass(frozen=True)
class CredentialState:
    data: dict | None = None  # validated sidecar; None when missing or unreadable
    error: str | None = None  # value-free reason it can't be used

    @property
    def revision(self) -> str | None:
        return self.data["revision"] if self.data else None


@dataclass(frozen=True)
class CredentialSave:
    state: CredentialState
    new_exposures: int = 0
    fallback: Path | None = None
    error: str | None = None


def _unreadable(reason: str) -> CredentialState:
    return CredentialState(None, f"credentials.json can't be read ({reason})")


def load_credentials(out_dir: Path) -> CredentialState:
    """The validated sidecar. A missing file is no evidence, not an error."""
    path = Path(out_dir) / SIDECAR
    if not path.exists():
        return CredentialState()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return _unreadable("file can't be opened")
    except (ValueError, RecursionError):
        return _unreadable("not JSON")
    if not has_schema_version(doc):
        return _unreadable("not a schema_version 1 object")
    if set(doc) != _ENVELOPE:
        return _unreadable("unexpected or missing top-level keys")
    if not isinstance(doc["revision"], str) or not doc["revision"]:
        return _unreadable("revision is not a string")
    updated = normalise_time(doc["updated_at"])
    if updated is None:
        return _unreadable("updated_at is not a time")
    for name in COLLECTIONS:
        if not isinstance(doc[name], list):
            return _unreadable(f"{name} is not a list")
    try:
        rows = validate_collections(doc, STORED_SPECS)
    except CollectionProblem as exc:
        return _unreadable(str(exc))
    return CredentialState({"schema_version": SCHEMA_VERSION, "revision": doc["revision"],
                            "updated_at": updated, **rows})


def _present(row: dict) -> dict:
    return {k: v for k, v in row.items() if v is not None}


def _key(name: str, row: dict) -> tuple:
    return tuple(row[k] for k in _KEYS[name])


def _index(name: str, rows) -> dict[tuple, dict]:
    return {_key(name, r): _present(r) for r in rows}


def _newer_wins(old: dict, new: dict, seen: str) -> dict:
    """Mutable fields come from the later retrieval; first_seen/last_seen span both."""
    keep = new if seen >= old["last_seen"] else old
    return {**keep, "first_seen": min(old["first_seen"], new["first_seen"]),
            "last_seen": max(old["last_seen"], new["last_seen"])}


def _canonical(content: dict[str, list[dict]]) -> str:
    return json.dumps({n: sorted(content[n], key=lambda r: _key(n, r)) for n in COLLECTIONS}, sort_keys=True)


def merge_credentials(prior: dict | None, batch: CredentialBatch) -> dict:
    """Merge a batch into the prior sidecar data: newer evidence wins, checks and first sightings are kept."""
    prior = prior or {}
    merged: dict[str, list[dict]] = {}
    for name, rows in (("exposures", batch.exposures), ("summaries", batch.summaries), ("checks", batch.checks)):
        table = _index(name, prior.get(name, ()))
        for key, new in _index(name, rows).items():
            old = table.get(key)
            if old is None:
                table[key] = new
            elif name == "checks":
                table[key] = merge_check(old, new)
            else:
                table[key] = _newer_wins(old, new, batch.retrieved_at)
        merged[name] = sorted(table.values(), key=lambda r: _key(name, r))
    before = {n: prior.get(n, []) for n in COLLECTIONS}
    if prior and _canonical(merged) == _canonical(before):
        revision, updated = prior["revision"], prior["updated_at"]
    else:
        revision = secrets.token_hex(8)
        updated = max(prior.get("updated_at") or "", batch.retrieved_at)
    return {"schema_version": SCHEMA_VERSION, "revision": revision, "updated_at": updated, **merged}


def _write_fallback(out_dir: Path, batch: CredentialBatch, stamp: str) -> Path:
    base = f"credentials.unmerged-{stamp.replace(':', '')}"
    path, number = out_dir / f"{base}.json", 1
    while path.exists():  # a second fallback in the same second must not overwrite the first
        number += 1
        path = out_dir / f"{base}-{number}.json"
    write_atomic(path, json.dumps(batch.to_json(), indent=2, sort_keys=True) + "\n", OWNER_MODE)
    return path


def save_credentials(out_dir: Path, batch: CredentialBatch, stamp: str) -> CredentialSave:
    """Merge `batch` into the sidecar and write it owner-only. An unreadable sidecar is left untouched and the
    batch goes to `credentials.unmerged-<stamp>.json` instead, as it does when the write itself fails."""
    out_dir = Path(out_dir)
    state = load_credentials(out_dir)
    error = state.error
    if error is None:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            merged = merge_credentials(state.data, batch)
            text = json.dumps(merged, indent=2, sort_keys=True) + "\n"
            write_atomic(out_dir / SIDECAR, text, OWNER_MODE)
        except OSError as exc:
            error = f"can't save credentials.json ({type(exc).__name__})"
        else:
            known = {r["id"] for r in (state.data or {}).get("exposures", ())}
            new = sum(1 for r in merged["exposures"] if r["id"] not in known)
            return CredentialSave(CredentialState(merged), new)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        fallback = _write_fallback(out_dir, batch, stamp)
    except OSError as exc:
        return CredentialSave(state, 0, None, f"{error}; can't write the fallback ({type(exc).__name__})")
    return CredentialSave(state, 0, fallback, error)


def attempt_summary(batch: CredentialBatch) -> list[dict]:
    """What a batch tried and got, per check, with no identities."""
    names = ("provider", "scope_domain", "query_kind", "operation", "status", "records", "origin")
    return [{n: c.get(n) for n in names} for c in batch.checks]


_EXPOSURE_FIELDS = ["id", "provider", "scope_domain", "query_kind", "operation", "identity", "relationship", "provider_relationship",
                    "service_host", "service_port", "match", "matched_asset", "exposure_type", "source_name", "malware_family",
                    "secret_types", "secret_evidence", "event_at", "event_date_basis", "provider_discovered_at", "reference",
                    "first_seen", "last_seen"]
_SUMMARY_FIELDS = ["provider", "scope_domain", "query_kind", "operation", "metric", "population", "count", "window_start",
                   "window_end", "reference", "first_seen", "last_seen"]
_CHECK_FIELDS = ["provider", "scope_domain", "query_kind", "operation", "status", "error", "limit_hit", "pages", "records",
                 "started_at", "completed_at", "last_complete_at", "origin"]


def write_credential_exports(out_dir: Path, data: Mapping, report: Mapping | None, today: date) -> None:
    """Regenerate the three owner-only credential CSVs from the sidecar `data`, matching exposures to `report`."""
    from .credential_assess import Correlator  # credential_assess imports this module

    out_dir = Path(out_dir)
    correlator = Correlator(report or {}, today)
    exposures = []
    for row in data["exposures"]:
        found = correlator.match(row)
        exposures.append({**row, "match": found.kind if found else None, "matched_asset": found.asset if found else None})
    for name, rows, fields in (("credential-exposures.csv", exposures, _EXPOSURE_FIELDS),
                               ("credential-summary.csv", data["summaries"], _SUMMARY_FIELDS),
                               ("credential-checks.csv", data["checks"], _CHECK_FIELDS)):
        write_atomic(out_dir / name, csv_text(list(rows), fields), OWNER_MODE)
