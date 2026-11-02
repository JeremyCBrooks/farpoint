"""Read operator-supplied, already-normalised credential exposure evidence (JSON, schema version 1).

Every file is validated, and the enabled query kinds enforced, before anything is returned, so a bad file
changes nothing. Errors name a file, collection, row and field and never a value.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Sequence
from pathlib import Path

from .credentials import (
    COLLECTIONS,
    IMPORT_SPECS,
    SCHEMA_VERSION,
    CollectionProblem,
    CredentialBatch,
    has_schema_version,
    normalise_exposure,
    normalise_time,
    validate_collections,
)
from .names import normalize_hostname


class CredentialImportError(ValueError):
    """An import file was rejected. The message is `<file>: <collection>[<row>].<field>: <problem>`."""


def _read(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):  # Unicode and JSON decode errors are ValueErrors
        raise CredentialImportError(f"{path}: not a readable JSON import") from None
    if not has_schema_version(doc) or set(doc) - {"schema_version", *COLLECTIONS}:
        raise CredentialImportError(f"{path}: not a schema_version {SCHEMA_VERSION} import object")
    return doc


def _load_one(path: Path, kinds: Collection[str]) -> dict[str, list[dict]]:
    doc = _read(path)
    try:
        rows = validate_collections(doc, IMPORT_SPECS)
    except CollectionProblem as exc:
        raise CredentialImportError(f"{path}: {exc}") from None
    for name in COLLECTIONS:
        for index, row in enumerate(rows[name]):
            if row["query_kind"] not in kinds:
                raise CredentialImportError(
                    f"{path}: {name}[{index}].query_kind: {row['query_kind']} queries are not enabled")
    return rows


def _in_domains(row: dict, domains: Sequence[str]) -> bool:
    scope = normalize_hostname(row["scope_domain"])
    if scope not in domains:
        return False
    row["scope_domain"] = scope
    return True


def _key(row: dict) -> tuple:
    return (row["provider"], row["scope_domain"], row["query_kind"], row["operation"])


def load_imports(paths: Sequence[Path], domains: Sequence[str], kinds: Collection[str],
                 retrieved_at: str) -> tuple[CredentialBatch, int]:
    """Validate every file, then return one batch and the number of rows rejected as out of scope.

    Exposures are scoped, related and identified by `normalise_exposure`. A provider/domain/kind/operation
    with rows but no declared check gets a `partial` one: the import cannot say it covered everything."""
    when = normalise_time(retrieved_at)
    if when is None:
        raise ValueError("retrieved_at: must be an ISO 8601 date or time")
    domains = [d for d in (normalize_hostname(d) for d in domains) if d]
    loaded = [_load_one(Path(p), kinds) for p in paths]
    rejected = 0
    exposures: dict[str, dict] = {}  # the last row with an id wins
    for rows in loaded:
        for raw in rows["exposures"]:
            row = normalise_exposure(raw, domains=domains, kinds=kinds)
            if row is None:
                rejected += 1
                continue
            exposures.pop(row["id"], None)
            exposures[row["id"]] = {**row, "first_seen": when, "last_seen": when}
    summaries, declared = [], {}
    for rows in loaded:
        for raw in rows["summaries"]:
            if _in_domains(raw, domains):
                summaries.append({**raw, "retrieved_at": when, "first_seen": when, "last_seen": when})
            else:
                rejected += 1
        for raw in rows["checks"]:
            if not _in_domains(raw, domains):
                rejected += 1
                continue
            at = normalise_time(raw.get("checked_at")) or when
            status = raw["status"]
            declared[_key(raw)] = {
                **raw, "limit_hit": None, "pages": None, "started_at": at, "completed_at": at,
                "last_complete_at": at if status == "complete" else None, "origin": "import",
            }
    counts: dict[tuple, int] = {}
    for row in exposures.values():
        counts[_key(row)] = counts.get(_key(row), 0) + 1
    for key in ({_key(r) for r in summaries} | counts.keys()) - declared.keys():
        provider, scope, kind, operation = key
        declared[key] = {
            "provider": provider, "scope_domain": scope, "query_kind": kind, "operation": operation,
            "status": "partial", "limit_hit": None, "pages": None, "started_at": when, "completed_at": when,
            "last_complete_at": None, "origin": "import",
        }
    for key, check in declared.items():
        check["records"] = counts.get(key, 0)
    batch = CredentialBatch(when, tuple(exposures.values()), tuple(summaries), tuple(declared.values()))
    return batch, rejected
