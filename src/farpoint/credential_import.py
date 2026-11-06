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
    STORED_CHECK_ORDER,
    STORED_SUMMARY_ORDER,
    CollectionProblem,
    CredentialBatch,
    has_schema_version,
    merge_check,
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


def _ordered(order: Sequence[str], row: dict, **added) -> dict:
    """A stored row with its keys in `order` (None where absent), so equal rows serialise identically."""
    merged = row | added
    return {name: merged.get(name) for name in order}


def _key(row: dict) -> tuple:
    return (row["provider"], row["scope_domain"], row["query_kind"], row["operation"])


def load_imports(paths: Sequence[Path], domains: Sequence[str], kinds: Collection[str],
                 retrieved_at: str) -> tuple[CredentialBatch, int]:
    """Validate every file, then return one batch and the number of rows rejected as out of scope."""
    return build_batch(read_imports(paths, kinds), domains, kinds, retrieved_at)


def read_imports(paths: Sequence[Path], kinds: Collection[str]) -> list[tuple[dict[str, list[dict]], str]]:
    """Every file's validated rows, tagged `import`, for `build_batch`; raises CredentialImportError."""
    return [(_load_one(Path(p), kinds), "import") for p in paths]


def build_batch(loaded: Sequence[tuple[dict[str, list[dict]], str]], domains: Sequence[str], kinds: Collection[str],
                retrieved_at: str) -> tuple[CredentialBatch, int]:
    """One batch from validated, import-shaped rows, each set with its origin (`import` or `live`), and the
    number of rows rejected as out of scope.

    Exposures are scoped, related and identified by `normalise_exposure`. A provider/domain/kind/operation
    with rows but no declared check gets a `partial` one: the rows alone cannot say they covered everything."""
    when = normalise_time(retrieved_at)
    if when is None:
        raise ValueError("retrieved_at: must be an ISO 8601 date or time")
    domains = [d for d in (normalize_hostname(d) for d in domains) if d]
    rejected = 0
    exposures: dict[str, dict] = {}  # the last row with an id wins
    origins: dict[tuple, str] = {}
    for rows, _ in loaded:
        for raw in rows["exposures"]:
            row = normalise_exposure(raw, domains=domains, kinds=kinds)
            if row is None:
                rejected += 1
                continue
            exposures.pop(row["id"], None)
            exposures[row["id"]] = {**row, "first_seen": when, "last_seen": when}
    summaries, declared = [], {}
    for rows, origin in loaded:
        for raw in [*rows["exposures"], *rows["summaries"]]:
            origins.setdefault(_key(raw | {"scope_domain": normalize_hostname(raw["scope_domain"])}), origin)
        for raw in rows["summaries"]:
            if _in_domains(raw, domains):
                summaries.append(_ordered(STORED_SUMMARY_ORDER, raw, retrieved_at=when, first_seen=when, last_seen=when))
            else:
                rejected += 1
        for raw in rows["checks"]:
            if not _in_domains(raw, domains):
                rejected += 1
                continue
            at = normalise_time(raw.get("checked_at")) or when
            status = raw["status"]
            check = _ordered(
                STORED_CHECK_ORDER, raw, started_at=at, completed_at=at,
                last_complete_at=at if status == "complete" else None, origin=origin)
            key = _key(raw)
            declared[key] = merge_check(declared[key], check) if key in declared else check
    counts: dict[tuple, int] = {}
    for row in exposures.values():
        counts[_key(row)] = counts.get(_key(row), 0) + 1
    for key in ({_key(r) for r in summaries} | counts.keys()) - declared.keys():
        provider, scope, kind, operation = key
        declared[key] = _ordered(
            STORED_CHECK_ORDER, {"provider": provider, "scope_domain": scope, "query_kind": kind, "operation": operation},
            status="partial", started_at=when, completed_at=when, origin=origins.get(key, "import"))
    for key, check in declared.items():
        check["records"] = counts.get(key, 0)
    batch = CredentialBatch(when, tuple(exposures.values()), tuple(summaries), tuple(declared.values()))
    return batch, rejected
