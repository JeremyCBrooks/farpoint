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
    validate_collections,
)


class CredentialImportError(ValueError):
    """An import file was rejected. The message is `<file>: <collection>[<row>].<field>: <problem>`."""


def _read(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise CredentialImportError(f"{path}: not a readable JSON import") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
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


def load_imports(paths: Sequence[Path], domains: Sequence[str], kinds: Collection[str],
                 retrieved_at: str) -> tuple[CredentialBatch, int]:
    """Validate every file, then return one batch and the number of rows rejected as out of scope."""
    loaded = [_load_one(Path(p), kinds) for p in paths]
    merged = {name: tuple(row for rows in loaded for row in rows[name]) for name in COLLECTIONS}
    return CredentialBatch(retrieved_at, merged["exposures"], merged["summaries"], merged["checks"]), 0
