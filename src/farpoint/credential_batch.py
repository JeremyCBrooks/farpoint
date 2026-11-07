"""Turn credential providers' validated rows into one batch: scoped, related, identified and stamped.

Rows reach here already checked against `credentials.PROVIDER_SPECS` by `collect_credentials`.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence

from .credentials import (
    STORED_CHECK_ORDER,
    STORED_SUMMARY_ORDER,
    CredentialBatch,
    merge_check,
    normalise_exposure,
    normalise_time,
    row_scope,
)
from .names import normalize_hostname

LIVE = "live"  # every check's origin: evidence comes only from live providers


def _scoped(row: dict, domains: Sequence[str], kinds: Collection[str]) -> dict | None:
    """The row with its normalised scope domain, or None when it is out of scope or of a disabled kind."""
    scope = row_scope(row, domains=domains, kinds=kinds)
    return None if scope is None else {**row, "scope_domain": scope}


def _ordered(order: Sequence[str], row: dict, **added) -> dict:
    """A stored row with its keys in `order` (None where absent), so equal rows serialise identically."""
    merged = row | added
    return {name: merged.get(name) for name in order}


def _key(row: dict) -> tuple:
    return (row["provider"], row["scope_domain"], row["query_kind"], row["operation"])


def build_batch(rows: Mapping[str, Sequence[dict]], domains: Sequence[str], kinds: Collection[str],
                retrieved_at: str) -> tuple[CredentialBatch, int]:
    """One batch from providers' validated rows, and the number of rows rejected as out of scope or of a
    disabled kind.

    Exposures are scoped, related and identified by `normalise_exposure`. A provider/domain/kind/operation
    with rows but no declared check gets a `partial` one: the rows alone cannot say they covered everything."""
    when = normalise_time(retrieved_at)
    if when is None:
        raise ValueError("retrieved_at: must be an ISO 8601 date or time")
    domains = [d for d in (normalize_hostname(d) for d in domains) if d]
    rejected = 0
    exposures: dict[str, dict] = {}  # the last row with an id wins
    for raw in rows["exposures"]:
        row = normalise_exposure(raw, domains=domains, kinds=kinds)
        if row is None:
            rejected += 1
            continue
        exposures.pop(row["id"], None)
        exposures[row["id"]] = {**row, "first_seen": when, "last_seen": when}
    summaries, declared = [], {}
    for raw in rows["summaries"]:
        if (row := _scoped(raw, domains, kinds)) is None:
            rejected += 1
            continue
        summaries.append(_ordered(STORED_SUMMARY_ORDER, row, retrieved_at=when, first_seen=when, last_seen=when))
    for raw in rows["checks"]:
        if (raw := _scoped(raw, domains, kinds)) is None:
            rejected += 1
            continue
        at = normalise_time(raw.get("checked_at")) or when
        status = raw["status"]
        check = _ordered(
            STORED_CHECK_ORDER, raw, started_at=at, completed_at=at,
            last_complete_at=at if status == "complete" else None, origin=LIVE)
        key = _key(raw)
        declared[key] = merge_check(declared[key], check) if key in declared else check
    counts: dict[tuple, int] = {}
    for row in exposures.values():
        counts[_key(row)] = counts.get(_key(row), 0) + 1
    for key in ({_key(r) for r in summaries} | counts.keys()) - declared.keys():
        provider, scope, kind, operation = key
        declared[key] = _ordered(
            STORED_CHECK_ORDER, {"provider": provider, "scope_domain": scope, "query_kind": kind, "operation": operation},
            status="partial", started_at=when, completed_at=when, origin=LIVE)
    for key, check in declared.items():
        check["records"] = counts.get(key, 0)
    batch = CredentialBatch(when, tuple(exposures.values()), tuple(summaries), tuple(declared.values()))
    return batch, rejected
