"""Live credential providers: the protocol, error categories and collection into normalised rows.

A provider turns a root domain into normalised `exposures` and `summaries` (validated against
`credentials.PROVIDER_SPECS`); `collect_credentials` adds one check per operation. Nothing here
writes a file or touches the inventory; `credential_batch.build_batch` makes the batch.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Sequence
from typing import Protocol

import httpx

from farpoint import runtime
from farpoint.credentials import PROVIDER_SPECS, validate_collections
from farpoint.sources.base import SourceFailure, UnexpectedResponse

log = logging.getLogger(__name__)


class CredentialProvider(Protocol):
    name: str
    kinds: frozenset[str]

    def operations(self, kinds: Collection[str]) -> list[tuple[str, str]]:
        """The (query_kind, operation) checks `collect` covers for the enabled kinds."""
        ...

    def collect(self, domain: str, kinds: Collection[str]) -> dict[str, list[dict]]:
        """Normalised `exposures` and `summaries` for the enabled kinds; raises on failure."""
        ...


def error_category(exc: BaseException) -> str:
    """A value-free category for a failed request: providers may echo URLs or identities in messages."""
    if isinstance(exc, httpx.HTTPStatusError):
        return "denied" if exc.response.status_code in (401, 403) else "schema"
    if isinstance(exc, UnexpectedResponse):
        return "schema"
    if isinstance(exc, SourceFailure):
        text = str(exc)
        if text.startswith("HTTP 429"):
            return "quota"
        return "server" if text.startswith("HTTP ") else "transport"
    if isinstance(exc, httpx.TransportError):
        return "transport"
    return "schema"


def collect_credentials(providers: Sequence[CredentialProvider], domains: Sequence[str], kinds: Collection[str],
                        at: str) -> dict[str, list[dict]]:
    """Every provider's rows for every domain, and a check per operation: `complete`, or `failed` with a category."""
    out: dict[str, list[dict]] = {"exposures": [], "summaries": [], "checks": []}
    for domain in domains:
        for provider in providers:
            operations = provider.operations(kinds)
            if not operations:
                continue
            runtime.status(f"{provider.name} {domain}")
            try:
                rows = validate_collections(provider.collect(domain, kinds), PROVIDER_SPECS)
            except (runtime.Cancelled, KeyboardInterrupt):
                raise
            except Exception as exc:
                error = error_category(exc)
                log.info("%s %s: %s", provider.name, domain, error)
                status = {"status": "failed", "error": error}
            else:
                out["exposures"].extend(rows["exposures"])
                out["summaries"].extend(rows["summaries"])
                status = {"status": "complete"}
            for kind, operation in operations:
                out["checks"].append({"provider": provider.name, "scope_domain": domain, "query_kind": kind,
                                      "operation": operation, "checked_at": at, **status})
    return out
