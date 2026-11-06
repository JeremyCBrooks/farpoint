"""`hudsonrock-osint`: Hudson Rock's free domain answer as credential evidence, with no identities.

Employee login URLs become workforce exposures, one per in-scope host and port, with how often Hudson Rock
saw them; customer ("User") URLs only with the `website` kind. Paths, queries and fragments are dropped
here, before anything is buffered: the URLs are unmasked and can carry password-reset tokens. Counts of
zero write nothing, because Hudson Rock answers an unknown domain with zeros.
"""

from __future__ import annotations

from collections.abc import Collection

from farpoint.credentials import normalise_service, normalise_time
from farpoint.names import in_scope
from farpoint.sources.hudsonrock import HudsonRock

NAME = "hudsonrock-osint"
_URLS = {"email": ("employees_urls", "employee-urls", "Employee"), "website": ("clients_urls", "user-urls", "User")}
_COUNTS = {"email": [("employees", "infected-employees", "last_employee_compromised"),
                     ("third_parties", "infected-third-parties", None), ("totalUrls", "urls-held", None)],
           "website": [("users", "infected-users", "last_user_compromised")]}


def _count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


class HudsonRockOsint:
    name = NAME
    kinds = frozenset({"email", "website"})

    def __init__(self, source: HudsonRock) -> None:
        self.source = source

    def operations(self, kinds: Collection[str]) -> list[tuple[str, str]]:
        return [(kind, op) for kind in ("email", "website") if kind in kinds
                for op in (_URLS[kind][1], "domain-summary")]

    def collect(self, domain: str, kinds: Collection[str]) -> dict[str, list[dict]]:
        answer = self.source.report(domain)
        exposures, summaries = [], []
        for kind in ("email", "website"):
            if kind not in kinds:
                continue
            exposures += self._exposures(domain, kind, answer["data"].get(_URLS[kind][0]) or [])
            summaries += self._summaries(domain, kind, answer)
        return {"exposures": exposures, "summaries": summaries}

    def _row(self, domain: str, kind: str, operation: str) -> dict:
        return {"provider": NAME, "scope_domain": domain, "query_kind": kind, "operation": operation,
                "reference": HudsonRock.URL}

    def _exposures(self, domain: str, kind: str, entries: list) -> list[dict]:
        _, operation, label = _URLS[kind]
        seen: dict[tuple[str, int | None], int] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            host, port = normalise_service(entry.get("url"))
            if host is None or not in_scope(host, domain):
                continue
            seen[(host, port)] = seen.get((host, port), 0) + _count(entry.get("occurrence"))
        return [self._row(domain, kind, operation) | {
            "provider_relationship": label, "service_host": host, "service_port": port, "exposure_type": "infostealer",
            "secret_types": ["password"], "secret_evidence": "dataset", "occurrences": n,
        } for (host, port), n in sorted(seen.items(), key=lambda item: (item[0][0], item[0][1] or 0))]

    def _summaries(self, domain: str, kind: str, answer: dict) -> list[dict]:
        rows = []
        for field, metric, when in _COUNTS[kind]:
            if n := _count(answer.get(field)):
                rows.append(self._row(domain, kind, "domain-summary") | {
                    "metric": metric, "count": n, "window_end": normalise_time(answer.get(when)) if when else None})
        if kind == "email":
            families = answer.get("stealerFamilies") if isinstance(answer.get("stealerFamilies"), dict) else {}
            for family, value in families.items():
                if family != "total" and (n := _count(value)):
                    rows.append(self._row(domain, kind, "domain-summary") | {"metric": f"stealer-family:{family}", "count": n})
        return [{k: v for k, v in row.items() if v is not None} for row in rows]
