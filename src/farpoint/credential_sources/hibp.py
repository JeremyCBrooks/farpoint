"""`hibp-public`: breaches of the organisation's own site, from HIBP's free breach list (no key).

These are the site's users, so this is a `website` query. Each breach is dataset-level evidence: HIBP's
data classes say what the breach held, not what any one account lost. Data from haveibeenpwned.com,
CC BY 4.0.
"""

from __future__ import annotations

from collections.abc import Collection

from farpoint.sources.base import HttpSource, UnexpectedResponse

NAME = "hibp-public"
URL = "https://haveibeenpwned.com/api/v3/breaches"
SECRET_CLASSES = {"Passwords": "password", "Security questions and answers": "security-question", "Auth tokens": "access-token"}


class HibpPublic(HttpSource):
    name = NAME
    kinds = frozenset({"website"})
    max_concurrency = 1
    min_interval = 1.0

    def operations(self, kinds: Collection[str]) -> list[tuple[str, str]]:
        return [("website", "breaches")] if "website" in kinds else []

    def collect(self, domain: str, kinds: Collection[str]) -> dict[str, list[dict]]:
        if "website" not in kinds:
            return {"exposures": [], "summaries": []}
        breaches = self.get(URL, params={"domain": domain}).json()
        if not isinstance(breaches, list):
            raise UnexpectedResponse("unexpected response")
        rows = []
        for breach in breaches:
            if breach.get("IsFabricated") or breach.get("IsSpamList"):
                continue
            name = breach["Name"]
            classes = breach.get("DataClasses") or []
            rows.append({
                "provider": NAME, "scope_domain": domain, "query_kind": "website", "operation": "breaches",
                "provider_record_id": name, "source_name": name, "reference": f"https://haveibeenpwned.com/api/v3/breach/{name}",
                "service_host": domain, "exposure_type": "breach", "event_at": breach.get("BreachDate"),
                "event_date_basis": "breach", "secret_evidence": "dataset",
                "secret_types": sorted({SECRET_CLASSES[c] for c in classes if c in SECRET_CLASSES}),
            })
        return {"exposures": rows, "summaries": []}
