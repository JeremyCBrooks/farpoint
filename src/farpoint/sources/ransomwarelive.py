"""ransomware.live: claims ransomware groups posted on their leak sites, for --ransomware.

One search per domain. Without RANSOMWARE_LIVE_API_KEY it uses the free API, which allows one request a
minute per endpoint and answers an unknown keyword with a 404; with a key, the PRO API. Both match the
keyword as a substring of victims' names and websites (the free API searches other text too), so only
claims whose website is the domain or a name under it are kept: a victim name alone is not enough, since company names collide.

The leak-site post, the description (which often links to the stolen files) and the screenshot are
dropped here, before anything is buffered: farpoint records that a claim exists, never where the data is.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from farpoint.names import in_scope, normalize_hostname
from farpoint.sources.base import HttpSource, UnexpectedResponse

FREE = "https://api.ransomware.live/v2/searchvictims/"
PRO = "https://api-pro.ransomware.live/victims/search"
REFERENCE = "https://www.ransomware.live/id/"


def _domain(website) -> str | None:
    """A victim's website as a hostname: `https://www.example.com/about` -> www.example.com."""
    if not isinstance(website, str):
        return None
    host = website.strip().split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return normalize_hostname(host) if host else None


def _claim(page, victim, website, group, attacked, discovered, country, activity) -> dict | None:
    """The kept fields, keyed by ransomware.live's victim id without base64 padding (the free API pads it,
    the PRO API doesn't), so both APIs' answers merge as one claim."""
    ident = page.rstrip("/").rsplit("/", 1)[-1].rstrip("=") if isinstance(page, str) and page.startswith(REFERENCE) else ""
    domain = _domain(website)
    if not ident or not domain:
        return None
    text = lambda v: v if isinstance(v, str) else ""  # noqa: E731
    return {"id": ident, "victim": text(victim), "domain": domain, "group": text(group), "attackdate": text(attacked),
            "discovered": text(discovered), "country": text(country), "activity": text(activity), "reference": REFERENCE + ident}


def _json(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        raise UnexpectedResponse("unexpected response (not JSON)") from None


def _no_victims(response: httpx.Response) -> bool:
    """The free API's answer for a keyword it has no victims for."""
    try:
        body = response.json()
    except ValueError:
        return False
    return response.status_code == 404 and isinstance(body, dict) and str(body.get("error", "")).startswith("No victims found")


class RansomwareLive(HttpSource):
    name = "ransomware"
    max_concurrency = 1
    min_interval = 61.0  # the free API allows one request a minute per endpoint

    def __init__(self, http: httpx.Client, api_key: str | None = None, **kwargs) -> None:
        super().__init__(http, api_key, **kwargs)
        if api_key:
            self.min_interval = 1.0  # PRO: no rate limit, but fair use

    def claims(self, domain: str) -> list[dict]:
        """Leak-site claims whose victim website is `domain` or a name under it."""
        if self.api_key:
            body = _json(self.get(PRO, params={"q": domain}, headers={"X-API-KEY": self.api_key}))
            if not isinstance(body, dict) or not isinstance(body.get("victims"), list):
                raise UnexpectedResponse("unexpected response")
            found = [_claim(v.get("permalink"), v.get("post_title"), v.get("website"), v.get("group_name"), v.get("published"),
                            v.get("discovered"), v.get("country"), v.get("activity")) for v in body["victims"] if isinstance(v, dict)]
        else:
            try:
                response = self.get(FREE + quote(domain, safe=""))
            except httpx.HTTPStatusError as exc:
                if _no_victims(exc.response):
                    return []
                raise
            body = _json(response)
            if not isinstance(body, list):
                raise UnexpectedResponse("unexpected response")
            found = [_claim(v.get("url"), v.get("victim"), v.get("domain"), v.get("group"), v.get("attackdate"),
                            v.get("discovered"), v.get("country"), v.get("activity")) for v in body if isinstance(v, dict)]
        return [c for c in found if c and in_scope(c["domain"], domain)]
