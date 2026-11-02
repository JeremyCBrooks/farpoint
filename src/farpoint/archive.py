"""Archived copies of homepages, for web services a bot defence hid from the scan (see fingerprint.Archive).

Passive: these requests go to the Internet Archive only, never to the organisation.
"""

from __future__ import annotations

from datetime import date, timedelta

import httpx

from farpoint.fingerprint import Capture
from farpoint.probe import BODY_LIMIT, HttpResult
from farpoint.sources.base import HttpSource

MAX_AGE_DAYS = 365  # an older copy says little about what runs there now
_ORIGINAL = "x-archive-orig-"  # the Wayback Machine replays the site's own headers under this prefix


class WaybackArchive(HttpSource):
    """The newest Wayback Machine capture of a host's homepage from the last year, as the site served it."""

    name = "wayback"
    max_concurrency = 2
    min_interval = 1.0

    def __init__(self, http: httpx.Client, max_age_days: int = MAX_AGE_DAYS, **kwargs) -> None:
        super().__init__(http, **kwargs)
        self.max_age_days = max_age_days

    def capture(self, host: str) -> Capture | None:
        since = (date.today() - timedelta(days=self.max_age_days)).strftime("%Y%m%d")
        params = {"url": f"{host}/", "output": "json", "fl": "timestamp,original", "filter": ["statuscode:200", "mimetype:text/html"],
                  "from": since, "limit": "-1", "fastLatest": "true"}  # -1: the newest one
        rows = self.get("https://web.archive.org/cdx/search/cdx", params=params).json()
        if len(rows) < 2:  # the first row names the fields
            return None
        timestamp, original = rows[-1][:2]
        # id_: the page as archived, without the Wayback Machine's toolbar or rewritten links
        resp = self.get(f"https://web.archive.org/web/{timestamp}id_/{original}")
        headers = [(k.lower().removeprefix(_ORIGINAL), v) for k, v in resp.headers.items() if k.lower().startswith(_ORIGINAL)]
        captured = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
        return Capture(captured, original, HttpResult(resp.status_code, headers, resp.content[:BODY_LIMIT]))
