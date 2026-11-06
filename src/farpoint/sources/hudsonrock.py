"""Hudson Rock's free OSINT search by domain (no key).

One answer per domain serves two readers: this hostname source, which takes the hosts of the login URLs
found in infostealer logs, and the `hudsonrock-osint` credential provider. The answer is kept in memory for
the run, never written, so each domain is requested at most once.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

from farpoint.credentials import normalise_service
from farpoint.models import Observation
from farpoint.sources.base import HttpSource, UnexpectedResponse

URL_LISTS = ("employees_urls", "clients_urls")


class HudsonRock(HttpSource):
    """Login URLs seen in infostealer logs, by Hudson Rock's Cavalier OSINT tool (no key)."""

    name = "hudsonrock"
    max_concurrency = 1
    min_interval = 1.0
    URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._lock = threading.Lock()
        self._answers: dict[str, dict | BaseException] = {}
        self._fetching: dict[str, threading.Event] = {}

    def report(self, domain: str) -> dict:
        """The parsed answer for `domain`, requested once per run; a failure is remembered and raised again."""
        with self._lock:
            done = domain in self._answers
            waiting = self._fetching.get(domain)
            if not done and waiting is None:
                self._fetching[domain] = threading.Event()
        if not done and waiting is not None:
            waiting.wait()
        elif not done:
            try:
                answer: dict | BaseException = self._fetch(domain)
            except Exception as exc:  # remembered: a second reader must not request again
                answer = exc
            with self._lock:
                self._answers[domain] = answer
                self._fetching.pop(domain).set()
        answer = self._answers[domain]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def _fetch(self, domain: str) -> dict:
        response = self.get(self.URL, params={"domain": domain})
        try:
            body = response.json()
        except ValueError:
            raise UnexpectedResponse("unexpected response (not JSON)") from None
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise UnexpectedResponse("unexpected response")
        return body

    def collect(self, domain: str) -> Iterator[Observation]:
        data = self.report(domain)["data"]
        for name in URL_LISTS:
            for entry in data.get(name) or []:
                host, _ = normalise_service(entry.get("url") if isinstance(entry, dict) else None)
                if host:
                    yield self.observe(host)
