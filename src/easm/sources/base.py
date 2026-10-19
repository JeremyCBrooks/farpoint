"""Source abstractions. A Source turns a root domain into Observations; nothing more."""

from __future__ import annotations

import random
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Protocol

import httpx

from easm.models import Observation


class SourceFailure(Exception):
    """The source answered, but with an error/quota message rather than data."""


class Source(Protocol):
    name: str

    def available(self) -> bool: ...

    def collect(self, domain: str) -> Iterable[Observation]: ...


MAX_WAIT = 60.0


def retry_after_seconds(value: str, now: datetime | None = None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) into seconds, or None if absent/invalid."""
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - (now or datetime.now(timezone.utc))).total_seconds())


class HttpSource:
    """Base for API/web sources. Subclasses implement collect() using self.get().

    Every request goes through a per-instance throttle: at most `max_concurrency` in flight and
    at least `min_interval` seconds between request starts. One instance serves all domains, so
    these limits hold for the whole run.
    """

    name = ""
    key_required = False
    max_pages = 10
    max_concurrency = 4
    min_interval = 0.0

    def __init__(self, http: httpx.Client, api_key: str | None = None, *, retries: int = 4, backoff: float = 2.0) -> None:
        self.http = http
        self.api_key = api_key
        self.retries = retries
        self.backoff = backoff
        self._slots = threading.BoundedSemaphore(self.max_concurrency)
        self._pace = threading.Lock()
        self._next_start = 0.0

    def available(self) -> bool:
        return bool(self.api_key) or not self.key_required

    def _wait_for_turn(self) -> None:
        with self._pace:
            delay = self._next_start - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_start = time.monotonic() + self.min_interval

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with jitter: ~backoff * 2^attempt, scaled by 0.5-1.0, capped at MAX_WAIT."""
        return min(self.backoff * 2**attempt, MAX_WAIT) * random.uniform(0.5, 1.0)

    def get(self, url: str, **kwargs) -> httpx.Response:
        """Throttled GET with retries on transport errors, 5xx and 429 (honouring Retry-After)."""
        with self._slots:
            for attempt in range(self.retries + 1):
                wait = self._backoff(attempt)
                self._wait_for_turn()
                try:
                    response = self.http.get(url, **kwargs)
                    transient = response.status_code >= 500 or response.status_code == 429
                    if not transient or attempt == self.retries:
                        response.raise_for_status()
                        return response
                    retry_after = retry_after_seconds(response.headers.get("Retry-After", ""))
                    if retry_after is not None:
                        wait = min(retry_after, MAX_WAIT)
                except httpx.TransportError:
                    if attempt == self.retries:
                        raise
                time.sleep(wait)
        raise AssertionError("unreachable")

    def observe(self, hostname: str, ip: str | None = None) -> Observation:
        return Observation(self.name, hostname, ip)


Runner = Callable[[Sequence[str]], str]


def run_command(argv: Sequence[str], timeout: float = 1800) -> str:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if done.returncode != 0 and not done.stdout:
        raise SourceFailure(f"{argv[0]} exited {done.returncode}: {done.stderr.strip()[-500:]}")
    return done.stdout


class CommandSource:
    """Base for external CLI tools. Subclasses define binary, argv() and parse()."""

    name = ""
    binary = ""

    def __init__(self, runner: Runner = run_command, which: Callable[[str], str | None] = shutil.which) -> None:
        self.runner = runner
        self.which = which

    def available(self) -> bool:
        return self.which(self.binary) is not None

    def argv(self, domain: str) -> list[str]:
        raise NotImplementedError

    def parse(self, output: str, domain: str) -> Iterable[Observation]:
        raise NotImplementedError

    def collect(self, domain: str) -> Iterable[Observation]:
        return list(self.parse(self.runner(self.argv(domain)), domain))
