"""Source abstractions. A Source turns a root domain into Observations; nothing more."""

from __future__ import annotations

import logging
import random
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Protocol

import httpx

from easm import runtime
from easm.models import Observation

log = logging.getLogger(__name__)


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
                runtime.status(f"rate limit: next request in {delay:.0f}s")
                runtime.sleep(delay)
            self._next_start = time.monotonic() + self.min_interval

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with jitter: ~backoff * 2^attempt, scaled by 0.5-1.0, capped at MAX_WAIT."""
        return min(self.backoff * 2**attempt, MAX_WAIT) * random.uniform(0.5, 1.0)

    def get(self, url: str, **kwargs) -> httpx.Response:
        """Throttled GET with retries on transport errors, 5xx and 429 (honouring Retry-After)."""
        attempts = self.retries + 1
        with self._slots:
            for attempt in range(attempts):
                runtime.check()
                wait = self._backoff(attempt)
                self._wait_for_turn()
                runtime.status(f"request {attempt + 1}/{attempts}" if attempt else "requesting")
                runtime.count_request()
                try:
                    response = self.http.get(url, **kwargs)
                except httpx.TransportError as exc:
                    if attempt == self.retries:
                        raise SourceFailure(f"{type(exc).__name__} after {attempts} attempts: {exc}") from exc
                    reason = type(exc).__name__
                else:
                    transient = response.status_code >= 500 or response.status_code == 429
                    if not transient:
                        response.raise_for_status()
                        return response
                    reason = f"HTTP {response.status_code}"
                    if attempt == self.retries:
                        raise SourceFailure(f"{reason} {response.reason_phrase} after {attempts} attempts: {response.url}")
                    retry_after = retry_after_seconds(response.headers.get("Retry-After", ""))
                    if retry_after is not None:
                        wait = min(retry_after, MAX_WAIT)
                message = f"{reason}, retrying in {wait:.0f}s ({attempt + 2}/{attempts})"
                log.info("%s: %s", self.name, message)
                runtime.status(message)
                runtime.sleep(wait)
        raise AssertionError("unreachable")

    def observe(self, hostname: str, ip: str | None = None) -> Observation:
        return Observation(self.name, hostname, ip)


Runner = Callable[[Sequence[str]], str]


def run_command(argv: Sequence[str], timeout: float = 1800, unit: str = "lines", waiting: str = "running") -> str:
    """Run a CLI tool, streaming its stdout so progress shows while it runs. Cancelling the run
    terminates it and returns what it printed so far; a non-zero exit only fails if it produced no output."""
    with tempfile.TemporaryFile("w+", encoding="utf-8") as stderr:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr, text=True, encoding="utf-8", errors="replace")
        runtime.track(proc)
        runtime.status(waiting)
        timed_out = threading.Event()
        timer = threading.Timer(timeout, lambda: (timed_out.set(), proc.kill()))
        timer.start()
        lines: list[str] = []
        try:
            for line in proc.stdout:
                lines.append(line)
                runtime.status(f"{len(lines)} {unit}")
            proc.wait()
        finally:
            timer.cancel()
            runtime.untrack(proc)
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        stdout = "".join(lines)
        if runtime.cancelled():
            return stdout  # terminated by us: keep what it found; collect() reports the cancellation
        if timed_out.is_set():
            raise SourceFailure(f"{argv[0]} timed out after {timeout:.0f}s")
        if proc.returncode != 0 and not stdout:
            stderr.seek(0)
            raise SourceFailure(f"{argv[0]} exited {proc.returncode}: {stderr.read().strip()[-500:]}")
        return stdout


class CommandSource:
    """Base for external CLI tools. Subclasses define binary, argv() and parse()."""

    name = ""
    binary = ""
    progress_unit = "lines"  # what one line of stdout is, for the progress display
    progress_waiting = "running"  # shown until the first line arrives

    def __init__(self, runner: Runner | None = None, which: Callable[[str], str | None] = shutil.which) -> None:
        self.runner = runner or (lambda argv: run_command(argv, unit=self.progress_unit, waiting=self.progress_waiting))
        self.which = which

    def available(self) -> bool:
        return self.which(self.binary) is not None

    def argv(self, domain: str) -> list[str]:
        raise NotImplementedError

    def parse(self, output: str, domain: str) -> Iterable[Observation]:
        raise NotImplementedError

    def collect(self, domain: str) -> Iterator[Observation]:
        output = self.runner(self.argv(domain))
        try:
            observations = list(self.parse(output, domain))
        except Exception:
            if runtime.cancelled():  # cut off mid-output (e.g. truncated JSON): nothing usable
                raise runtime.Cancelled() from None
            raise
        yield from observations
        runtime.check()  # interrupted part-way: the caller keeps these, and the job shows as interrupted
