"""Source abstractions. A Source turns a root domain into Observations; nothing more."""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable, Iterable, Sequence
from typing import Protocol

import httpx

from easm.models import Observation


class SourceFailure(Exception):
    """The source answered, but with an error/quota message rather than data."""


class Source(Protocol):
    name: str

    def available(self) -> bool: ...

    def collect(self, domain: str) -> Iterable[Observation]: ...


class HttpSource:
    """Base for API/web sources. Subclasses implement collect() using self.get()."""

    name = ""
    key_required = False
    max_pages = 10

    def __init__(self, http: httpx.Client, api_key: str | None = None, *, retries: int = 2, backoff: float = 2.0) -> None:
        self.http = http
        self.api_key = api_key
        self.retries = retries
        self.backoff = backoff

    def available(self) -> bool:
        return bool(self.api_key) or not self.key_required

    def get(self, url: str, **kwargs) -> httpx.Response:
        """GET with retries on transport errors, 5xx and 429 (honouring Retry-After)."""
        for attempt in range(self.retries + 1):
            wait = self.backoff * (attempt + 1)
            try:
                response = self.http.get(url, **kwargs)
                transient = response.status_code >= 500 or response.status_code == 429
                if not transient or attempt == self.retries:
                    response.raise_for_status()
                    return response
                retry_after = response.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    wait = min(float(retry_after), 60.0)
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
