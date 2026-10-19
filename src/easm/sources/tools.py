"""External CLI tools, always invoked in passive mode. Each is skipped if not installed."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator

from easm.models import Observation
from easm.names import extract_hostnames
from easm.sources.base import CommandSource


class Subfinder(CommandSource):
    """ProjectDiscovery subfinder: passive-only by design."""

    name = binary = "subfinder"
    progress_unit = "names"
    progress_waiting = "running (subfinder prints its results only when it finishes)"

    def argv(self, domain: str) -> list[str]:
        return [self.binary, "-d", domain, "-silent", "-all"]

    def parse(self, output: str, domain: str) -> Iterator[Observation]:
        return (Observation(self.name, h) for h in extract_hostnames(output, domain))


class Bbot(CommandSource):
    """BBOT subdomain-enum preset restricted to modules flagged passive."""

    name = binary = "bbot"
    progress_unit = "events"

    def argv(self, domain: str) -> list[str]:
        return [self.binary, "-t", domain, "-p", "subdomain-enum", "-rf", "passive", "-y", "--silent", "--json"]

    def parse(self, output: str, domain: str) -> Iterator[Observation]:
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") != "DNS_NAME":
                continue
            yield Observation(self.name, event["data"])
            for ip in event.get("resolved_hosts") or []:
                yield Observation(self.name, event["data"], ip)


class Dnstwist(CommandSource):
    """Registered typosquat/lookalike domains (DNS lookups only, no web/SMTP probing)."""

    name = "dnstwist"
    progress_waiting = "running (dnstwist prints its results only when it finishes; often minutes)"

    def available(self) -> bool:
        return importlib.util.find_spec("dnstwist") is not None

    def argv(self, domain: str) -> list[str]:
        return [sys.executable, "-m", "dnstwist", "--registered", "--format", "json", domain]

    def parse(self, output: str, domain: str) -> Iterator[Observation]:
        for row in json.loads(output or "[]"):
            if row.get("fuzzer") == "*original":
                continue
            ips = row.get("dns_a", []) + row.get("dns_aaaa", [])
            for ip in ips or [None]:
                yield Observation(self.name, row["domain"], ip, lookalike=True)
