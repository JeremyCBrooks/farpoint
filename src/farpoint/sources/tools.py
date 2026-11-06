"""External CLI tools, always invoked in passive mode. Each is skipped if not installed."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator, Sequence

from farpoint.models import Observation
from farpoint.names import extract_hostnames
from farpoint.sources.base import CommandSource, SourceFailure


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
        seen = False
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            seen = True
            if event.get("type") != "DNS_NAME":
                continue
            yield Observation(self.name, event["data"])
            for ip in event.get("resolved_hosts") or []:
                yield Observation(self.name, event["data"], ip)
        if not seen:  # a scan that ran emits its SCAN event at least; bbot exits 0 when module setup fails
            raise SourceFailure("bbot printed no events: its scan never started (run bbot without --silent to see why)")


# Permutations with only DNS failures are dropped as resolver overload when there are at least
# OVERLOAD_MIN of them and they are more than OVERLOAD_SHARE of the rows dnstwist reported.
OVERLOAD_MIN, OVERLOAD_SHARE = 10, 0.5


def _answers(row: dict, *keys: str) -> list[str]:
    """A dnstwist row's records under `keys`, without its "!ServFail" failure markers."""
    return [v for k in keys for v in row.get(k, []) if not v.startswith("!")]


class Dnstwist(CommandSource):
    """Registered typosquat/lookalike domains (DNS lookups only, no web/SMTP probing)."""

    name = "dnstwist"
    progress_waiting = "running (dnstwist prints its results only when it finishes; often minutes)"

    def __init__(self, nameservers: Sequence[str] = (), **kwargs) -> None:
        super().__init__(**kwargs)
        self.nameservers = list(nameservers)

    def available(self) -> bool:
        return importlib.util.find_spec("dnstwist") is not None

    def argv(self, domain: str) -> list[str]:
        resolvers = ["--nameservers", ",".join(self.nameservers)] if self.nameservers else []
        return [sys.executable, "-m", "dnstwist", "--registered", "--format", "json", *resolvers, domain]

    def parse(self, output: str, domain: str) -> Iterator[Observation]:
        rows = [r for r in json.loads(output or "[]") if r.get("fuzzer") != "*original"]
        # A failed query is recorded as "!ServFail", which --registered counts as an answer. A few such
        # rows are registered lookalikes with dead nameservers; many mean the resolver was overloaded.
        answered = [(row, *(_answers(row, *keys) for keys in (("dns_a", "dns_aaaa"), ("dns_mx",), ("dns_ns",)))) for row in rows]
        failed = sum(1 for _, ips, mx, ns in answered if not (ips or mx or ns))
        overloaded = failed >= OVERLOAD_MIN and failed > len(rows) * OVERLOAD_SHARE
        for row, ips, mx, ns in answered:
            if overloaded and not (ips or mx or ns):
                continue
            for ip in ips or [None]:
                yield Observation(self.name, row["domain"], ip, lookalike=True, mx=tuple(mx), ns=tuple(ns))
        if overloaded:
            raise SourceFailure(f"{failed} of {len(rows)} permutations reported as registered got only DNS failures, so whether they exist is unknown; not reported (is the resolver overloaded?)")
