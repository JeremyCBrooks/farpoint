"""Orchestration: sources -> scoped inventory -> DNS resolution -> IP enrichment."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from easm.enrich import Enricher
from easm.models import Inventory, Observation, SourceError
from easm.names import is_public_ip
from easm.resolve import Resolution
from easm.sources.base import Source

log = logging.getLogger(__name__)


@dataclass
class Pipeline:
    sources: Sequence[Source]
    lookup: Callable[[str], Resolution] | None = None
    enrichers: Sequence[Enricher] = ()
    workers: int = 16

    def run(self, domains: Iterable[str]) -> Inventory:
        inv = Inventory(domains)
        for domain in inv.domains:
            inv.add(Observation("input", domain))
        self._collect(inv)
        if self.lookup:
            self._resolve(inv)
        if self.enrichers:
            self._enrich(inv)
        return inv

    def _fan_out(self, inv: Inventory, jobs: dict[tuple[str, str], Callable]) -> Iterable[tuple[tuple[str, str], object]]:
        """Run jobs concurrently; yield (key, result) for successes, record failures on the inventory."""
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(fn): key for key, fn in jobs.items()}
            for future in as_completed(futures):
                name, target = key = futures[future]
                try:
                    yield key, future.result()
                except Exception as exc:  # one bad source must never sink the run
                    message = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
                    log.warning("%s failed for %s: %s", name, target, message)
                    inv.errors.append(SourceError(name, target, message))

    def _collect(self, inv: Inventory) -> None:
        active = [s for s in self.sources if s.available()]
        inv.skipped = [s.name for s in self.sources if s not in active]
        jobs = {(s.name, d): (lambda s=s, d=d: list(s.collect(d))) for s in active for d in inv.domains}
        for (name, target), observations in self._fan_out(inv, jobs):
            log.info("%-18s %-30s %d results", name, target, len(observations))
            for obs in observations:
                inv.add(obs)

    def _resolve(self, inv: Inventory) -> None:
        pending, attempted = set(inv.hosts), set()
        while pending:
            attempted |= pending
            jobs = {("dns", h): (lambda h=h: self.lookup(h)) for h in pending}
            for (_, host), res in self._fan_out(inv, jobs):
                record = inv.hosts[host]
                record.resolves = bool(res.ips)
                record.cnames.update(res.cnames)
                for ip in res.ips:
                    inv.add(Observation("dns", host, ip))
                for cname in res.cnames:
                    inv.add(Observation("dns-cname", cname))
            pending = set(inv.hosts) - attempted

    def _enrich(self, inv: Inventory) -> None:
        public = [ip for ip in inv.ips if is_public_ip(ip)]
        jobs = {(e.name, ip): (lambda e=e, ip=ip: e.enrich(ip)) for e in self.enrichers for ip in public}
        for (name, ip), details in self._fan_out(inv, jobs):
            inv.enrich(ip, details)
            for hostname in details.hostnames:
                inv.add(Observation(name, hostname, ip))
