"""Orchestration: sources -> scoped inventory -> DNS resolution -> IP enrichment."""

from __future__ import annotations

import contextlib
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

    def _fan_out(
        self, inv: Inventory, jobs: dict[tuple[str, str], Callable], limits: dict[str, int] | None = None
    ) -> Iterable[tuple[tuple[str, str], object]]:
        """Run jobs concurrently; yield (key, result) for successes, record failures on the inventory.

        Each job name (source/enricher) gets its own pool, sized by `limits` (capped at `workers`), so a
        throttled source's queued jobs block only its own threads, never another source's.
        """
        limits = limits or {}
        with contextlib.ExitStack() as stack:
            pools: dict[str, ThreadPoolExecutor] = {}
            futures = {}
            for key, fn in jobs.items():
                name = key[0]
                if name not in pools:
                    size = min(self.workers, limits.get(name, self.workers))
                    pools[name] = stack.enter_context(ThreadPoolExecutor(max_workers=size, thread_name_prefix=name))
                futures[pools[name].submit(fn)] = key
            for future in as_completed(futures):
                name, target = key = futures[future]
                try:
                    yield key, future.result()
                except Exception as exc:  # one bad source must never sink the run
                    _record_failure(inv, name, target, exc)

    def _collect(self, inv: Inventory) -> None:
        active = [s for s in self.sources if s.available()]
        inv.skipped = [s.name for s in self.sources if s not in active]
        jobs = {(s.name, d): (lambda s=s, d=d: _drain(s, d)) for s in active for d in inv.domains}
        for (name, target), (observations, exc) in self._fan_out(inv, jobs, _limits(active)):
            log.info("%-18s %-30s %d results", name, target, len(observations))
            for obs in observations:
                inv.add(obs)
            if exc is not None:
                _record_failure(inv, name, target, exc)

    def _resolve(self, inv: Inventory) -> None:
        pending, attempted = set(inv.hosts), set()
        while pending:
            attempted |= pending
            jobs = {("dns", h): (lambda h=h: self.lookup(h)) for h in pending}
            for (_, host), res in self._fan_out(inv, jobs):
                record = inv.hosts[host]
                record.resolves = None if res.timed_out else bool(res.ips)
                record.cnames.update(res.cnames)
                for ip in res.ips:
                    inv.add(Observation("dns", host, ip))
                for cname in res.cnames:
                    inv.add(Observation("dns-cname", cname))
            pending = set(inv.hosts) - attempted

    def _enrich(self, inv: Inventory) -> None:
        public = [ip for ip in inv.ips if is_public_ip(ip)]
        jobs = {(e.name, ip): (lambda e=e, ip=ip: e.enrich(ip)) for e in self.enrichers for ip in public}
        for (name, ip), details in self._fan_out(inv, jobs, _limits(self.enrichers)):
            inv.enrich(ip, details)
            for hostname in details.hostnames:
                inv.add(Observation(name, hostname, ip))


def _limits(workers: Iterable) -> dict[str, int]:
    """Per-name pool sizes from each source's/enricher's own concurrency cap, where it declares one."""
    return {w.name: w.max_concurrency for w in workers if isinstance(getattr(w, "max_concurrency", None), int)}


def _drain(source: Source, domain: str) -> tuple[list[Observation], Exception | None]:
    """Collect what a source yields; if it fails part-way (e.g. rate-limited on page 3), keep the earlier pages."""
    observations: list[Observation] = []
    try:
        for obs in source.collect(domain):
            observations.append(obs)
    except Exception as exc:
        return observations, exc
    return observations, None


def _record_failure(inv: Inventory, name: str, target: str, exc: Exception) -> None:
    message = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
    log.warning("%s failed for %s: %s", name, target, message)
    inv.errors.append(SourceError(name, target, message))
