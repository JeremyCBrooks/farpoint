"""Orchestration: sources -> scoped inventory -> DNS resolution -> IP enrichment."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from easm import runtime
from easm.enrich import Enricher
from easm.models import Inventory, Observation, SourceError
from easm.names import is_public_ip
from easm.progress import NullReporter, ProgressReporter
from easm.resolve import Resolution
from easm.sources.base import Source

log = logging.getLogger(__name__)

Key = tuple[str, str]


@dataclass
class Pipeline:
    sources: Sequence[Source]
    lookup: Callable[[str], Resolution] | None = None
    enrichers: Sequence[Enricher] = ()
    workers: int = 16
    reporter: ProgressReporter = field(default_factory=NullReporter)
    checkpoint: Callable[[Inventory, Mapping[Key, list[Observation]]], None] | None = None  # after each job: (inv, in-progress pages)
    _pending: dict[Key, list[Observation]] = field(default_factory=dict, init=False, repr=False)

    def run(self, domains: Iterable[str]) -> Inventory:
        """Collect, resolve, enrich. On Ctrl-C, stop and return what was gathered, marked interrupted.

        Cancellation is process-wide (see easm.runtime): call runtime.reset() before re-running."""
        inv = Inventory(domains)
        for domain in inv.domains:
            inv.add(Observation("input", domain))
        try:
            self._collect(inv)
            if self.lookup:
                self._resolve(inv)
            if self.enrichers:
                self._enrich(inv)
        except KeyboardInterrupt:
            pass
        if runtime.cancelled():  # also catches a deferred Ctrl-C whose only remaining jobs just got cancelled
            inv.interrupted = True
            self.reporter.interrupted()
        return inv

    def _fan_out(
        self,
        inv: Inventory,
        jobs: dict[Key, Callable],
        limits: dict[str, int] | None = None,
        rows: bool = False,
        on_done: Callable[[bool], None] | None = None,
    ) -> Iterable[tuple[Key, object]]:
        """Run jobs concurrently; yield (key, result) for successes, record failures on the inventory.

        Each job name (source/enricher) gets its own pool, sized by `limits` (capped at `workers`), so a
        throttled source's queued jobs block only its own threads, never another source's. With `rows`,
        each job is reported as its own progress line. If the consumer is interrupted, in-flight jobs
        are cancelled and abandoned rather than waited for.
        """
        limits = limits or {}
        pools: dict[str, ThreadPoolExecutor] = {}
        futures = {}

        def bound(key: Key, fn: Callable) -> Callable:
            def job():
                runtime.bind(self.reporter, key)
                if rows:
                    self.reporter.job_started(key)
                try:
                    return fn()
                finally:
                    runtime.bind(None, None)

            return job

        try:
            for key, fn in jobs.items():
                name = key[0]
                if name not in pools:
                    size = min(self.workers, limits.get(name, self.workers))
                    pools[name] = ThreadPoolExecutor(max_workers=size, thread_name_prefix=name)
                if rows:
                    self.reporter.job_queued(key)
                futures[pools[name].submit(bound(key, fn))] = key
            pending = as_completed(futures)
            while True:
                with runtime.interruptible():  # the only place Ctrl-C is delivered: between results
                    future = next(pending, None)
                if future is None:
                    break
                name, target = key = futures[future]
                try:
                    result = future.result()
                except runtime.Cancelled:
                    continue
                except Exception as exc:  # one bad source must never sink the run
                    ok = False
                    message = _record_failure(inv, name, target, exc)
                    if rows:
                        self.reporter.job_finished(key, 0, message)
                else:
                    ok = True
                    yield key, result
                if on_done:
                    on_done(ok)
                if self.checkpoint:
                    self.checkpoint(inv, self._pending)
        except BaseException:
            runtime.cancel()
            for pool in pools.values():
                pool.shutdown(wait=False, cancel_futures=True)
            raise
        for pool in pools.values():
            pool.shutdown(wait=True)

    def _collect(self, inv: Inventory) -> None:
        active = [s for s in self.sources if s.available()]
        inv.skipped = [s.name for s in self.sources if s not in active]
        partial = self._pending  # created here, before any worker starts; workers only append to their own list
        partial.clear()
        partial.update({(s.name, d): [] for s in active for d in inv.domains})
        jobs = {(s.name, d): (lambda s=s, d=d: _drain(s, d, partial[(s.name, d)])) for s in active for d in inv.domains}
        try:
            for key, (observations, exc) in self._fan_out(inv, jobs, _limits(active), rows=True):
                partial.pop(key, None)
                log.info("%-18s %-30s %d results", *key, len(observations))
                for obs in observations:
                    inv.add(obs)
                if isinstance(exc, runtime.Cancelled):
                    continue  # left as running; reporter.interrupted() marks it once the run stops
                message = _record_failure(inv, *key, exc) if exc is not None else None
                self.reporter.job_finished(key, len(observations), message)
        except KeyboardInterrupt:
            for observations in list(partial.values()):  # pages fetched by jobs still running
                for obs in list(observations):
                    inv.add(obs)
            raise
        finally:
            partial.clear()

    def _resolve(self, inv: Inventory) -> None:
        pending, attempted = set(inv.hosts), set()
        done, failed = [0], [0]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("resolving", done[0], len(attempted), failed[0])

        while pending:
            attempted |= pending
            self.reporter.phase("resolving", done[0], len(attempted), failed[0])
            jobs = {("dns", h): (lambda h=h: self.lookup(h)) for h in pending}
            for (_, host), res in self._fan_out(inv, jobs, on_done=tick):
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
        done, failed = [0], [0]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("enriching", done[0], len(jobs), failed[0])

        self.reporter.phase("enriching", 0, len(jobs))
        for (name, ip), details in self._fan_out(inv, jobs, _limits(self.enrichers), on_done=tick):
            inv.enrich(ip, details)
            for hostname in details.hostnames:
                inv.add(Observation(name, hostname, ip))


def _limits(workers: Iterable) -> dict[str, int]:
    """Per-name pool sizes from each source's/enricher's own concurrency cap, where it declares one."""
    return {w.name: w.max_concurrency for w in workers if isinstance(getattr(w, "max_concurrency", None), int)}


def _drain(source: Source, domain: str, observations: list[Observation]) -> tuple[list[Observation], Exception | None]:
    """Collect what a source yields into `observations` (readable mid-run); if it fails part-way
    (e.g. rate-limited on page 3), keep the earlier pages."""
    try:
        for obs in source.collect(domain):
            observations.append(obs)
    except Exception as exc:
        return observations, exc
    return observations, None


def _record_failure(inv: Inventory, name: str, target: str, exc: Exception) -> str:
    message = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
    log.warning("%s failed for %s: %s", name, target, message)
    inv.errors.append(SourceError(name, target, message))
    return message
