"""Orchestration: sources -> (opt-in) related domains -> scoped inventory -> DNS resolution -> (opt-in)
tenants and guessing -> IP enrichment."""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from easm import runtime
from easm.enrich import Enricher
from easm.guess import GuessConfig, Taxonomy, parent_of
from easm.models import Inventory, Observation, RelatedRecord, SourceError, TenantRecord
from easm.related import TIERS as RELATED_TIERS
from easm.related import Probes, Profile, bundled_suffixes, random_under, split, tie, variants
from easm.suffixes import registered as registered_domain
from easm.names import is_public_ip
from easm.progress import NullReporter, ProgressReporter
from easm.resolve import Resolution
from easm.sources.base import Source
from easm.tenants import TIES, TenantConfig, bundled_vendors, candidate_names, named_after, org_modifiers, org_tokens, plan, random_name, registered

log = logging.getLogger(__name__)

Key = tuple[str, str]

WILDCARD_PROBES = 3  # random names looked up per parent before guessing under it
RELATED_WORKERS = 8  # concurrent lookups for --related, whose ~1,800 per domain mostly go to registries
MIN_SHARE = 1 + WILDCARD_PROBES  # a round's share always covers a guess under a parent not yet probed
IMPLAUSIBLE_MIN, IMPLAUSIBLE_SHARE = 10, 0.5  # this many guesses under a parent, more than this share resolving


@dataclass
class Pipeline:
    sources: Sequence[Source]
    lookup: Callable[[str], Resolution] | None = None
    enrichers: Sequence[Enricher] = ()
    workers: int = 16
    reporter: ProgressReporter = field(default_factory=NullReporter)
    checkpoint: Callable[[Inventory, Mapping[Key, list[Observation]]], None] | None = None  # after each job: (inv, in-progress pages)
    guess: GuessConfig | None = None  # predict unseen names and test them in DNS (needs `lookup`)
    tenants: TenantConfig | None = None  # look for the organisation's tenants on SaaS platforms (needs `lookup`, `txt`)
    txt: Callable[[str], list[str]] | None = None  # a name's TXT strings
    related: Probes | None = None  # look for other domains the organisation owns (see easm.related)
    _pending: dict[Key, list[Observation]] = field(default_factory=dict, init=False, repr=False)

    def run(self, domains: Iterable[str]) -> Inventory:
        """Collect, resolve, enrich. On Ctrl-C, stop and return what was gathered, marked interrupted.

        Cancellation is process-wide (see easm.runtime): call runtime.reset() before re-running."""
        inv = Inventory(domains)
        for domain in inv.domains:
            inv.add(Observation("input", domain))
        try:
            self._collect(inv)
            if self.related:
                self._related(inv)
            if self.lookup:
                self._resolve(inv)
                if self.tenants and self.txt:
                    self._tenants(inv)
                if self.guess:
                    self._guess(inv)
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

    def _resolve(self, inv: Inventory, skip: Iterable[str] = ()) -> None:
        attempted = set(skip)
        pending = set(inv.hosts) - attempted
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
                _record_resolution(inv, host, res)
            pending = set(inv.hosts) - attempted

    def _related(self, inv: Inventory) -> None:
        """Domains in the scan domains' Microsoft 365 tenants, then the scan domains' names under every
        other suffix, tied to the organisation by evidence (easm.related). Subdomains of the scan
        domains a tenant lists join the inventory; registered variants with no tie are lookalikes."""
        probes, suffixes = self.related, bundled_suffixes()
        done, failed, total = [0], [0], [0]

        def run(kind: str, jobs: dict[str, Callable]) -> dict[str, object]:
            total[0] += len(jobs)

            def tick(ok: bool) -> None:
                done[0] += 1
                failed[0] += not ok
                self.reporter.phase("related", done[0], total[0], failed[0])

            keyed = {(kind, target): fn for target, fn in jobs.items()}
            return {target: result for (_, target), result in self._fan_out(inv, keyed, {kind: RELATED_WORKERS}, on_done=tick)}

        tenants = run("related-m365", {d: (lambda d=d: probes.tenant_domains(d)) for d in inv.domains})
        own = set(inv.domains)
        for domain, names in sorted(tenants.items()):
            for name in names:
                if inv.scope_of(name):
                    inv.add(Observation("m365", name))  # a subdomain the tenant verified
                elif registered_domain(name) == name and not name.endswith(".onmicrosoft.com"):
                    own.add(name)
                    inv.related_checked.add(name)
                    _record_related(inv, name, domain, "strong", f"in the Microsoft 365 tenant of {domain}")

        candidates: dict[str, list[str]] = {}  # variant -> the scan domains whose name it carries
        for d in inv.domains:
            for v in variants(d, suffixes):
                if v not in own and not inv.scope_of(v):
                    candidates.setdefault(v, []).append(d)
        ns = run("related-ns", {v: (lambda v=v: probes.records(v, "NS")) for v in candidates})
        inv.related_checked.update(ns)  # looked up (a timeout is an error, not "unregistered")
        found_under = {split(v)[1] for v, r in ns.items() if r}
        wild = {s for s, r in run("related-wildcard", {s: (lambda s=s: probes.records(random_under(s), "NS")) for s in found_under}).items() if r}
        found = {v: ds for v, ds in candidates.items() if ns.get(v) and split(v)[1] not in wild}

        names = sorted(set(found) | set(inv.domains))
        profiles = run("related-dns", {n: (lambda n=n: Profile.of(probes, n, ns.get(n))) for n in names})
        redirects = run("related-http", {v: (lambda v=v: probes.redirects(v)) for v in found})
        shared = {ip for v, ds in found.items() for d in ds if v in profiles and d in profiles for ip in profiles[v].a & profiles[d].a}
        owners = run("related-rdap", {ip: (lambda ip=ip: probes.network_owner(ip)) for ip in shared})
        for variant, domains in sorted(found.items()):
            ties = [(t, d) for d in domains if variant in profiles and d in profiles and (t := tie(variant, d, profiles, own, redirects.get(variant, []), owners))]
            if ties:
                (tier, evidence), domain = max(ties, key=lambda td: RELATED_TIERS.index(td[0][0]))
                _record_related(inv, variant, domain, tier, evidence)
            elif variant in profiles:
                for ip in sorted(profiles[variant].a) or [None]:
                    inv.add(Observation("tld-swap", variant, ip, lookalike=True))
        log.info("related: %d domains", len(inv.related))

    def _tenants(self, inv: Inventory) -> None:
        """Tenant patterns from the domains' own TXT/SPF records, their CNAMEs and the bundled table,
        strongest tie first, each checked with random names and then tried, within the budget."""
        config = self.tenants
        txt: dict[str, list[str]] = {}
        for (_, domain), strings in self._fan_out(inv, {("tenants-txt", d): (lambda d=d: self.txt(d)) for d in inv.domains}):
            txt[domain] = strings
        hosts = {h: set(c) for h, c in config.known.items() if inv.scope_of(h)}
        for h, r in inv.hosts.items():
            hosts[h] = hosts.get(h, set()) | r.cnames
        probes = plan(inv.domains, txt, [c for cnames in hosts.values() for c in cnames], config.vendors if config.vendors is not None else bundled_vendors())
        tokens = org_tokens(inv.domains)
        modifiers, sep = org_modifiers(hosts, inv.domains)
        _cname_tenants(inv, hosts)

        budget, chosen = config.budget, []
        for probe in probes:
            names = candidate_names(probe, tokens, modifiers, sep)[: max(budget - WILDCARD_PROBES, 0)]
            if not names:
                break
            budget -= WILDCARD_PROBES + len(names)
            chosen.append((probe, names))
        done, failed, total = [0], [0], [sum(WILDCARD_PROBES + len(names) for _, names in chosen)]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("tenants", done[0], total[0], failed[0])

        self.reporter.phase("tenants", 0, total[0])
        jobs = {("tenants-wildcard", f"{probe.pattern}#{i}"): (lambda p=probe: self.lookup(random_name(p))) for probe, _ in chosen for i in range(WILDCARD_PROBES)}
        answers: dict[str, list[Resolution]] = {}
        for (_, key), res in self._fan_out(inv, jobs, on_done=tick):
            answers.setdefault(key.rsplit("#", 1)[0], []).append(res)
        wildcards: dict[str, Resolution | None] = {}
        for probe, _ in chosen:
            got = answers.get(probe.pattern, [])
            if len(got) < WILDCARD_PROBES or any(a.timed_out for a in got):
                inv.errors.append(SourceError("tenants", probe.pattern, "wildcard check got no answer; pattern not tried"))
            elif found := [a for a in got if a.found]:
                wildcards[probe.pattern] = Resolution(
                    tuple(sorted({ip for a in found for ip in a.ips})), tuple(sorted({c for a in found for c in a.cnames})), exists=True
                )
            else:
                wildcards[probe.pattern] = None
        tries = {name: (probe, domain, bare) for probe, names in chosen if probe.pattern in wildcards for name, domain, bare in names}
        jobs = {("tenants", name): (lambda n=name: self.lookup(n)) for name in tries}
        for (_, name), res in self._fan_out(inv, jobs, on_done=tick):
            probe, domain, bare = tries[name]
            if res.timed_out or not res.found:
                continue
            verified = not _wildcard_answer(res, wildcards[probe.pattern])
            tie, evidence = probe.tie_for(domain)
            if verified or (bare and tie == "records"):
                _record_tenant(inv, name, probe.vendor, domain, tie, evidence, verified, res)
        log.info("tenants: %d found", len(inv.tenants))

    def _guess(self, inv: Inventory) -> None:
        """Rounds of: learn the naming taxonomy from everything known, test the best untried candidates
        per domain (probes included, within its budget), keep those that resolve and aren't a
        wildcard's answer, then resolve whatever in-scope CNAME targets the new names point at.

        The budget is shared out so that later rounds have something to spend: each of the `rounds`
        gets an equal part of what is left, minus a `follow_up` share kept for one more round, so what
        the last regular round finds still has its variants tried in this run. A round that finds
        nothing just goes on down the list. `rounds=0` means no guessing."""
        config = self.guess
        known = {h: cnames for h, cnames in config.known.items() if inv.scope_of(h)}
        tried = set(inv.hosts) | set(known) | set(config.tried)  # never offered again
        lookup = _paced(self.lookup, config.rate)
        checked = set(inv.hosts)  # resolution already attempted this run
        budget = dict.fromkeys(inv.domains, config.budget)
        wildcards: dict[str, Resolution | None] = {}  # parent -> wildcard answer; timed_out: unknown, don't guess there
        done, failed, total = [0], [0], [0]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("guessing", done[0], total[0], failed[0])

        def has_address(host: str) -> bool:
            record = inv.hosts.get(host)
            return bool(record and record.ips) or (host in known and host not in config.known_weak)

        reserve = min(config.budget, max(int(config.budget * config.follow_up), MIN_SHARE)) if config.follow_up else 0
        model = None
        for i in range(config.rounds + 1 if config.rounds else 0):
            last = i == config.rounds
            caps = {d: budget[d] if last else min(budget[d], max((budget[d] - reserve) // (config.rounds - i), MIN_SHARE)) for d in inv.domains}
            if model is None:  # rebuilt only when the last round found something
                hosts = {h: set(c) for h, c in known.items()}
                for h, r in inv.hosts.items():
                    hosts[h] = hosts.get(h, set()) | r.cnames
                tenants = {**config.tenants, **{t.hostname: t.domain for t in inv.tenants.values() if t.verified}}
                model = Taxonomy(hosts, inv.domains, config.prior, weak={h for h in hosts if not has_address(h)}, tenants=tenants)
            batch, probing, spent = self._pick(model, inv.domains, tried, caps, wildcards)
            for d, n in spent.items():
                budget[d] -= n
            if not batch:
                if last or not any(budget.values()):
                    break
                continue  # nothing fit this round's share: the next round's is larger
            tried.update(batch)
            self._probe_wildcards(inv, probing, wildcards, lookup)
            usable = []
            for name, domain in batch.items():
                if (w := wildcards.get(parent_of(name))) and w.timed_out:
                    budget[domain] += 1  # not looked up: spend it in a later round
                else:
                    usable.append(name)
            total[0] += len(usable)
            self.reporter.phase("guessing", done[0], total[0], failed[0])
            answers = {}
            inv.guessed.update(usable)
            jobs = {("guess", h): (lambda h=h: lookup(h)) for h in usable}
            for (_, host), res in self._fan_out(inv, jobs, on_done=tick):
                if res.ips and not _wildcard_answer(res, wildcards.get(parent_of(host))):
                    answers[host] = res
            for parent in self._implausible(usable, answers):
                wildcards[parent] = Resolution(timed_out=True)
                inv.errors.append(SourceError("guess", parent, "most guesses resolved: wildcard-like DNS, results discarded"))
                log.warning("guessing: most guesses under %s resolved; treating it as wildcard DNS", parent)
                answers = {h: res for h, res in answers.items() if parent_of(h) != parent}
            for host, res in answers.items():
                inv.add(Observation("guess", host))
                _record_resolution(inv, host, res)
            checked.update(usable)
            self._resolve(inv, skip=checked)  # in-scope CNAME targets the new names point at
            checked.update(inv.hosts)
            if self.tenants:  # a found name's alias may be a tenant, whose words teach the next round
                _cname_tenants(inv, {h: inv.hosts[h].cnames for h in answers})
            log.info("guessing: %d of %d candidates resolved", len(answers), len(usable))
            if answers:
                model = None

    @staticmethod
    def _pick(
        model: Taxonomy, domains: Sequence[str], tried: set[str], caps: Mapping[str, int], wildcards: Mapping[str, object]
    ) -> tuple[dict[str, str], set[str], dict[str, int]]:
        """The best untried candidates per domain ({name: domain}), the parents still to probe for
        wildcards, and the lookups that costs per domain (one per candidate plus the probes it needs),
        at most `caps`."""
        batch: dict[str, str] = {}
        probing: set[str] = set()
        spent = dict.fromkeys(domains, 0)
        for domain in domains:
            for name in model.candidates(domain):
                left = caps[domain] - spent[domain]
                if left < 1:
                    break
                parent = parent_of(name)
                cost = 1 + (WILDCARD_PROBES if parent not in wildcards and parent not in probing else 0)
                if name in tried or cost > left:
                    continue
                spent[domain] += cost
                if parent not in wildcards:
                    probing.add(parent)
                batch[name] = domain
        return batch, probing, spent

    @staticmethod
    def _implausible(tested: Iterable[str], answers: Mapping[str, Resolution]) -> set[str]:
        """Parents where most guesses resolved: real naming never looks like that, a wildcard whose
        addresses rotate past the probes does."""
        per_parent = Counter(parent_of(h) for h in tested)
        hits = Counter(parent_of(h) for h in answers)
        return {p for p, n in hits.items() if per_parent[p] >= IMPLAUSIBLE_MIN and n / per_parent[p] > IMPLAUSIBLE_SHARE}

    def _probe_wildcards(
        self, inv: Inventory, parents: Iterable[str], wildcards: dict[str, Resolution | None], lookup: Callable[[str], Resolution]
    ) -> None:
        """Look up random names under each parent. If any resolves, everything there does: record what
        it answers. If a probe gets no answer either way, the parent is unknown and not guessed under."""

        def probe(parent: str) -> Resolution | None:
            answers = [lookup(f"{secrets.token_hex(8)}.{parent}") for _ in range(WILDCARD_PROBES)]
            ips = {ip for a in answers for ip in a.ips}
            if ips:
                return Resolution(tuple(sorted(ips)), tuple(sorted({c for a in answers for c in a.cnames})))
            return Resolution(timed_out=True) if any(a.timed_out for a in answers) else None

        parents = set(parents)
        jobs = {("wildcard", p): (lambda p=p: probe(p)) for p in parents}
        for (_, parent), res in self._fan_out(inv, jobs):
            wildcards[parent] = res
            if res and not res.timed_out:
                log.info("wildcard DNS under %s: guesses there must answer differently", parent)
        for parent in parents - set(wildcards):  # the probe raised (recorded as an error)
            wildcards[parent] = Resolution(timed_out=True)
        for parent in sorted(p for p in parents if (w := wildcards[p]) and w.timed_out):
            inv.errors.append(SourceError("guess", parent, "wildcard check got no answer; no guesses tested there"))

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


def _record_resolution(inv: Inventory, host: str, res: Resolution) -> None:
    record = inv.hosts[host]
    record.resolves = None if res.timed_out else bool(res.ips)
    record.cnames.update(res.cnames)
    for ip in res.ips:
        inv.add(Observation("dns", host, ip))
    for cname in res.cnames:
        inv.add(Observation("dns-cname", cname))


def _record_related(inv: Inventory, domain: str, related_to: str, tier: str, evidence: str) -> None:
    record = inv.related.get(domain)
    if record is None:
        record = inv.related[domain] = RelatedRecord(domain, related_to, tier)
    elif RELATED_TIERS.index(tier) > RELATED_TIERS.index(record.tie):
        record.tie, record.related_to = tier, related_to
    record.evidence.add(evidence)


def _paced(lookup: Callable[[str], Resolution], rate: float | None) -> Callable[[str], Resolution]:
    """`lookup`, started at most `rate` times a second across all threads (None: as fast as workers go)."""
    if not rate:
        return lookup
    pace, next_start = threading.Lock(), [0.0]

    def paced(name: str) -> Resolution:
        with pace:
            delay = next_start[0] - time.monotonic()
            if delay > 0:
                runtime.sleep(delay)
            next_start[0] = max(next_start[0], time.monotonic()) + 1 / rate
        return lookup(name)

    return paced


def _cname_tenants(inv: Inventory, hosts: Mapping[str, Iterable[str]]) -> None:
    """An alias to a name outside scope that carries the organisation's (example-files.vault.io) is a tenant."""
    tokens = org_tokens(inv.domains)
    for host, targets in sorted(hosts.items()):
        for target in sorted(targets):
            if not inv.scope_of(target) and (domain := named_after(target, tokens)):
                _record_tenant(inv, target, registered(target), domain, "cname", f"CNAME of {host}", True, Resolution())


def _record_tenant(inv: Inventory, name: str, vendor: str, domain: str, tie: str, evidence: str, verified: bool, res: Resolution) -> None:
    record = inv.tenants.get(name)
    if record is None:
        record = inv.tenants[name] = TenantRecord(name, vendor, domain, tie, verified)
    elif TIES.index(tie) > TIES.index(record.tie):
        record.tie, record.vendor = tie, vendor
    record.verified = record.verified or verified
    record.evidence.add(evidence)
    record.ips.update(res.ips)
    record.cnames.update(res.cnames)


def _wildcard_answer(res: Resolution, wildcard: Resolution | None) -> bool:
    """Whether `res` is what a wildcard returns for any name: its alias, or only its addresses. A name
    with an address of its own counts as real, even if it shares a load balancer with the wildcard."""
    if wildcard is None:
        return False
    return bool(set(res.cnames) & set(wildcard.cnames)) or set(res.ips) <= set(wildcard.ips)


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
