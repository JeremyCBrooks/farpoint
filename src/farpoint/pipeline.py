"""Orchestration: sources -> (opt-in) related domains -> (opt-in) ransomware claims -> scoped inventory ->
DNS resolution -> (opt-in) tenants and guessing -> IP enrichment -> (opt-in) fingerprinting."""

from __future__ import annotations

import ipaddress
import logging
import secrets
import threading
import time
from collections import Counter
from datetime import date, timedelta
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from farpoint import runtime
from farpoint.enrich import Enricher, NoRdapService
from farpoint.fingerprint import (
    own_certificate_org,
    HTTP_FIRST, SERVICE_NAMES, TLS_FIRST, WEB_ONLY, Archive, FingerprintConfig, fingerprint_service, for_host, from_capture, shared_address,
    takeover_platform, was_turned_away,
)
from farpoint.posture import Dns, assess_domain, check_mx, hosted
from farpoint.probe import Prober, ScopedProber
from farpoint.guess import GuessConfig, Taxonomy, parent_of
from farpoint.identity import SignIn, classify, classify_google, m365_tenant_name, tenant_id
from farpoint.lookalikes import RECENT_DAYS, LookalikeConfig
from farpoint.models import KNOWN, RANGE, Inventory, Observation, RelatedRecord, SourceError, TenantRecord, describe
from farpoint.related import TIERS as RELATED_TIERS
from farpoint.related import Probes, Profile, bundled_suffixes, random_under, split, tie, variants
from farpoint.suffixes import registered as registered_domain
from farpoint.names import Exclusions, is_public_ip, normalize_hostname, normalize_ip
from farpoint.progress import NullReporter, ProgressReporter
from farpoint.resolve import Resolution
from farpoint.sources.base import Source
from farpoint.udp import check as udp_check
from farpoint.buckets import candidates as bucket_candidates, judge as judge_bucket
from farpoint.tenants import TIES, TenantConfig, bundled_vendors, candidate_names, confirmed, named_after, org_modifiers, org_tokens, plan, random_name, registered

log = logging.getLogger(__name__)

Key = tuple[str, str]

WILDCARD_PROBES = 3  # random names looked up per parent to tell a wildcard (guesses, split lookalikes)
RELATED_WORKERS = 8  # concurrent lookups for --related, whose ~1,800 per domain mostly go to registries
MIN_SHARE = 1 + WILDCARD_PROBES  # a round's share always covers a guess under a parent not yet probed
IMPLAUSIBLE_MIN, IMPLAUSIBLE_SHARE = 10, 0.5  # this many guesses under a parent, more than this share resolving
ENRICH_ROUNDS = 3  # enrich, resolve the names it reported, enrich their new addresses: at most this many times


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
    related: Probes | None = None  # look for other domains the organisation owns (see farpoint.related)
    related_rate: float | None = None  # start at most this many --related lookups a second (None: as fast as workers go)
    fingerprint: FingerprintConfig | None = None  # probe live hosts and the domains' mail/DNS (needs `lookup`, `prober`, `dns`)
    prober: Prober | None = None
    archive: Archive | None = None  # with `fingerprint`: identify what a bot defence hid from an archived copy
    dns: Dns | None = None  # records()/txt() for posture and dangling-CNAME checks
    rdap_domain: Callable[[str], Mapping] | None = None  # a registered domain's RDAP record
    sign_in: SignIn | None = None  # how each scan domain signs in to Microsoft (with `tenants`)
    google: object | None = None  # identity.GoogleSignIn: where Google Workspace sends each scan domain to sign in (with `tenants`)
    lookalikes: LookalikeConfig | None = None  # registration and certificate lookups for lookalikes that can mail or serve
    exclusions: Exclusions = field(default_factory=Exclusions)  # --out-of-scope: recorded, never contacted
    known: Sequence[str] = ()  # the inventory's earlier hosts: resolved again (and fingerprinted while live) though no source reported them
    ranges: Sequence = ()  # --ranges: the organisation's own address ranges (PTR, passive lookups, and probing by address)
    certificate_orgs: Mapping[str, str] = field(default_factory=dict)  # with `related`: organisation -> scan domain, from earlier scans' certificates
    web: Callable[[str], tuple[int, str] | None] | None = None  # GET a platform's URL (never the organisation's): (status, body)
    buckets: bool = False  # --buckets: storage buckets named after the organisation (needs `web`)
    code: object | None = None  # --code: leads(domain) -> files naming it next to a credential word (sources.github.GitHubCode)
    ransomware: object | None = None  # --ransomware: claims(domain) -> leak-site claims against it (sources.ransomwarelive.RansomwareLive)
    _pending: dict[Key, list[Observation]] = field(default_factory=dict, init=False, repr=False)

    def run(self, domains: Iterable[str]) -> Inventory:
        """Collect, resolve, enrich. On Ctrl-C, stop and return what was gathered, marked interrupted.

        Cancellation is process-wide (see farpoint.runtime): call runtime.reset() before re-running."""
        inv = Inventory(domains)
        inv.ranges = list(self.ranges)
        if self.exclusions and self.prober and not isinstance(self.prober, ScopedProber):
            self.prober = ScopedProber(self.prober, self.exclusions)  # whatever a stage plans, nothing reaches an excluded host
        for domain in inv.domains:
            inv.add(Observation("input", domain))
        try:
            self._collect(inv)
            if self.code:
                self._code(inv)
            for host in self.known:
                inv.add(Observation(KNOWN, host))  # in scope only, like everything else
            if self.related:
                self._related(inv)
            if self.ransomware:
                self._ransomware(inv)
            if self.lookup:
                self._resolve(inv)
                if self.ranges and self.dns:
                    self._ranges(inv)
                if self.tenants and self.txt:
                    self._tenants(inv)
                if self.buckets and self.web:
                    self._buckets(inv)
                if self.guess:
                    self._guess(inv)
            if self.enrichers:
                self._enrich(inv)
            if self.lookalikes:
                self._lookalikes(inv)
            if self.fingerprint and self.prober and self.dns and self.lookup:
                self._fingerprint(inv)
            if self.related:
                self._certificate_related(inv)
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
        on_error: Callable[[Key, Exception], bool] | None = None,
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
                    if on_error and on_error(key, exc):  # the stage reports it itself
                        message = describe(exc)
                    else:
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
        other suffix, tied to the organisation by evidence (farpoint.related). Subdomains of the scan
        domains a tenant lists join the inventory; registered variants with no tie are lookalikes."""
        probes = _PacedProbes(self.related, self.related_rate)
        suffixes = bundled_suffixes()
        done, failed, total = [0], [0], [0]

        def run(kind: str, jobs: dict[str, Callable], on_error: Callable[[Key, Exception], bool] | None = None) -> dict[str, object]:
            total[0] += len(jobs)

            def tick(ok: bool) -> None:
                done[0] += 1
                failed[0] += not ok
                self.reporter.phase("related", done[0], total[0], failed[0])

            keyed = {(kind, target): fn for target, fn in jobs.items()}
            return {target: result for (_, target), result in self._fan_out(inv, keyed, {kind: RELATED_WORKERS}, on_done=tick, on_error=on_error)}

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
        failed_under: dict[str, list[tuple[str, Exception]]] = {}  # TLD -> variants whose NS lookup failed

        def ns_failed(key: Key, exc: Exception) -> bool:
            failed_under.setdefault(key[1].rsplit(".", 1)[-1], []).append((key[1], exc))
            return True

        ns = run("related-ns", {v: (lambda v=v: probes.records(v, "NS")) for v in candidates}, ns_failed)
        for tld, failures in sorted(failed_under.items()):  # one registry that won't answer is one error, not one per name
            names = sorted(name for name, _ in failures)
            shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
            message = f"NS lookup failed for {len(names)} name{'s' if len(names) != 1 else ''} under .{tld} ({shown}): {describe(failures[0][1])}"
            log.warning("related-ns failed under .%s: %s", tld, message)
            inv.errors.append(SourceError("related-ns", f".{tld}", message))
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
                profile = profiles[variant]
                for ip in sorted(profile.a) or [None]:
                    inv.add(Observation("tld-swap", variant, ip, lookalike=True, mx=tuple(profile.mx), ns=tuple(profile.ns)))
        log.info("related: %d domains", len(inv.related))

    def _code(self, inv: Inventory) -> None:
        """--code: public files that name a scan domain next to a credential word. Third parties only."""
        for (_, domain), leads in self._fan_out(inv, {("github-leads", d): (lambda d=d: list(self.code.leads(d))) for d in inv.domains}, rows=True):
            for lead in leads:
                inv.code_leads.setdefault(lead["url"], lead)
            self.reporter.job_finished(("github-leads", domain), len(leads), None)

    def _ransomware(self, inv: Inventory) -> None:
        """--ransomware: claims on ransomware leak sites against the scan domains and their strongly tied
        related domains. Third parties only; a failed search is an error, never "no claims"."""
        related = {d: r.related_to for d, r in sorted(inv.related.items()) if r.tie == "strong" and d not in inv.domains}
        jobs = {("ransomware", d): (lambda d=d: self.ransomware.claims(d)) for d in [*inv.domains, *related]}
        for (_, domain), claims in self._fan_out(inv, jobs, rows=True):
            for claim in claims:
                inv.ransomware_claims.setdefault(claim["id"], {**claim, "scope_domain": domain, "related_to": related.get(domain, "")})
            self.reporter.job_finished(("ransomware", domain), len(claims), None)

    def _ranges(self, inv: Inventory) -> None:
        """--ranges: every address in the organisation's ranges is recorded (and later looked up passively),
        and its PTR name asked. A name under the scan domains joins the inventory; another domain whose name
        carries the organisation's is a weak related domain; anything else (an ISP's generic name) is dropped."""
        import dns.reversename

        addresses = [str(ip) for ip in _range_addresses(self.ranges)]
        for ip in addresses:
            inv.add_address(ip, RANGE)
        progress = _Progress(self.reporter, "ptr", len(addresses))

        def ptr(ip: str) -> list[str]:
            return self.dns.records(dns.reversename.from_address(ip).to_text(omit_final_dot=True), "PTR") or []

        tokens, known = org_tokens(inv.domains), set(inv.hosts)
        for (_, ip), names in self._fan_out(inv, {("ptr", ip): (lambda ip=ip: ptr(ip)) for ip in addresses}, on_done=progress.tick):
            network = next(str(n) for n in self.ranges if ipaddress.ip_address(ip) in n)
            for raw in names:
                name = normalize_hostname(raw)
                if name is None:
                    continue
                if inv.scope_of(name):
                    inv.add(Observation("ptr", name, ip))
                elif (reg := registered_domain(name)) and reg not in inv.domains and (scan := named_after(reg, tokens)):
                    _record_related(inv, reg, scan, "weak", f"PTR of {ip} in the organisation's range {network}: {name}")
        self._resolve(inv, skip=known)

    def _certificate_related(self, inv: Inventory) -> None:
        """Other domains on certificates issued to the organisation: a CA validated the organisation named
        in the subject of a certificate for the scan domains' own names, so other names on certificates
        issued to it are likely its own too (medium: another organisation can carry the same name). Names
        under the scan domains join the inventory."""
        orgs: dict[str, str] = {org: d for org, d in self.certificate_orgs.items() if d in inv.domains}
        for service in inv.services.values():
            if service.ip in inv.ips and _shared_address(inv, service.ip, [service.hostname]):
                continue  # a CDN's or SaaS front end's certificate: theirs, shared with their other customers
            if found := own_certificate_org(service.tls or {}, inv.scope_of):
                orgs.setdefault(*found)
        if not orgs:
            return
        known = set(inv.hosts)
        jobs = {("crtsh-organization", org): (lambda org=org: self.related.certificate_names(org)) for org in sorted(orgs)}
        own = set(inv.domains)
        for (_, org), names in self._fan_out(inv, jobs):
            for raw in names:
                name = normalize_hostname(raw)
                if name is None:
                    continue
                if inv.scope_of(name):
                    inv.add(Observation("crtsh-organization", name))
                elif (reg := registered_domain(name)) and reg not in own:
                    _record_related(inv, reg, orgs[org], "medium", f"on certificates issued to {org} (organisation-validated), as are the scan domains'")
        if self.lookup and set(inv.hosts) - known:
            self._resolve(inv, skip=known)

    def _tenants(self, inv: Inventory) -> None:
        """Tenant patterns from the domains' own TXT/SPF records, their CNAMEs and the bundled table,
        strongest tie first, each checked with random names and then tried, within the budget."""
        config = self.tenants
        if self.sign_in or self.google:
            self._sign_in(inv)
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
        ask: dict[str, Resolution] = {}  # DNS can't tell them from any name: the platform itself is asked
        for (_, name), res in self._fan_out(inv, jobs, on_done=tick):
            probe, domain, bare = tries[name]
            if res.timed_out or not res.found:
                continue
            verified = not _wildcard_answer(res, wildcards[probe.pattern])
            tie, evidence = probe.tie_for(domain)
            if not verified and probe.verify and self.web:
                ask[name] = res
            elif verified or (bare and tie == "records"):
                _record_tenant(inv, name, probe.vendor, domain, tie, evidence, verified, res)
        urls = {name: tries[name][0].verify[0].replace("{name}", name) for name in ask}
        for (_, name), answer in self._fan_out(inv, {("tenants-http", n): (lambda u=urls[n]: self.web(u)) for n in sorted(ask)}):
            probe, domain, bare = tries[name]
            tie, evidence = probe.tie_for(domain)
            if confirmed(probe.verify, name, answer):
                _record_tenant(inv, name, probe.vendor, domain, tie, evidence, True, ask[name])
                inv.tenants[name].evidence.add(f"{urls[name]} answers for it")
            elif bare and tie == "records" and (answer is None or answer[0] == 429 or answer[0] >= 500):
                _record_tenant(inv, name, probe.vendor, domain, tie, evidence, False, ask[name])  # the platform couldn't say: kept unverified, as before
        if self.sign_in:
            self._check_m365_names(inv)
        log.info("tenants: %d found", len(inv.tenants))

    def _buckets(self, inv: Inventory) -> None:
        """--buckets: S3 and Google Cloud Storage buckets the organisation's CNAMEs point at, or named after it,
        each asked once at the storage provider (farpoint.buckets). Found ones are recorded as tenants."""
        hosts = {h: r.cnames for h, r in inv.hosts.items()}
        modifiers, _ = org_modifiers({h: set(c) for h, c in hosts.items()}, inv.domains)
        wanted = bucket_candidates(org_tokens(inv.domains), modifiers, hosts, inv.scope_of)
        progress = _Progress(self.reporter, "buckets", len(wanted))
        by_key = {f"{c.vendor}|{c.name}": c for c in wanted}
        what = {"public": "lists its contents to anyone", "private": "exists, not public", "exists": "exists in another region: whether it lists is unknown"}
        for (_, key), answer in self._fan_out(inv, {("buckets", k): (lambda c=c: self.web(c.url)) for k, c in by_key.items()}, on_done=progress.tick):
            c = by_key[key]
            verdict = judge_bucket(*answer) if answer else None
            if verdict in what:
                _record_tenant(inv, c.hostname, c.vendor, c.domain, c.tie, c.evidence, True, Resolution())
                record = inv.tenants[c.hostname]
                record.evidence.add(f"{c.url}: HTTP {answer[0]}, {what[verdict]}")
                record.public = {"public": True, "private": False}.get(verdict, record.public)

    def _check_m365_names(self, inv: Inventory) -> None:
        """A Microsoft 365 tenant found by its name alone is compared with the tenant the scan domains sign
        in to (one OpenID request per tenant name): someone else's is dropped, the organisation's is tied."""
        ours = {row["tenant_id"]: domain for domain, row in sorted(inv.identity.items(), reverse=True) if row.get("tenant_id")}  # the first domain wins
        if not ours:
            return  # nothing to compare with: name matches stay as they are
        by_tenant: dict[str, list[str]] = {}
        for host, record in inv.tenants.items():
            if record.tie == "name" and (tenant := m365_tenant_name(host)):
                by_tenant.setdefault(tenant, []).append(host)
        jobs = {("entra-tenant", t): (lambda t=t: tenant_id(self.sign_in.openid(t))) for t in sorted(by_tenant)}
        for (_, tenant), found in self._fan_out(inv, jobs):
            if found is None:
                continue  # no answer about it: unknown, left as it is
            for host in by_tenant[tenant]:
                if found in ours:
                    record = inv.tenants[host]
                    record.tie = "records"
                    record.evidence.add(f"same Microsoft 365 tenant as {ours[found]}'s sign-in")
                else:
                    log.info("tenants: %s is Microsoft 365 tenant %s, not the organisation's; dropped", host, found)
                    del inv.tenants[host]
                    inv.tenants_rejected.add(host)  # and out of the running inventory, where an earlier run kept it

    def _sign_in(self, inv: Inventory) -> None:
        """Each scan domain's Microsoft sign-in (farpoint.identity). A self-hosted sign-in server under
        the scan domains joins the inventory, so later stages see it."""
        sign_in = self.sign_in

        def look(domain: str) -> tuple[dict, Exception | None]:
            realm = sign_in.realm(domain)
            try:
                return classify(domain, realm, sign_in.openid(domain)), None
            except Exception as exc:  # the tenant ID is extra: losing it must not lose the sign-in answer
                return classify(domain, realm, None), exc

        jobs = {("entra", d): (lambda d=d: look(d)) for d in inv.domains} if sign_in else {}
        if self.google:
            jobs.update({("google-sso", d): (lambda d=d: (classify_google(d, self.google.saml(d)), None)) for d in inv.domains})
        known = set(inv.hosts)
        for (kind, domain), (row, exc) in self._fan_out(inv, jobs):
            if kind == "google-sso":
                inv.google_identity[domain] = row
                host = row["google_sign_in_host"]
            else:
                inv.identity[domain] = row
                host = row["sign_in_host"]
            if exc is not None:
                _record_failure(inv, "entra-tenant", domain, exc)
            if host and inv.scope_of(host):
                inv.add(Observation(kind, host))
        self._resolve(inv, skip=known)

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
            batch, probing, spent = self._pick(model, inv.domains, tried, caps, wildcards, self.exclusions.host)
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
        model: Taxonomy, domains: Sequence[str], tried: set[str], caps: Mapping[str, int], wildcards: Mapping[str, object],
        excluded: Callable[[str], bool] = lambda name: False,
    ) -> tuple[dict[str, str], set[str], dict[str, int]]:
        """The best untried candidates per domain ({name: domain}), the parents still to probe for
        wildcards, and the lookups that costs per domain (one per candidate plus the probes it needs),
        at most `caps`. Names `excluded` (--out-of-scope) are never offered."""
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
                if name in tried or cost > left or excluded(name):
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
        self, inv: Inventory, parents: Iterable[str], wildcards: dict[str, Resolution | None], lookup: Callable[[str], Resolution],
        stage: str = "guess", unknown: str = "no guesses tested there",
    ) -> None:
        """Look up random names under each parent. If any resolves, everything there does: record what
        it answers. If a probe gets no answer either way, the parent is unknown: an error from `stage`
        says what that means for it (`unknown`)."""

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
                log.info("%s: wildcard DNS under %s", stage, parent)
        for parent in parents - set(wildcards):  # the probe raised (recorded as an error)
            wildcards[parent] = Resolution(timed_out=True)
        for parent in sorted(p for p in parents if (w := wildcards[p]) and w.timed_out):
            inv.errors.append(SourceError(stage, parent, f"wildcard check got no answer; {unknown}"))

    def _enrich(self, inv: Inventory) -> None:
        """Each public address's owner and history. In-scope names an enricher reports join the inventory
        and are resolved, and the new addresses they resolve to are enriched in turn (a few rounds at most),
        so later stages see them this run."""
        progress = _Progress(self.reporter, "enriching")
        asked: set[Key] = set()  # (enricher, address): a range address named since is asked again by the rest
        for _ in range(ENRICH_ROUNDS):
            # An address only --ranges knows of goes only to enrichers cheap enough to ask about a whole range (`bulk`).
            jobs = {(e.name, ip): (lambda e=e, ip=ip: e.enrich(ip)) for e in self.enrichers for ip in list(inv.ips)
                    if is_public_ip(ip) and (e.name, ip) not in asked and (getattr(e, "bulk", False) or not inv.range_only(ip))}
            if not jobs:
                break
            asked.update(jobs)
            progress.grow(len(jobs))
            known = set(inv.hosts)
            for (name, ip), details in self._fan_out(inv, jobs, _limits(self.enrichers), on_done=progress.tick):
                inv.enrich(ip, details)
                for hostname in details.hostnames:
                    inv.add(Observation(name, hostname, ip))
            if self.lookup and set(inv.hosts) - known:
                self._resolve(inv, skip=known)

    def _lookalikes(self, inv: Inventory) -> None:
        """When each lookalike that can handle mail or serve a site was registered, and for recent ones
        the newest certificate (farpoint.lookalikes). Registries and crt.sh, plus a wildcard DNS check
        under the parent of each split name (ex.ample.com)."""
        config = self.lookalikes
        wanted = sorted(d for d, r in inv.lookalikes.items() if (r.mx or r.ips) and d not in config.fresh)
        done, failed, total = [0], [0], [len(wanted)]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("lookalikes", done[0], total[0], failed[0])

        self.reporter.phase("lookalikes", 0, total[0])
        under_wildcards = self._under_a_wildcard(inv, wanted)
        wanted = [d for d in wanted if d not in under_wildcards]
        total[0] = len(wanted)
        if self.dns and wanted:  # the organisation's own NS and MX: a lookalike sharing them is its own
            own = {("scan-dns", d): (lambda d=d: {"domain": d, "ns": self.dns.records(d, "NS") or [], "mx": self.dns.records(d, "MX") or []}) for d in inv.domains}
            for (_, domain), row in self._fan_out(inv, own):
                inv.scan_dns[domain] = row
        def look(domain: str) -> dict | None | NoRdapService:
            try:
                return config.lookups.registration(domain)
            except NoRdapService as exc:  # unknown, not a failure: one note for all of them below
                return exc

        jobs = {("rdap-domain", d): (lambda d=d: look(d)) for d in wanted}
        recent = (date.today() - timedelta(days=RECENT_DAYS)).isoformat()
        unsupported: dict[str, int] = {}  # TLD -> lookalikes under it whose registration is unknown
        for (_, domain), reg in self._fan_out(inv, jobs, on_done=tick):
            if isinstance(reg, NoRdapService):  # left unchecked, so its date stays unknown and it is asked again next run
                unsupported[reg.tld] = unsupported.get(reg.tld, 0) + 1
                continue
            record = inv.lookalikes[domain]
            record.registration, record.checked = reg, True
        if unsupported:
            n = sum(unsupported.values())
            tlds = " ".join(f".{t}" for t in sorted(unsupported))
            inv.errors.append(SourceError("rdap-domain", tlds, f"no RDAP service for these TLDs: registration dates unknown for {n} lookalike{'s' if n != 1 else ''}"))
        new = [d for d in wanted if (inv.lookalikes[d].registration or {}).get("created") and inv.lookalikes[d].registration["created"] >= recent]
        total[0] += len(new)
        jobs = {("crtsh-certificate", d): (lambda d=d: config.lookups.last_certificate(d)) for d in new}
        for (_, domain), started in self._fan_out(inv, jobs, on_done=tick):
            inv.lookalikes[domain].last_certificate = started

    def _under_a_wildcard(self, inv: Inventory, lookalikes: Sequence[str]) -> set[str]:
        """Lookalikes under someone else's registered domain (dnstwist's ex.ample.com) whose parent answers
        any name the same way: a wildcard's answer, not a name set up to look like the organisation, so
        the parent's registration date says nothing about it. Random names are looked up under each parent;
        without an answer either way the lookalike is left undated too."""
        split = {d: parent_of(d) for d in lookalikes if (reg := registered_domain(d)) and reg != d}
        if not split:
            return set()
        if self.lookup is None:
            for domain in sorted(split):
                inv.errors.append(SourceError("lookalikes", domain, "no DNS lookups (--no-resolve): its wildcard check couldn't run, so it is left undated"))
            return set(split)
        wildcards: dict[str, Resolution | None] = {}
        self._probe_wildcards(inv, set(split.values()), wildcards, self.lookup, "lookalikes", "its lookalikes are left undated")
        skipped = set()
        for domain, parent in split.items():
            wildcard, ips = wildcards[parent], inv.lookalikes[domain].ips
            # The check asks for addresses only: it says nothing about a name that only has mail servers.
            if (wildcard and wildcard.timed_out) or (ips and _wildcard_answer(Resolution(tuple(sorted(ips))), wildcard)):
                skipped.add(domain)
        return skipped

    def _fingerprint(self, inv: Inventory) -> None:
        """Sweep each live host's address for open ports, ask each open port who it is, check every
        scan domain's mail/DNS posture and the mail servers it runs itself, and look for CNAMEs that
        point at nothing. See farpoint.fingerprint and farpoint.posture."""
        config, prober = self.fingerprint, self.prober
        pace = _paced(lambda: None, config.rate)
        targets: dict[str, str] = {}  # host -> the address it is probed at
        excluded_at: set[str] = set()  # addresses of hosts excluded by name
        for host, record in sorted(inv.hosts.items()):
            # Only what DNS answers now: an address from passive-DNS history may belong to someone else today.
            public = sorted((ip for ip in record.resolved_ips if ip in inv.ips and is_public_ip(ip)), key=_ip_key)
            if not (record.resolves and public):
                continue
            allowed = [] if self.exclusions.host(host) else [ip for ip in public if not self.exclusions.ip(ip)]
            if allowed:
                targets[host] = allowed[0]
            else:
                inv.excluded.add(host)
                excluded_at.update(public)  # never probed by address through --ranges either
        hosts_at: dict[str, list[str]] = {}
        for host, ip in targets.items():
            hosts_at.setdefault(ip, []).append(host)
        for addr in _range_addresses(self.ranges):  # the organisation's own addresses with no name probed there: asked by address
            ip = str(addr)
            if ip not in hosts_at and ip not in excluded_at and ip in inv.ips and is_public_ip(ip) and not self.exclusions.ip(ip):
                hosts_at[ip] = [ip]
        shared = {ip for ip, hosts in hosts_at.items() if _shared_address(inv, ip, hosts)}

        def ports_for(ip: str) -> list[int]:
            if ip in shared or not config.ports:
                return list(WEB_ONLY)
            return sorted(set(config.ports) | {p for p in inv.ips[ip].ports if 0 < p < 65536})

        def sweep(ip: str) -> dict[int, str]:
            ports, states = ports_for(ip), {}
            for i, port in enumerate(ports):
                pace()
                runtime.status(f"port {port} ({i + 1}/{len(ports)})")
                states[port] = prober.connect(ip, port)
            return states

        done, failed, total = [0], [0], [len(hosts_at)]

        def tick(name: str) -> Callable[[bool], None]:
            def on_done(ok: bool) -> None:
                done[0] += 1
                failed[0] += not ok
                self.reporter.phase(name, done[0], total[0], failed[0])

            return on_done

        self.reporter.phase("ports", 0, total[0])
        open_at: dict[str, list[int]] = {}
        for (_, ip), states in self._fan_out(inv, {("ports", ip): (lambda ip=ip: sweep(ip)) for ip in hosts_at}, on_done=tick("ports")):
            record = inv.ips[ip]
            record.probed_ports.update(states)
            record.open_ports = {p for p, state in states.items() if state == "open"}
            open_at[ip] = sorted(record.open_ports)
            for host in hosts_at[ip]:
                # Only a refusal counts as closed: a timeout may be one dropped packet, so its old row stays.
                inv.closed.update(f"{host}:{p}" for p, state in states.items() if state == "closed")

        def identify_service(host: str, ip: str, port: int):
            pace()
            return fingerprint_service(prober, host, ip, port, inv.hosts[host].cnames if host in inv.hosts else (), config)

        # Web (and unknown) ports are asked per host, since each virtual host can serve something
        # different; other services are the address's, asked once and recorded for each host there.
        jobs, copies = {}, {}
        for ip, ports in open_at.items():
            for port in ports:
                per_host = port in TLS_FIRST or port in HTTP_FIRST or port not in SERVICE_NAMES
                for host in hosts_at[ip] if per_host else hosts_at[ip][:1]:
                    jobs[("service", f"{host}:{port}")] = lambda h=host, ip=ip, p=port: identify_service(h, ip, p)
                if not per_host:
                    copies[f"{hosts_at[ip][0]}:{port}"] = hosts_at[ip][1:]
        done[0] = failed[0] = 0
        total[0] = len(jobs)
        self.reporter.phase("fingerprinting", 0, total[0])
        for (_, key), service in self._fan_out(inv, jobs, on_done=tick("fingerprinting")):
            inv.services[key] = service
            for other in copies.get(key, []):
                inv.services[f"{other}:{service.port}"] = for_host(service, other)
            for signal in service.signals:
                if signal.startswith("takeover:"):
                    inv.dangling[service.hostname] = {"reason": f"serves {signal.split(':', 1)[1]}'s page for an unclaimed name", "claimable": True}
        # A name that resolves now has nothing dangling, unless its page just said otherwise (above).
        inv.dangling_checked.update(h for h, r in inv.hosts.items() if r.resolves)
        if config.scripts:  # names the organisation's own pages and scripts mention: resolved now, probed next scan
            known = set(inv.hosts)
            for service in list(inv.services.values()):
                for name in service.links:
                    inv.add(Observation("javascript", name))
            if set(inv.hosts) - known:
                self._resolve(inv, skip=known)
        if config.udp:
            self._udp(inv, {ip: hosts for ip, hosts in hosts_at.items() if ip not in shared}, pace)
        if self.archive:
            self._archived(inv)
        self._posture(inv)

    def _udp(self, inv: Inventory, hosts_at: Mapping[str, list[str]], pace: Callable[[], None]) -> None:
        """--udp: each of the organisation's own addresses asked once per UDP port (farpoint.udp), the
        answer recorded for every name there. A shared front end's address is the provider's machine: never asked."""
        ports = self.fingerprint.udp

        def ask(ip: str) -> list[tuple[int, str, object]]:
            found = []
            for port in ports:
                pace()
                runtime.status(f"udp {port}")
                found.append((port, *udp_check(self.prober, hosts_at[ip][0], ip, port)))
            return found

        progress = _Progress(self.reporter, "udp", len(hosts_at))
        for (_, ip), answers in self._fan_out(inv, {("udp", ip): (lambda ip=ip: ask(ip)) for ip in hosts_at}, on_done=progress.tick):
            inv.ips[ip].udp_probed.update(port for port, _, _ in answers)
            for port, state, service in answers:
                for host in hosts_at[ip]:
                    if state == "closed":  # ICMP port unreachable: its old row goes; a silence keeps it
                        inv.closed.add(f"{host}:{port}/udp")
                    elif service is not None:
                        inv.services[f"{host}:{port}/udp"] = for_host(service, host)

    def _archived(self, inv: Inventory) -> None:
        """For web services a bot defence hid, what the newest archived copy of the host's homepage shows.
        One lookup per host, to the archive only. Recorded apart from what the scan saw: inventory, not findings."""
        archive, hidden = self.archive, {}
        for key, service in inv.services.items():
            if service.service in ("http", "https") and was_turned_away(service.signals):
                hidden.setdefault(service.hostname, []).append(key)
        done, failed = [0], [0]

        def tick(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("archive", done[0], len(hidden), failed[0])

        self.reporter.phase("archive", 0, len(hidden))
        jobs = {("archive", host): (lambda h=host: archive.capture(h)) for host in sorted(hidden)}
        for (_, host), capture in self._fan_out(inv, jobs, on_done=tick):
            if capture and (found := from_capture(archive.name, capture)):
                for key in hidden[host]:
                    inv.services[key].archived = found

    def _posture(self, inv: Inventory) -> None:
        dns, prober = self.dns, self.prober
        own = lambda host: inv.scope_of(host) is not None or registered_domain(host) in inv.domains
        jobs: dict[Key, Callable] = {("posture", d): (lambda d=d: assess_domain(dns, prober, d, own, self.rdap_domain, axfr=self.fingerprint.axfr)) for d in inv.domains}
        quiet = [h for h, r in sorted(inv.hosts.items()) if r.resolves is False]
        jobs.update({("dangling", h): (lambda h=h: _dangling(dns, inv, h)) for h in quiet})
        done, failed, total = [0], [0], [len(jobs)]

        def counter(ok: bool) -> None:
            done[0] += 1
            failed[0] += not ok
            self.reporter.phase("posture", done[0], total[0], failed[0])

        self.reporter.phase("posture", 0, total[0])
        for (kind, target), result in self._fan_out(inv, jobs, on_done=counter):
            if kind == "posture":
                inv.posture[target] = result
                for message in result.get("check_errors", []):
                    inv.errors.append(SourceError("posture", target, message))
                if result.get("mta_sts_error"):
                    inv.errors.append(SourceError("posture", target, result["mta_sts_error"]))
                if result.get("registration_error"):
                    inv.errors.append(SourceError("posture", target, f"registration unknown: {result['registration_error']}"))
                for rdtype, key in (("DS", "dnssec"), ("CAA", "caa")):
                    if result.get(key) is None and result.get("ns"):
                        inv.errors.append(SourceError("posture", target, f"the resolver failed {rdtype} queries, so {key} is unknown (try --nameserver 1.1.1.1)"))
                continue
            inv.dangling_checked.add(target)
            if result:
                inv.dangling[target] = result
        # Only mail servers named under the organisation's own domains: a hosted provider's or an ISP's are theirs.
        mx_hosts = sorted({m for p in inv.posture.values() for m in p.get("mx", []) if own(m) and not hosted(m)})
        mx_jobs = {("mx", m): (lambda m=m: _mx(self.lookup, self.prober, m, self.exclusions)) for m in mx_hosts}
        total[0] += len(mx_jobs)
        health = {m: r for (_, m), r in self._fan_out(inv, mx_jobs, on_done=counter) if r}
        for row in inv.posture.values():
            row["mx_health"] = [health[m] for m in row.get("mx", []) if m in health]


class _Progress:
    """A phase's progress line: done, failed and total jobs, reported as each finishes."""

    def __init__(self, reporter: ProgressReporter, phase: str, total: int = 0) -> None:
        self.reporter, self.phase, self.done, self.failed, self.total = reporter, phase, 0, 0, total
        reporter.phase(phase, 0, total)

    def grow(self, n: int) -> None:
        self.total += n
        self.reporter.phase(self.phase, self.done, self.total, self.failed)

    def tick(self, ok: bool) -> None:
        self.done += 1
        self.failed += not ok
        self.reporter.phase(self.phase, self.done, self.total, self.failed)


def _range_addresses(ranges: Iterable) -> Iterable:
    """Every usable address in the ranges: not a block's network or broadcast address."""
    for net in ranges:
        yield from (net.hosts() if net.num_addresses > 2 else net)


def _ip_key(ip: str) -> tuple[int, int]:
    import ipaddress

    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def _shared_address(inv: Inventory, ip: str, hosts: Sequence[str]) -> bool:
    """A CDN's or SaaS front end's address: the organisation's names answer there, but the machine (and
    every other port on it) is the provider's, so only its web ports are asked. Addresses behind a
    CNAME to a cloud VM or load balancer (cloudapp.azure.com, elb.amazonaws.com) are the organisation's."""
    return shared_address(inv.ips[ip].org, [inv.hosts[h].cnames for h in hosts if h in inv.hosts], inv.ips[ip].tags)


def _dangling(dns: Dns, inv: Inventory, host: str) -> dict | None:
    """A name that doesn't resolve because its CNAME points at a name that doesn't exist (outside the
    organisation's domains): whoever registers that name, or claims it on the platform, gets the host."""
    targets = dns.records(host, "CNAME")
    if not targets:
        return None
    target = targets[0]
    if inv.scope_of(target) or dns.records(target, "A") is not None:
        return None
    platform = takeover_platform(target)
    reg = registered_domain(target)
    if reg and dns.records(reg, "NS") is None:  # also when the target is itself the lapsed domain
        return {"reason": f"CNAME to {target}, whose domain {reg} is not registered: anyone can register it", "claimable": True}
    if platform:
        return {"reason": f"CNAME to {target}, which does not exist ({platform}: the name may be claimable)", "claimable": True}
    return {"reason": f"CNAME to {target}, which does not exist", "claimable": False}


def _mx(lookup: Callable[[str], Resolution], prober: Prober, host: str, exclusions: Exclusions = Exclusions()) -> dict | None:
    if exclusions.host(host):
        return None
    res = lookup(host)
    ip = next((ip for ip in res.ips if is_public_ip(ip) and not exclusions.ip(ip)), None)
    return check_mx(prober, host, ip) if ip else None


def _record_resolution(inv: Inventory, host: str, res: Resolution) -> None:
    record = inv.hosts[host]
    ips = {ip for raw in res.ips if (ip := normalize_ip(raw))}
    blocked = bool(res.ips) and not ips  # only a filtering resolver's block page: unknown, like a timeout
    record.resolves = None if res.timed_out or blocked else bool(ips)
    record.resolved_ips.update(ips)
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


def _paced(fn: Callable, rate: float | None) -> Callable:
    """`fn`, started at most `rate` times a second across all threads (None: as fast as workers go)."""
    if not rate:
        return fn
    pace, next_start = threading.Lock(), [0.0]

    def paced(*args, **kwargs):
        with pace:
            delay = next_start[0] - time.monotonic()
            if delay > 0:
                runtime.sleep(delay)
            next_start[0] = max(next_start[0], time.monotonic()) + 1 / rate
        return fn(*args, **kwargs)

    return paced


class _PacedProbes:
    """`probes` with every call, of every kind, started at most `rate` times a second in all (None: unpaced)."""

    def __init__(self, probes: Probes, rate: float | None) -> None:
        self._probes, self._pace = probes, _paced(lambda: None, rate)

    def __getattr__(self, name: str):
        attr = getattr(self._probes, name)
        if not callable(attr):
            return attr

        def paced(*args, **kwargs):
            self._pace()
            return attr(*args, **kwargs)

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
    message = describe(exc)
    log.warning("%s failed for %s: %s", name, target, message)
    inv.errors.append(SourceError(name, target, message))
    return message
