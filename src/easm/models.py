"""Core data model: sources emit Observations, the Inventory scopes and merges them."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from easm.names import in_scope, normalize_hostname, normalize_ip


@dataclass(frozen=True)
class Observation:
    """One raw fact from one source: 'hostname exists' and optionally 'it pointed at ip'."""

    source: str
    hostname: str
    ip: str | None = None
    lookalike: bool = False


@dataclass
class HostRecord:
    hostname: str
    ips: set[str] = field(default_factory=set)
    cnames: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    resolves: bool | None = None  # None = not checked


@dataclass
class IpRecord:
    ip: str
    hostnames: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    org: str | None = None
    network: str | None = None
    ports: set[int] = field(default_factory=set)
    vulns: set[str] = field(default_factory=set)


@dataclass
class IpDetails:
    """What an enricher learned about an IP."""

    org: str | None = None
    network: str | None = None
    ports: set[int] = field(default_factory=set)
    vulns: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)


@dataclass
class LookalikeRecord:
    domain: str
    ips: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


@dataclass
class TenantRecord:
    """A name on a third-party platform that carries the organisation's name (see easm.tenants)."""

    hostname: str
    vendor: str
    domain: str  # the scan domain whose name it carries
    tie: str  # what links it to the organisation: "records", "cname" or "name" (a name match only)
    verified: bool  # False: the platform answers any name, so DNS can't tell whether it exists
    evidence: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cnames: set[str] = field(default_factory=set)


@dataclass
class RelatedRecord:
    """Another registered domain the organisation appears to own (see easm.related)."""

    domain: str
    related_to: str  # the scan domain it was found from
    tie: str  # "strong", "medium" or "weak"
    evidence: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class SourceError:
    source: str
    target: str
    message: str


class Inventory:
    def __init__(self, domains: Iterable[str]) -> None:
        self.domains = list(domains)
        self.hosts: dict[str, HostRecord] = {}
        self.ips: dict[str, IpRecord] = {}
        self.lookalikes: dict[str, LookalikeRecord] = {}
        self.tenants: dict[str, TenantRecord] = {}
        self.related: dict[str, RelatedRecord] = {}
        self.related_checked: set[str] = set()  # domains --related looked at this run, tied or not
        self.guessed: set[str] = set()  # names --guess tested this run (whether or not they exist)
        self.errors: list[SourceError] = []
        self.skipped: list[str] = []
        self.interrupted = False  # stopped early (Ctrl-C): what is here is partial

    def scope_of(self, hostname: str) -> str | None:
        return next((d for d in self.domains if in_scope(hostname, d)), None)

    def add(self, obs: Observation) -> None:
        hostname = normalize_hostname(obs.hostname)
        if hostname is None:
            return
        ip = normalize_ip(obs.ip)
        if obs.lookalike:
            rec = self.lookalikes.setdefault(hostname, LookalikeRecord(hostname))
            rec.sources.add(obs.source)
            if ip:
                rec.ips.add(ip)
            return
        if self.scope_of(hostname) is None:
            return
        host = self.hosts.setdefault(hostname, HostRecord(hostname))
        host.sources.add(obs.source)
        if ip:
            host.ips.add(ip)
            ip_rec = self.ips.setdefault(ip, IpRecord(ip))
            ip_rec.hostnames.add(hostname)
            ip_rec.sources.add(obs.source)

    def enrich(self, ip: str, details: IpDetails) -> None:
        rec = self.ips[ip]
        rec.org = rec.org or details.org
        rec.network = rec.network or details.network
        rec.ports |= details.ports
        rec.vulns |= details.vulns
