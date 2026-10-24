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
    resolved_ips: set[str] = field(default_factory=set)  # what DNS answered this run (`ips` also holds history)


@dataclass
class IpRecord:
    ip: str
    hostnames: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    org: str | None = None
    network: str | None = None
    ports: set[int] = field(default_factory=set)
    vulns: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)  # Shodan's labels for the address (cdn, cloud, vpn, ...)
    open_ports: set[int] = field(default_factory=set)  # seen open by --fingerprint this run (`ports` is Shodan's history)
    probed_ports: set[int] = field(default_factory=set)  # every port --fingerprint tried this run


@dataclass
class IpDetails:
    """What an enricher learned about an IP."""

    org: str | None = None
    network: str | None = None
    ports: set[int] = field(default_factory=set)
    vulns: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)


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


@dataclass
class Tech:
    """A technology a service appears to run (see easm.fingerprint)."""

    name: str  # "FortiGate SSL-VPN"
    category: str  # edge, cdn, waf, server, cms, framework, mail, panel, platform, database, remote-access, language
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None  # cpe:2.3:a:vendor:product:version, only when the version is known
    evidence: str = ""

    def row(self) -> dict:
        return {k: v for k, v in vars(self).items() if v not in (None, "")}


@dataclass
class ServiceRecord:
    """What one open port on one host answered (--fingerprint). Key: hostname:port."""

    hostname: str
    ip: str
    port: int
    service: str = "tcp"  # http, https, ssh, smtp, ftp, ... or tcp when nothing identified it
    banner: str | None = None
    status: int | None = None
    title: str | None = None
    server: str | None = None
    location: str | None = None  # where it redirects, when off-host or past the redirect limit
    headers: dict[str, str] = field(default_factory=dict)  # the identifying ones only
    cookies: list[str] = field(default_factory=list)  # names only
    tls: dict | None = None  # see easm.probe.cert_summary
    favicon: int | None = None  # Shodan-style mmh3 hash
    paths: dict[str, dict] = field(default_factory=dict)  # well-known path -> {status, note}
    tech: list[Tech] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)  # e.g. "directory-listing", "basic-auth", "git-exposed"

    @property
    def key(self) -> str:
        return f"{self.hostname}:{self.port}"


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
        self.services: dict[str, ServiceRecord] = {}  # hostname:port -> what --fingerprint found there
        self.closed: set[str] = set()  # hostname:port pairs --fingerprint found closed this run (their old rows go)
        self.posture: dict[str, dict] = {}  # scan domain -> mail/DNS/registration facts (easm.posture)
        self.dangling: dict[str, dict] = {}  # hostname -> {"reason", "claimable"}: a CNAME into nothing
        self.dangling_checked: set[str] = set()  # hostnames checked for that this run
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
        rec.tags |= details.tags
