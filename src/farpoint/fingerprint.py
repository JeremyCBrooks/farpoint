"""Opt-in host fingerprinting (--fingerprint): what each live endpoint appears to run.

For every in-scope host that resolves to a public address, the address's ports are checked with
plain TCP connects, and each open port is asked who it is in the most ordinary way: read what it
says first (SSH, FTP, SMTP, MySQL greet you), a TLS handshake, `GET /`, the favicon and a few
well-known paths. The answers are matched against bundled rules (data/fingerprints.json) to name
technologies and versions. Nothing logs in, sends a payload or tries a vulnerability.

This module decides what to ask; farpoint.probe does the asking.
"""

from __future__ import annotations

import base64
import html
import re
import struct
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from functools import cache
from importlib import resources
from urllib.parse import urljoin, urlsplit

from farpoint import runtime
from farpoint.models import ServiceRecord, Tech
from farpoint.probe import HttpResult, Prober, UnsupportedHere, _name_matches, cert_summary

# Management and data services attackers scan for first, plus the common web and appliance ports.
DEFAULT_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2375, 3306, 3389,
    4443, 5432, 5443, 5900, 5985, 5986, 6379, 6443, 7443, 8000, 8080, 8443, 8888, 9200, 9443, 10443, 20443,
    30443, 40443, 50443, 60443, 27017,
)
DEFAULT_PATHS = ("/robots.txt", "/.well-known/security.txt", "/.git/HEAD")
WEB_ONLY = (80, 443)  # ports tried on shared CDN/hosting addresses, which aren't the organisation's machines

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 5986: "winrm", 6379: "redis", 6443: "kubernetes", 9200: "elasticsearch", 27017: "mongodb",
}
SMTP_PORTS = frozenset({25, 587})
TLS_FIRST = frozenset({443, 4443, 5443, 5986, 6443, 7443, 8443, 9443, 10443, 20443, 30443, 40443, 50443, 60443})
HTTP_FIRST = frozenset({80, 2375, 5985, 8000, 8080, 8888, 9200})
TLS_ONLY = frozenset({465, 636, 990, 993, 995})  # implicit TLS, not web: the certificate is what we learn
SILENT = frozenset({53, 445, 1433, 1521, 3389, 5432, 6379, 27017})  # binary protocols: open is all we learn
MAX_REDIRECTS = 3

# Headers whose values change on every request, or that carry nothing about the software.
_DROP_HEADERS = frozenset({
    "date", "content-length", "set-cookie", "etag", "expires", "last-modified", "age", "connection",
    "keep-alive", "transfer-encoding", "accept-ranges", "vary", "cache-control", "pragma", "content-type",
    "x-request-id", "x-correlation-id", "report-to", "nel", "alt-svc", "x-amz-cf-pop", "cf-cache-status",
})


@dataclass
class FingerprintConfig:
    ports: tuple[int, ...] = DEFAULT_PORTS  # empty: no sweep, just 80 and 443
    paths: tuple[str, ...] = DEFAULT_PATHS
    rate: float | None = 20.0  # connections a second, across all threads
    legacy_tls: bool = True  # also check whether TLS 1.0/1.1 are still accepted (two extra handshakes)


def parse_ports(value: str) -> tuple[int, ...]:
    """`--ports`: a list replaces the defaults, `+list` adds to them, `none` sweeps nothing. Ranges allowed (8000-8010)."""
    value = value.strip()
    if value.lower() == "none":
        return ()
    extra = value.startswith("+")
    ports: set[int] = set(DEFAULT_PORTS) if extra else set()
    for part in value.lstrip("+").split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            start, end = int(lo), int(hi or lo)
        except ValueError:
            raise ValueError(f"bad port {part!r}") from None
        if not (1 <= start <= end <= 65535):
            raise ValueError(f"bad port {part!r}")
        if end - start > 1000:
            raise ValueError(f"port range {part!r} is too wide for a light sweep")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("no ports given")
    return tuple(sorted(ports))


def parse_paths(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "none":
        return ()
    return tuple(p if p.startswith("/") else f"/{p}" for p in (s.strip() for s in value.split(",")) if p)


# --- rules ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Matcher:
    field: str  # header, cookie, title, body, location, banner, cname, generator, cert
    regex: re.Pattern
    header: str | None = None


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    cpe: str | None
    matchers: tuple[Matcher, ...]


def load_rules(data: Mapping) -> tuple[Rule, ...]:
    rules = []
    for r in data["rules"]:
        matchers = []
        for m in r["match"]:
            if "header" in m:
                matchers.append(Matcher("header", re.compile(m["regex"], re.I | re.S), m["header"].lower()))
            else:
                (fld, regex), = m.items()
                matchers.append(Matcher(fld, re.compile(regex, re.I | re.S)))
        rules.append(Rule(r["name"], r["category"], r.get("cpe"), tuple(matchers)))
    return tuple(rules)


@cache
def bundled_rules() -> tuple[Rule, ...]:
    import json

    return load_rules(json.loads(resources.files("farpoint.data").joinpath("fingerprints.json").read_text(encoding="utf-8")))


@dataclass
class Evidence:
    """Everything one service said, as the rules see it."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    title: str = ""
    body: str = ""
    location: str = ""
    banner: str = ""
    cnames: list[str] = field(default_factory=list)
    generator: str = ""
    cert: str = ""

    def values(self, m: Matcher) -> list[str]:
        if m.field == "header":
            v = self.headers.get(m.header or "")
            return [v] if v is not None else []
        if m.field == "cookie":
            return self.cookies
        if m.field == "cname":
            return self.cnames
        return [getattr(self, m.field, "")] if getattr(self, m.field, "") else []


def identify(ev: Evidence, rules: Sequence[Rule] | None = None) -> list[Tech]:
    """Technologies whose rules match, each with the first version any matcher captured."""
    found = []
    for rule in rules if rules is not None else bundled_rules():
        version, evidence = None, None
        for m in rule.matchers:
            for value in ev.values(m):
                hit = m.regex.search(value)
                if not hit:
                    continue
                if evidence is None:
                    shown = hit.group(0).strip()[:60] or value[:60]
                    evidence = f"{m.field}{' ' + m.header if m.header else ''}: {shown}"
                if version is None and hit.groups() and hit.group(1):
                    version = hit.group(1).rstrip(".-")
                    evidence = f"{m.field}{' ' + m.header if m.header else ''}: {hit.group(0).strip()[:60]}"
        if evidence is not None:
            found.append(Tech(rule.name, rule.category, *(_vendor_product(rule.cpe)), version, cpe_for(rule.cpe, version), evidence))
    return found


def _vendor_product(cpe: str | None) -> tuple[str | None, str | None]:
    if not cpe:
        return None, None
    _, vendor, product = cpe.split(":")
    return vendor, product


def cpe_for(cpe: str | None, version: str | None) -> str | None:
    """cpe:2.3 name for a rule's part:vendor:product at a version (OpenSSH 8.9p1 -> 8.9:p1, as NVD lists it)."""
    if not cpe or not version:
        return None
    if m := re.fullmatch(r"(\d+(?:\.\d+)+)(p\d+)", version):
        version = f"{m.group(1)}:{m.group(2)}"
    return f"cpe:2.3:{cpe}:{version}"


# --- subdomain takeover --------------------------------------------------------------------------


@cache
def bundled_takeovers() -> tuple[tuple[str, re.Pattern, re.Pattern | None], ...]:
    import json

    data = json.loads(resources.files("farpoint.data").joinpath("takeover.json").read_text(encoding="utf-8"))
    return tuple((p["service"], re.compile(p["cname"], re.I), re.compile(p["body"], re.I) if p.get("body") else None) for p in data["platforms"])


def takeover_platform(cname: str) -> str | None:
    """The takeover-prone platform a CNAME target belongs to, if any."""
    return next((service for service, pattern, _ in bundled_takeovers() if pattern.search(cname)), None)


def unclaimed(cnames: Iterable[str], body: str) -> str | None:
    """The platform whose 'nothing here' page a host serves through its CNAME: claimable by anyone."""
    for service, pattern, page in bundled_takeovers():
        if page is not None and any(pattern.search(c) for c in cnames) and page.search(body):
            return service
    return None


SHARED_NETWORKS = re.compile(
    r"cloudflare|akamai|fastly|incapsula|imperva|sucuri|edgecast|stackpath|cdn77|bunny|limelight|zscaler|"
    r"squarespace|wix\.com|shopify|automattic|github|hubspot|netlify|vercel|wp ?engine|pantheon",
    re.I,
)
# CNAME targets on multi-tenant front ends: the address answers for many customers, not just this one.
SHARED_FRONTENDS = re.compile(
    r"\.(cloudfront\.net|azurefd\.net|azureedge\.net|azurewebsites\.net|azure-api\.net|akamaiedge\.net|edgekey\.net|"
    r"edgesuite\.net|akamaized\.net|fastly\.net|fastlylb\.net|cdn\.cloudflare\.net|herokudns\.com|herokuapp\.com|"
    r"netlify\.(app|com)|vercel-dns\.com|github\.io|myshopify\.com|hubspot\.net|hs-sites\.com|wixdns\.net|"
    r"squarespace\.com|wpengine\.com|pantheonsite\.io|kinsta\.cloud|force\.com|my\.site\.com|zendesk\.com|"
    r"outlook\.com|office\.com|office365\.com|lync\.com|cloud\.microsoft|msappproxy\.net|ghs\.googlehosted\.com|"
    r"googlehosted\.com|appspot\.com|run\.app)$",
    re.I,
)


def shared_address(org: str | None, cnames_per_host: Iterable[Iterable[str]], tags: Iterable[str] = ()) -> bool:
    """Whether an address is a CDN's or SaaS front end's (the provider's machine, answering for many
    customers) rather than the organisation's: by its network owner, or because every one of the
    organisation's names there is a CNAME into such a platform. Cloud VMs and load balancers
    (cloudapp.azure.com, elb.amazonaws.com) are the organisation's."""
    if SHARED_NETWORKS.search(org or "") or "cdn" in set(tags):
        return True
    hosts = [list(c) for c in cnames_per_host]
    return bool(hosts) and all(any(SHARED_FRONTENDS.search(c) for c in cnames) for cnames in hosts)


# --- end of life ---------------------------------------------------------------------------------


@cache
def bundled_eol() -> dict[str, list[dict]]:
    import json

    data = json.loads(resources.files("farpoint.data").joinpath("eol.json").read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def end_of_life(name: str, version: str | None, today: date | None = None, table: Mapping | None = None) -> dict | None:
    """The end-of-life entry `version` of `name` falls under, if its date has passed."""
    if not version:
        return None
    today = today or date.today()
    for entry in (table if table is not None else bundled_eol()).get(name, []):
        prefix = entry["prefix"]
        if not (version == prefix or version.startswith(prefix + ".")):
            continue
        if entry.get("before") and _version_key(version) >= _version_key(entry["before"]):
            continue
        if date.fromisoformat(entry["eol"]) <= today:
            return entry
    return None


# --- favicon -------------------------------------------------------------------------------------


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed (what Python's mmh3.hash returns)."""
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h = seed & mask
    n = len(data) // 4
    for (k,) in struct.iter_unpack("<I", data[: n * 4]):
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask
    tail, k = data[n * 4 :], 0
    if len(tail) == 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = (k * c2) & mask
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def favicon_hash(data: bytes) -> int:
    """Shodan's http.favicon.hash: mmh3 of the base64 with a newline every 76 characters."""
    return murmur3_32(base64.encodebytes(data))


# --- one service ---------------------------------------------------------------------------------

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(rb"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)|<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator", re.I)
_ICON = re.compile(rb"<link[^>]+rel=[\"'](?:shortcut )?icon[\"'][^>]*>", re.I)
_HREF = re.compile(rb"href=[\"']([^\"']+)", re.I)
_WP_ASSET = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9_-]+)/[^\"'?\s]*\?ver=([\d.]+)", re.I)
_DEFAULT_PAGES = re.compile(
    r"^(IIS Windows Server|IIS\d*|Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page.*|Test Page for the (Apache|Nginx) HTTP Server.*|"
    r"Apache HTTP Server Test Page.*|Welcome to CentOS|Default Web Site Page|Welcome to OpenResty!|Apache Tomcat/[\d.]+|Domain Default page)$",
    re.I,
)
_STACK_TRACE = re.compile(
    r"Traceback \(most recent call last\)|Server Error in '/' Application|<b>(Fatal|Parse) error</b>:|\bat (java|org|com)\.[\w.$]+\([\w]+\.java:\d+\)|"
    r"Whitelabel Error Page|SQLSTATE\[|Microsoft OLE DB Provider|ORA-\d{5}|You have an error in your SQL syntax|DEBUG = True|Laravel.*Whoops",
    re.S,
)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _banner_text(raw: bytes) -> str:
    return raw.decode("latin-1")


def _printable(text: str, limit: int = 200) -> str:
    return re.sub(r"[^\x20-\x7e]+", " ", text).strip()[:limit]


def _cookies(resp: HttpResult) -> list[str]:
    return sorted({c.split("=", 1)[0].strip() for c in resp.all("set-cookie") if "=" in c})


def _same_service(url: str, scheme: str, host: str, port: int) -> bool:
    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    try:
        target_port = parts.port or default
    except ValueError:  # a malformed port (host:abc, host:99999): not this service
        return False
    return parts.scheme == scheme and (parts.hostname or "").lower() == host and target_port == port


def for_host(service: ServiceRecord, host: str) -> ServiceRecord:
    """An address-wide service (SSH, IMAPS, ...) as seen from another of the names on that address:
    the same answers, with the certificate judged against this name."""
    tls = dict(service.tls) if service.tls else None
    if tls and "sans" in tls:
        names = tls["sans"] or ([tls["subject"].lower()] if tls.get("subject") else [])
        tls["matches"] = any(_name_matches(host, n) for n in names)
    return replace(service, hostname=host, tls=tls, tech=list(service.tech), signals=list(service.signals), headers=dict(service.headers), paths=dict(service.paths))


def fingerprint_service(
    prober: Prober,
    host: str,
    ip: str,
    port: int,
    cnames: Iterable[str] = (),
    config: FingerprintConfig | None = None,
    rules: Sequence[Rule] | None = None,
) -> ServiceRecord:
    """Ask one open port who it is, and name what it runs."""
    config = config or FingerprintConfig()
    rec = ServiceRecord(host, ip, port, service=SERVICE_NAMES.get(port, "tcp"))
    ev = Evidence(cnames=sorted(cnames))
    tls = None

    def web(scheme: str) -> bool:
        return _web(prober, rec, ev, scheme, config)

    if port in SMTP_PORTS:
        try:
            smtp = prober.smtp(host, ip, port)
        except OSError:  # it closed again between the sweep and now
            return rec
        rec.banner = _printable(smtp.banner)
        ev.banner = smtp.banner
        if smtp.ehlo and not smtp.starttls:  # only once it answered EHLO: a server that stalled told us nothing
            rec.signals.append("no-starttls")
        tls = smtp.tls
    elif port in TLS_FIRST:
        tls = prober.tls(host, ip, port)
        if not web("https" if tls else "http") and tls:
            rec.service = "tls"
    elif port in HTTP_FIRST:
        if not web("http"):
            tls = prober.tls(host, ip, port)
            if tls and not web("https"):
                rec.service = "tls"
    elif port in TLS_ONLY:
        tls = prober.tls(host, ip, port)
    elif port in SILENT:
        pass
    else:
        first = prober.banner(ip, port)
        if first:
            ev.banner = _banner_text(first)
            rec.banner = _printable(ev.banner)
        else:
            tls = prober.tls(host, ip, port)
            if not web("https" if tls else "http") and tls:
                rec.service = "tls"
    if port not in SMTP_PORTS and rec.banner is None and ev.banner:
        rec.banner = _printable(ev.banner)
    if tls:
        rec.tls = {"version": tls.version, "cipher": tls.cipher, **(cert_summary(tls.cert, host) or {})}
        ev.cert = f"{rec.tls.get('subject', '')} {rec.tls.get('issuer', '')}"
        if config.legacy_tls and port not in SMTP_PORTS:
            rec.tls["legacy"] = _legacy_tls(prober, host, ip, port)
    rec.tech = identify(ev, rules) + _wordpress_assets(ev.body)
    if ev.banner and rec.service == "tcp":
        rec.service = _service_from_banner(ev.banner) or rec.service
    return rec


def _service_from_banner(banner: str) -> str | None:
    for prefix, name in (("SSH-", "ssh"), ("RFB ", "vnc"), ("220", "ftp"), ("+OK", "pop3"), ("* OK", "imap"), ("\xff", "telnet")):
        if banner.startswith(prefix):
            return name
    return None


def _legacy_tls(prober: Prober, host: str, ip: str, port: int) -> dict[str, bool | None]:
    """Whether each legacy version is accepted: True/False, or None when this machine can't offer it."""
    accepted: dict[str, bool | None] = {}
    for version in ("TLSv1", "TLSv1.1"):
        try:
            accepted[version] = prober.tls(host, ip, port, version) is not None
        except UnsupportedHere:
            accepted[version] = None
        except OSError:
            accepted[version] = None
    return accepted


def _web(prober: Prober, rec: ServiceRecord, ev: Evidence, scheme: str, config: FingerprintConfig) -> bool:
    """GET / (following redirects within this service), the favicon and the well-known paths. False: not HTTP."""
    host, ip, port = rec.hostname, rec.ip, rec.port
    path, resp = "/", None
    for _ in range(MAX_REDIRECTS + 1):
        runtime.check()
        resp = prober.http(scheme, host, ip, port, path)
        if resp is None:
            return False
        location = resp.header("location")
        if not (300 <= resp.status < 400 and location):
            break
        target = urljoin(f"{scheme}://{host}:{port}{path}", location)
        if not _same_service(target, scheme, host, port):
            rec.location = target
            ev.location = target
            break
        parts = urlsplit(target)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        ev.location = target
    else:
        rec.location = ev.location
    assert resp is not None
    rec.service = scheme
    rec.status = resp.status
    rec.headers = {k: v[:200] for k, v in resp.headers if k not in _DROP_HEADERS}
    rec.cookies = _cookies(resp)
    rec.server = resp.header("server")
    if path != "/" and not rec.location:
        rec.location = f"{scheme}://{host}:{port}{path}" if port not in (80, 443) else f"{scheme}://{host}{path}"
    ev.headers = {k: v for k, v in resp.headers}
    ev.cookies = rec.cookies
    ev.body = _text(resp.body)
    if m := _TITLE.search(resp.body):
        rec.title = html.unescape(_text(m.group(1))).strip()[:200] or None
        ev.title = rec.title or ""
    if m := _GENERATOR.search(resp.body):
        ev.generator = html.unescape(_text(m.group(1) or m.group(2))).strip()
    rec.signals.extend(_web_signals(rec, resp, ev))
    if service := unclaimed(ev.cnames, ev.body):
        rec.signals.append(f"takeover:{service}")

    icon = "/favicon.ico"
    if (m := _ICON.search(resp.body)) and (href := _HREF.search(m.group(0))):
        target = urljoin(f"{scheme}://{host}:{port}{path}", html.unescape(_text(href.group(1))))
        icon = urlsplit(target).path if _same_service(target, scheme, host, port) else icon
    got = prober.http(scheme, host, ip, port, icon)
    if got is not None and got.status == 200 and got.body and not got.body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
        rec.favicon = favicon_hash(got.body)

    for p in config.paths:
        got = prober.http(scheme, host, ip, port, p)
        if got is None:
            continue
        rec.paths[p] = {"status": got.status, **({"note": note} if (note := _path_note(p, got, resp)) else {})}
        if rec.paths[p].get("note") == "git repository exposed":
            rec.signals.append("git-exposed")
    return True


def _path_note(path: str, got: HttpResult, home: HttpResult) -> str | None:
    if got.status != 200 or not got.body or got.body == home.body:  # a soft 404 serves the home page
        return None
    text = _text(got.body[:4096])
    if path.endswith(".git/HEAD") and text.startswith("ref: refs/"):
        return "git repository exposed"
    if path.endswith("security.txt") and re.search(r"^Contact:", text, re.M | re.I):
        return "security contact published"
    if path.endswith("robots.txt") and (dis := re.findall(r"^Disallow:\s*(\S+)", text, re.M | re.I)):
        return "disallows " + " ".join(sorted(set(dis))[:15])
    return None


def _web_signals(rec: ServiceRecord, resp: HttpResult, ev: Evidence) -> list[str]:
    signals = []
    title = rec.title or ""
    if re.match(r"Index of /", title) or "<h1>Index of /" in ev.body:
        signals.append("directory-listing")
    if _DEFAULT_PAGES.match(title.strip()):
        signals.append("default-page")
    if "<ListBucketResult" in ev.body:
        signals.append("bucket-listing")
    auth = (resp.header("www-authenticate") or "").lower()
    if auth.startswith("basic"):
        signals.append("basic-auth")
    if auth.startswith(("ntlm", "negotiate")):
        signals.append("ntlm-auth")
    if re.search(r"<input[^>]+type=[\"']?password", ev.body, re.I):
        signals.append("login-form")
    if _STACK_TRACE.search(ev.body):
        signals.append("error-detail")
    if re.search(r"\d", resp.header("server") or "") or resp.header("x-powered-by") or resp.header("x-aspnet-version"):
        signals.append("version-disclosure")
    if resp.header("access-control-allow-origin") == "*" and (resp.header("access-control-allow-credentials") or "").lower() == "true":
        signals.append("cors-any-origin-with-credentials")
    return signals


def _wordpress_assets(body: str) -> list[Tech]:
    """Plugins and themes a WordPress page loads with ?ver=: their versions, for free."""
    seen: dict[tuple[str, str], str] = {}
    for kind, slug, version in _WP_ASSET.findall(body):
        seen.setdefault((kind.lower(), slug.lower()), version)
    return [
        Tech(f"WordPress {kind[:-1]} {slug}", "cms-plugin", None, slug, version, None, f"asset ?ver={version}")
        for (kind, slug), version in sorted(seen.items())
    ]
