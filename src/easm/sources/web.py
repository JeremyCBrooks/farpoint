"""Free / freemium web APIs: certificate transparency, passive DNS, archives, search engines."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from easm.models import Observation
from easm.names import extract_hostnames
from easm.sources.base import HttpSource, SourceFailure

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class CrtSh(HttpSource):
    """Certificate transparency via crt.sh (no key)."""

    name = "crtsh"
    max_concurrency = 1  # overloaded public service

    def collect(self, domain: str) -> Iterator[Observation]:
        rows = self.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}).json()
        names = {n for row in rows for n in row.get("name_value", "").splitlines()}
        return (self.observe(n) for n in names)


class CertSpotter(HttpSource):
    """Certificate transparency via SSLMate CertSpotter (key optional, raises rate limit)."""

    name = "certspotter"

    def collect(self, domain: str) -> Iterator[Observation]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        for _ in range(self.max_pages):
            issuances = self.get("https://api.certspotter.com/v1/issuances", params=params, headers=headers).json()
            if not issuances:
                return
            for issuance in issuances:
                for name in issuance.get("dns_names", []):
                    yield self.observe(name)
            params["after"] = issuances[-1]["id"]


class HackerTarget(HttpSource):
    """HackerTarget host search: passive DNS host,ip pairs (key optional)."""

    name = "hackertarget"

    def collect(self, domain: str) -> Iterator[Observation]:
        params = {"q": domain} | ({"apikey": self.api_key} if self.api_key else {})
        text = self.get("https://api.hackertarget.com/hostsearch/", params=params).text
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if any("," not in line for line in lines):
            raise SourceFailure(text.strip()[:200])
        for line in lines:
            host, _, ip = line.partition(",")
            yield self.observe(host, ip)


class Wayback(HttpSource):
    """Hostnames seen in Internet Archive URLs."""

    name = "wayback"
    limit = 100_000
    max_concurrency = 2

    def collect(self, domain: str) -> Iterator[Observation]:
        params = {"url": f"*.{domain}", "fl": "original", "collapse": "urlkey", "limit": str(self.limit)}
        text = self.get("https://web.archive.org/cdx/search/cdx", params=params).text
        hosts = {urlsplit(line.strip()).hostname for line in text.splitlines() if "://" in line}
        return (self.observe(h) for h in hosts if h)


class Otx(HttpSource):
    """AlienVault OTX passive DNS (key optional)."""

    name = "otx"
    max_concurrency = 2

    def collect(self, domain: str) -> Iterator[Observation]:
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        for rec in self.get(url, headers=headers).json().get("passive_dns", []):
            yield self.observe(rec["hostname"], rec.get("address"))


class UrlScan(HttpSource):
    """urlscan.io search of previously submitted scans (key optional). Read-only: never submits."""

    name = "urlscan"

    def collect(self, domain: str) -> Iterator[Observation]:
        headers = {"API-Key": self.api_key} if self.api_key else {}
        params = {"q": f"domain:{domain}", "size": "1000" if self.api_key else "100"}
        for result in self.get("https://urlscan.io/api/v1/search/", params=params, headers=headers).json().get("results", []):
            page, task = result.get("page", {}), result.get("task", {})
            if page.get("domain"):
                yield self.observe(page["domain"], page.get("ip"))
            if task.get("domain") and task["domain"] != page.get("domain"):
                yield self.observe(task["domain"])


class RapidDns(HttpSource):
    """rapiddns.io subdomain table (HTML)."""

    name = "rapiddns"
    max_concurrency = 1

    def collect(self, domain: str) -> Iterator[Observation]:
        html = self.get(f"https://rapiddns.io/subdomain/{domain}", params={"full": "1"}).text
        for row in html.split("<tr")[1:]:
            hosts = extract_hostnames(row, domain)
            ips = _IPV4_RE.findall(row)
            for host in hosts:
                yield self.observe(host, ips[0] if len(hosts) == 1 and ips else None)


class Shodan(HttpSource):
    """Shodan DNS database (requires key; 1 query credit per page)."""

    name = "shodan"
    key_required = True
    max_pages = 5
    max_concurrency = 1
    min_interval = 1.0  # API limit: 1 request/second

    def collect(self, domain: str) -> Iterator[Observation]:
        for page in range(1, self.max_pages + 1):
            body = self.get(f"https://api.shodan.io/dns/domain/{domain}", params={"key": self.api_key, "page": str(page)}).json()
            for sub in body.get("subdomains", []):
                yield self.observe(f"{sub}.{domain}")
            for rec in body.get("data", []):
                host = f"{rec['subdomain']}.{domain}" if rec.get("subdomain") else domain
                yield self.observe(host, rec["value"] if rec.get("type") in ("A", "AAAA") else None)
            if not body.get("more"):
                return


class VirusTotal(HttpSource):
    """VirusTotal subdomain relationships (requires free key)."""

    name = "virustotal"
    key_required = True
    max_concurrency = 1
    min_interval = 15.5  # free tier: 4 requests/minute

    def collect(self, domain: str) -> Iterator[Observation]:
        url: str | None = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        for _ in range(self.max_pages):
            if not url:
                return
            body = self.get(url, headers={"x-apikey": self.api_key}).json()
            for item in body.get("data", []):
                yield self.observe(item["id"])
            url = body.get("links", {}).get("next")
