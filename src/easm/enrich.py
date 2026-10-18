"""Per-IP enrichment from passive datasets. Nothing here contacts the IP itself."""

from __future__ import annotations

import ipaddress
import threading
from typing import Protocol

import httpx

from easm.models import IpDetails
from easm.sources.base import HttpSource


class Enricher(Protocol):
    name: str

    def enrich(self, ip: str) -> IpDetails: ...


class InternetDb(HttpSource):
    """Shodan InternetDB: free, keyless, pre-collected ports/CVEs/hostnames."""

    name = "shodan-internetdb"

    def enrich(self, ip: str) -> IpDetails:
        try:
            body = self.get(f"https://internetdb.shodan.io/{ip}").json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return IpDetails()
            raise
        return IpDetails(ports=set(body.get("ports", [])), vulns=set(body.get("vulns", [])), hostnames=set(body.get("hostnames", [])))


class Rdap(HttpSource):
    """RDAP network owner/allocation, queried at the RIR chosen by the IANA bootstrap registry.

    Going direct avoids rdap.org's aggressive rate limit; rdap.org stays as the fallback.
    """

    name = "rdap"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._bootstrap: dict[int, list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]] = {}
        self._lock = threading.Lock()

    def _registries(self, version: int):
        with self._lock:
            if version not in self._bootstrap:
                try:
                    services = self.get(f"https://data.iana.org/rdap/ipv{version}.json").json()["services"]
                except (httpx.HTTPError, ValueError, KeyError):
                    services = []
                self._bootstrap[version] = [
                    (ipaddress.ip_network(prefix), next((u for u in urls if u.startswith("https")), urls[0]))
                    for prefixes, urls in services
                    for prefix in prefixes
                ]
            return self._bootstrap[version]

    def _base_url(self, ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        for network, url in self._registries(addr.version):
            if addr in network:
                return url.rstrip("/") + "/"
        return "https://rdap.org/"

    def enrich(self, ip: str) -> IpDetails:
        body = self.get(f"{self._base_url(ip)}ip/{ip}", follow_redirects=True).json()
        return IpDetails(org=_registrant(body) or body.get("name"), network=_network(body))


def _vcard_fn(entity: dict) -> str | None:
    vcard = entity.get("vcardArray") or [None, []]
    return next((prop[3] for prop in vcard[1] if prop[0] == "fn"), None)


def _registrant(body: dict) -> str | None:
    for entity in body.get("entities", []):
        if "registrant" in entity.get("roles", []) and (fn := _vcard_fn(entity)):
            return fn
    return None


def _network(body: dict) -> str | None:
    for cidr in body.get("cidr0_cidrs", []):
        prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
        if prefix:
            return f"{prefix}/{cidr['length']}"
    if body.get("startAddress"):
        return f"{body['startAddress']}-{body['endAddress']}"
    return None
