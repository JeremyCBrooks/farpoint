"""DNS resolution of discovered names via dnspython (queries recursive resolvers only)."""

from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver


@dataclass(frozen=True)
class Resolution:
    ips: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()


class DnsResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.lifetime = timeout

    def lookup(self, hostname: str) -> Resolution:
        ips: list[str] = []
        cnames: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                answer = self._resolver.resolve(hostname, rdtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            ips.extend(r.to_text() for r in answer)
            for rrset in answer.chaining_result.cnames:
                cnames.extend(r.target.to_text().rstrip(".") for r in rrset)
        return Resolution(tuple(dict.fromkeys(ips)), tuple(dict.fromkeys(cnames)))
