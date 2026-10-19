"""DNS resolution of discovered names via dnspython (queries recursive resolvers only)."""

from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver


@dataclass(frozen=True)
class Resolution:
    ips: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    timed_out: bool = False  # no answer either way: the name is unchecked, not "doesn't resolve"


class DnsResolver:
    """A/AAAA lookups. A timeout is retried; a name that still times out, with no addresses and no NXDOMAIN
    from the other record type, comes back as `timed_out` so it is recorded as unchecked."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0, retries: int = 1) -> None:
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.lifetime = timeout
        self._retries = retries

    def _resolve(self, hostname: str, rdtype: str) -> dns.resolver.Answer:
        for attempt in range(self._retries + 1):
            try:
                return self._resolver.resolve(hostname, rdtype)
            except dns.exception.Timeout:
                if attempt == self._retries:
                    raise
        raise AssertionError("unreachable")

    def lookup(self, hostname: str) -> Resolution:
        ips: list[str] = []
        cnames: list[str] = []
        timed_out = nxdomain = False
        for rdtype in ("A", "AAAA"):
            try:
                answer = self._resolve(hostname, rdtype)
            except dns.resolver.NXDOMAIN:
                nxdomain = True
                continue
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                timed_out = True
                continue
            ips.extend(r.to_text() for r in answer)
            for rrset in answer.chaining_result.cnames:
                cnames.extend(r.target.to_text().rstrip(".") for r in rrset)
        unchecked = timed_out and not ips and not nxdomain
        return Resolution(tuple(dict.fromkeys(ips)), tuple(dict.fromkeys(cnames)), timed_out=unchecked)
