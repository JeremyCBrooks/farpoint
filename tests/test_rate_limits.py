import threading
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx
import pytest

from conftest import fake_http, pairs
from test_pipeline import StaticSource
from easm.models import Observation
from easm.pipeline import Pipeline
from easm.resolve import DnsResolver, Resolution
from easm.sources.base import MAX_WAIT, SourceFailure, retry_after_seconds
from easm.sources.web import CrtSh, VirusTotal

D = "example.com"
OK = httpx.Response(200, json=[{"name_value": "a.example.com"}])


def test_backoff_is_exponential_with_jitter(sleeps):
    http = fake_http({"crt.sh/": [httpx.Response(503)] * 5})

    with pytest.raises(SourceFailure):
        list(CrtSh(http).collect(D))

    assert len(sleeps) == 4
    for attempt, wait in enumerate(sleeps):
        assert 2.0 * 2**attempt * 0.5 <= wait <= 2.0 * 2**attempt


def test_retry_after_header_is_capped(sleeps):
    http = fake_http({"crt.sh/": [httpx.Response(429, headers={"Retry-After": "3600"}), OK]})

    assert pairs(CrtSh(http).collect(D)) == {("a.example.com", None)}
    assert sleeps == [MAX_WAIT]


def test_retry_after_accepts_seconds_and_http_dates():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    assert retry_after_seconds("30") == 30.0
    assert retry_after_seconds("Thu, 01 Jan 2026 12:00:45 GMT", now) == 45.0
    assert retry_after_seconds("Thu, 01 Jan 2026 11:00:00 GMT", now) == 0.0
    assert retry_after_seconds("soon") is None
    assert retry_after_seconds("") is None


def test_virustotal_is_paced_to_free_tier_limit(sleeps):
    page = lambda nxt: httpx.Response(200, json={"data": [{"id": "a.example.com"}], "links": {"next": nxt} if nxt else {}})
    http = fake_http({"www.virustotal.com/api/v3/domains/example.com/subdomains": [page("https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=2"), page(None)]})

    list(VirusTotal(http, "k").collect(D))

    assert sleeps == [VirusTotal.min_interval]


def test_concurrency_is_capped_per_source():
    in_flight, peak, lock = [0], [0], threading.Lock()

    def handler(request):
        with lock:
            in_flight[0] += 1
            peak[0] = max(peak[0], in_flight[0])
        threading.Event().wait(0.02)
        with lock:
            in_flight[0] -= 1
        return httpx.Response(200, json=[])

    source = CrtSh(fake_http({"crt.sh/": handler}))
    threads = [threading.Thread(target=lambda: list(source.collect(D))) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert peak[0] == CrtSh.max_concurrency == 1


class FailsAfterFirstPage:
    name = "virustotal"

    def available(self):
        return True

    def collect(self, domain):
        yield Observation(self.name, f"a.{domain}")
        raise httpx.HTTPStatusError("429", request=httpx.Request("GET", "https://x"), response=httpx.Response(429))


def test_pages_collected_before_a_failure_are_kept():
    inv = Pipeline(sources=[FailsAfterFirstPage()]).run([D])

    assert "a.example.com" in inv.hosts
    assert [(e.source, e.target) for e in inv.errors] == [("virustotal", D)]


class FakeResolver:
    def __init__(self, script):
        self.script = script  # rdtype -> list of exceptions/answers served in order
        self.calls = []

    def resolve(self, hostname, rdtype):
        self.calls.append(rdtype)
        result = self.script[rdtype].pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class FakeAnswer:
    def __init__(self, *ips):
        self.ips = ips
        self.chaining_result = type("Chain", (), {"cnames": []})()

    def __iter__(self):
        return iter(type("R", (), {"to_text": lambda s, ip=ip: ip})() for ip in self.ips)


def _resolver(script):
    r = DnsResolver()
    r._resolver = FakeResolver(script)
    return r


def test_dns_timeout_is_retried():
    r = _resolver({"A": [dns.exception.Timeout(), FakeAnswer("192.0.2.1")], "AAAA": [dns.resolver.NoAnswer()]})

    assert r.lookup("www.example.com").ips == ("192.0.2.1",)
    assert r._resolver.calls == ["A", "A", "AAAA"]


def test_dns_persistent_timeout_is_unchecked_not_not_resolving():
    r = _resolver({"A": [dns.exception.Timeout()] * 2, "AAAA": [dns.exception.Timeout()] * 2})

    assert r.lookup("slow.example.com") == Resolution(timed_out=True)


def test_dns_nxdomain_is_definitive_even_if_the_other_type_times_out():
    r = _resolver({"A": [dns.resolver.NXDOMAIN()], "AAAA": [dns.exception.Timeout()] * 2})

    assert r.lookup("gone.example.com") == Resolution()


def test_a_timed_out_host_is_left_unchecked_without_an_error():
    src = StaticSource("crtsh", [Observation("crtsh", "slow.example.com")])

    inv = Pipeline(sources=[src], lookup=lambda h: Resolution(timed_out=True)).run([D])

    assert inv.hosts["slow.example.com"].resolves is None
    assert inv.errors == []


def test_dns_timeout_on_one_record_type_still_returns_addresses():
    r = _resolver({"A": [FakeAnswer("192.0.2.1")], "AAAA": [dns.exception.Timeout()] * 2})

    assert r.lookup("www.example.com").ips == ("192.0.2.1",)


class GatedSource:
    """A throttled source whose jobs block until released, like VirusTotal pacing."""

    name = "slow"
    max_concurrency = 1

    def __init__(self):
        self.release = threading.Event()
        self.timed_out = 0

    def available(self):
        return True

    def collect(self, domain):
        if not self.release.wait(timeout=1):
            self.timed_out += 1
        return []


class ReleasingSource:
    name = "fast"

    def __init__(self, gate, expected):
        self.gate, self.expected, self.done, self.lock = gate, expected, 0, threading.Lock()

    def available(self):
        return True

    def collect(self, domain):
        with self.lock:
            self.done += 1
            if self.done == self.expected:
                self.gate.release.set()
        return [Observation(self.name, f"www.{domain}")]


def test_a_throttled_source_does_not_starve_other_sources():
    domains = [f"d{i}.example" for i in range(8)]
    slow = GatedSource()
    fast = ReleasingSource(slow, len(domains))

    inv = Pipeline(sources=[slow, fast], workers=2).run(domains)

    assert slow.timed_out == 0  # fast finished every domain while slow's jobs were still queued
    assert fast.done == len(domains)
