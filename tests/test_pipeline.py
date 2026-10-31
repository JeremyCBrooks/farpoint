from farpoint.models import IpDetails, Observation
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution


class StaticSource:
    def __init__(self, name, observations=(), available=True, error=None):
        self.name = name
        self._obs = list(observations)
        self._available = available
        self._error = error
        self.calls = 0

    def available(self):
        return self._available

    def collect(self, domain):
        self.calls += 1
        if self._error:
            raise self._error
        return [o for o in self._obs if o.hostname.endswith(domain)]


class TableEnricher:
    name = "table"

    def __init__(self, table):
        self.table = table
        self.seen = []

    def enrich(self, ip):
        self.seen.append(ip)
        return self.table.get(ip, IpDetails())


def dns_table(table):
    return lambda host: table.get(host, Resolution())


def test_input_domains_are_always_in_the_inventory():
    inv = Pipeline(sources=[]).run(["example.com"])
    assert inv.hosts["example.com"].sources == {"input"}


def test_a_failing_source_is_recorded_and_does_not_lose_other_results():
    good = StaticSource("good", [Observation("good", "www.example.com")])
    bad = StaticSource("bad", error=TimeoutError("read timed out"))

    inv = Pipeline(sources=[bad, good]).run(["example.com"])

    assert "www.example.com" in inv.hosts
    assert [(e.source, e.target) for e in inv.errors] == [("bad", "example.com")]
    assert "read timed out" in inv.errors[0].message


def test_unavailable_sources_are_skipped_not_called():
    shodan = StaticSource("shodan", available=False)

    inv = Pipeline(sources=[shodan]).run(["example.com"])

    assert shodan.calls == 0
    assert inv.skipped == ["shodan"]


def test_each_source_runs_once_per_domain():
    src = StaticSource("crtsh", [Observation("crtsh", "a.example.com"), Observation("crtsh", "b.example.org")])

    inv = Pipeline(sources=[src]).run(["example.com", "example.org"])

    assert src.calls == 2
    assert {"a.example.com", "b.example.org"} <= set(inv.hosts)


def test_resolution_marks_live_and_dead_hosts():
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com"), Observation("crtsh", "old.example.com")])
    lookup = dns_table({"www.example.com": Resolution(ips=("93.184.216.34",))})

    inv = Pipeline(sources=[src], lookup=lookup).run(["example.com"])

    assert inv.hosts["www.example.com"].resolves is True
    assert inv.hosts["www.example.com"].ips == {"93.184.216.34"}
    assert "dns" in inv.ips["93.184.216.34"].sources
    assert inv.hosts["old.example.com"].resolves is False



def test_a_name_the_resolver_blocked_is_unchecked_not_live():
    src = StaticSource("crtsh", [Observation("crtsh", "blocked.example.com")])
    lookup = dns_table({"blocked.example.com": Resolution(ips=("146.112.61.106",))})  # Cisco Umbrella's block page

    inv = Pipeline(sources=[src], lookup=lookup).run(["example.com"])

    assert inv.hosts["blocked.example.com"].resolves is None
    assert inv.hosts["blocked.example.com"].resolved_ips == set() and inv.ips == {}

def test_in_scope_cname_targets_become_hosts_and_get_resolved_too():
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com")])
    lookup = dns_table({
        "www.example.com": Resolution(ips=("192.0.2.1",), cnames=("edge.example.com",)),
        "edge.example.com": Resolution(ips=("192.0.2.1",), cnames=("example.cdn-provider.net",)),
    })

    inv = Pipeline(sources=[src], lookup=lookup).run(["example.com"])

    assert inv.hosts["www.example.com"].cnames == {"edge.example.com"}
    assert inv.hosts["edge.example.com"].resolves is True
    assert inv.hosts["edge.example.com"].cnames == {"example.cdn-provider.net"}
    assert "example.cdn-provider.net" not in inv.hosts


def test_enrichment_only_queries_public_ips_and_feeds_back_in_scope_hostnames():
    public_ip = "8.8.4.4"
    src = StaticSource("otx", [
        Observation("otx", "vpn.example.com", "203.0.113.9"),
        Observation("otx", "intranet.example.com", "10.0.0.5"),
        Observation("otx", "dns.example.com", public_ip),
    ])
    enricher = TableEnricher({public_ip: IpDetails(org="Google LLC", hostnames={"resolver.example.com", "dns.google"})})

    inv = Pipeline(sources=[src], enrichers=[enricher]).run(["example.com"])

    # 203.0.113.0/24 (TEST-NET-3) and 10/8 are not globally routable
    assert enricher.seen == [public_ip]
    assert inv.ips[public_ip].org == "Google LLC"
    assert "resolver.example.com" in inv.hosts
    assert "dns.google" not in inv.hosts


def test_enricher_failure_is_recorded_per_ip():
    class Broken:
        name = "rdap"

        def enrich(self, ip):
            raise ConnectionError("refused")

    src = StaticSource("otx", [Observation("otx", "a.example.com", "8.8.8.8")])

    inv = Pipeline(sources=[src], enrichers=[Broken()]).run(["example.com"])

    assert [(e.source, e.target) for e in inv.errors] == [("rdap", "8.8.8.8")]


def test_a_host_whose_lookup_failed_is_not_retried_in_later_rounds():
    calls = []
    chain = {
        "www.example.com": Resolution(ips=("192.0.2.1",), cnames=("edge.example.com",)),
        "edge.example.com": Resolution(ips=("192.0.2.1",), cnames=("deep.example.com",)),
    }

    def lookup(host):
        calls.append(host)
        if host == "flaky.example.com":
            raise TimeoutError("lifetime exceeded")
        return chain.get(host, Resolution())

    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com"), Observation("crtsh", "flaky.example.com")])

    inv = Pipeline(sources=[src], lookup=lookup).run(["example.com"])

    assert calls.count("flaky.example.com") == 1
    assert inv.hosts["flaky.example.com"].resolves is None
