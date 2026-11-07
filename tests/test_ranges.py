"""Discovery beyond the scan domains' names: the organisation's own address ranges (--ranges), the
networks its addresses sit in (netblocks.csv), and other domains on certificates issued to it."""

import csv
import ipaddress

import pytest

from farpoint import cli
from farpoint.assess import derive
from farpoint.fingerprint import FingerprintConfig
from farpoint.models import Inventory, IpDetails, Observation
from farpoint.names import Exclusions
from farpoint.output import run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.probe import TlsResult
from farpoint.resolve import Resolution

from test_fingerprint import FakeProber, make_cert
from test_pipeline import StaticSource, TableEnricher, dns_table
from test_posture import FakeDns
from test_related import FakeNet

D = "example.com"
RANGE = ipaddress.ip_network("93.184.216.32/29")  # .33 to .38
MAIL, VPN, ISP, RDP, WEB, EXCLUDED = (f"93.184.216.{n}" for n in range(33, 39))


def reverse(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


class BulkEnricher(TableEnricher):
    name = "shodan-internetdb"
    bulk = True  # cheap enough to ask about every address in a range


def scenario(fingerprint=False):
    dns = FakeDns({
        reverse(MAIL): {"PTR": ["mail.example.com"]},
        reverse(VPN): {"PTR": ["vpn.example-group.com"]},  # another domain carrying the organisation's name
        reverse(ISP): {"PTR": ["static-35.isp-provider.net"]},  # the ISP's generic name: says nothing
    })
    internetdb = BulkEnricher({RDP: IpDetails(ports={3389})})
    rdap = TableEnricher({MAIL: IpDetails(org="Example Corp", network=str(RANGE))})
    prober = FakeProber(ports={(RDP, 3389): "open", (WEB, 443): "open", (EXCLUDED, 443): "open"})
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", "www.example.com")])],
        lookup=dns_table({"www.example.com": Resolution(ips=("151.101.1.1",)), "mail.example.com": Resolution(ips=(MAIL,))}),
        enrichers=[internetdb, rdap], dns=dns, ranges=(RANGE,), exclusions=Exclusions.parse([EXCLUDED]),
        prober=prober if fingerprint else None,
        fingerprint=FingerprintConfig(ports=(443, 3389), paths=(), rate=None, legacy_tls=False) if fingerprint else None,
    )
    return pipeline, prober, internetdb, rdap


def test_a_ranges_ptr_names_join_the_inventory_or_the_related_domains_and_its_addresses_are_looked_up_passively():
    pipeline, _, internetdb, rdap = scenario()

    inv = pipeline.run([D])

    assert "ptr" in inv.hosts["mail.example.com"].sources and inv.hosts["mail.example.com"].resolves is True
    assert inv.related["example-group.com"].tie == "weak" and any("PTR" in e for e in inv.related["example-group.com"].evidence)
    assert not [d for d in inv.related if "isp-provider" in d] and "static-35.isp-provider.net" not in inv.hosts
    assert set(internetdb.seen) >= {str(ip) for ip in RANGE.hosts()}  # every address, passively
    assert RDP not in rdap.seen and MAIL in rdap.seen  # the registry is asked about addresses with a name, not the whole range
    ips = {r["ip"] for r in run_report(inv)["ips"]}
    assert {MAIL, RDP} <= ips and WEB not in ips  # an address nothing was found at isn't listed


def test_with_fingerprint_every_address_in_a_range_is_probed_by_address_except_excluded_ones():
    pipeline, prober, _, _ = scenario(fingerprint=True)

    inv = pipeline.run([D])

    assert {f"{RDP}:3389", f"{WEB}:443"} <= set(inv.services)
    assert not [c for c in prober.calls if EXCLUDED in c]
    findings = {(f["kind"], f["target"]) for f in derive(run_report(inv))}
    assert ("exposed-service", f"{RDP}:3389") in findings


def test_a_certificate_on_a_service_asked_by_address_is_not_judged_against_the_address():
    tls = {"subject": "portal.example.com", "matches": False, "not_after": "2099-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z"}
    rows = [{"endpoint": f"{WEB}:443", "hostname": WEB, "ip": WEB, "port": 443, "service": "https", "status": 200, "tls": tls},
            {"endpoint": "shop.example.com:443", "hostname": "shop.example.com", "ip": WEB, "port": 443, "service": "https", "status": 200, "tls": tls}]

    mismatches = {f["target"] for f in derive({"domains": [D], "fingerprints": rows}) if f["kind"] == "certificate-mismatch"}

    assert mismatches == {"shop.example.com:443"}


def test_netblocks_csv_lists_the_networks_the_organisations_addresses_sit_in(tmp_path):
    inv = Inventory([D])
    inv.ranges = [RANGE]
    for host, ip, org, network in (("www.example.com", MAIL, "Example Corp", "93.184.216.0/24"), ("app.example.com", VPN, "Example Corp", "93.184.216.0/24"),
                                   ("api.example.com", "52.1.2.3", "Amazon.com, Inc.", "52.0.0.0/11")):
        inv.add(Observation("dns", host, ip))
        inv.hosts[host].resolves = True
        inv.enrich(ip, IpDetails(org=org, network=network))

    write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")

    with open(tmp_path / "netblocks.csv", newline="") as fh:
        rows = {r["network"]: r for r in csv.DictReader(fh)}
    assert rows["93.184.216.0/24"]["org"] == "Example Corp" and rows["93.184.216.0/24"]["addresses"] == "2"
    assert rows["93.184.216.0/24"]["hosting"] == "no" and rows["52.0.0.0/11"]["hosting"] == "yes"
    assert rows["93.184.216.0/24"]["in_ranges"] == "partly" and rows["52.0.0.0/11"]["in_ranges"] == "no"
    assert list(rows)[0] == "93.184.216.0/24"  # the organisation's own networks first


class CertNet(FakeNet):
    def __init__(self, names_by_org):
        super().__init__({})
        self.names_by_org, self.orgs_asked = names_by_org, []

    def certificate_names(self, org):
        self.orgs_asked.append(org)
        return self.names_by_org.get(org, [])


def test_other_domains_on_certificates_issued_to_the_organisation_are_related():
    net = CertNet({"Example Corp": ["www.example-shop.de", "login.example.com", "*.examplecloud.io", "not a name"]})
    ours = make_cert(cn="www.example.com", sans=("www.example.com",), org="Example Corp")
    providers = make_cert(cn="sni.cdn.net", sans=("sni.cdn.net",), org="Some CDN Inc")  # not issued for the organisation's names
    prober = FakeProber(ports={("93.184.216.34", 443): "open", ("93.184.216.35", 443): "open"},
                        tls={("www.example.com", 443): TlsResult("TLSv1.3", cert=ours), ("cdn.example.com", 443): TlsResult("TLSv1.3", cert=providers)})
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", h) for h in ("www.example.com", "cdn.example.com")])],
        lookup=dns_table({"www.example.com": Resolution(ips=("93.184.216.34",)), "cdn.example.com": Resolution(ips=("93.184.216.35",))}),
        related=net, dns=FakeDns({}), prober=prober,
        fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False),
    )

    inv = pipeline.run([D])

    assert net.orgs_asked == ["Example Corp"]
    assert {d: r.tie for d, r in inv.related.items() if "certificate" in " ".join(r.evidence)} == {"example-shop.de": "medium", "examplecloud.io": "medium"}
    assert "certificates issued to Example Corp" in " ".join(inv.related["example-shop.de"].evidence)
    assert "login.example.com" in inv.hosts  # in scope: a host, not a related domain


def test_cli_checks_ranges(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--ranges", "10.0.0.0/8", "-o", str(tmp_path)])
    assert "--ranges" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--ranges", "93.184.216.0/24", "--no-resolve", "-o", str(tmp_path)])
    assert "--ranges needs DNS" in capsys.readouterr().err


def test_a_shared_cdn_certificate_names_the_cdn_not_the_organisation():
    net = CertNet({"Incapsula Inc": ["shop.othercustomer.com"]})
    shared = make_cert(cn="incapsula.com", sans=("incapsula.com", "www.example.com", "shop.othercustomer.com"), org="Incapsula Inc")
    prober = FakeProber(ports={("45.60.1.1", 443): "open"}, tls={("www.example.com", 443): TlsResult("TLSv1.3", cert=shared)})
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", "www.example.com")])],
        lookup=dns_table({"www.example.com": Resolution(ips=("45.60.1.1",))}),
        enrichers=[TableEnricher({"45.60.1.1": IpDetails(org="Incapsula Inc")})],
        related=net, dns=FakeDns({}), prober=prober, fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False),
    )

    inv = pipeline.run([D])

    assert net.orgs_asked == [] and "othercustomer.com" not in inv.related


def test_certificate_pivot_hosts_are_resolved_and_earlier_organisations_keep_their_domain():
    net = CertNet({"B Corp": ["login.b.com", "other-b.net"]})
    inv = Pipeline(sources=[], lookup=dns_table({"login.b.com": Resolution(ips=("93.184.216.40",))}), related=net,
                   certificate_orgs={"B Corp": "b.com"}).run(["a.com", "b.com"])

    assert inv.hosts["login.b.com"].resolves is True
    assert inv.related["other-b.net"].related_to == "b.com"


def test_a_range_address_named_during_enrichment_is_then_sent_to_rdap():
    rdap = TableEnricher({MAIL: IpDetails(org="Example Corp", network="93.184.216.0/24")})
    Pipeline(sources=[], lookup=dns_table({"vpn.example.com": Resolution(ips=(MAIL,))}), dns=FakeDns({}),
             enrichers=[BulkEnricher({MAIL: IpDetails(hostnames={"vpn.example.com"})}), rdap], ranges=(RANGE,)).run([D])

    assert MAIL in rdap.seen and rdap.seen.count(MAIL) == 1


def test_hosting_providers_are_named_by_whole_words():
    from farpoint.output import HOSTING

    assert all(HOSTING.search(o) for o in ("Amazon.com, Inc.", "Microsoft Corporation", "Google LLC", "OVH SAS", "Hetzner Online GmbH", "DigitalOcean, LLC"))
    assert not any(HOSTING.search(o) for o in ("Shaws Holdings Ltd", "Gibmore Group", "Novacdnx Ltd", "Googleplex Dental"))
