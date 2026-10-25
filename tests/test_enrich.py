import httpx

from conftest import fake_http
from farpoint.enrich import InternetDb, Rdap

IP = "93.184.216.34"


def test_internetdb_reports_ports_vulns_and_hostnames():
    body = {"cpes": ["cpe:/a:nginx:nginx"], "hostnames": ["www.example.com"], "ip": IP, "ports": [443, 80], "tags": ["cdn"], "vulns": ["CVE-2023-44487"]}
    details = InternetDb(fake_http({f"internetdb.shodan.io/{IP}": httpx.Response(200, json=body)})).enrich(IP)

    assert details.ports == {80, 443}
    assert details.vulns == {"CVE-2023-44487"}
    assert details.hostnames == {"www.example.com"}


def test_internetdb_no_data_is_empty_not_an_error():
    http = fake_http({f"internetdb.shodan.io/{IP}": httpx.Response(404, json={"detail": "No information available"})})

    details = InternetDb(http).enrich(IP)

    assert (details.ports, details.hostnames) == (set(), set())


BOOTSTRAP_V4 = {
    "version": "1.0",
    "services": [
        [["41.0.0.0/8", "102.0.0.0/8"], ["https://rdap.afrinic.net/rdap/", "http://rdap.afrinic.net/rdap/"]],
        [["93.0.0.0/8"], ["https://rdap.db.ripe.net/"]],
    ],
}


def test_rdap_queries_registry_chosen_by_iana_bootstrap_and_fetches_bootstrap_once():
    bootstrap_hits = []

    def bootstrap(request):
        bootstrap_hits.append(1)
        return httpx.Response(200, json=BOOTSTRAP_V4)

    ripe = {"startAddress": "93.184.0.0", "endAddress": "93.184.255.255", "name": "RIPE-NET", "entities": []}
    http = fake_http({
        "data.iana.org/rdap/ipv4.json": bootstrap,
        f"rdap.db.ripe.net/ip/{IP}": httpx.Response(200, json=ripe),
        "rdap.db.ripe.net/ip/93.1.1.1": httpx.Response(200, json=ripe),
    })
    rdap = Rdap(http)

    assert rdap.enrich(IP).org == "RIPE-NET"
    assert rdap.enrich("93.1.1.1").org == "RIPE-NET"
    assert len(bootstrap_hits) == 1


def test_rdap_falls_back_to_rdap_org_redirector_when_bootstrap_has_no_match():
    arin = {
        "objectClassName": "ip network",
        "handle": "NET-93-184-216-0-1",
        "startAddress": "93.184.216.0",
        "endAddress": "93.184.216.255",
        "name": "EDGECAST-NETBLK-03",
        "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
        "entities": [
            {"handle": "ABUSE", "roles": ["abuse"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse Desk"]]]},
            {"handle": "EDGEC-20", "roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Edgecast Inc."], ["kind", {}, "text", "org"]]]},
        ],
    }
    http = fake_http({
        "data.iana.org/rdap/ipv4.json": httpx.Response(200, json={"services": []}),
        f"rdap.org/ip/{IP}": httpx.Response(302, headers={"location": f"https://rdap.arin.net/registry/ip/{IP}"}),
        f"rdap.arin.net/registry/ip/{IP}": httpx.Response(200, json=arin),
    })

    details = Rdap(http).enrich(IP)

    assert (details.org, details.network) == ("Edgecast Inc.", "93.184.216.0/24")


def test_rdap_falls_back_to_network_name_and_address_range():
    body = {"startAddress": "198.51.100.0", "endAddress": "198.51.100.255", "name": "EXAMPLE-NET", "entities": []}
    http = fake_http({
        "data.iana.org/rdap/ipv4.json": httpx.Response(200, json=BOOTSTRAP_V4),
        "rdap.org/ip/198.51.100.7": httpx.Response(200, json=body),
    })
    details = Rdap(http).enrich("198.51.100.7")

    assert (details.org, details.network) == ("EXAMPLE-NET", "198.51.100.0-198.51.100.255")
