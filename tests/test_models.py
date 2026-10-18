from easm.models import Inventory, IpDetails, Observation


def test_same_host_from_different_sources_merges_into_one_record():
    inv = Inventory(["example.com"])
    inv.add(Observation("crtsh", hostname="*.WWW.example.com"))
    inv.add(Observation("otx", hostname="www.example.com.", ip="93.184.216.34"))

    assert list(inv.hosts) == ["www.example.com"]
    assert inv.hosts["www.example.com"].sources == {"crtsh", "otx"}
    assert inv.hosts["www.example.com"].ips == {"93.184.216.34"}


def test_out_of_scope_hostnames_are_dropped():
    inv = Inventory(["example.com"])
    inv.add(Observation("wayback", hostname="cdn.thirdparty.net", ip="1.2.3.4"))
    inv.add(Observation("wayback", hostname="notexample.com"))

    assert inv.hosts == {}
    assert inv.ips == {}


def test_ip_record_links_back_to_every_host_that_points_at_it():
    inv = Inventory(["example.com", "example.org"])
    inv.add(Observation("dns", hostname="a.example.com", ip="203.0.113.7"))
    inv.add(Observation("hackertarget", hostname="b.example.org", ip="203.0.113.7"))

    rec = inv.ips["203.0.113.7"]
    assert rec.hostnames == {"a.example.com", "b.example.org"}
    assert rec.sources == {"dns", "hackertarget"}


def test_invalid_ip_is_ignored_but_hostname_is_kept():
    inv = Inventory(["example.com"])
    inv.add(Observation("otx", hostname="app.example.com", ip="app.azurewebsites.net"))

    assert inv.hosts["app.example.com"].ips == set()
    assert inv.ips == {}


def test_lookalikes_are_kept_apart_from_owned_assets():
    inv = Inventory(["example.com"])
    inv.add(Observation("dnstwist", hostname="examp1e.com", ip="198.51.100.9", lookalike=True))

    assert inv.hosts == {}
    assert inv.ips == {}
    assert inv.lookalikes["examp1e.com"].ips == {"198.51.100.9"}


def test_enrichment_fills_ip_details_without_clobbering_known_values():
    inv = Inventory(["example.com"])
    inv.add(Observation("dns", hostname="a.example.com", ip="203.0.113.7"))
    inv.enrich("203.0.113.7", IpDetails(org="Example Hosting", network="203.0.113.0/24"))
    inv.enrich("203.0.113.7", IpDetails(ports={443, 80}, vulns={"CVE-2021-44228"}))

    rec = inv.ips["203.0.113.7"]
    assert (rec.org, rec.network) == ("Example Hosting", "203.0.113.0/24")
    assert rec.ports == {80, 443}
    assert rec.vulns == {"CVE-2021-44228"}
