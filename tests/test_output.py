import csv
import json

from easm.models import Inventory, IpDetails, Observation, SourceError
from easm.output import write_outputs


def sample_inventory() -> Inventory:
    inv = Inventory(["example.com"])
    inv.add(Observation("input", "example.com"))
    inv.add(Observation("crtsh", "www.example.com"))
    inv.add(Observation("dns", "www.example.com", "93.184.216.34"))
    inv.add(Observation("dns", "www.example.com", "2606:2800:220:1::1"))
    inv.add(Observation("wayback", "old.example.com"))
    inv.hosts["www.example.com"].resolves = True
    inv.hosts["www.example.com"].cnames.add("www.example.com.cdn.net")
    inv.hosts["old.example.com"].resolves = False
    inv.enrich("93.184.216.34", IpDetails(org="Edgecast Inc.", network="93.184.216.0/24", ports={443, 80}))
    inv.add(Observation("dnstwist", "examp1e.com", "198.51.100.1", lookalike=True))
    inv.errors.append(SourceError("hackertarget", "example.com", "SourceFailure: API count exceeded"))
    return inv


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_text_lists_are_sorted_and_unique(tmp_path):
    write_outputs(sample_inventory(), tmp_path)

    assert (tmp_path / "hosts.txt").read_text().splitlines() == ["example.com", "old.example.com", "www.example.com"]
    assert (tmp_path / "ips.txt").read_text().splitlines() == ["93.184.216.34", "2606:2800:220:1::1"]


def test_host_and_ip_csvs_flatten_multi_values(tmp_path):
    write_outputs(sample_inventory(), tmp_path)

    hosts = {r["hostname"]: r for r in read_csv(tmp_path / "hosts.csv")}
    assert hosts["www.example.com"] == {
        "hostname": "www.example.com",
        "resolves": "yes",
        "ips": "93.184.216.34 2606:2800:220:1::1",
        "cnames": "www.example.com.cdn.net",
        "sources": "crtsh dns",
    }
    assert hosts["old.example.com"]["resolves"] == "no"
    assert hosts["example.com"]["resolves"] == ""

    ips = {r["ip"]: r for r in read_csv(tmp_path / "ips.csv")}
    assert ips["93.184.216.34"] == {
        "ip": "93.184.216.34",
        "org": "Edgecast Inc.",
        "network": "93.184.216.0/24",
        "ports": "80 443",
        "vulns": "",
        "hostnames": "www.example.com",
        "sources": "dns",
    }


def test_json_report_includes_lookalikes_and_errors(tmp_path):
    write_outputs(sample_inventory(), tmp_path)

    report = json.loads((tmp_path / "assets.json").read_text())

    assert report["domains"] == ["example.com"]
    assert report["lookalikes"] == [{"domain": "examp1e.com", "ips": ["198.51.100.1"], "sources": ["dnstwist"]}]
    assert report["errors"] == [{"source": "hackertarget", "target": "example.com", "message": "SourceFailure: API count exceeded"}]
    assert [h["hostname"] for h in report["hosts"]] == ["example.com", "old.example.com", "www.example.com"]
