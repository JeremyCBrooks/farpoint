import csv
import json
import os
from datetime import datetime, timezone

import pytest

from easm.models import Inventory, IpDetails, Observation, SourceError
from easm.output import ReportError, load_report, merge_reports, run_report, write_outputs


def without_seen(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in ("first_seen", "last_seen")}


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
    assert without_seen(hosts["www.example.com"]) == {
        "hostname": "www.example.com",
        "resolves": "yes",
        "ips": "93.184.216.34 2606:2800:220:1::1",
        "cnames": "www.example.com.cdn.net",
        "sources": "crtsh dns",
    }
    assert hosts["old.example.com"]["resolves"] == "no"
    assert hosts["example.com"]["resolves"] == ""

    ips = {r["ip"]: r for r in read_csv(tmp_path / "ips.csv")}
    assert without_seen(ips["93.184.216.34"]) == {
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
    assert [without_seen(r) for r in report["lookalikes"]] == [{"domain": "examp1e.com", "ips": ["198.51.100.1"], "sources": ["dnstwist"]}]
    assert report["errors"] == [{"source": "hackertarget", "target": "example.com", "message": "SourceFailure: API count exceeded"}]
    assert [h["hostname"] for h in report["hosts"]] == ["example.com", "old.example.com", "www.example.com"]


def run_of(domain: str, *observations: Observation, resolves: dict | None = None) -> Inventory:
    inv = Inventory([domain])
    for obs in observations:
        inv.add(obs)
    for host, flag in (resolves or {}).items():
        inv.hosts[host].resolves = flag
    return inv


def test_runs_into_the_same_directory_accumulate(tmp_path):
    write_outputs(run_of("example.com", Observation("crtsh", "a.example.com", "192.0.2.1")), tmp_path)
    write_outputs(run_of("example.com", Observation("otx", "a.example.com", "192.0.2.2"), Observation("otx", "b.example.com")), tmp_path)
    write_outputs(run_of("example.org", Observation("crtsh", "www.example.org")), tmp_path)

    report = json.loads((tmp_path / "assets.json").read_text())
    hosts = {h["hostname"]: h for h in report["hosts"]}

    assert report["domains"] == ["example.com", "example.org"]
    assert set(hosts) == {"a.example.com", "b.example.com", "www.example.org"}
    assert hosts["a.example.com"]["ips"] == ["192.0.2.1", "192.0.2.2"]
    assert hosts["a.example.com"]["sources"] == ["crtsh", "otx"]
    assert [r["ip"] for r in report["ips"]] == ["192.0.2.1", "192.0.2.2"]
    assert len(report["runs"]) == 3
    assert (tmp_path / "hosts.txt").read_text().splitlines() == ["a.example.com", "b.example.com", "www.example.org"]


def test_merge_tracks_first_and_last_seen_and_keeps_known_resolution():
    first = merge_reports(None, run_report(run_of("example.com", Observation("crtsh", "a.example.com"), Observation("crtsh", "b.example.com"), resolves={"a.example.com": True, "b.example.com": True})), "T1")
    second = merge_reports(first, run_report(run_of("example.com", Observation("otx", "a.example.com"), Observation("otx", "c.example.com"), resolves={"a.example.com": None})), "T2")

    hosts = {h["hostname"]: h for h in second["hosts"]}
    assert (hosts["a.example.com"]["first_seen"], hosts["a.example.com"]["last_seen"]) == ("T1", "T2")
    assert (hosts["b.example.com"]["first_seen"], hosts["b.example.com"]["last_seen"]) == ("T1", "T1")
    assert (hosts["c.example.com"]["first_seen"], hosts["c.example.com"]["last_seen"]) == ("T2", "T2")
    assert hosts["a.example.com"]["resolves"] is True  # not re-checked this run: keep the last known answer


def test_merge_prefers_this_runs_resolution_and_ip_details():
    first = merge_reports(None, run_report(run_of("example.com", Observation("dns", "a.example.com", "192.0.2.1"), resolves={"a.example.com": True})), "T1")
    later = run_of("example.com", Observation("dns", "a.example.com", "192.0.2.1"), resolves={"a.example.com": False})
    later.enrich("192.0.2.1", IpDetails(org="New Org", ports={443}))
    second = merge_reports(first, run_report(later), "T2")

    assert second["hosts"][0]["resolves"] is False
    assert (second["ips"][0]["org"], second["ips"][0]["ports"]) == ("New Org", [443])


def test_unreadable_inventory_is_never_overwritten(tmp_path):
    (tmp_path / "assets.json").write_text("{not json")

    with pytest.raises(ReportError):
        write_outputs(sample_inventory(), tmp_path)

    assert (tmp_path / "assets.json").read_text() == "{not json"


def test_inventory_from_before_merging_is_adopted(tmp_path):
    legacy_file = tmp_path / "assets.json"
    legacy_file.write_text(json.dumps({"domains": ["example.com"], "hosts": [{"hostname": "legacy.example.com", "resolves": False, "ips": [], "cnames": [], "sources": ["crtsh"]}], "ips": [], "lookalikes": []}))
    mtime = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()
    os.utime(legacy_file, (mtime, mtime))

    report = write_outputs(sample_inventory(), tmp_path)

    legacy = next(h for h in report["hosts"] if h["hostname"] == "legacy.example.com")
    assert (legacy["first_seen"], legacy["last_seen"]) == ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z")
    assert "www.example.com" in {h["hostname"] for h in report["hosts"]}



def test_output_files_respect_the_umask(tmp_path):
    old = os.umask(0o022)
    try:
        write_outputs(sample_inventory(), tmp_path)
    finally:
        os.umask(old)

    assert {p.name: p.stat().st_mode & 0o777 for p in tmp_path.iterdir() if not p.name.startswith(".")} == {
        name: 0o644 for name in ("assets.json", "hosts.txt", "ips.txt", "hosts.csv", "ips.csv", "lookalikes.csv")
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"hosts": ["a.example.com"]},
        {"hosts": [{"ips": []}]},
        {"hosts": [{"hostname": "a.example.com", "ips": "192.0.2.1"}]},
        {"ips": [{"ip": "not-an-ip"}]},
        {"domains": "example.com"},
        {"runs": {}},
    ],
)
def test_malformed_rows_are_rejected_before_merging(tmp_path, bad):
    (tmp_path / "assets.json").write_text(json.dumps(bad))

    with pytest.raises(ReportError):
        load_report(tmp_path)


def test_a_run_that_cannot_merge_is_saved_beside_the_inventory(tmp_path):
    (tmp_path / "assets.json").write_text("{not json")

    with pytest.raises(ReportError, match="assets.unmerged-"):
        write_outputs(sample_inventory(), tmp_path)

    (saved,) = tmp_path.glob("assets.unmerged-*.json")
    assert "www.example.com" in {h["hostname"] for h in json.loads(saved.read_text())["hosts"]}
    assert (tmp_path / "assets.json").read_text() == "{not json"


def test_new_counts_do_not_depend_on_timestamps():
    first = merge_reports(None, run_report(run_of("example.com", Observation("crtsh", "a.example.com"))), "T")
    second = merge_reports(first, run_report(run_of("example.com", Observation("crtsh", "a.example.com"), Observation("crtsh", "b.example.com"))), "T")

    assert first["runs"][-1]["new"]["hosts"] == 1
    assert second["runs"][-1]["new"]["hosts"] == 1  # same-second runs: only b is new
