import csv
import json

import pytest

from farpoint import cli
from farpoint.fingerprint import FingerprintConfig
from farpoint.models import IpDetails, Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.probe import HttpResult, SmtpResult
from farpoint.resolve import Resolution

from test_fingerprint import FakeProber
from test_pipeline import StaticSource, TableEnricher, dns_table
from test_posture import FakeDns

D = "example.com"
ORIGIN, CDN = "93.184.216.34", "151.101.1.1"


def scenario(open_ports=(22, 443)):
    src = StaticSource("crtsh", [Observation("crtsh", h) for h in ("www.example.com", "app.example.com", "cdn.example.com", "intranet.example.com", "old.example.com")]
                       + [Observation("otx", "www.example.com", "203.0.113.200"), Observation("otx", "www.example.com", "8.8.8.8")])  # history: maybe someone else's now
    lookup = dns_table({
        "www.example.com": Resolution(ips=(ORIGIN,)),
        "app.example.com": Resolution(ips=(ORIGIN,)),
        "cdn.example.com": Resolution(ips=(CDN,), cnames=("example.global.fastly.net",)),
        "intranet.example.com": Resolution(ips=("10.0.0.5",)),
        "mx.example.com": Resolution(ips=(ORIGIN,)),
    })
    dns = FakeDns({
        D: {"MX": ["mx.example.com", "example-com.mail.protection.outlook.com", "mail.isp.net"], "TXT": ["v=spf1 -all"], "NS": ["ns1.dnshost.net"]},
        "old.example.com": {"CNAME": ["gone-app.azurewebsites.net"]},
        "azurewebsites.net": {"NS": ["ns1-01.azure-dns.com"]},
    })
    home = HttpResult(200, [("server", "nginx/1.18.0")], b"<title>Home</title>")
    prober = FakeProber(
        ports={(ORIGIN, p): "open" for p in open_ports} | {(CDN, 443): "open"},
        banners={(ORIGIN, 22): b"SSH-2.0-OpenSSH_8.9p1\r\n"},
        http={("http", h, 443, "/"): home for h in ("www.example.com", "app.example.com", "cdn.example.com")},
        smtp={("mx.example.com", 25): SmtpResult("mx.example.com ESMTP Postfix", ["STARTTLS"], starttls=True)},
    )
    enricher = TableEnricher({ORIGIN: IpDetails(org="Example Hosting", ports={8443}), CDN: IpDetails(org="Fastly, Inc.", ports={2052})})
    pipeline = Pipeline(
        sources=[src], lookup=lookup, enrichers=[enricher], dns=dns, prober=prober,
        fingerprint=FingerprintConfig(ports=(22, 443, 3389), paths=(), rate=None, legacy_tls=False),
        rdap_domain=lambda d: {"status": ["client transfer prohibited"]},
    )
    return pipeline, prober


def test_only_live_public_in_scope_hosts_are_probed_and_shared_addresses_only_on_web_ports():
    pipeline, prober = scenario()

    inv = pipeline.run([D])

    swept = {(ip, port) for kind, ip, port in (c for c in prober.calls if c[0] == "connect")}
    assert swept == {(ORIGIN, p) for p in (22, 443, 3389, 8443)} | {(CDN, 80), (CDN, 443)}  # Shodan's 8443 too; never 10.0.0.5 or 8.8.8.8
    assert inv.ips[ORIGIN].open_ports == {22, 443} and inv.ips[ORIGIN].probed_ports == {22, 443, 3389, 8443}
    assert set(inv.services) == {"www.example.com:22", "app.example.com:22", "www.example.com:443", "app.example.com:443", "cdn.example.com:443"}
    assert sum(1 for c in prober.calls if c[0] == "banner") == 1  # SSH asked once per address, recorded for both hosts
    assert inv.services["app.example.com:22"].hostname == "app.example.com"
    assert "www.example.com:3389" in inv.closed and "www.example.com:443" not in inv.closed and "intranet.example.com:443" not in inv.closed
    assert inv.dangling == {"old.example.com": {"reason": "CNAME to gone-app.azurewebsites.net, which does not exist (Azure: the name may be claimable)", "claimable": True}}
    posture = inv.posture[D]
    assert posture["spf_all"] == "-all" and posture["status"] == ["client transfer prohibited"]
    assert [m["host"] for m in posture["mx_health"]] == ["mx.example.com"]  # never Microsoft's or the ISP's
    assert [c for c in prober.calls if c[0] == "smtp"] == [("smtp", "mx.example.com", 25)]


def test_results_merge_as_snapshots_and_closed_ports_drop_out(tmp_path):
    pipeline, _ = scenario()
    first = write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")
    assert {r["endpoint"] for r in first["fingerprints"]} >= {"www.example.com:22", "www.example.com:443"}

    pipeline, _ = scenario(open_ports=(443,))  # SSH closed since
    second = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z")

    rows = {r["endpoint"]: r for r in second["fingerprints"]}
    assert "www.example.com:22" not in rows
    assert (rows["www.example.com:443"]["first_seen"], rows["www.example.com:443"]["last_seen"]) == ("2026-10-01T00:00:00Z", "2026-10-24T00:00:00Z")
    assert next(r for r in second["ips"] if r["ip"] == ORIGIN)["open_ports"] == [443]
    assert second["runs"][-1]["new"]["fingerprints"] == 0
    with open(tmp_path / "fingerprints.csv", newline="") as fh:
        row = next(r for r in csv.DictReader(fh) if r["endpoint"] == "www.example.com:443")
    assert row["tech"] == "nginx 1.18.0" and row["title"] == "Home"
    with open(tmp_path / "technologies.csv", newline="") as fh:
        assert {r["technology"]: r["count"] for r in csv.DictReader(fh)}["nginx"] == "3"
    assert (tmp_path / "posture.csv").exists() and not (tmp_path / "findings.csv").exists()  # findings need --assess
    assert json.loads((tmp_path / "assets.json").read_text())["dangling"][0]["hostname"] == "old.example.com"


def test_assessment_judges_the_merged_report_when_saving(tmp_path):
    from farpoint.assess import assessed

    pipeline, _ = scenario(open_ports=(22, 443, 3389))
    report = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z", assess=lambda r: assessed(r, [], {}, "2026-10-24T00:00:00Z"))

    kinds = {(f["kind"], f["target"]) for f in report["findings"]}
    assert ("exposed-service", "www.example.com:3389") in kinds and ("subdomain-takeover", "old.example.com") in kinds
    with open(tmp_path / "findings.csv", newline="") as fh:
        assert next(csv.DictReader(fh))["level"] == "high"


def test_cli_checks_its_new_flags(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--fingerprint", "--no-resolve", "-o", str(tmp_path)])
    assert "--fingerprint needs DNS resolution" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--fingerprint", "--ports", "1-65535", "-o", str(tmp_path)])
    assert "too wide" in capsys.readouterr().err
    assert cli.main(["--assess", "-o", str(tmp_path / "empty")]) == 2
    assert "no inventory" in capsys.readouterr().err


def test_assess_alone_rejudges_an_existing_inventory_without_scanning(tmp_path, capsys):
    pipeline, _ = scenario(open_ports=(22, 443, 3389))
    write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")
    runs_before = json.loads((tmp_path / "assets.json").read_text())["runs"]

    assert cli.main(["--assess", "--no-cve", "-o", str(tmp_path)]) == 0

    report = json.loads((tmp_path / "assets.json").read_text())
    assert report["runs"] == runs_before and report["findings"]
    assert "findings:" in capsys.readouterr().out


def test_progress_phases_count_their_own_jobs():
    from test_progress import Recorder

    pipeline, _ = scenario()
    pipeline.reporter = rec = Recorder()
    pipeline.run([D])

    last = {}
    for e in rec.events:
        if e[0] == "phase":
            last[e[1]] = e[2:]
    assert last["ports"] == (2, 2, 0)  # two addresses
    assert last["fingerprinting"] == (4, 4, 0)  # SSH once for the address, 443 per host
    assert last["posture"] == (4, 4, 0)  # the domain's posture, two non-resolving names checked for dangling CNAMEs, one self-run MX


def test_an_interrupt_while_fingerprinting_keeps_what_was_found():
    from farpoint import runtime

    pipeline, _ = scenario()
    seen = []

    def stop_once_fingerprinting(inv, pending):
        if inv.services:
            seen.append(len(inv.services))
            raise KeyboardInterrupt

    pipeline.checkpoint = stop_once_fingerprinting
    inv = pipeline.run([D])

    assert inv.interrupted and runtime.cancelled()
    assert inv.ips[ORIGIN].open_ports == {22, 443}  # the sweep had finished
    assert inv.services and not inv.posture
    assert len(seen) == 1  # stopped at the first result


def test_a_cdn_address_known_only_from_shodans_tags_gets_web_ports_only():
    pipeline, prober = scenario()
    pipeline.enrichers = [TableEnricher({ORIGIN: IpDetails(), CDN: IpDetails(tags={"cdn"})})]  # no owner known
    pipeline.lookup = dns_table({"cdn.example.com": Resolution(ips=(CDN,))})  # an apex ALIAS: no CNAME either
    pipeline.run([D])
    assert {port for kind, ip, port in (c for c in prober.calls if c[0] == "connect") if ip == CDN} == {80, 443}


def test_a_service_that_failed_this_time_keeps_its_old_row(tmp_path):
    pipeline, _ = scenario()
    write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")

    pipeline, prober = scenario()
    real_banner = prober.banner

    def broken(ip, port, wait=3.0):
        raise RuntimeError("unexpected")

    prober.banner = broken  # the SSH check fails outright this run
    second = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z")

    row = next(r for r in second["fingerprints"] if r["endpoint"] == "www.example.com:22")
    assert row["last_seen"] == "2026-10-01T00:00:00Z"  # kept, not deleted


def test_a_cname_to_a_lapsed_domain_is_claimable():
    from farpoint.models import Inventory
    from farpoint.pipeline import _dangling

    inv = Inventory([D])
    inv.add(Observation("x", "old.example.com"))
    found = _dangling(FakeDns({"old.example.com": {"CNAME": ["expired-vendor.com"]}}), inv, "old.example.com")
    assert found["claimable"] and "not registered" in found["reason"]


def test_a_takeover_that_was_fixed_leaves_the_inventory(tmp_path):
    pipeline, _ = scenario()
    write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")

    pipeline, _ = scenario()
    pipeline.lookup = dns_table({"www.example.com": Resolution(ips=(ORIGIN,)), "old.example.com": Resolution(ips=("93.184.216.99",))})  # resolves again, nothing open
    report = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z")

    assert not [d for d in report.get("dangling", []) if d["hostname"] == "old.example.com"]


def test_a_port_that_timed_out_keeps_its_row_but_one_refused_drops_it(tmp_path):
    pipeline, _ = scenario(open_ports=(22, 443, 3389))
    write_outputs(pipeline.run([D]), tmp_path, "2026-10-01T00:00:00Z")

    pipeline, prober = scenario(open_ports=(443,))
    prober.ports[(ORIGIN, 3389)] = "filtered"  # one dropped packet; 22 now refuses
    rows = {r["endpoint"] for r in write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z")["fingerprints"]}

    assert "www.example.com:3389" in rows and "www.example.com:22" not in rows


def test_an_address_wide_service_judges_the_certificate_per_name():
    from test_fingerprint import make_cert
    from farpoint.probe import TlsResult

    pipeline, prober = scenario(open_ports=(993,))
    pipeline.fingerprint.ports = (993,)
    cert = TlsResult("TLSv1.3", "x", make_cert(cn="www.example.com", sans=("www.example.com",)))
    prober.tls_[("app.example.com", 993)] = prober.tls_[("www.example.com", 993)] = cert
    inv = pipeline.run([D])

    app, www = inv.services["app.example.com:993"], inv.services["www.example.com:993"]
    assert (app.tls["matches"], www.tls["matches"]) == (False, True) and app.tls is not www.tls


def test_a_failed_assessment_still_saves_the_scan(tmp_path):
    pipeline, _ = scenario()

    def broken(report):
        raise KeyError("reason")

    report = write_outputs(pipeline.run([D]), tmp_path, "2026-10-24T00:00:00Z", assess=broken)

    assert json.loads((tmp_path / "assets.json").read_text())["runs"]
    assert report["errors"][-1]["source"] == "assess"
