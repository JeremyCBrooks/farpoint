from datetime import date, datetime, timezone

import httpx

from conftest import fake_http
from farpoint.assess import Kev, Nvd, assessed, derive, lookup_vulns, technologies

TODAY = date(2026, 10, 24)


def endpoint(host, port, service="https", tech=(), signals=(), tls=None, status=200, headers=None, banner=None):
    row = {"endpoint": f"{host}:{port}", "hostname": host, "ip": "192.0.2.1", "port": port, "service": service,
           "tech": list(tech), "signals": list(signals), "cookies": [], "status": status, "headers": headers if headers is not None else {"strict-transport-security": "x"}}
    if tls:
        row["tls"] = tls
    if banner:
        row["banner"] = banner
    return row


def kinds(findings, target=None):
    return {(f["level"], f["kind"]) for f in findings if target is None or f["target"] == target}


def test_what_an_attacker_looks_for_first_is_high():
    report = {"fingerprints": [
        endpoint("vpn.example.com", 443, tech=[{"name": "FortiGate SSL-VPN", "category": "edge", "evidence": "location: /remote/login"}]),
        endpoint("db.example.com", 3389, service="rdp"),
        endpoint("ci.example.com", 443, tech=[{"name": "Jenkins", "category": "panel", "version": "2.401"}]),
        endpoint("old.example.com", 443, tech=[{"name": "PHP", "category": "language", "version": "7.4.3"}], signals=["git-exposed"]),
        endpoint("www.example.com", 443, tls={"not_after": "2026-01-01T00:00:00Z", "days_left": -296, "self_signed": False, "matches": True, "subject": "www.example.com"}),
    ], "dangling": [{"hostname": "promo.example.com", "reason": "CNAME to gone.azurewebsites.net, which does not exist"}]}

    found = derive(report, today=TODAY)

    assert ("high", "edge-device") in kinds(found, "vpn.example.com:443")
    assert ("high", "exposed-service") in kinds(found, "db.example.com:3389")
    assert ("high", "admin-interface") in kinds(found, "ci.example.com:443")
    assert {("high", "end-of-life"), ("high", "git-exposed")} <= kinds(found, "old.example.com:443")
    assert ("medium", "non-production-exposed") in kinds(found, "old.example.com")
    assert ("high", "certificate-expired") in kinds(found, "www.example.com:443")
    assert ("high", "subdomain-takeover") in kinds(found, "promo.example.com")
    assert [f["level"] for f in found] == sorted((f["level"] for f in found), key=["high", "medium", "low"].index)


def test_data_services_that_speak_http_are_still_exposed():
    assert ("high", "exposed-service") in kinds(derive({"fingerprints": [endpoint("es.example.com", 9200, service="http")]}, today=TODAY))


def test_findings_of_one_kind_on_one_endpoint_stay_distinct():
    report = {"fingerprints": [endpoint("gw.example.com", 443, tech=[{"name": "F5 BIG-IP", "category": "edge"}, {"name": "F5 BIG-IP APM", "category": "edge"}])]}
    ids = [f["id"] for f in derive(report, today=TODAY)]
    assert len(ids) == len(set(ids)) and "edge-device|gw.example.com:443|F5 BIG-IP APM" in ids


def test_dmarc_pct_zero_and_unknown_checks():
    p = {"domain": "example.com", "spf": "v=spf1 -all", "spf_all": "-all", "dmarc": "v=DMARC1; p=reject; pct=0", "dmarc_policy": "reject", "dmarc_pct": 0}
    assert ("medium", "dmarc-partial") in kinds(derive({"posture": [p]}, today=TODAY))
    failed = {"domain": "example.com", "check_errors": ["spf: NoNameservers: SERVFAIL"], "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject"}
    assert ("high", "spf-missing") not in kinds(derive({"posture": [failed]}, today=TODAY))  # unknown is not missing


def test_a_cname_into_nothing_is_only_a_takeover_when_someone_could_claim_it():
    report = {"dangling": [{"hostname": "a.example.com", "reason": "x", "claimable": True}, {"hostname": "b.example.com", "reason": "y", "claimable": False}]}
    assert kinds(derive(report, today=TODAY)) == {("high", "subdomain-takeover"), ("low", "dangling-cname")}


def test_cleartext_http_and_tls_hygiene():
    report = {"fingerprints": [
        endpoint("a.example.com", 80, service="http"),
        endpoint("b.example.com", 80, service="http"),
        endpoint("b.example.com", 443, headers={}, tls={"not_after": "2027-01-01T00:00:00Z", "days_left": 60, "self_signed": True, "subject": "localhost",
                                                    "legacy": {"TLSv1": True, "TLSv1.1": None}, "key": "RSA 1024", "sans": ["dc01.corp.local"]}),
    ]}
    found = derive(report, today=TODAY)
    assert ("medium", "cleartext-http") in kinds(found, "a.example.com:80")
    assert ("low", "no-https-redirect") in kinds(found, "b.example.com:80")
    assert {("medium", "certificate-self-signed"), ("medium", "legacy-tls"), ("medium", "weak-certificate-key"),
            ("low", "internal-names-in-certificate"), ("low", "no-hsts")} <= kinds(found, "b.example.com:443")


def test_cve_matches_are_ranked_by_exploitation_and_score_and_capped_for_distro_packages():
    ssh = {"name": "OpenSSH", "category": "remote-access", "version": "8.9p1", "cpe": "cpe:2.3:a:openbsd:openssh:8.9:p1"}
    nginx = {"name": "nginx", "category": "server", "version": "1.18.0", "cpe": "cpe:2.3:a:f5:nginx:1.18.0"}
    report = {
        "fingerprints": [endpoint("a.example.com", 22, "ssh", [ssh], banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), endpoint("a.example.com", 443, tech=[nginx])],
        "vulns": [
            {"cpe": ssh["cpe"], "cves": [{"id": "CVE-2023-38408", "score": 9.8}, {"id": "CVE-2023-48795", "score": 5.9}]},
            {"cpe": nginx["cpe"], "cves": [{"id": "CVE-2021-23017", "score": 7.7}, {"id": "CVE-2023-44487", "score": 7.5}]},
        ],
    }

    plain = {f["target"]: f for f in derive(report, today=TODAY) if f["kind"] == "known-vulnerable-version"}
    assert plain["a.example.com:22"]["level"] == "medium"  # 9.8, but an Ubuntu package may carry the fix
    assert plain["a.example.com:443"]["level"] == "medium"

    exploited = {f["target"]: f for f in derive(report, kev={"CVE-2023-44487": {}}, today=TODAY) if f["kind"] == "known-vulnerable-version"}
    assert exploited["a.example.com:443"]["level"] == "high"
    assert exploited["a.example.com:443"]["evidence"][0] == "CVE-2023-44487 7.5 KEV"


def test_spoofable_mail_and_dns_posture():
    weak = {"domain": "example.com", "mx": ["mx.example.com"], "spf": "v=spf1 include:x ~all", "spf_all": "~all", "spf_lookups": 12,
            "spf_unregistered_includes": ["spf.lapsed.net"], "spf_missing_includes": ["spf.lapsed.net"], "dmarc": "v=DMARC1; p=none", "dmarc_policy": "none",
            "dkim": {"selector1": 1024}, "mta_sts": None, "ns": ["ns1.example.com", "ns2.example.com"], "ns_providers": ["example.com"],
            "axfr": ["ns1.example.com"], "dnssec": False, "caa": [], "expires": "2026-11-01", "status": ["active"],
            "mx_health": [{"host": "mx.example.com", "starttls": False, "banner": "ESMTP"}]}
    found = derive({"posture": [weak]}, today=TODAY)
    assert {("high", "dmarc-not-enforced"), ("high", "spf-include-unregistered"), ("high", "zone-transfer"), ("high", "domain-expiring"),
            ("medium", "spf-too-many-lookups"), ("medium", "dkim-weak-key"), ("low", "mta-sts-missing"), ("low", "no-dnssec"),
            ("low", "no-caa"), ("low", "no-transfer-lock")} <= kinds(found, "example.com")
    assert ("medium", "mx-no-starttls") in kinds(found, "mx.example.com")
    assert ("medium", "spf-include-missing") not in kinds(found)  # reported once, as unregistered

    parked = {"domain": "example.net", "mx": [], "spf": None, "dmarc": None, "ns": ["ns1.example.com"], "dnssec": True, "caa": ["x"]}
    assert {("high", "spf-missing"), ("high", "dmarc-missing")} <= kinds(derive({"posture": [parked]}, today=TODAY))

    strong = {"domain": "example.org", "mx": ["m.example.org"], "spf": "v=spf1 -all", "spf_all": "-all", "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject",
              "dkim": {"selector1": 2048}, "mta_sts": "enforce", "ns": ["a", "b"], "ns_providers": ["x.net"], "dnssec": True, "caa": ["x"],
              "status": ["client transfer prohibited"]}
    assert derive({"posture": [strong]}, today=TODAY) == []


def test_shodan_cves_on_addresses():
    found = derive({"ips": [{"ip": "192.0.2.1", "vulns": ["CVE-2021-44228", "CVE-2020-1"]}]}, kev={"CVE-2021-44228": {}}, today=TODAY)
    assert found[0]["level"] == "high" and found[0]["evidence"] == ["CVE-2021-44228"]


def test_shodan_cves_on_a_shared_front_end_are_the_providers():
    report = {
        "hosts": [{"hostname": "www.example.com", "cnames": ["example.azurefd.net"]}, {"hostname": "app.example.com", "cnames": ["app.eastus.cloudapp.azure.com"]}],
        "ips": [
            {"ip": "192.0.2.1", "org": "Microsoft Corporation", "hostnames": ["www.example.com"], "vulns": ["CVE-2023-44487"]},
            {"ip": "192.0.2.2", "org": "Microsoft Corporation", "hostnames": ["app.example.com"], "vulns": ["CVE-2023-44487"]},
            {"ip": "192.0.2.3", "org": "Cloudflare, Inc.", "hostnames": [], "vulns": ["CVE-2023-44487"]},
        ],
    }
    levels = {f["target"]: f["level"] for f in derive(report, kev={"CVE-2023-44487": {}}, today=TODAY)}
    assert levels == {"192.0.2.1": "low", "192.0.2.2": "high", "192.0.2.3": "low"}  # an Azure VM is the organisation's


def nvd_page(ids, total=None, per_page=None):
    vulns = [{"cve": {"id": i, "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}} for i in ids]
    return httpx.Response(200, json={"totalResults": total if total is not None else len(ids), "resultsPerPage": per_page or len(ids), "vulnerabilities": vulns})


def test_lookups_use_the_cache_and_keep_old_answers_when_nvd_fails():
    now = datetime(2026, 10, 24, tzinfo=timezone.utc)
    report = {
        "fingerprints": [endpoint("a.example.com", 443, tech=[
            {"name": "nginx", "category": "server", "cpe": "cpe:2.3:a:f5:nginx:1.18.0"},
            {"name": "PHP", "category": "language", "cpe": "cpe:2.3:a:php:php:7.4.3"},
            {"name": "OpenSSL", "category": "language", "cpe": "cpe:2.3:a:openssl:openssl:1.0.2k"},
        ])],
        "vulns": [
            {"cpe": "cpe:2.3:a:php:php:7.4.3", "cves": [{"id": "CVE-OLD"}], "checked_at": "2026-10-20T00:00:00Z"},  # fresh: not asked again
            {"cpe": "cpe:2.3:a:openssl:openssl:1.0.2k", "cves": [{"id": "CVE-KEPT"}], "checked_at": "2026-01-01T00:00:00Z"},  # stale
        ],
    }

    def nvd(request):
        cpe = request.url.params["virtualMatchString"]
        if "openssl" in cpe:
            return httpx.Response(400, text="bad")
        start = int(request.url.params["startIndex"])
        return nvd_page(["CVE-1"] if start == 0 else ["CVE-2"], total=2, per_page=1)

    http = fake_http({
        "services.nvd.nist.gov/rest/json/cves/2.0": nvd,
        "www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json": httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2", "knownRansomwareCampaignUse": "Known"}]}),
    })
    progress = []

    rows, kev, errors = lookup_vulns(report, Nvd(http, retries=0), Kev(http, retries=0), now, lambda *a: progress.append(a))

    by_cpe = {r["cpe"]: r for r in rows}
    assert [c["id"] for c in by_cpe["cpe:2.3:a:f5:nginx:1.18.0"]["cves"]] == ["CVE-1", "CVE-2"]
    assert by_cpe["cpe:2.3:a:php:php:7.4.3"]["cves"] == [{"id": "CVE-OLD"}]
    assert by_cpe["cpe:2.3:a:openssl:openssl:1.0.2k"]["cves"] == [{"id": "CVE-KEPT"}]
    assert [e["target"] for e in errors] == ["cpe:2.3:a:openssl:openssl:1.0.2k"]
    assert kev["CVE-2"]["ransomware"] is True
    assert progress[-1] == (2, 2, 1)

    judged = assessed({**report, "updated_at": "2026-10-01T00:00:00Z"}, rows, kev, "2026-10-24T00:00:00Z", errors)
    nginx = next(r for r in judged["vulns"] if r["cpe"].endswith("nginx:1.18.0"))
    assert nginx["cves"][1] == {"id": "CVE-2", "score": 7.5, "severity": "high", "kev": True}  # remembered for runs without the catalogue
    assert judged["errors"] == errors
    rollup = {r["technology"]: r for r in technologies(judged)}
    assert rollup["nginx"]["kev"] == ["CVE-2"] and rollup["nginx"]["cves"] == 2


def test_findings_keep_when_they_were_first_seen():
    report = {"updated_at": "2026-10-01T00:00:00Z", "fingerprints": [endpoint("db.example.com", 3389, service="rdp")]}
    first = assessed(report, [], {}, "2026-10-01T00:00:00Z")
    again = assessed({**first, "updated_at": "2026-10-24T00:00:00Z"}, [], {}, "2026-10-24T00:00:00Z")
    f = next(f for f in again["findings"] if f["kind"] == "exposed-service")
    assert (f["first_seen"], f["last_seen"]) == ("2026-10-01T00:00:00Z", "2026-10-24T00:00:00Z")


def test_technologies_rank_edge_devices_first():
    report = {"fingerprints": [
        endpoint("a.example.com", 443, tech=[{"name": "nginx", "category": "server"}]),
        endpoint("b.example.com", 443, tech=[{"name": "nginx", "category": "server"}]),
        endpoint("vpn.example.com", 443, tech=[{"name": "FortiGate SSL-VPN", "category": "edge"}]),
        endpoint("c.example.com", 443, tech=[{"name": "PHP", "category": "language", "version": "7.4.3"}]),
    ]}
    rows = technologies(report, TODAY)
    assert [r["technology"] for r in rows] == ["FortiGate SSL-VPN", "PHP", "nginx"]
    assert rows[2]["count"] == 2 and rows[2]["hosts"] == ["a.example.com", "b.example.com"]
    assert rows[1]["eol"] == "2022-11-28"


def test_unknowns_and_real_suffixes_are_not_findings():
    failed = {"domain": "example.com", "mx": ["mx.example.com"], "spf": "v=spf1 -all", "spf_all": "-all", "dmarc": "v=DMARC1; p=reject",
              "dmarc_policy": "reject", "check_errors": ["dkim: X: SERVFAIL", "mta-sts: X: SERVFAIL"],
              "mx_health": [{"host": "mx.example.com", "starttls": None}]}
    assert kinds(derive({"posture": [failed]}, today=TODAY)) == set()
    tls = {"not_after": "2027-06-01T00:00:00Z", "days_left": 200, "matches": True, "sans": ["shop.example.ad", "dc01.corp.local"]}
    found = [f for f in derive({"fingerprints": [endpoint("a.example.com", 443, tls=tls)]}, today=TODAY) if f["kind"] == "internal-names-in-certificate"]
    assert found[0]["evidence"] == ["dc01.corp.local"]  # .ad is Andorra, not internal


def test_transfer_lock_reads_the_same_in_posture_and_findings():
    from farpoint.assess import transfer_locked
    from farpoint.output import _posture_csv_rows

    row = {"domain": "example.com", "status": ["pending transfer", "active"]}
    assert transfer_locked(row["status"]) is False
    assert _posture_csv_rows({"posture": [row]})[0]["transfer_lock"] is False
    assert ("low", "no-transfer-lock") in kinds(derive({"posture": [row]}, today=TODAY))
    assert transfer_locked(["client transfer prohibited"]) and transfer_locked(["clientTransferProhibited"])


def test_certificates_are_judged_against_today_not_the_day_they_were_fingerprinted():
    fingerprinted = {"not_after": "2026-10-01T00:00:00Z", "days_left": 45, "self_signed": False, "matches": True, "subject": "www.example.com"}
    report = {
        "fingerprints": [endpoint("www.example.com", 443, tls=fingerprinted)],
        "posture": [{"domain": "example.com", "mx_health": [{"host": "mx.example.com", "ip": "192.0.2.25", "starttls": True, "tls": fingerprinted}]}],
    }

    found = derive(report, today=TODAY)  # TODAY is past not_after

    assert ("high", "certificate-expired") in kinds(found, "www.example.com:443")
    assert ("low", "mx-certificate-invalid") in kinds(found, "mx.example.com")
    assert ("medium", "certificate-expiring") in kinds(derive(report, today=date(2026, 9, 20)), "www.example.com:443")


def test_a_scan_domain_named_like_a_test_system_does_not_make_every_host_one():
    report = {"domains": ["demo-corp.com", "test.co.uk"], "fingerprints": [
        endpoint("www.demo-corp.com", 443), endpoint("demo-corp.com", 443), endpoint("www.test.co.uk", 443),
        endpoint("staging.demo-corp.com", 443), endpoint("api.dev.test.co.uk", 443),
    ]}

    flagged = {f["target"] for f in derive(report, today=TODAY) if f["kind"] == "non-production-exposed"}

    assert flagged == {"staging.demo-corp.com", "api.dev.test.co.uk"}
