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
    assert ("high", "exposed-service") in kinds(found, "192.0.2.1:3389")
    assert ("high", "admin-interface") in kinds(found, "ci.example.com:443")
    assert {("high", "end-of-life"), ("high", "git-exposed")} <= kinds(found, "old.example.com:443")
    assert ("medium", "non-production-exposed") in kinds(found, "old.example.com")
    assert ("high", "certificate-expired") in kinds(found, "www.example.com:443")
    assert ("high", "subdomain-takeover") in kinds(found, "promo.example.com")
    assert [f["level"] for f in found] == sorted((f["level"] for f in found), key=["high", "medium", "low"].index)


def test_data_services_that_speak_http_are_still_exposed():
    assert ("high", "exposed-service") in kinds(derive({"fingerprints": [endpoint("es.example.com", 9200, service="http")]}, today=TODAY))


def test_a_router_answering_bgp_is_exposed_once_per_address():
    report = {"fingerprints": [endpoint(h, 179, service="tcp") for h in ("vpn.example.com", "intranet.example.com", "remote.example.com")]}

    exposed = [f for f in derive(report, today=TODAY) if f["kind"] == "exposed-service"]

    assert [(f["level"], f["target"]) for f in exposed] == [("medium", "192.0.2.1:179")]  # one router, however many names point at it
    assert exposed[0]["evidence"] == ["intranet.example.com", "remote.example.com", "vpn.example.com"]


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


def test_a_scan_domain_with_no_nameservers_may_be_free_to_register():
    gone = {"domain": "example.eu", "mx": [], "ns": [], "spf": None, "dmarc": None, "caa": []}
    report = {"posture": [gone], "hosts": [{"hostname": "example.eu", "sources": ["input", "m365"]}]}

    found = [f for f in derive(report, today=TODAY) if f["target"] == "example.eu"]

    assert [(f["level"], f["kind"]) for f in found] == [("high", "domain-unregistered")]  # not SPF/DMARC: there is no zone to publish them in
    assert "Microsoft 365" in found[0]["detail"]
    unknown = {**gone, "check_errors": ["dns: LifetimeTimeout: timed out"]}
    assert ("high", "domain-unregistered") not in kinds(derive({"posture": [unknown]}, today=TODAY))
    subdomain = {**gone, "domain": "eu.example.com"}  # a subdomain has no NS records of its own
    assert ("high", "domain-unregistered") not in kinds(derive({"posture": [subdomain]}, today=TODAY))


def test_a_parked_scan_domain_is_reported_once():
    parking = [{"name": "Parking page", "category": "parking", "evidence": "title: Domain registered"}]
    report = {"domains": ["example.net"], "fingerprints": [
        endpoint("example.net", 80, service="http", tech=parking), endpoint("example.net", 443, tech=parking),
        endpoint("www.example.net", 443, tech=parking),
    ]}

    parked = [f for f in derive(report, today=TODAY) if f["kind"] == "parked-domain"]

    assert [(f["level"], f["target"]) for f in parked] == [("medium", "example.net")]
    assert "www.example.net:443" in parked[0]["evidence"]
    deeper = {"domains": ["example.org"], "fingerprints": [endpoint("shop.example.org", 443, tech=parking)]}  # one site, not the domain
    assert [f for f in derive(deeper, today=TODAY) if f["kind"] == "parked-domain"] == []


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


def test_shodan_cves_on_addresses_no_longer_in_live_dns_are_not_urgent():
    latest, older = "2026-10-26T00:19:33Z", "2026-10-19T20:59:28Z"
    report = {"ips": [
        {"ip": "192.0.2.1", "sources": ["dns"], "last_seen": latest, "vulns": ["CVE-2023-44487"]},
        {"ip": "192.0.2.2", "sources": ["bbot", "dns"], "last_seen": older, "vulns": ["CVE-2023-44487"]},  # resolved once, not in the latest scan
        {"ip": "192.0.2.3", "sources": ["otx"], "last_seen": latest, "vulns": ["CVE-2023-44487"]},  # only ever in passive DNS
    ]}

    found = {f["target"]: f for f in derive(report, kev={"CVE-2023-44487": {}}, today=TODAY)}

    assert {ip: f["level"] for ip, f in found.items()} == {"192.0.2.1": "high", "192.0.2.2": "low", "192.0.2.3": "low"}
    assert "live DNS" in found["192.0.2.3"]["detail"]


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


def test_findings_are_last_seen_when_their_evidence_was_not_when_they_were_assessed():
    # 2026-10-24 fingerprinted and checked posture; 2026-10-31 a discovery-only run re-assessed
    report = {"updated_at": "2026-10-31T00:00:00Z",
              "fingerprints": [{**endpoint("db.example.com", 3389, service="rdp"), "last_seen": "2026-10-24T19:37:39Z"}],
              "posture": [{"domain": "example.com", "ns": ["ns1.example.net"], "spf": None, "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject",
                           "caa": ["x"], "last_seen": "2026-10-24T20:00:00Z"}]}

    judged = {f["kind"]: f for f in assessed(report, [], {}, "2026-10-31T00:00:00Z")["findings"]}

    assert (judged["exposed-service"]["first_seen"], judged["exposed-service"]["last_seen"]) == ("2026-10-24T19:37:39Z", "2026-10-24T19:37:39Z")
    assert judged["spf-missing"]["last_seen"] == "2026-10-24T20:00:00Z"
    undated = assessed({"fingerprints": [endpoint("db.example.com", 3389, service="rdp")]}, [], {}, "2026-10-31T00:00:00Z")["findings"]
    assert [f["last_seen"] for f in undated] == ["2026-10-31T00:00:00Z"]  # evidence with no date: seen when assessed


def test_a_parked_scan_domain_still_in_the_microsoft_365_tenant_is_high():
    parking = [{"name": "Parking page", "category": "parking", "evidence": "title: Domain registered | Dynadot"}]
    report = {"domains": ["example.net"], "fingerprints": [endpoint("example.net", 443, tech=parking)],
              "hosts": [{"hostname": "example.net", "sources": ["input", "m365"]}]}

    parked = [f for f in derive(report, today=TODAY) if f["kind"] == "parked-domain"]

    assert [(f["level"], f["target"]) for f in parked] == [("high", "example.net")]
    assert "Microsoft 365" in parked[0]["detail"]


def test_spf_at_the_lookup_limit_is_one_include_from_breaking():
    at_limit = {"domain": "example.com", "spf": "v=spf1 include:a include:b ~all", "spf_all": "~all", "spf_lookups": 10,
                "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject"}
    assert ("low", "spf-at-lookup-limit") in kinds(derive({"posture": [at_limit]}, today=TODAY), "example.com")
    assert "spf-at-lookup-limit" not in {f["kind"] for f in derive({"posture": [{**at_limit, "spf_lookups": 9}]}, today=TODAY)}
    over = {f["kind"] for f in derive({"posture": [{**at_limit, "spf_lookups": 11}]}, today=TODAY)}
    assert "spf-too-many-lookups" in over and "spf-at-lookup-limit" not in over


def test_a_providers_certificate_on_a_name_pointed_at_the_provider_is_its_to_renew():
    intune = {"not_after": "2026-11-10T00:00:00Z", "matches": False, "subject": "NA01.manage.microsoft.com", "sans": ["manage.microsoft.com"]}
    parked = {"not_after": "2026-11-10T00:00:00Z", "matches": False, "subject": "*.dynadot.com", "sans": ["*.dynadot.com"]}
    report = {"fingerprints": [endpoint("enterpriseenrollment.example.com", 443, tls=intune), endpoint("example.com", 443, tls=parked)],
              "hosts": [{"hostname": "enterpriseenrollment.example.com", "cnames": ["enterpriseenrollment-s.manage.microsoft.com"]},
                        {"hostname": "example.com", "cnames": []}]}

    found = derive(report, today=TODAY)

    assert kinds(found, "enterpriseenrollment.example.com:443") == {("low", "certificate-mismatch")}  # not expiring: the provider renews it
    assert {("medium", "certificate-mismatch"), ("medium", "certificate-expiring")} <= kinds(found, "example.com:443")


def test_a_short_lived_automated_certificate_is_only_expiring_when_renewal_has_failed():
    def cert(not_before, not_after):
        return {"not_before": not_before, "not_after": not_after, "matches": True, "subject": "www.example.com"}
    report = lambda tls: {"fingerprints": [endpoint("www.example.com", 443, tls=tls)]}

    assert derive(report(cert("2026-08-27T00:00:00Z", "2026-11-15T00:00:00Z")), today=TODAY) == []  # 90-day certificate, 22 days left: renews at 30
    assert ("medium", "certificate-expiring") in kinds(derive(report(cert("2026-08-01T00:00:00Z", "2026-10-29T00:00:00Z")), today=TODAY))
    assert ("medium", "certificate-expiring") in kinds(derive(report(cert("2025-11-15T00:00:00Z", "2026-11-15T00:00:00Z")), today=TODAY))


def test_one_wildcard_certificate_is_one_finding_however_many_names_serve_it():
    wildcard = {"not_after": "2027-06-01T00:00:00Z", "matches": True, "wildcard": True, "subject": "*.example.com"}
    report = {"fingerprints": [endpoint(h, 443, tls=wildcard) for h in ("a.example.com", "b.example.com")]}

    found = [f for f in derive(report, today=TODAY) if f["kind"] == "wildcard-certificate"]

    assert [(f["level"], f["target"]) for f in found] == [("low", "*.example.com")]
    assert found[0]["evidence"] == ["a.example.com:443", "b.example.com:443"]


def test_managed_file_transfer_is_a_first_target():
    mft = [{"name": "Axway SecureTransport", "category": "file-transfer", "evidence": "cname: acme-mft.axwaycloud.co"}]
    found = derive({"fingerprints": [endpoint("mft.example.com", 443, tech=mft)]}, today=TODAY)
    assert ("high", "file-transfer") in kinds(found, "mft.example.com:443")
    rows = technologies({"fingerprints": [endpoint("mft.example.com", 443, tech=mft), endpoint("a.example.com", 443, tech=[{"name": "nginx", "category": "server"}]),
                                          endpoint("vpn.example.com", 443, tech=[{"name": "FortiGate SSL-VPN", "category": "edge"}])]}, TODAY)
    assert [r["technology"] for r in rows] == ["FortiGate SSL-VPN", "Axway SecureTransport", "nginx"]


def test_a_name_pointed_within_the_organisations_own_domain_still_owns_its_certificate():
    own = {"not_after": "2026-11-10T00:00:00Z", "matches": True, "wildcard": True, "subject": "*.example.com"}
    report = {"fingerprints": [endpoint("www.example.com", 443, tls=own)], "hosts": [{"hostname": "www.example.com", "cnames": ["lb.example.com"]}]}
    assert ("medium", "certificate-expiring") in kinds(derive(report, today=TODAY), "www.example.com:443")


def test_a_providers_wildcard_certificate_is_not_the_organisations_wildcard():
    theirs = {"not_after": "2027-06-01T00:00:00Z", "matches": False, "wildcard": True, "subject": "*.msappproxy.net"}
    report = {"fingerprints": [endpoint("apps.example.com", 443, tls=theirs)], "hosts": [{"hostname": "apps.example.com", "cnames": ["apps-acme.msappproxy.net"]}]}
    assert "wildcard-certificate" not in {f["kind"] for f in derive(report, today=TODAY)}
