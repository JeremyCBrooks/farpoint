import json
from datetime import date

import pytest
from conftest import AT, LATER, batch, credential_sidecar, exposure_row, read_csv, sample_inventory

from farpoint.assess import assessed, derive
from farpoint.credential_assess import credential_status
from farpoint.credential_store import load_credentials, merge_credentials
from farpoint.output import load_report, rewrite, write_outputs

TODAY = date(2026, 11, 1)
SEEN = "2026-10-20T00:00:00Z"
INFRA = {
    "domains": ["example.com"],
    "hosts": [{"hostname": f"{h}.example.com"} for h in ("vpn", "dns-only", "old", "sts")],
    "fingerprints": [
        {"endpoint": "vpn.example.com:443", "hostname": "vpn.example.com", "port": 443, "service": "https", "last_seen": SEEN},
        {"endpoint": "old.example.com:443", "hostname": "old.example.com", "port": 443, "service": "https", "last_seen": "2026-05-01T00:00:00Z"},
    ],
    "identity": [{"domain": "example.com", "provider": "adfs", "sign_in_host": "sts.example.com", "last_seen": SEEN}],
    "tenants": [
        {"tenant": "example.okta.com", "vendor": "Okta", "domain": "example.com", "tie": "cname", "last_seen": SEEN},
        {"tenant": "example.zendesk.com", "vendor": "Zendesk", "domain": "example.com", "tie": "name", "last_seen": SEEN},
    ],
}


def creds(report_rows):
    return [f for f in report_rows if f["kind"].startswith("credential-")]


def level_for(tmp_path, **fields):
    found = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(tmp_path, [exposure_row(**fields)])))
    assert len(found) == 1
    return found[0]


@pytest.mark.parametrize("service,port,expected", [("vpn.example.com", 443, "high"), ("sts.example.com", None, "high"), ("example.okta.com", None, "high"),
    ("vpn.example.com", None, "high"), ("example.zendesk.com", None, "medium"), ("dns-only.example.com", None, "medium"),
    ("old.example.com", 443, "medium"), ("login.microsoftonline.com", None, "medium"), ("new.example.com", None, "medium")])
def test_fresh_theft_is_high_only_with_current_positive_service_evidence(tmp_path, service, port, expected):
    assert level_for(tmp_path, service_host=service, service_port=port, event_at="2026-10-01")["level"] == expected


def test_a_dns_only_match_suggests_fingerprinting(tmp_path):
    assert "--fingerprint could confirm the service" in level_for(tmp_path, service_host="dns-only.example.com")["detail"]


def test_a_missing_port_never_becomes_443(tmp_path):
    f = level_for(tmp_path, service_host="vpn.example.com")
    assert f["target"] == "vpn.example.com"


@pytest.mark.parametrize("event_at,basis,expected", [("2026-08-03", "compromised", "high"), ("2026-08-02", "compromised", "medium"),
    ("2026-12-01", "compromised", "medium"), (None, None, "medium"), ("2026-10-01", "uploaded", "medium"), ("2026-10-01", "published", "medium")])
def test_recent_theft_boundaries(tmp_path, event_at, basis, expected):
    assert level_for(tmp_path, service_host="vpn.example.com", service_port=443, event_at=event_at, event_date_basis=basis)["level"] == expected


def test_breach_wide_password_classes_stay_low_and_account_specific_ones_are_medium(tmp_path):
    base = dict(operation="breaches", exposure_type="breach", source_name="ExampleBreach", event_date_basis="breach")
    assert level_for(tmp_path, secret_evidence="dataset", **base)["level"] == "low"
    assert level_for(tmp_path, secret_evidence="record", secret_types=["password-hash"], **base)["level"] == "medium"


def test_findings_group_identities_and_never_name_them(tmp_path):
    rows = [exposure_row(service_host="vpn.example.com", service_port=443),
            exposure_row(service_host="vpn.example.com", service_port=443, source_event_id="log-2"),
            exposure_row(identity="bob@example.com", service_host="vpn.example.com", service_port=443),
            exposure_row(identity="cust@gmail.com", query_kind="website", service_host="vpn.example.com", service_port=443, provider_relationship="customer")]
    found = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(tmp_path, rows)))
    work = next(f for f in found if f["id"].endswith("|workforce-associated"))
    assert work["detail"].startswith("2 workforce-associated identities (3 records)") and work["level"] == "high"
    assert {f["id"] for f in found} == {"credential-theft|vpn.example.com:443|workforce-associated", "credential-theft|vpn.example.com:443|customer-reported"}
    assert not any(s in json.dumps(found) for s in ("alice", "bob", "cust@", "gmail"))  # "cust" alone is in "customer-reported"


def test_overlapping_providers_do_not_inflate_identity_counts(tmp_path):
    rows = [exposure_row(), exposure_row(provider="other-intel")]
    [f] = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(tmp_path, rows)))
    assert f["detail"].startswith("1 workforce-associated identity (2 records)")


def test_a_partial_check_is_shown_beside_the_finding(tmp_path):
    f = level_for(tmp_path, service_host="vpn.example.com", service_port=443)
    assert "latest acme-intel/email/stealers check: partial" in f["detail"]


def test_findings_are_dated_by_credential_retrieval_not_infrastructure(tmp_path):
    f = level_for(tmp_path, service_host="vpn.example.com", service_port=443)
    assert f["seen"] == "2026-10-25T00:00:00Z"


def test_an_aggregate_is_a_low_summary_finding(tmp_path):
    summary = {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers",
               "metric": "accounts", "count": 42}
    [f] = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(tmp_path, [], summaries=[summary])))
    assert (f["level"], f["kind"], f["target"]) == ("low", "credential-summary", "example.com")
    assert f["detail"].startswith("acme-intel reports 42 for accounts") and "not a list of confirmed accounts" in f["detail"]


def test_old_theft_stays_old_after_refetch(tmp_path):
    row = exposure_row(service_host="vpn.example.com", service_port=443, event_at="2026-06-01")
    again = merge_credentials(credential_sidecar(tmp_path, [row]), batch(tmp_path, [row], "2026-10-31T00:00:00Z"))
    [f] = creds(derive(INFRA, today=TODAY, credentials=again))
    assert f["level"] == "medium" and "theft older than 90 days" in f["detail"]


def judge(r, c):
    return assessed(r, [], {}, AT, credentials=c)


def csv_credential_rows(tmp_path):
    return [r for r in read_csv(tmp_path / "findings.csv") if r["kind"].startswith("credential-")]


def test_new_evidence_makes_credential_findings_stale_until_reassessed(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch(tmp_path, [exposure_row()], AT))
    assert any(r["kind"].startswith("credential-") for r in read_csv(tmp_path / "findings.csv"))
    report = write_outputs(sample_inventory(), tmp_path, LATER, credentials=batch(tmp_path, [exposure_row(identity="b@example.com")], LATER))
    assert credential_status(report, load_credentials(tmp_path)) == "stale"
    assert not any(r["kind"].startswith("credential-") for r in read_csv(tmp_path / "findings.csv"))
    assert any(f["kind"].startswith("credential-") for f in report["findings"])      # snapshot kept in assets.json
    rewrite(tmp_path, judge)
    assert credential_status(load_report(tmp_path), load_credentials(tmp_path)) == "current"


def test_a_deleted_sidecar_makes_old_findings_stale_and_reassessment_clears_them(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch(tmp_path, [exposure_row()], AT))
    (tmp_path / "credentials.json").unlink()
    report = rewrite(tmp_path, lambda r, c: r)
    assert credential_status(report, load_credentials(tmp_path)) == "stale" and creds(report["findings"])
    assert not csv_credential_rows(tmp_path)
    report = rewrite(tmp_path, judge)
    assert credential_status(report, load_credentials(tmp_path)) == "none" and not creds(report["findings"])


def test_an_unreadable_sidecar_keeps_findings_as_an_unavailable_snapshot(tmp_path):
    first = write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch(tmp_path, [exposure_row()], AT))
    before = creds(first["findings"])
    (tmp_path / "credentials.json").write_text("{", encoding="utf-8")
    report = rewrite(tmp_path, lambda r, c: assessed(r, [], {}, LATER, credentials=c))
    assert credential_status(report, load_credentials(tmp_path)) == "unavailable"
    assert report["credential_assessment"] == {"status": "unavailable", "revision": first["credential_assessment"]["revision"], "assessed_at": LATER}
    assert before and creds(report["findings"]) == before  # kept verbatim, first_seen/last_seen included
    assert not csv_credential_rows(tmp_path)


def test_an_old_inventory_without_a_sidecar_is_unchanged(tmp_path):     # Review Focus 4
    write_outputs(sample_inventory(), tmp_path, AT, assess=lambda r, c: assessed(r, [], {}, AT, credentials=c))
    assert not list(tmp_path.glob("credential*")) and credential_status(load_report(tmp_path), load_credentials(tmp_path)) == "none"
