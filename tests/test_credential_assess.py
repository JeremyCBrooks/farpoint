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


def level_for(**fields):
    found = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar([exposure_row(**fields)])))
    assert len(found) == 1
    return found[0]


@pytest.mark.parametrize("service,port,expected", [("vpn.example.com", 443, "high"), ("sts.example.com", None, "high"), ("example.okta.com", None, "high"),
    ("vpn.example.com", None, "high"), ("example.zendesk.com", None, "medium"), ("dns-only.example.com", None, "medium"),
    ("old.example.com", 443, "medium"), ("login.microsoftonline.com", None, "medium"), ("new.example.com", None, "medium"),
    ("vpn.example.com", 8443, "medium")])
def test_fresh_theft_is_high_only_with_current_positive_service_evidence(service, port, expected):
    assert level_for(service_host=service, service_port=port, event_at="2026-10-01")["level"] == expected


def test_a_dns_only_match_suggests_fingerprinting():
    assert "--fingerprint could confirm the service" in level_for(service_host="dns-only.example.com")["detail"]


def test_a_missing_port_never_becomes_443():
    f = level_for(service_host="vpn.example.com")
    assert f["target"] == "vpn.example.com"


def test_a_reported_port_that_was_not_observed_is_not_the_host():
    f = level_for(service_host="vpn.example.com", service_port=8443)
    assert f["target"] == "vpn.example.com:8443"
    assert "reported port not observed" in f["detail"]


@pytest.mark.parametrize("host", ["sts.example.com", "example.okta.com"])
def test_host_only_identity_or_tenant_evidence_does_not_confirm_an_explicit_port(host):
    f = level_for(service_host=host, service_port=8443)
    assert f["level"] == "medium"
    assert f["target"] == f"{host}:8443"
    assert "reported port not observed" in f["detail"]


def test_a_closed_federation_endpoint_is_not_high_after_merge(tmp_path):
    from farpoint.models import ServiceRecord

    inv = sample_inventory()
    inv.identity["example.com"] = {"domain": "example.com", "provider": "adfs", "sign_in_host": "sts.example.com"}
    inv.services["sts.example.com:8443"] = ServiceRecord("sts.example.com", "93.184.216.34", 8443, service="https")
    evidence = batch([exposure_row(service_host="sts.example.com", service_port=8443)], AT)
    first = write_outputs(inv, tmp_path, AT, credentials=evidence, assess=judge)
    assert creds(first["findings"])[0]["level"] == "high"
    closed = sample_inventory()
    closed.closed.add("sts.example.com:8443")
    report = write_outputs(closed, tmp_path, LATER, assess=judge)
    [finding] = creds(report["findings"])
    assert finding["level"] == "medium" and finding["target"] == "sts.example.com:8443"


def test_a_shared_provider_sign_in_page_is_context_even_when_federated():
    infra = {**INFRA, "identity": [{"domain": "example.com", "provider": "google", "sign_in_host": "accounts.google.com", "last_seen": SEEN}]}
    rows = [exposure_row(service_host="accounts.google.com")]
    [f] = creds(derive(infra, today=TODAY, credentials=credential_sidecar(rows)))
    assert f["level"] == "medium" and f["target"] == "example.com"


@pytest.mark.parametrize("event_at,basis,expected", [("2026-08-03", "compromised", "high"), ("2026-08-02", "compromised", "medium"),
    ("2026-12-01", "compromised", "medium"), (None, None, "medium"), ("2026-10-01", "uploaded", "medium"), ("2026-10-01", "published", "medium")])
def test_recent_theft_boundaries(event_at, basis, expected):
    assert level_for(service_host="vpn.example.com", service_port=443, event_at=event_at, event_date_basis=basis)["level"] == expected


def test_breach_wide_password_classes_stay_low_and_account_specific_ones_are_medium():
    base = dict(operation="breaches", exposure_type="breach", source_name="ExampleBreach", event_date_basis="breach")
    assert level_for(secret_evidence="dataset", **base)["level"] == "low"
    assert level_for(secret_evidence="record", secret_types=["password-hash"], **base)["level"] == "medium"


def test_findings_group_identities_and_never_name_them():
    rows = [exposure_row(service_host="vpn.example.com", service_port=443),
            exposure_row(service_host="vpn.example.com", service_port=443, source_event_id="log-2"),
            exposure_row(identity="bob@example.com", service_host="vpn.example.com", service_port=443),
            exposure_row(identity="cust@gmail.com", query_kind="website", service_host="vpn.example.com", service_port=443, provider_relationship="customer")]
    found = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(rows)))
    work = next(f for f in found if f["id"].endswith("|workforce-associated"))
    assert work["detail"].startswith("2 workforce-associated identities (3 records)") and work["level"] == "high"
    assert {f["id"] for f in found} == {"credential-theft|vpn.example.com:443|example.com|workforce-associated",
                                        "credential-theft|vpn.example.com:443|example.com|customer-reported"}
    assert not any(s in json.dumps(found) for s in ("alice", "bob", "cust@", "gmail"))  # "cust" alone is in "customer-reported"


def test_overlapping_providers_do_not_inflate_identity_counts():
    rows = [exposure_row(), exposure_row(provider="other-intel")]
    [f] = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(rows)))
    assert f["detail"].startswith("1 workforce-associated identity (2 records)")


def test_an_identity_spelt_with_another_domain_case_is_one_identity():
    rows = [exposure_row(identity="E@Example.com"), exposure_row(provider="other-intel", identity="E@example.com.")]
    [f] = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(rows)))
    assert f["detail"].startswith("1 workforce-associated identity (2 records)")


def test_each_scope_domain_gets_its_own_finding_on_a_shared_asset():
    infra = {**INFRA, "domains": ["example.com", "example.org"]}
    rows = [exposure_row(service_host="vpn.example.com", service_port=443),
            exposure_row(scope_domain="example.org", identity="b@example.org", service_host="vpn.example.com", service_port=443)]
    found = creds(derive(infra, today=TODAY, credentials=credential_sidecar(rows, domains=("example.com", "example.org"))))
    assert {f["id"] for f in found} == {"credential-theft|vpn.example.com:443|example.com|workforce-associated",
                                        "credential-theft|vpn.example.com:443|example.org|workforce-associated"}
    assert {f["detail"].split(";")[0] for f in found} == {"1 workforce-associated identity (1 record) for example.com",
                                                         "1 workforce-associated identity (1 record) for example.org"}


def test_a_stealer_log_name_never_reaches_findings_but_a_breach_name_does():
    rows = [exposure_row(source_name="VICTIM-LAPTOP-jdoe"),
            exposure_row(identity="b@example.com", operation="breaches", exposure_type="breach", source_name="ExampleBreach",
                         event_date_basis="breach")]
    found = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar(rows)))
    assert "VICTIM" not in json.dumps(found)
    assert any("ExampleBreach" in f["evidence"] for f in found)


def test_a_partial_check_is_shown_beside_the_finding():
    f = level_for(service_host="vpn.example.com", service_port=443)
    assert "latest acme-intel/email/stealers check: partial" in f["detail"]


def test_findings_are_dated_by_credential_retrieval_not_infrastructure():
    f = level_for(service_host="vpn.example.com", service_port=443)
    assert f["seen"] == "2026-10-25T00:00:00Z"


def test_an_aggregate_is_a_low_summary_finding():
    summary = {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers",
               "metric": "accounts", "count": 42}
    [f] = creds(derive(INFRA, today=TODAY, credentials=credential_sidecar([], summaries=[summary])))
    assert (f["level"], f["kind"], f["target"]) == ("low", "credential-summary", "example.com")
    assert f["detail"].startswith("acme-intel reports 42 for accounts") and "not a list of confirmed accounts" in f["detail"]


def test_old_theft_stays_old_after_refetch():
    row = exposure_row(service_host="vpn.example.com", service_port=443, event_at="2026-06-01")
    again = merge_credentials(credential_sidecar([row]), batch([row], "2026-10-31T00:00:00Z"))
    [f] = creds(derive(INFRA, today=TODAY, credentials=again))
    assert f["level"] == "medium" and "theft older than 90 days" in f["detail"]


def judge(r, c):
    return assessed(r, [], {}, AT, credentials=c)


def csv_credential_rows(tmp_path):
    return [r for r in read_csv(tmp_path / "findings.csv") if r["kind"].startswith("credential-")]


def test_new_evidence_makes_credential_findings_stale_until_reassessed(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch([exposure_row()], AT))
    assert any(r["kind"].startswith("credential-") for r in read_csv(tmp_path / "findings.csv"))
    report = write_outputs(sample_inventory(), tmp_path, LATER, credentials=batch([exposure_row(identity="b@example.com")], LATER))
    assert credential_status(report, load_credentials(tmp_path)) == "stale"
    assert not any(r["kind"].startswith("credential-") for r in read_csv(tmp_path / "findings.csv"))
    assert any(f["kind"].startswith("credential-") for f in report["findings"])      # snapshot kept in assets.json
    rewrite(tmp_path, judge)
    assert credential_status(load_report(tmp_path), load_credentials(tmp_path)) == "current"


def test_a_deleted_sidecar_makes_old_findings_stale_and_reassessment_clears_them(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch([exposure_row()], AT))
    (tmp_path / "credentials.json").unlink()
    report = rewrite(tmp_path, lambda r, c: r)
    assert credential_status(report, load_credentials(tmp_path)) == "stale" and creds(report["findings"])
    assert not csv_credential_rows(tmp_path)
    report = rewrite(tmp_path, judge)
    assert credential_status(report, load_credentials(tmp_path)) == "none" and not creds(report["findings"])


def test_an_unreadable_sidecar_keeps_findings_as_an_unavailable_snapshot(tmp_path):
    first = write_outputs(sample_inventory(), tmp_path, AT, assess=judge, credentials=batch([exposure_row()], AT))
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


def _employee(host, n=1, **fields):
    return exposure_row(provider="hudsonrock-osint", operation="employee-urls", identity=None, provider_relationship="Employee",
                        service_host=host, occurrences=n, secret_evidence="dataset", event_at=None, event_date_basis=None, **fields)


def _snapshot_check(at, status="complete", provider="hudsonrock-osint", operation="employee-urls"):
    from conftest import check_row
    return check_row(provider=provider, operation=operation, status=status, checked_at=at)


def _sidecar(*batches):
    """Merge successive live (at, exposures, checks) batches the way successive runs would."""
    data = None
    for at, exposures, checks in batches:
        data = merge_credentials(data, batch(exposures, at, checks=checks))
    return data


LATEST = "2026-11-03T00:00:00Z"


def test_identityless_findings_say_identities_were_not_reported_and_show_occurrences():
    data = _sidecar((AT, [_employee("vpn.example.com", 12)], [_snapshot_check(AT)]))
    (f,) = [f for f in creds(derive(INFRA, today=TODAY, credentials=data)) if f["kind"] == "credential-theft"]
    assert "0 " not in f["detail"] and "identities not reported by provider" in f["detail"]
    assert "seen 12 times" in f["detail"] and f["level"] == "medium"  # a fresh fingerprint, but no theft date


@pytest.mark.parametrize("later_failure", [False, True])
def test_only_rows_from_the_latest_complete_snapshot_produce_findings(later_failure):
    runs = [(AT, [_employee("vpn.example.com")], [_snapshot_check(AT)]),
            (LATER, [_employee("sts.example.com")], [_snapshot_check(LATER)])]
    if later_failure:
        runs.append((LATEST, [], [_snapshot_check(LATEST, status="failed")]))
    found = creds(derive(INFRA, today=TODAY, credentials=_sidecar(*runs)))
    assert [f["target"] for f in found] == ["sts.example.com"]


def test_a_latest_all_zero_snapshot_retires_older_findings():
    data = _sidecar((AT, [_employee("vpn.example.com")], [_snapshot_check(AT)]), (LATER, [], [_snapshot_check(LATER)]))
    assert creds(derive(INFRA, today=TODAY, credentials=data)) == []
    assert len(data["exposures"]) == 1  # kept as history


def test_the_snapshot_rule_does_not_retire_other_providers_rows():
    accumulating = exposure_row(service_host="vpn.example.com")
    data = _sidecar((AT, [accumulating], [_snapshot_check(AT, provider="acme-intel", operation="stealers")]),
                    (LATER, [], [_snapshot_check(LATER, provider="acme-intel", operation="stealers")]))
    assert [f["target"] for f in creds(derive(INFRA, today=TODAY, credentials=data))] == ["vpn.example.com"]
