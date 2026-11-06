import json

import pytest
from conftest import AT, batch, check_row, exposure_row, summary_row

from farpoint.credential_sources.base import collect_credentials
from farpoint.credentials import STORED_EXPOSURE_ORDER, CredentialBatch


class RowsProvider:
    """A provider that answers with the given rows, whatever they hold."""

    name = "acme-intel"
    kinds = frozenset({"email", "website"})

    def __init__(self, exposures=(), summaries=()):
        self.rows = {"exposures": list(exposures), "summaries": list(summaries)}

    def operations(self, kinds):
        return [(k, "stealers") for k in sorted(kinds) if k in self.kinds]

    def collect(self, domain, kinds):
        return self.rows


def _collected(*exposures, summaries=()):
    return collect_credentials([RowsProvider(exposures, summaries)], ["example.com"], ["email"], AT)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("newer_status,older_status", [("complete", "failed"), ("failed", "complete")])
def test_checks_follow_time_and_keep_last_success(reverse, newer_status, older_status):
    newer = check_row(status=newer_status, checked_at="2026-10-30T00:00:00Z")
    older = check_row(status=older_status, checked_at="2026-10-01T00:00:00Z")
    [check] = batch(checks=[older, newer] if reverse else [newer, older], kinds=("email",)).checks
    assert check["status"] == newer_status
    assert check["completed_at"] == "2026-10-30T00:00:00Z"
    assert check["last_complete_at"] == ("2026-10-30T00:00:00Z" if newer_status == "complete" else "2026-10-01T00:00:00Z")


def test_a_provider_row_with_an_unknown_field_fails_the_check_and_keeps_nothing():
    rows = _collected(exposure_row(), exposure_row(password="SENTINEL-PW"))
    assert rows["exposures"] == [] and [(c["status"], c["error"]) for c in rows["checks"]] == [("failed", "schema")]
    assert "SENTINEL" not in json.dumps(rows)


@pytest.mark.parametrize("bad", [{"exposure_type": "rumour"}, {"secret_types": ["password", "mystery"]},
                                 {"secret_evidence": "maybe"}, {"event_date_basis": "vibes"}, {"event_at": "last tuesday"},
                                 {"service_port": 70000}, {"provider": ""}, {"reference": None}])
def test_bad_enumerations_and_types_fail_the_check(bad):
    rows = _collected(exposure_row(**bad))
    assert rows["exposures"] == [] and rows["checks"][0]["error"] == "schema"


@pytest.mark.parametrize("bad", [{"metric": "accounts", "count": -1}, {"metric": "accounts", "count": True}, {"count": 3, "metric": None}])
def test_bad_summaries_fail_the_check(bad):
    rows = _collected(summaries=[summary_row(**bad)])
    assert rows["summaries"] == [] and rows["checks"][0]["error"] == "schema"


def test_stored_batches_round_trip_and_reject_unknown_fields():
    stored = exposure_row(id="acme-intel:1", relationship="workforce-associated", identity_domain="example.com",
                          first_seen=AT, last_seen=AT)
    b = CredentialBatch(AT, (stored,))
    assert CredentialBatch.from_json(b.to_json()) == b
    doc = b.to_json()
    doc["exposures"][0]["password"] = "SENTINEL-PW"
    with pytest.raises(ValueError) as exc:
        CredentialBatch.from_json(doc)
    assert "SENTINEL" not in str(exc.value) and "exposures[0]" in str(exc.value)
    for bad in (True, 1.0, 2):
        with pytest.raises(ValueError):
            CredentialBatch.from_json({**b.to_json(), "schema_version": bad})


def _rejected(*rows, kinds=("email", "website")):
    from farpoint.credential_batch import build_batch

    return build_batch({"exposures": list(rows), "summaries": [], "checks": []}, ["example.com"], set(kinds), AT)


def test_email_scope_uses_label_boundaries_and_keeps_identity_as_supplied():
    built, rejected = _rejected(exposure_row(identity="Bob@Example.COM."), exposure_row(identity="x@example.com.evil.net"),
                                exposure_row(identity="x@notexample.com"), exposure_row(identity="dev@eu.example.com"), exposure_row(identity=None))
    assert sorted(e["identity"] for e in built.exposures) == ["Bob@Example.COM.", "dev@eu.example.com"]
    assert {e["identity_domain"] for e in built.exposures} == {"example.com", "eu.example.com"}
    assert rejected == 3


def test_without_website_a_customer_on_an_in_scope_host_is_never_kept():
    row = exposure_row(query_kind="email", identity="cust@gmail.com", service_host="shop.example.com")
    built, rejected = _rejected(row, kinds=("email",))
    assert built.exposures == () and rejected == 1


def test_a_website_row_is_dropped_when_website_is_not_enabled():
    row = exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.com")
    built, rejected = _rejected(row, kinds=("email",))
    assert built.exposures == () and rejected == 1


def test_website_rows_need_an_in_scope_service_and_label_relationships():
    built, rejected = _rejected(
        exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.com", provider_relationship="User"),
        exposure_row(query_kind="website", identity="bob@example.com", service_host="shop.example.com", provider_relationship="customer"),
        exposure_row(query_kind="website", identity="anon", service_host="shop.example.com"),
        exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.org"))
    assert sorted(e["relationship"] for e in built.exposures) == ["customer-reported", "service-account-unknown", "workforce-associated"]
    assert {e["provider_relationship"] for e in built.exposures} >= {"User", "customer"} and rejected == 1


def test_service_urls_lose_secrets_and_never_gain_a_port():
    b = batch([exposure_row(service_host="https://SENTINEL-USER:SENTINEL-PW@vpn.example.com/login?token=SENTINEL-TOKEN#SENTINEL"),
               exposure_row(identity="b@example.com", service_host="sts.example.com:8443"),
               exposure_row(identity="c@example.com", reference="https://intel.example.net/case/9?apikey=SENTINEL-KEY")])
    rows = {e["identity"]: e for e in b.exposures}
    assert (rows["alice@example.com"]["service_host"], rows["alice@example.com"]["service_port"]) == ("vpn.example.com", None)
    assert (rows["b@example.com"]["service_host"], rows["b@example.com"]["service_port"]) == ("sts.example.com", 8443)
    assert rows["c@example.com"]["reference"] == "https://intel.example.net/case/9"
    assert "SENTINEL" not in json.dumps(b.to_json())


@pytest.mark.parametrize("raw,stored", [("2026-10-01", "2026-10-01"), ("2026-10-01T12:00:00+02:00", "2026-10-01T10:00:00Z"),
                                        ("2026-10-01T12:00:00", "2026-10-01T12:00:00")])
def test_event_times_keep_their_precision(raw, stored):
    assert batch([exposure_row(event_at=raw)]).exposures[0]["event_at"] == stored


def test_ids_survive_corrections_and_retrieval_time_but_not_identity_changes():
    a = batch([exposure_row()], "2026-10-01T00:00:00Z")
    b = batch([exposure_row(exposure_type="phishing", event_at="2026-09-01", malware_family="Lumma")], "2026-11-01T00:00:00Z")
    c = batch([exposure_row(identity="ALICE@example.com")])
    d = batch([exposure_row(provider_record_id="r-1")])
    assert a.exposures[0]["id"] == b.exposures[0]["id"] != c.exposures[0]["id"]
    assert d.exposures[0]["id"] == "acme-intel:r-1" and ":v1:" in a.exposures[0]["id"]


def test_only_the_domain_of_an_identity_is_case_folded_for_its_id():
    a = batch([exposure_row(identity="alice@example.com")])
    b = batch([exposure_row(identity="alice@EXAMPLE.com.")])
    assert a.exposures[0]["id"] == b.exposures[0]["id"]


def test_rows_without_a_check_are_partial_and_declared_checks_are_kept():
    rows = [exposure_row(), exposure_row(identity="b@example.com", operation="breaches", exposure_type="breach", source_name="ExampleBreach")]
    b = batch(rows, checks=[check_row(operation="breaches", checked_at="2026-10-30")], kinds=("email",))
    by_op = {c["operation"]: c for c in b.checks}
    assert by_op["stealers"]["status"] == "partial" and by_op["stealers"]["records"] == 1
    assert by_op["breaches"]["status"] == "complete" and by_op["breaches"]["completed_at"] == "2026-10-30"
    assert by_op["breaches"]["last_complete_at"] == "2026-10-30" and by_op["breaches"]["records"] == 1
    assert by_op["stealers"].get("last_complete_at") is None
    assert {c["origin"] for c in b.checks} == {"live"}


def test_summaries_get_a_partial_check_and_retrieval_times():
    b = batch([], summaries=[summary_row(metric="accounts")])
    assert b.summaries[0]["first_seen"] == AT == b.summaries[0]["last_seen"]
    assert [(c["status"], c["records"]) for c in b.checks] == [("partial", 0)]


def test_a_scope_domain_outside_the_scan_is_rejected():
    built, rejected = _rejected(exposure_row(scope_domain="example.org", identity="a@example.org"))
    assert built.exposures == () and rejected == 1


def test_batches_set_seen_times_dedupe_by_id_and_validate_retrieved_at():
    first = exposure_row(provider_record_id="r-1", exposure_type="breach")
    last = exposure_row(provider_record_id="r-1", exposure_type="phishing", source_observed_at="2026-10-20")
    b = batch([first, last], at="2026-11-01T02:00:00+02:00")
    assert len(b.exposures) == 1 and b.exposures[0]["exposure_type"] == "phishing"
    assert b.exposures[0]["first_seen"] == b.exposures[0]["last_seen"] == b.retrieved_at == "2026-11-01T00:00:00Z"
    assert b.exposures[0]["source_observed_at"] == "2026-10-20"
    with pytest.raises(ValueError):
        batch([], at="yesterday")


def test_declared_checks_for_other_domains_are_dropped():
    b = batch([exposure_row()], checks=[check_row(), check_row(scope_domain="example.org")])
    assert [c["scope_domain"] for c in b.checks] == ["example.com"]


def test_a_reference_without_a_scheme_never_keeps_a_secret():
    refs = ["intel.example.net/case/9?apikey=SENTINEL", "intel.example.net/case/9#SENTINEL", "user:SENTINEL@intel.example.net/case/9"]
    for ref in refs:
        b = batch([exposure_row(reference=ref)])
        assert "SENTINEL" not in json.dumps(b.exposures[0]) and b.exposures[0]["reference"] == "intel.example.net/case/9"


def test_stored_rows_have_a_fixed_key_order_and_no_raw_checked_at():
    b = batch([exposure_row()], checks=[check_row(checked_at="2026-10-30")])
    [row], [chk] = b.exposures, b.checks
    assert list(row)[0] == "id" and list(row) == [k for k in STORED_EXPOSURE_ORDER]
    assert "checked_at" not in chk and chk["completed_at"] == "2026-10-30"
    CredentialBatch.from_json(b.to_json())  # the stored form is accepted back


def test_an_identityless_employee_row_on_an_in_scope_host_is_workforce():
    row = exposure_row(identity=None, provider_relationship="Employee", service_host="https://vpn.example.com/x?t=1",
                       secret_evidence="dataset", event_at=None, event_date_basis=None, occurrences=12)
    built, rejected = _rejected(row, kinds=("email",))
    (stored,) = built.exposures
    assert rejected == 0 and stored["relationship"] == "workforce-associated"
    assert stored["service_host"] == "vpn.example.com" and stored["occurrences"] == 12


def test_an_identityless_row_without_a_workforce_label_or_off_scope_host_is_dropped():
    built, rejected = _rejected(exposure_row(identity=None, service_host="vpn.example.com"),
                                exposure_row(identity=None, provider_relationship="Employee", service_host="login.microsoftonline.com"),
                                kinds=("email",))
    assert built.exposures == () and rejected == 2


def test_occurrences_are_a_snapshot_and_do_not_change_the_id():
    from farpoint.credential_store import merge_credentials

    def employee(n):
        return exposure_row(identity=None, provider_relationship="Employee", service_host="vpn.example.com", occurrences=n)

    first = merge_credentials(None, batch([employee(3)], "2026-10-01T00:00:00Z"))
    again = merge_credentials(first, batch([employee(5)], "2026-11-01T00:00:00Z"))
    (row,) = again["exposures"]
    assert row["occurrences"] == 5 and row["id"] == first["exposures"][0]["id"]
