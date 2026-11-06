import json
from pathlib import Path

import pytest
from conftest import AT, batch, check_row, exposure_row, write_import

from farpoint.credential_import import CredentialImportError, load_imports
from farpoint.credentials import (
    IMPORT_CHECK_FIELDS,
    IMPORT_EXPOSURE_FIELDS,
    IMPORT_SUMMARY_FIELDS,
    STORED_EXPOSURE_ORDER,
    CredentialBatch,
)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("newer_status,older_status", [("complete", "failed"), ("failed", "complete")])
def test_multi_file_checks_follow_time_and_keep_last_success(tmp_path, reverse, newer_status, older_status):
    newer = write_import(tmp_path / "newer.json", checks=[check_row(status=newer_status, checked_at="2026-10-30T00:00:00Z")])
    older = write_import(tmp_path / "older.json", checks=[check_row(status=older_status, checked_at="2026-10-01T00:00:00Z")])
    paths = [older, newer] if reverse else [newer, older]
    imported, _ = load_imports(paths, ["example.com"], {"email"}, AT)
    [check] = imported.checks
    assert check["status"] == newer_status
    assert check["completed_at"] == "2026-10-30T00:00:00Z"
    assert check["last_complete_at"] == ("2026-10-30T00:00:00Z" if newer_status == "complete" else "2026-10-01T00:00:00Z")


def test_unknown_fields_reject_the_whole_import_without_echoing_values(tmp_path):
    path = write_import(tmp_path / "e.json", [exposure_row(), exposure_row(password="SENTINEL-PW")])
    with pytest.raises(CredentialImportError) as exc:
        load_imports([path], ["example.com"], {"email"}, AT)
    assert "e.json" in str(exc.value) and "exposures[1]" in str(exc.value) and "password" in str(exc.value)
    assert "SENTINEL" not in str(exc.value)


def test_an_unknown_field_name_that_looks_like_data_is_not_echoed(tmp_path):
    path = write_import(tmp_path / "e.json", [exposure_row(**{"bob@example.com": 1})])
    with pytest.raises(CredentialImportError) as exc:
        load_imports([path], ["example.com"], {"email"}, AT)
    assert "bob" not in str(exc.value) and "unknown field" in str(exc.value)
    path = write_import(tmp_path / "f.json", [exposure_row(**{"abc\n": 1})])
    with pytest.raises(CredentialImportError) as exc:
        load_imports([path], ["example.com"], {"email"}, AT)
    assert "abc" not in str(exc.value)


def test_a_disabled_query_kind_rejects_every_file(tmp_path):
    ok = write_import(tmp_path / "a.json", [exposure_row()])
    web = write_import(tmp_path / "b.json", [exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.com")])
    with pytest.raises(CredentialImportError) as exc:
        load_imports([ok, web], ["example.com"], {"email"}, AT)
    assert "b.json" in str(exc.value) and "website" in str(exc.value) and "cust" not in str(exc.value)
    batch, _ = load_imports([ok, web], ["example.com"], {"email", "website"}, AT)
    assert len(batch.exposures) == 2


@pytest.mark.parametrize("content", [b"not json", b"\xff\xfe\x00", b"[]", b'{"schema_version": 2, "exposures": []}',
                                     b'{"schema_version": true}', b'{"schema_version": 1.0}',
                                     b'{"schema_version": 1, "extra": []}', pytest.param(b"[" * 100000 + b"]" * 100000, id="deeply-nested")])
def test_malformed_import_files_fail_cleanly(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(CredentialImportError) as exc:
        load_imports([path], ["example.com"], {"email"}, AT)
    assert "bad.json" in str(exc.value) and "not json" not in str(exc.value)


def test_bad_enumerations_and_types_are_rejected(tmp_path):
    for bad in ({"exposure_type": "rumour"}, {"secret_types": ["password", "mystery"]}, {"secret_evidence": "maybe"},
                {"event_date_basis": "vibes"}, {"event_at": "last tuesday"}, {"service_port": 70000}, {"provider": ""},
                {"reference": None}):
        path = write_import(tmp_path / "x.json", [exposure_row(**bad)])
        with pytest.raises(CredentialImportError) as exc:
            load_imports([path], ["example.com"], {"email"}, AT)
        assert f"exposures[0].{next(iter(bad))}" in str(exc.value)


def test_summaries_and_checks_are_validated(tmp_path):
    base = {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers"}
    bad_rows = [
        ("summaries", {**base, "metric": "accounts", "count": -1}),
        ("summaries", {**base, "metric": "accounts", "count": True}),
        ("summaries", {**base, "count": 3}),
        ("checks", {**base, "status": "great"}),
        ("checks", {**base, "status": "failed", "error": "bespoke"}),
    ]
    for collection, row in bad_rows:
        path = write_import(tmp_path / "s.json", **{collection: [row]})
        with pytest.raises(CredentialImportError) as exc:
            load_imports([path], ["example.com"], {"email"}, AT)
        assert f"{collection}[0]" in str(exc.value)


def test_stored_batches_round_trip_and_reject_unknown_fields():
    stored = exposure_row(id="acme-intel:1", relationship="workforce-associated", identity_domain="example.com",
                          first_seen=AT, last_seen=AT)
    batch = CredentialBatch(AT, (stored,))
    assert CredentialBatch.from_json(batch.to_json()) == batch
    doc = batch.to_json()
    doc["exposures"][0]["password"] = "SENTINEL-PW"
    with pytest.raises(ValueError) as exc:
        CredentialBatch.from_json(doc)
    assert "SENTINEL" not in str(exc.value) and "exposures[0]" in str(exc.value)
    for bad in (True, 1.0, 2):
        with pytest.raises(ValueError):
            CredentialBatch.from_json({**batch.to_json(), "schema_version": bad})


def test_the_documented_example_imports():
    root = Path(__file__).parent.parent / "docs" / "credential-import"
    batch, rejected = load_imports([root / "example.json"], ["example.com"], {"email", "website"}, AT)
    assert batch.exposures and batch.summaries and batch.checks and rejected == 0
    schema = json.loads((root / "schema.json").read_text())
    assert set(schema["$defs"]["exposure"]["properties"]) == IMPORT_EXPOSURE_FIELDS
    assert set(schema["$defs"]["summary"]["properties"]) == IMPORT_SUMMARY_FIELDS
    assert set(schema["$defs"]["check"]["properties"]) == IMPORT_CHECK_FIELDS


def batch_of(tmp_path, *rows, kinds=("email", "website")):
    return load_imports([write_import(tmp_path / "e.json", list(rows))], ["example.com"], set(kinds), AT)


def test_email_scope_uses_label_boundaries_and_keeps_identity_as_supplied(tmp_path):
    batch, rejected = batch_of(tmp_path, exposure_row(identity="Bob@Example.COM."), exposure_row(identity="x@example.com.evil.net"),
                               exposure_row(identity="x@notexample.com"), exposure_row(identity="dev@eu.example.com"), exposure_row(identity=None))
    assert sorted(e["identity"] for e in batch.exposures) == ["Bob@Example.COM.", "dev@eu.example.com"]
    assert {e["identity_domain"] for e in batch.exposures} == {"example.com", "eu.example.com"}
    assert rejected == 3


def test_without_website_a_customer_on_an_in_scope_host_is_never_kept(tmp_path):
    row = exposure_row(query_kind="email", identity="cust@gmail.com", service_host="shop.example.com")
    batch, rejected = batch_of(tmp_path, row, kinds=("email",))
    assert batch.exposures == () and rejected == 1


def test_website_rows_need_an_in_scope_service_and_label_relationships(tmp_path):
    batch, rejected = batch_of(tmp_path,
        exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.com", provider_relationship="User"),
        exposure_row(query_kind="website", identity="bob@example.com", service_host="shop.example.com", provider_relationship="customer"),
        exposure_row(query_kind="website", identity="anon", service_host="shop.example.com"),
        exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.org"))
    assert sorted(e["relationship"] for e in batch.exposures) == ["customer-reported", "service-account-unknown", "workforce-associated"]
    assert {e["provider_relationship"] for e in batch.exposures} >= {"User", "customer"} and rejected == 1


def test_service_urls_lose_secrets_and_never_gain_a_port(tmp_path):
    batch, _ = batch_of(tmp_path,
        exposure_row(service_host="https://SENTINEL-USER:SENTINEL-PW@vpn.example.com/login?token=SENTINEL-TOKEN#SENTINEL"),
        exposure_row(identity="b@example.com", service_host="sts.example.com:8443"),
        exposure_row(identity="c@example.com", reference="https://intel.example.net/case/9?apikey=SENTINEL-KEY"))
    rows = {e["identity"]: e for e in batch.exposures}
    assert (rows["alice@example.com"]["service_host"], rows["alice@example.com"]["service_port"]) == ("vpn.example.com", None)
    assert (rows["b@example.com"]["service_host"], rows["b@example.com"]["service_port"]) == ("sts.example.com", 8443)
    assert rows["c@example.com"]["reference"] == "https://intel.example.net/case/9"
    assert "SENTINEL" not in json.dumps(batch.to_json())


@pytest.mark.parametrize("raw,stored", [("2026-10-01", "2026-10-01"), ("2026-10-01T12:00:00+02:00", "2026-10-01T10:00:00Z"),
                                        ("2026-10-01T12:00:00", "2026-10-01T12:00:00")])
def test_event_times_keep_their_precision(tmp_path, raw, stored):
    batch, _ = batch_of(tmp_path, exposure_row(event_at=raw))
    assert batch.exposures[0]["event_at"] == stored


def test_ids_survive_corrections_and_retrieval_time_but_not_identity_changes(tmp_path):
    a, _ = load_imports([write_import(tmp_path / "a.json", [exposure_row()])], ["example.com"], {"email"}, "2026-10-01T00:00:00Z")
    b, _ = load_imports([write_import(tmp_path / "b.json", [exposure_row(exposure_type="phishing", event_at="2026-09-01", malware_family="Lumma")])],
                        ["example.com"], {"email"}, "2026-11-01T00:00:00Z")
    c, _ = load_imports([write_import(tmp_path / "c.json", [exposure_row(identity="ALICE@example.com")])], ["example.com"], {"email"}, AT)
    d, _ = load_imports([write_import(tmp_path / "d.json", [exposure_row(provider_record_id="r-1")])], ["example.com"], {"email"}, AT)
    assert a.exposures[0]["id"] == b.exposures[0]["id"] != c.exposures[0]["id"]
    assert d.exposures[0]["id"] == "acme-intel:r-1" and ":v1:" in a.exposures[0]["id"]


def test_only_the_domain_of_an_identity_is_case_folded_for_its_id(tmp_path):
    a = batch(tmp_path, [exposure_row(identity="alice@example.com")])
    b = batch(tmp_path, [exposure_row(identity="alice@EXAMPLE.com.")])
    assert a.exposures[0]["id"] == b.exposures[0]["id"]


def test_imports_without_coverage_are_partial_and_declared_checks_are_kept(tmp_path):
    rows = [exposure_row(), exposure_row(identity="b@example.com", operation="breaches", exposure_type="breach", source_name="ExampleBreach")]
    checks = [{"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "breaches", "status": "complete", "checked_at": "2026-10-30"}]
    batch, _ = load_imports([write_import(tmp_path / "e.json", rows, checks=checks)], ["example.com"], {"email"}, AT)
    by_op = {c["operation"]: c for c in batch.checks}
    assert by_op["stealers"]["status"] == "partial" and by_op["stealers"]["origin"] == "import" and by_op["stealers"]["records"] == 1
    assert by_op["breaches"]["status"] == "complete" and by_op["breaches"]["completed_at"] == "2026-10-30"
    assert by_op["breaches"]["last_complete_at"] == "2026-10-30" and by_op["breaches"]["records"] == 1
    assert by_op["stealers"].get("last_complete_at") is None


def test_summaries_get_a_partial_check_and_retrieval_times(tmp_path):
    summary = {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers",
               "metric": "accounts", "count": 4}
    b = batch(tmp_path, [], summaries=[summary])
    assert b.summaries[0]["first_seen"] == AT == b.summaries[0]["last_seen"]
    assert [(c["status"], c["records"]) for c in b.checks] == [("partial", 0)]


def test_a_scope_domain_outside_the_scan_is_rejected(tmp_path):
    batch, rejected = batch_of(tmp_path, exposure_row(scope_domain="example.org", identity="a@example.org"))
    assert batch.exposures == () and rejected == 1


def test_batches_set_seen_times_dedupe_by_id_and_validate_retrieved_at(tmp_path):
    first = exposure_row(provider_record_id="r-1", exposure_type="breach")
    last = exposure_row(provider_record_id="r-1", exposure_type="phishing", source_observed_at="2026-10-20")
    b = batch(tmp_path, [first, last], at="2026-11-01T02:00:00+02:00")
    assert len(b.exposures) == 1 and b.exposures[0]["exposure_type"] == "phishing"
    assert b.exposures[0]["first_seen"] == b.exposures[0]["last_seen"] == b.retrieved_at == "2026-11-01T00:00:00Z"
    assert b.exposures[0]["source_observed_at"] == "2026-10-20"
    with pytest.raises(ValueError):
        batch(tmp_path, [], at="yesterday")


def test_declared_checks_for_other_domains_are_dropped(tmp_path):
    b = batch(tmp_path, [exposure_row()], checks=[check_row(), check_row(scope_domain="example.org")])
    assert [c["scope_domain"] for c in b.checks] == ["example.com"]


def test_a_reference_without_a_scheme_never_keeps_a_secret(tmp_path):
    refs = ["intel.example.net/case/9?apikey=SENTINEL", "intel.example.net/case/9#SENTINEL", "user:SENTINEL@intel.example.net/case/9"]
    for ref in refs:
        b = batch(tmp_path, [exposure_row(reference=ref)])
        assert "SENTINEL" not in json.dumps(b.exposures[0]) and b.exposures[0]["reference"] == "intel.example.net/case/9"


def test_stored_rows_have_a_fixed_key_order_and_no_raw_checked_at(tmp_path):
    b = batch(tmp_path, [exposure_row()], checks=[check_row(checked_at="2026-10-30")])
    [row], [chk] = b.exposures, b.checks
    assert list(row)[0] == "id" and list(row) == [k for k in STORED_EXPOSURE_ORDER]
    assert "checked_at" not in chk and chk["completed_at"] == "2026-10-30"
    CredentialBatch.from_json(b.to_json())  # the stored form is accepted back


def test_an_identityless_employee_row_on_an_in_scope_host_is_workforce(tmp_path):
    row = exposure_row(identity=None, provider_relationship="Employee", service_host="https://vpn.example.com/x?t=1",
                       secret_evidence="dataset", event_at=None, event_date_basis=None, occurrences=12)
    imported, rejected = load_imports([write_import(tmp_path / "e.json", [row])], ["example.com"], ["email"], AT)
    (stored,) = imported.exposures
    assert rejected == 0 and stored["relationship"] == "workforce-associated"
    assert stored["service_host"] == "vpn.example.com" and stored["occurrences"] == 12


def test_an_identityless_row_without_a_workforce_label_or_off_scope_host_is_dropped(tmp_path):
    rows = [exposure_row(identity=None, service_host="vpn.example.com"),
            exposure_row(identity=None, provider_relationship="Employee", service_host="login.microsoftonline.com")]
    imported, rejected = load_imports([write_import(tmp_path / "e.json", rows)], ["example.com"], ["email"], AT)
    assert imported.exposures == () and rejected == 2


def test_occurrences_are_a_snapshot_and_do_not_change_the_id(tmp_path):
    from farpoint.credential_store import merge_credentials

    def employee(n):
        return exposure_row(identity=None, provider_relationship="Employee", service_host="vpn.example.com", occurrences=n)

    first = merge_credentials(None, batch(tmp_path, [employee(3)], "2026-10-01T00:00:00Z"))
    again = merge_credentials(first, batch(tmp_path, [employee(5)], "2026-11-01T00:00:00Z"))
    (row,) = again["exposures"]
    assert row["occurrences"] == 5 and row["id"] == first["exposures"][0]["id"]
