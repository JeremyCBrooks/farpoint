import json
from pathlib import Path

import pytest
from conftest import AT, exposure_row, write_import

from farpoint.credential_import import CredentialImportError, load_imports
from farpoint.credentials import IMPORT_CHECK_FIELDS, IMPORT_EXPOSURE_FIELDS, IMPORT_SUMMARY_FIELDS, CredentialBatch


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


def test_a_disabled_query_kind_rejects_every_file(tmp_path):
    ok = write_import(tmp_path / "a.json", [exposure_row()])
    web = write_import(tmp_path / "b.json", [exposure_row(query_kind="website", identity="cust@gmail.com", service_host="shop.example.com")])
    with pytest.raises(CredentialImportError) as exc:
        load_imports([ok, web], ["example.com"], {"email"}, AT)
    assert "b.json" in str(exc.value) and "website" in str(exc.value) and "cust" not in str(exc.value)
    batch, _ = load_imports([ok, web], ["example.com"], {"email", "website"}, AT)
    assert len(batch.exposures) == 2


@pytest.mark.parametrize("content", [b"not json", b"\xff\xfe\x00", b"[]", b'{"schema_version": 2, "exposures": []}'])
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
        with pytest.raises(CredentialImportError):
            load_imports([path], ["example.com"], {"email"}, AT)


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


def test_the_documented_example_imports():
    root = Path(__file__).parent.parent / "docs" / "credential-import"
    batch, rejected = load_imports([root / "example.json"], ["example.com"], {"email", "website"}, AT)
    assert batch.exposures and batch.summaries and batch.checks and rejected == 0
    schema = json.loads((root / "schema.json").read_text())
    assert set(schema["$defs"]["exposure"]["properties"]) == IMPORT_EXPOSURE_FIELDS
    assert set(schema["$defs"]["summary"]["properties"]) == IMPORT_SUMMARY_FIELDS
    assert set(schema["$defs"]["check"]["properties"]) == IMPORT_CHECK_FIELDS
