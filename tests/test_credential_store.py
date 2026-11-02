import json
import os

import pytest
from conftest import AT, batch, check_row as check, exposure_row

from farpoint.credential_store import CredentialState, load_credentials, merge_credentials, save_credentials
from farpoint.credentials import CredentialBatch
from farpoint.files import locked


def test_refetching_updates_retrieval_but_not_event_age(tmp_path):
    first = merge_credentials(None, batch(tmp_path, [exposure_row()], "2026-10-01T00:00:00Z"))
    again = merge_credentials(first, batch(tmp_path, [exposure_row(event_at="2026-09-15")], "2026-11-01T00:00:00Z"))
    [row] = again["exposures"]
    assert (row["first_seen"], row["last_seen"], row["event_at"]) == ("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-09-15")


def test_an_older_replay_cannot_regress_newer_evidence_or_checks(tmp_path):
    new = merge_credentials(None, batch(tmp_path, [exposure_row(malware_family="Lumma")], "2026-11-01T00:00:00Z",
                                         checks=[check(status="complete", checked_at="2026-11-01")]))
    old = batch(tmp_path, [exposure_row(malware_family="RedLine")], "2026-10-01T00:00:00Z",
                checks=[check(status="failed", error="server", checked_at="2026-10-01")])
    merged = merge_credentials(new, old)
    assert merged["exposures"][0]["malware_family"] == "Lumma" and merged["exposures"][0]["first_seen"] == "2026-10-01T00:00:00Z"
    assert merged["checks"][0]["status"] == "complete"


def test_last_complete_survives_a_later_failure(tmp_path):
    ok = merge_credentials(None, batch(tmp_path, [], "2026-10-01T00:00:00Z", checks=[check(status="complete", checked_at="2026-10-01")]))
    failed = merge_credentials(ok, batch(tmp_path, [], "2026-11-01T00:00:00Z", checks=[check(status="failed", error="quota", checked_at="2026-11-01")]))
    assert (failed["checks"][0]["status"], failed["checks"][0]["last_complete_at"]) == ("failed", "2026-10-01")


def _summary(count):
    return {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers",
            "metric": "accounts", "count": count}


def test_summaries_replace_rather_than_accumulate(tmp_path):
    first = merge_credentials(None, batch(tmp_path, [], "2026-10-01T00:00:00Z", summaries=[_summary(40)]))
    again = merge_credentials(first, batch(tmp_path, [], "2026-11-01T00:00:00Z", summaries=[_summary(42)]))
    [row] = again["summaries"]
    assert row["count"] == 42 and row["first_seen"] == "2026-10-01T00:00:00Z" and row["last_seen"] == "2026-11-01T00:00:00Z"


def test_operations_keep_independent_checks(tmp_path):
    merged = merge_credentials(None, batch(tmp_path, [], checks=[
        check(operation="breaches", status="complete"), check(operation="stealers", status="failed", error="quota")]))
    assert {c["operation"]: c["status"] for c in merged["checks"]} == {"breaches": "complete", "stealers": "failed"}


def test_repeating_the_same_merge_keeps_the_revision(tmp_path):
    b = batch(tmp_path, [exposure_row()], "2026-10-01T00:00:00Z")
    once = merge_credentials(None, b)
    assert merge_credentials(once, b)["revision"] == once["revision"]
    assert merge_credentials(once, batch(tmp_path, [exposure_row()], "2026-10-02T00:00:00Z"))["revision"] != once["revision"]


def test_saving_round_trips_and_counts_new(tmp_path):
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    assert saved.new_exposures == 1 and load_credentials(tmp_path).data == saved.state.data
    assert saved.state.revision == saved.state.data["revision"]
    with locked(tmp_path):
        again = save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    assert again.new_exposures == 0 and again.state.revision == saved.state.revision


def test_equal_content_serialises_identically_whatever_the_row_order(tmp_path):
    rows = [exposure_row(identity="a@example.com"), exposure_row(identity="b@example.com")]
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir(), two.mkdir()
    for directory, order in ((one, rows), (two, rows[::-1])):
        with locked(directory):
            save_credentials(directory, batch(directory, order, AT), AT)
    a, b = (json.loads((d / "credentials.json").read_text()) for d in (one, two))
    assert a["exposures"] == b["exposures"]


def test_an_attempt_summary_has_no_identities(tmp_path):
    from farpoint.credential_store import attempt_summary
    b = batch(tmp_path, [exposure_row()], checks=[check(status="complete")])
    assert attempt_summary(b) == [{"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email",
                                   "operation": "stealers", "status": "complete", "records": 1, "origin": "import"}]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_sidecar_and_fallback_are_owner_only_whatever_the_umask(tmp_path):
    old = os.umask(0)
    try:
        with locked(tmp_path):
            save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
        (tmp_path / "credentials.json").write_bytes(b"{")
        with locked(tmp_path):
            saved = save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    finally:
        os.umask(old)
    assert saved.fallback.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_the_sidecar_is_owner_only(tmp_path):
    old = os.umask(0)
    try:
        with locked(tmp_path):
            save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    finally:
        os.umask(old)
    assert (tmp_path / "credentials.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("content", [b"{", b'{"schema_version": 1, "exposures": {}}', b'{"schema_version": 9}'])
def test_an_unreadable_sidecar_is_preserved_and_new_evidence_goes_to_a_fallback(tmp_path, content):
    (tmp_path / "credentials.json").write_bytes(content)
    assert load_credentials(tmp_path).error and load_credentials(tmp_path).data is None
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    assert (tmp_path / "credentials.json").read_bytes() == content
    assert saved.fallback.name == "credentials.unmerged-2026-11-01T000000Z.json" and saved.error
    assert CredentialBatch.from_json(json.loads(saved.fallback.read_text())).exposures


def test_an_unreadable_sidecar_error_never_echoes_its_values(tmp_path):
    (tmp_path / "credentials.json").write_text(json.dumps(
        {"schema_version": 1, "revision": "r", "updated_at": AT, "exposures": [{"password": "SENTINEL"}]}))
    error = load_credentials(tmp_path).error
    assert error.startswith("credentials.json can't be read") and "SENTINEL" not in error


def test_a_failed_write_falls_back_without_echoing_the_error(tmp_path, monkeypatch):
    from farpoint import credential_store

    real = credential_store.write_atomic

    def fail(path, text, mode):
        if path.name == "credentials.json":
            raise PermissionError("SENTINEL-PATH")
        real(path, text, mode)

    monkeypatch.setattr(credential_store, "write_atomic", fail)
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch(tmp_path, [exposure_row()], AT), AT)
    assert saved.error == "can't save credentials.json (PermissionError)" and saved.fallback.exists()
    assert not (tmp_path / "credentials.json").exists()


def test_a_missing_sidecar_is_no_evidence_not_an_error(tmp_path):
    assert load_credentials(tmp_path) == CredentialState(None, None)
