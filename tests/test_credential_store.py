import json
import os

import pytest
from conftest import AT, LATER, batch, check_row as check, exposure_row, read_csv, sample_inventory

from farpoint.credential_store import CredentialState, load_credentials, merge_credentials, save_credentials
from farpoint.credentials import CredentialBatch
from farpoint.files import FILE_MODE, OWNER_MODE, locked, write_atomic
from farpoint.models import Inventory
from farpoint.output import Checkpointer, ReportError, recover_checkpoints, write_outputs


def test_refetching_updates_retrieval_but_not_event_age():
    first = merge_credentials(None, batch([exposure_row()], "2026-10-01T00:00:00Z"))
    again = merge_credentials(first, batch([exposure_row(event_at="2026-09-15")], "2026-11-01T00:00:00Z"))
    [row] = again["exposures"]
    assert (row["first_seen"], row["last_seen"], row["event_at"]) == ("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-09-15")


def test_an_older_replay_cannot_regress_newer_evidence_or_checks():
    new = merge_credentials(None, batch([exposure_row(malware_family="Lumma")], "2026-11-01T00:00:00Z",
                                         checks=[check(status="complete", checked_at="2026-11-01")]))
    old = batch([exposure_row(malware_family="RedLine")], "2026-10-01T00:00:00Z",
                checks=[check(status="failed", error="server", checked_at="2026-10-01")])
    merged = merge_credentials(new, old)
    assert merged["exposures"][0]["malware_family"] == "Lumma" and merged["exposures"][0]["first_seen"] == "2026-10-01T00:00:00Z"
    assert merged["checks"][0]["status"] == "complete"


def test_last_complete_survives_a_later_failure():
    ok = merge_credentials(None, batch([], "2026-10-01T00:00:00Z", checks=[check(status="complete", checked_at="2026-10-01")]))
    failed = merge_credentials(ok, batch([], "2026-11-01T00:00:00Z", checks=[check(status="failed", error="quota", checked_at="2026-11-01")]))
    assert (failed["checks"][0]["status"], failed["checks"][0]["last_complete_at"]) == ("failed", "2026-10-01")


def _summary(count):
    return {"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email", "operation": "stealers",
            "metric": "accounts", "count": count}


def test_summaries_replace_rather_than_accumulate():
    first = merge_credentials(None, batch([], "2026-10-01T00:00:00Z", summaries=[_summary(40)]))
    again = merge_credentials(first, batch([], "2026-11-01T00:00:00Z", summaries=[_summary(42)]))
    [row] = again["summaries"]
    assert row["count"] == 42 and row["first_seen"] == "2026-10-01T00:00:00Z" and row["last_seen"] == "2026-11-01T00:00:00Z"


def test_operations_keep_independent_checks():
    merged = merge_credentials(None, batch([], checks=[
        check(operation="breaches", status="complete"), check(operation="stealers", status="failed", error="quota")]))
    assert {c["operation"]: c["status"] for c in merged["checks"]} == {"breaches": "complete", "stealers": "failed"}


def test_repeating_the_same_merge_keeps_the_revision():
    b = batch([exposure_row()], "2026-10-01T00:00:00Z")
    once = merge_credentials(None, b)
    assert merge_credentials(once, b)["revision"] == once["revision"]
    assert merge_credentials(once, batch([exposure_row()], "2026-10-02T00:00:00Z"))["revision"] != once["revision"]


def test_saving_round_trips_and_counts_new(tmp_path):
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch([exposure_row()], AT), AT)
    assert saved.new_exposures == 1 and load_credentials(tmp_path).data == saved.state.data
    assert saved.state.revision == saved.state.data["revision"]
    with locked(tmp_path):
        again = save_credentials(tmp_path, batch([exposure_row()], AT), AT)
    assert again.new_exposures == 0 and again.state.revision == saved.state.revision


def test_equal_content_serialises_identically_whatever_the_row_order(tmp_path):
    rows = [exposure_row(identity="a@example.com"), exposure_row(identity="b@example.com")]
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir(), two.mkdir()
    for directory, order in ((one, rows), (two, rows[::-1])):
        with locked(directory):
            save_credentials(directory, batch(order, AT), AT)
    a, b = (json.loads((d / "credentials.json").read_text()) for d in (one, two))
    assert a["exposures"] == b["exposures"]


def test_an_attempt_summary_has_no_identities():
    from farpoint.credential_store import attempt_summary
    b = batch([exposure_row()], checks=[check(status="complete")])
    assert attempt_summary(b) == [{"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email",
                                   "operation": "stealers", "status": "complete", "records": 1, "origin": "live"}]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_sidecar_and_fallback_are_owner_only_whatever_the_umask(tmp_path):
    old = os.umask(0)
    try:
        with locked(tmp_path):
            save_credentials(tmp_path, batch([exposure_row()], AT), AT)
        (tmp_path / "credentials.json").write_bytes(b"{")
        with locked(tmp_path):
            saved = save_credentials(tmp_path, batch([exposure_row()], AT), AT)
    finally:
        os.umask(old)
    assert saved.fallback.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_the_sidecar_is_owner_only(tmp_path):
    old = os.umask(0)
    try:
        with locked(tmp_path):
            save_credentials(tmp_path, batch([exposure_row()], AT), AT)
    finally:
        os.umask(old)
    assert (tmp_path / "credentials.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("content", [b"{", b'{"schema_version": 1, "exposures": {}}', b'{"schema_version": 9}'])
def test_an_unreadable_sidecar_is_preserved_and_new_evidence_goes_to_a_fallback(tmp_path, content):
    (tmp_path / "credentials.json").write_bytes(content)
    assert load_credentials(tmp_path).error and load_credentials(tmp_path).data is None
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch([exposure_row()], AT), AT)
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
        saved = save_credentials(tmp_path, batch([exposure_row()], AT), AT)
    assert saved.error == "can't save credentials.json (PermissionError)" and saved.fallback.exists()
    assert not (tmp_path / "credentials.json").exists()


def test_a_missing_sidecar_is_no_evidence_not_an_error(tmp_path):
    assert load_credentials(tmp_path) == CredentialState(None, None)


@pytest.mark.parametrize("collection,field", [
    ("exposures", "first_seen"), ("exposures", "last_seen"), ("summaries", "retrieved_at"),
    ("summaries", "first_seen"), ("summaries", "last_seen"), ("checks", "started_at")])
def test_a_sidecar_row_missing_a_merge_field_is_unreadable_not_a_crash(tmp_path, collection, field):
    with locked(tmp_path):
        save_credentials(tmp_path, batch([exposure_row()], AT, summaries=[_summary(4)]), AT)
    path = tmp_path / "credentials.json"
    doc = json.loads(path.read_text())
    del doc[collection][0][field]
    path.write_text(json.dumps(doc))
    before = path.read_bytes()
    assert load_credentials(tmp_path).error
    with locked(tmp_path):
        saved = save_credentials(tmp_path, batch([exposure_row()], LATER), LATER)
    assert path.read_bytes() == before and saved.error and saved.fallback.exists()


def test_two_fallbacks_in_the_same_second_both_survive(tmp_path):
    (tmp_path / "credentials.json").write_bytes(b"{")
    saves = []
    for identity in ("a@example.com", "b@example.com"):
        with locked(tmp_path):
            saves.append(save_credentials(tmp_path, batch([exposure_row(identity=identity)], AT), AT))
    first, second = saves[0].fallback, saves[1].fallback
    assert first != second and first.name == "credentials.unmerged-2026-11-01T000000Z.json"
    ids = [CredentialBatch.from_json(json.loads(f.read_text())).exposures[0]["identity"] for f in (first, second)]
    assert ids == ["a@example.com", "b@example.com"]


def test_credentials_are_saved_even_when_the_inventory_cannot_be(tmp_path):
    (tmp_path / "assets.json").write_text("{broken")
    with pytest.raises(ReportError):
        write_outputs(Inventory(["example.com"]), tmp_path, AT, credentials=batch([exposure_row()], AT))
    assert load_credentials(tmp_path).data["exposures"][0]["identity"] == "alice@example.com"


def test_identities_stay_out_of_the_inventory_and_the_run_records_attempts(tmp_path):
    report = write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row()], AT))
    assert "alice" not in (tmp_path / "assets.json").read_text()
    assert "credential_run" not in report
    assert report["runs"][-1]["credentials"] == {"new": 1, "checks": [{"provider": "acme-intel", "scope_domain": "example.com", "query_kind": "email",
                                                                         "operation": "stealers", "status": "partial", "records": 1, "origin": "live"}]}


def test_an_unreadable_sidecar_still_lets_the_scan_save(tmp_path):
    (tmp_path / "credentials.json").write_text("{")
    report = write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row()], AT))
    assert any(e["source"] == "credentials" and "alice" not in e["message"] for e in report["errors"])
    assert (tmp_path / "hosts.csv").exists() and list(tmp_path.glob("credentials.unmerged-*.json"))


def test_the_assessment_is_handed_the_sidecar_state(tmp_path):
    seen = []
    write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row()], AT),
                  assess=lambda report, credentials: seen.append(credentials) or report)
    write_outputs(sample_inventory(), tmp_path, LATER, assess=lambda report, credentials: seen.append(credentials) or report)
    assert seen[0].revision and seen[0].revision == seen[1].revision


def test_exports_carry_identities_matches_and_coverage(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row(service_host="www.example.com")], AT))
    [row] = read_csv(tmp_path / "credential-exposures.csv")
    assert (row["identity"], row["match"], row["matched_asset"]) == ("alice@example.com", "dns-only", "www.example.com")
    assert list(row)[0] == "id" and row["id"] == load_credentials(tmp_path).data["exposures"][0]["id"]
    assert read_csv(tmp_path / "credential-checks.csv")[0]["status"] == "partial"
    assert read_csv(tmp_path / "credential-summary.csv") == []


def test_formula_like_identities_are_quoted_in_exports(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row(identity='=HYPERLINK("x")@example.com')], AT))
    assert read_csv(tmp_path / "credential-exposures.csv")[0]["identity"].startswith("'=")
    assert load_credentials(tmp_path).data["exposures"][0]["identity"].startswith("=")


def test_an_emptied_sidecar_rewrites_exports_rather_than_leaving_stale_ones(tmp_path):
    write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row()], AT))
    assert len(read_csv(tmp_path / "credential-exposures.csv")) == 1
    empty = merge_credentials(None, CredentialBatch(AT))
    write_atomic(tmp_path / "credentials.json", json.dumps(empty), OWNER_MODE)
    write_outputs(sample_inventory(), tmp_path, LATER)
    assert read_csv(tmp_path / "credential-exposures.csv") == []
    assert "identity" in (tmp_path / "credential-exposures.csv").read_text(encoding="utf-8").splitlines()[0]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_exports_are_owner_only(tmp_path):
    old = os.umask(0)
    try:
        write_outputs(sample_inventory(), tmp_path, AT, credentials=batch([exposure_row()], AT))
    finally:
        os.umask(old)
    for name in ("credential-exposures.csv", "credential-summary.csv", "credential-checks.csv"):
        assert (tmp_path / name).stat().st_mode & 0o777 == OWNER_MODE
    assert (tmp_path / "hosts.csv").stat().st_mode & 0o777 == FILE_MODE


def _die(cp):
    cp._lock_fh.close()  # the process died: its lock is free


def test_a_killed_run_leaves_credentials_that_the_next_run_recovers(tmp_path):
    dead = Checkpointer(tmp_path, credentials=batch([exposure_row()], AT))
    dead(sample_inventory())
    _die(dead)
    [run] = recover_checkpoints(tmp_path)
    assert run["exposures"] == 1 and load_credentials(tmp_path).data["exposures"]
    assert not list(tmp_path.glob(".credential-checkpoint-*")) and not list(tmp_path.glob(".checkpoint-*"))


def test_a_lone_credential_member_uses_the_paired_lock(tmp_path):
    live = Checkpointer(tmp_path, credentials=batch([exposure_row()], AT))
    live(sample_inventory())
    next(tmp_path.glob(".checkpoint-*.json")).unlink()
    assert recover_checkpoints(tmp_path) == []
    assert len(list(tmp_path.glob(".credential-checkpoint-*.json"))) == 1
    live.clear()


def test_replaying_a_recovered_member_does_not_duplicate_or_change_the_revision(tmp_path):
    dead = Checkpointer(tmp_path, credentials=batch([exposure_row()], AT))
    dead(sample_inventory())
    _die(dead)
    member = next(tmp_path.glob(".credential-checkpoint-*.json"))
    saved = member.read_bytes()
    recover_checkpoints(tmp_path)
    first = load_credentials(tmp_path)
    member.write_bytes(saved)  # a crash before cleanup left the member behind
    recover_checkpoints(tmp_path)
    again = load_credentials(tmp_path)
    assert len(again.data["exposures"]) == 1 and again.revision == first.revision


def test_an_invalid_credential_member_stays_with_a_value_free_warning(tmp_path):
    member = tmp_path / ".credential-checkpoint-1-ab.json"
    member.write_text(json.dumps({"schema_version": 1, "retrieved_at": AT, "exposures": [{"identity": "SENTINEL"}]}))
    result = recover_checkpoints(tmp_path)
    assert member.exists()
    assert result and "warning" in result[0] and "SENTINEL" not in json.dumps(result)


def test_a_credential_member_that_is_not_utf8_warns_without_quoting_its_bytes(tmp_path):
    member = tmp_path / ".credential-checkpoint-1-ab.json"
    member.write_bytes(b'{"identity": "SENTINEL-\xff\xfe"}')
    result = recover_checkpoints(tmp_path)
    assert member.exists()
    assert "not valid UTF-8" in result[0]["warning"] and "SENTINEL" not in json.dumps(result)


def test_the_namespaces_do_not_match_each_others_globs(tmp_path):
    cp = Checkpointer(tmp_path, credentials=batch([exposure_row()], AT))
    cp(sample_inventory())
    assert len(list(tmp_path.glob(".checkpoint-*.json"))) == 1 and len(list(tmp_path.glob(".credential-checkpoint-*.json"))) == 1
    cp.clear()
    assert not list(tmp_path.glob(".*checkpoint-*"))


def test_exports_mark_snapshot_membership_and_no_data(tmp_path):
    from datetime import date

    from farpoint.credential_store import write_credential_exports

    def employee(host):
        return exposure_row(provider="hudsonrock-osint", operation="employee-urls", identity=None, provider_relationship="Employee",
                            service_host=host, occurrences=4, secret_evidence="dataset", event_at=None, event_date_basis=None)

    def snap(at):
        return check(provider="hudsonrock-osint", operation="employee-urls", checked_at=at)

    from conftest import batch

    data = merge_credentials(None, batch([employee("vpn.example.com")], AT, checks=[snap(AT)]))
    data = merge_credentials(data, batch([], LATER, checks=[snap(LATER), check(checked_at=LATER)]))
    out = tmp_path / "out"
    out.mkdir()
    write_credential_exports(out, data, {"domains": ["example.com"]}, date(2026, 11, 2))
    (row,) = read_csv(out / "credential-exposures.csv")
    assert row["occurrences"] == "4" and row["in_latest_snapshot"] == "no"
    assert {c["result"] for c in read_csv(out / "credential-checks.csv")} == {"no data"}
