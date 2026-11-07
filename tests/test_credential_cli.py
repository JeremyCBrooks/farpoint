import pytest

from conftest import exposure_row, read_csv, sample_inventory
from farpoint import cli
from farpoint.output import write_outputs

STAMP = "2026-10-01T00:00:00Z"


def test_import_into_an_existing_inventory_and_assess(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row(), exposure_row(identity="x@other.org"))
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    printed, err = capsys.readouterr()
    assert "credential scope: example.com" in err and "1 provider rows outside scope or of a disabled kind were dropped" in printed
    assert "assessment: current" in printed and "alice" not in printed + err
    assert any(r["kind"] == "credential-theft" for r in read_csv(out / "findings.csv"))


def test_credentials_only_mode_needs_an_inventory_and_touches_nothing(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    (out / "credentials.json").write_bytes(b'{"keep": "me"}')
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "-o", str(out)]) == 2
    assert "no inventory in" in capsys.readouterr().err
    assert (out / "credentials.json").read_bytes() == b'{"keep": "me"}' and not (out / "assets.json").exists()


@pytest.mark.parametrize("argv,message", [(["--credential-queries", "email", "--assess"], "add --credentials"),
                                          (["--credentials", "hudsonrock-osint", "--credential-queries", "sms"], "unknown kind")])
def test_credential_argument_errors(tmp_path, capsys, argv, message):
    out = tmp_path / "out"
    with pytest.raises(SystemExit):
        cli.main(["example.com", *argv, "-o", str(out)])
    assert message in capsys.readouterr().err
    assert not out.exists()  # rejected before recovery, saves or requests




def test_no_sentinel_secret_reaches_any_file_or_message(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row(service_host="https://u:SENTINEL-PW@www.example.com/?session=SENTINEL-COOKIE",
                                                           reference="https://intel.example.net/c?token=SENTINEL-TOKEN#SENTINEL"))
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    printed, err = capsys.readouterr()
    assert "SENTINEL" not in printed + err
    for f in out.rglob("*"):
        if f.is_file():
            assert b"SENTINEL" not in f.read_bytes(), f.name


def test_infrastructure_outputs_never_contain_identities(tmp_path, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    allowed = {"credentials.json", "credential-exposures.csv"}
    checked = 0
    for f in out.iterdir():
        if f.is_file() and f.name not in allowed:
            checked += 1
            assert b"alice" not in f.read_bytes(), f.name
    assert checked > 3 and (out / "credential-exposures.csv").exists()


def test_reassessing_without_new_evidence_keeps_credential_findings_current(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "-o", str(out)]) == 0
    assert "(run --assess to update)" in capsys.readouterr().out
    assert not (out / "findings.csv").exists()  # never assessed, so no credential findings yet
    assert cli.main(["--assess", "--no-cve", "-o", str(out)]) == 0
    assert "assessment: current" in capsys.readouterr().out
    assert any(r["kind"] == "credential-theft" for r in read_csv(out / "findings.csv"))


def _refuse_sidecar_writes(monkeypatch):
    from farpoint import credential_store

    real = credential_store.write_atomic

    def write(path, *args, **kwargs):
        if path.name == "credentials.json":
            raise PermissionError("read-only")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(credential_store, "write_atomic", write)


def _offline_scan(monkeypatch):
    """A scan with no sources, no DNS and no enrichment: it only records the input domain."""
    monkeypatch.setattr(cli, "build_sources", lambda http, env, nameservers=(): [])
    return ["example.com", "--no-resolve", "--no-enrich"]


def test_evidence_that_cannot_be_saved_is_reported_and_fails_the_import(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    assert cli.main([*_evidence(monkeypatch, exposure_row()), "-o", str(out)]) == 0
    capsys.readouterr()
    _refuse_sidecar_writes(monkeypatch)
    argv = _evidence(monkeypatch, exposure_row(identity="bob@example.com"))
    assert cli.main([*argv, "-o", str(out)]) == 1
    printed, err = capsys.readouterr()
    [fallback] = out.glob("credentials.unmerged-*.json")
    assert f"warning: credential evidence not saved (can't save credentials.json (PermissionError)); kept in {fallback.name}" in err
    assert "bob" not in printed + err


def test_a_scan_whose_evidence_cannot_be_saved_exits_1(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    assert cli.main([*_evidence(monkeypatch, exposure_row()), "-o", str(out)]) == 0
    _refuse_sidecar_writes(monkeypatch)
    argv = _evidence(monkeypatch, exposure_row(identity="bob@example.com"))
    assert cli.main([*_offline_scan(monkeypatch), *argv, "-o", str(out)]) == 1
    [fallback] = out.glob("credentials.unmerged-*.json")
    assert f"kept in {fallback.name}" in capsys.readouterr().err


def test_a_stored_assessment_is_reported_stale_after_the_sidecar_is_deleted(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    (out / "credentials.json").unlink()
    capsys.readouterr()
    assert cli.main([*_offline_scan(monkeypatch), "-o", str(out)]) == 0
    assert "assessment: stale (run --assess to update)" in capsys.readouterr().out


def test_an_unreadable_sidecar_is_reported_as_unavailable(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    (out / "credentials.json").write_text("{", encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["--assess", "--no-cve", "-o", str(out)]) == 0
    assert "assessment: unavailable: credentials.json can't be read (not JSON)" in capsys.readouterr().out


def _findings_total(printed):
    import re

    line = next(line for line in printed.splitlines() if line.startswith("findings:"))
    return sum(int(n) for n in re.findall(r"(\d+) (?:high|medium|low)", line))


def test_stale_credential_findings_are_left_out_of_the_findings_totals(tmp_path, capsys, monkeypatch):
    import json

    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "--assess", "--no-cve", "-o", str(out)]) == 0
    stored = json.loads((out / "assets.json").read_text(encoding="utf-8"))["findings"]
    assert _findings_total(capsys.readouterr().out) == len(stored)
    argv = _evidence(monkeypatch, exposure_row(identity="bob@example.com"))
    assert cli.main([*argv, "-o", str(out)]) == 0  # new evidence, not reassessed: stale
    credential = [f for f in stored if f["kind"].startswith("credential-")]
    assert credential and _findings_total(capsys.readouterr().out) == len(stored) - len(credential)


def test_recovering_only_credential_evidence_says_so(tmp_path, capsys, monkeypatch):
    import json

    from conftest import batch

    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    left = batch([exposure_row()], "2026-10-02T00:00:00Z")
    (out / ".credential-checkpoint-1-ab.json").write_text(json.dumps(left.to_json()), encoding="utf-8")  # its run was killed
    argv = _evidence(monkeypatch, exposure_row(identity="bob@example.com"))
    assert cli.main([*argv, "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "recovered 1 credential exposure from an interrupted run at 2026-10-02T00:00:00Z" in err and "hosts)" not in err


@pytest.mark.parametrize("bad_inventory", [False, True])
def test_failed_sidecar_and_fallback_saves_keep_a_recoverable_checkpoint(tmp_path, monkeypatch, bad_inventory):
    from farpoint import credential_store
    from farpoint.models import Observation
    from farpoint.output import recover_checkpoints

    class SeedSource:
        name = "seed"

        def available(self):
            return True

        def collect(self, domain):
            yield Observation(self.name, domain)
            if bad_inventory:
                # The inventory becomes unreadable after startup, before the final merge.
                (out / "assets.json").write_text("{", encoding="utf-8")

    out = tmp_path / "out"
    argv = _evidence(monkeypatch, exposure_row())
    monkeypatch.setattr(cli, "build_sources", lambda http, env, nameservers=(): [SeedSource()])
    out.mkdir()
    real = credential_store.write_atomic

    def fail(path, *args, **kwargs):
        if path.name == "credentials.json" or path.name.startswith("credentials.unmerged-"):
            raise PermissionError("injected credential write failure")
        return real(path, *args, **kwargs)

    with monkeypatch.context() as failing:
        failing.setattr(credential_store, "write_atomic", fail)
        assert cli.main(["example.com", "--no-resolve", "--no-enrich", *argv, "-o", str(out)]) == 1
    assert not (out / "credentials.json").exists()
    assert not list(out.glob("credentials.unmerged-*"))
    assert len(list(out.glob(".credential-checkpoint-*.json"))) == 1
    if bad_inventory:
        (out / "assets.json").unlink()
    recover_checkpoints(out)
    assert credential_store.load_credentials(out).data["exposures"][0]["identity"] == "alice@example.com"
    assert not list(out.glob(".credential-checkpoint-*.json"))


def test_credentials_only_keeps_a_recoverable_checkpoint_when_sidecar_and_fallback_fail(tmp_path, monkeypatch):
    from farpoint import credential_store
    from farpoint.output import recover_checkpoints

    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    real = credential_store.write_atomic

    def fail(path, *args, **kwargs):
        if path.name == "credentials.json" or path.name.startswith("credentials.unmerged-"):
            raise PermissionError("injected credential write failure")
        return real(path, *args, **kwargs)

    with monkeypatch.context() as failing:
        failing.setattr(credential_store, "write_atomic", fail)
        assert cli.main([*argv, "-o", str(out)]) == 1
    assert not (out / "credentials.json").exists()
    recover_checkpoints(out)
    assert credential_store.load_credentials(out).data["exposures"][0]["identity"] == "alice@example.com"
    assert not list(out.glob(".credential-checkpoint-*")) and not list(out.glob(".checkpoint-*"))


def test_credentials_only_leaves_no_checkpoint_after_saving(tmp_path, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "-o", str(out)]) == 0
    assert (out / "credentials.json").exists()
    assert not list(out.glob(".credential-checkpoint-*")) and not list(out.glob(".checkpoint-*"))


def test_assess_recreates_missing_credential_exports(tmp_path, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "-o", str(out)]) == 0
    for name in ("credential-exposures.csv", "credential-summary.csv", "credential-checks.csv"):
        (out / name).unlink()
    assert cli.main(["--assess", "--no-cve", "-o", str(out)]) == 0
    assert read_csv(out / "credential-exposures.csv")[0]["identity"] == "alice@example.com"
    assert read_csv(out / "credential-checks.csv")[0]["status"] == "complete"
    assert read_csv(out / "credential-summary.csv") == []


def test_assess_clears_exports_after_sidecar_is_emptied(tmp_path, monkeypatch):
    import json

    from farpoint.credential_store import merge_credentials
    from farpoint.credentials import CredentialBatch

    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch, exposure_row())
    assert cli.main([*argv, "-o", str(out)]) == 0
    (out / "credentials.json").write_text(json.dumps(merge_credentials(None, CredentialBatch(STAMP))), encoding="utf-8")
    assert cli.main(["--assess", "--no-cve", "-o", str(out)]) == 0
    assert read_csv(out / "credential-exposures.csv") == []
    assert read_csv(out / "credential-checks.csv") == []


def test_the_cli_reports_no_data_checks(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    argv = _evidence(monkeypatch)
    assert cli.main([*argv, "-o", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "checks: 1 no data" in printed and "1 complete" not in printed


class FakeProvider:
    """A credential provider that returns one workforce exposure on www.example.com, or raises `fail`."""

    name = "hudsonrock-osint"
    kinds = frozenset({"email", "website"})

    def __init__(self, fail=None):
        self.fail = fail

    def operations(self, kinds):
        return [("email", "employee-urls")] if "email" in kinds else []

    def collect(self, domain, kinds):
        if self.fail:
            raise self.fail
        row = exposure_row(provider=self.name, operation="employee-urls", identity=None, provider_relationship="Employee",
                           service_host="www.example.com", occurrences=6, secret_evidence="dataset", event_at=None,
                           event_date_basis=None, scope_domain=domain)
        return {"exposures": [row], "summaries": []}


class RowsProvider:
    """An `acme-intel` provider that answers with the given rows."""

    name = "acme-intel"
    kinds = frozenset({"email", "website"})

    def __init__(self, exposures):
        self.exposures = list(exposures)

    def operations(self, kinds):
        return [(k, "stealers") for k in sorted(kinds) if k in self.kinds]

    def collect(self, domain, kinds):
        return {"exposures": self.exposures, "summaries": []}


def _evidence(monkeypatch, *exposures):
    """Serve these rows from an `acme-intel` provider; returns the arguments that collect them."""
    _providers(monkeypatch, RowsProvider(exposures))
    return ["--credentials", "acme-intel"]


def _providers(monkeypatch, provider):
    from farpoint.credential_sources import build_credential_providers

    def build(http, sources):
        return build_credential_providers(http, sources) | {provider.name: provider}

    monkeypatch.setattr(cli, "build_credential_providers", build)


def _counting_hudson(monkeypatch):
    """The real hudsonrock source over a fake network; returns the list of requests it made."""
    import httpx
    from conftest import HUDSON_ROUTE, fake_http, hudson_body

    from farpoint.sources.hudsonrock import HudsonRock

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=hudson_body(employee_urls=[("https://vpn.example.com/remote?token=SENTINEL", 3)], employees=2))

    hudson = HudsonRock(fake_http({HUDSON_ROUTE: handler}), backoff=0)
    monkeypatch.setattr(cli, "build_sources", lambda http, env, nameservers=(): [hudson])
    return calls


def _hosts(out):
    from farpoint.output import load_report

    return {h["hostname"] for h in load_report(out)["hosts"]}


def test_credentials_flag_collects_into_an_existing_inventory_and_assesses(tmp_path, monkeypatch, capsys):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    _providers(monkeypatch, FakeProvider())
    assert cli.main(["--credentials", "hudsonrock-osint", "--assess", "--no-cve", "-o", str(out)]) == 0
    assert "credential scope: example.com" in capsys.readouterr().err
    from farpoint.credential_store import load_credentials

    (row,) = load_credentials(out).data["exposures"]
    assert row["provider"] == "hudsonrock-osint" and row["occurrences"] == 6
    (finding,) = [f for f in read_csv(out / "findings.csv") if f["kind"] == "credential-theft"]
    assert finding["level"] == "medium" and "seen 6 times" in finding["detail"]


def test_one_hudson_request_serves_the_source_and_the_provider(tmp_path, monkeypatch):
    out = tmp_path / "out"
    calls = _counting_hudson(monkeypatch)
    assert cli.main(["example.com", "--no-resolve", "--no-enrich", "--credentials", "hudsonrock-osint", "-o", str(out)]) == 0
    assert len(calls) == 1
    assert "vpn.example.com" in _hosts(out)
    text = (out / "credentials.json").read_text(encoding="utf-8")
    assert "vpn.example.com" in text and "SENTINEL" not in text


def test_without_the_flag_the_source_runs_but_nothing_reaches_credentials_json(tmp_path, monkeypatch):
    out = tmp_path / "out"
    calls = _counting_hudson(monkeypatch)
    assert cli.main(["example.com", "--no-resolve", "--no-enrich", "-o", str(out)]) == 0
    assert len(calls) == 1 and "vpn.example.com" in _hosts(out)
    assert not (out / "credentials.json").exists()


def test_excluding_the_source_still_collects_credentials(tmp_path, monkeypatch):
    out = tmp_path / "out"
    calls = _counting_hudson(monkeypatch)
    argv = ["example.com", "--no-resolve", "--no-enrich", "--exclude", "hudsonrock", "--credentials", "hudsonrock-osint", "-o", str(out)]
    assert cli.main(argv) == 0
    assert len(calls) == 1 and "vpn.example.com" not in _hosts(out)
    assert "vpn.example.com" in (out / "credentials.json").read_text(encoding="utf-8")


def test_a_failed_provider_warns_and_keeps_exit_zero(tmp_path, monkeypatch, capsys):
    from farpoint.sources.base import SourceFailure

    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    _providers(monkeypatch, FakeProvider(fail=SourceFailure("HTTP 503 Service Unavailable after 5 attempts: https://x/?domain=example.com")))
    assert cli.main(["--credentials", "hudsonrock-osint", "-o", str(out)]) == 0
    assert "warning: hudsonrock-osint example.com: server" in capsys.readouterr().err
    assert [(c["status"], c["error"]) for c in read_csv(out / "credential-checks.csv")] == [("failed", "server")]


@pytest.mark.parametrize("scan", [False, True])
def test_ctrl_c_during_collection_changes_nothing(tmp_path, monkeypatch, capsys, scan):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    _providers(monkeypatch, FakeProvider(fail=KeyboardInterrupt()))
    argv = (_offline_scan(monkeypatch) if scan else []) + ["--credentials", "hudsonrock-osint", "-o", str(out)]
    assert cli.main(argv) == 130
    assert "interrupted: nothing changed" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


def test_list_sources_shows_credential_providers(capsys):
    assert cli.main(["--list-sources"]) == 0
    printed = capsys.readouterr().out
    assert "hudsonrock " in printed and "credential providers:" in printed
    assert "hudsonrock-osint" in printed and "hibp-public" in printed and "no key needed" in printed


@pytest.mark.parametrize("argv,message", [(["--credentials", "dehashed"], "choose from hudsonrock-osint, hibp-public"),
                                          (["--credentials", "hibp-public"], "add --credential-queries email,website")])
def test_credentials_argument_errors(tmp_path, capsys, argv, message):
    out = tmp_path / "out"
    with pytest.raises(SystemExit):
        cli.main(["example.com", *argv, "-o", str(out)])
    assert message in capsys.readouterr().err
    assert not out.exists()
