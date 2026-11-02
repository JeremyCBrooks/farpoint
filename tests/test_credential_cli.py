import pytest

from conftest import exposure_row, read_csv, sample_inventory, write_import
from farpoint import cli
from farpoint.output import write_outputs

STAMP = "2026-10-01T00:00:00Z"


def test_import_into_an_existing_inventory_and_assess(tmp_path, capsys):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    path = write_import(tmp_path / "e.json", [exposure_row(), exposure_row(identity="x@other.org")])
    assert cli.main(["--credential-import", str(path), "--assess", "--no-cve", "-o", str(out)]) == 0
    printed, err = capsys.readouterr()
    assert "credential scope: example.com" in err and "1 import rows outside scope were dropped" in printed
    assert "assessment: current" in printed and "alice" not in printed + err
    assert any(r["kind"] == "credential-theft" for r in read_csv(out / "findings.csv"))


def test_credentials_only_mode_needs_an_inventory_and_touches_nothing(tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "credentials.json").write_bytes(b'{"keep": "me"}')
    path = write_import(tmp_path / "e.json", [exposure_row()])
    assert cli.main(["--credential-import", str(path), "-o", str(out)]) == 2
    assert "no inventory in" in capsys.readouterr().err
    assert (out / "credentials.json").read_bytes() == b'{"keep": "me"}' and not (out / "assets.json").exists()


@pytest.mark.parametrize("argv,message", [(["--credential-queries", "email", "--assess"], "add one of them"),
                                          (["--credential-import", "e.json", "--credential-queries", "sms"], "unknown kind")])
def test_credential_argument_errors(tmp_path, capsys, argv, message):
    out = tmp_path / "out"
    with pytest.raises(SystemExit):
        cli.main(["example.com", *argv, "-o", str(out)])
    assert message in capsys.readouterr().err
    assert not out.exists()  # rejected before recovery, saves or requests


def test_a_bad_import_is_rejected_before_a_scan_touches_the_directory(tmp_path, capsys):
    out = tmp_path / "out"
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--credential-import", str(bad), "-o", str(out)])
    assert capsys.readouterr().err and not out.exists()


def test_a_disabled_kind_rejects_the_import_before_anything_is_saved(tmp_path, capsys):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    path = write_import(tmp_path / "e.json", [exposure_row(query_kind="website", identity="c@gmail.com", service_host="www.example.com")])
    assert cli.main(["--credential-import", str(path), "-o", str(out)]) == 2
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before
    assert cli.main(["--credential-import", str(path), "--credential-queries", "email,website", "-o", str(out)]) == 0


def test_no_sentinel_secret_reaches_any_file_or_message(tmp_path, capsys):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    path = write_import(tmp_path / "e.json", [exposure_row(service_host="https://u:SENTINEL-PW@www.example.com/?session=SENTINEL-COOKIE",
                                                           reference="https://intel.example.net/c?token=SENTINEL-TOKEN#SENTINEL")])
    assert cli.main(["--credential-import", str(path), "--assess", "--no-cve", "-o", str(out)]) == 0
    printed, err = capsys.readouterr()
    assert "SENTINEL" not in printed + err
    for f in out.rglob("*"):
        if f.is_file():
            assert b"SENTINEL" not in f.read_bytes(), f.name


def test_infrastructure_outputs_never_contain_identities(tmp_path):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    path = write_import(tmp_path / "e.json", [exposure_row()])
    assert cli.main(["--credential-import", str(path), "--assess", "--no-cve", "-o", str(out)]) == 0
    allowed = {"credentials.json", "credential-exposures.csv"}
    checked = 0
    for f in out.iterdir():
        if f.is_file() and f.name not in allowed:
            checked += 1
            assert b"alice" not in f.read_bytes(), f.name
    assert checked > 3 and (out / "credential-exposures.csv").exists()


def test_reassessing_without_new_evidence_keeps_credential_findings_current(tmp_path, capsys):
    out = tmp_path / "out"
    write_outputs(sample_inventory(), out, STAMP)
    path = write_import(tmp_path / "e.json", [exposure_row()])
    assert cli.main(["--credential-import", str(path), "-o", str(out)]) == 0
    assert "(run --assess to update)" in capsys.readouterr().out
    assert not (out / "findings.csv").exists()  # never assessed, so no credential findings yet
    assert cli.main(["--assess", "--no-cve", "-o", str(out)]) == 0
    assert "assessment: current" in capsys.readouterr().out
    assert any(r["kind"] == "credential-theft" for r in read_csv(out / "findings.csv"))
