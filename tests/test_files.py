import json

from conftest import read_csv

from farpoint.models import Inventory, Observation, TenantRecord
from farpoint.output import write_outputs


def test_csv_cells_that_spreadsheets_would_run_are_quoted(tmp_path):
    inv = Inventory(["example.com"])
    inv.add(Observation("input", "example.com"))
    risky = {"=HYPERLINK(\"http://x\")", "+cmd", "-1+1", "@SUM(1)", "\tx", "\rx"}
    inv.tenants["example.zendesk.com"] = TenantRecord("example.zendesk.com", "Zendesk", "example.com", "name", False, {*risky, "plain", "two words"})
    write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")

    row = read_csv(tmp_path / "tenants.csv")[0]
    cells = row["evidence"].split("; ")
    assert set(cells) == {*(f"'{v}" for v in risky), "plain", "two words"}
    assert all(c.startswith("'") for c in cells if c not in ("plain", "two words"))
    assert json.loads((tmp_path / "assets.json").read_text())["tenants"][0]["evidence"][0].startswith(("+", "-", "=", "@", "\t", "\r"))
