"""Public code that mentions the organisation (GitHub code search): its hostnames, and files that name the
domain next to a credential word (--code), recorded without the text itself."""

import csv

import httpx
import pytest

from conftest import fake_http, pairs
from farpoint import cli
from farpoint.assess import derive
from farpoint.models import Observation
from farpoint.output import run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.sources.github import GitHubCode

from test_pipeline import StaticSource

D = "example.com"


def item(repo, path, fragment="", url=None):
    return {"path": path, "html_url": url or f"https://github.com/{repo}/blob/main/{path}", "repository": {"full_name": repo},
            "text_matches": [{"fragment": fragment}]}


def search(pages_by_query):
    seen = []

    def handler(request):
        seen.append(request)
        q, page = request.url.params["q"], int(request.url.params.get("page", "1"))
        assert request.headers["authorization"] == "Bearer t0ken" and "text-match" in request.headers["accept"]
        pages = pages_by_query.get(q, [[]])
        items = pages[page - 1] if page <= len(pages) else []
        return httpx.Response(200, json={"total_count": sum(map(len, pages)), "items": items})

    return fake_http({"api.github.com/search/code": handler}), seen


def test_github_code_search_yields_the_in_scope_hostnames_its_matches_mention():
    pages = [[item("acme/deploy", "hosts.yml", "api: https://api.example.com/v2 and https://www.example.com.evil.io")] * 100,
             [item("acme/app", "README.md", "see grafana.internal.example.com")]]
    http, seen = search({'"example.com"': pages})

    got = pairs(GitHubCode(http, "t0ken").collect(D))

    assert got == {("api.example.com", None), ("grafana.internal.example.com", None)}
    assert len(seen) == 2  # the second page had fewer than a page's worth: no third request
    assert not GitHubCode(http, None).available()


def test_leads_name_the_file_and_the_word_but_never_keep_what_the_file_says():
    secret_line = "DB_PASSWORD=hunter2 # prod.example.com"
    http, _ = search({'"example.com" password': [[item("someone/dotfiles", "config/.env", secret_line)]],
                      '"example.com" api_key': [[item("acme/docs", "docs/usage.md", "api_key: <yours> for api.example.com")]]})

    leads = list(GitHubCode(http, "t0ken").leads(D))

    assert {(l["repository"], l["path"], l["keyword"]) for l in leads} == {("someone/dotfiles", "config/.env", "password"), ("acme/docs", "docs/usage.md", "api_key")}
    assert "hunter2" not in repr(leads)


class FakeCode:
    def __init__(self, leads):
        self._leads = leads

    def leads(self, domain):
        return [dict(l, domain=domain) for l in self._leads]


def test_code_leads_are_saved_and_judged_config_files_higher(tmp_path):
    code = FakeCode([
        {"url": "https://github.com/someone/dotfiles/blob/main/config/.env", "repository": "someone/dotfiles", "path": "config/.env", "keyword": "password"},
        {"url": "https://github.com/acme/docs/blob/main/docs/usage.md", "repository": "acme/docs", "path": "docs/usage.md", "keyword": "api_key"},
    ])
    inv = Pipeline(sources=[StaticSource("crtsh", [Observation("crtsh", "www.example.com")])], code=code).run([D])

    report = write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")

    levels = {f["target"]: f["level"] for f in derive(report) if f["kind"] == "code-leak-lead"}
    assert levels == {"someone/dotfiles/config/.env": "medium", "acme/docs/docs/usage.md": "low"}
    with open(tmp_path / "code.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["path"] for r in rows} == {"config/.env", "docs/usage.md"} and set(rows[0]) >= {"url", "repository", "keyword", "domain", "first_seen"}


def test_cli_needs_a_github_token_for_code(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--code", "-o", str(tmp_path)])
    assert "--code needs GITHUB_TOKEN" in capsys.readouterr().err
