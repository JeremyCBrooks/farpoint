import json

from farpoint import visibility


def web(endpoint, signals=(), status=200, title=None, headers=None, service="https"):
    host, port = endpoint.rsplit(":", 1)
    return {"endpoint": endpoint, "hostname": host, "port": int(port), "service": service, "status": status,
            "title": title, "headers": headers or {}, "signals": list(signals), "tech": []}


REPORT = {"fingerprints": [
    web("www.example.com:443"),
    web("shop.example.com:443", ["bot-challenge:cloudflare"], 403),
    web("api.example.com:443", ["bot-block:akamai"], 403),
    web("old.example.com:443", ["bot-challenge"], 403),  # recorded before signals named the vendor
    # recorded before farpoint marked bot defences at all: read again from what was kept
    web("older.example.com:443", [], 403, "Attention Required! | Cloudflare", {"server": "cloudflare"}),
    web("mail.example.com:22", service="ssh"),  # not a web service
]}


def test_a_scan_says_how_much_of_the_web_was_hidden_and_by_whom():
    assert visibility.summarise(REPORT) == {
        "web": 5,
        "seen": 1,
        "challenged": {"cloudflare": 2, "unknown": 1},
        "blocked": {"akamai": 1},
    }


def test_the_report_can_be_read_from_any_scan_directory(tmp_path, capsys):
    (tmp_path / "assets.json").write_text(json.dumps(REPORT))

    assert visibility.main([str(tmp_path)]) == 0

    out = capsys.readouterr().out
    assert "web services  5" in out
    assert "challenged    3  (cloudflare 2, unknown 1)" in out
    assert "blocked       1  (akamai 1)" in out
