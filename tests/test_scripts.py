"""--scripts: a web service's own JavaScript, for the hostnames and API paths it names."""

from farpoint.fingerprint import FingerprintConfig, fingerprint_service
from farpoint.models import Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.probe import HttpResult, TlsResult
from farpoint.resolve import Resolution

from test_fingerprint import FakeProber
from test_pipeline import StaticSource, dns_table
from test_posture import FakeDns

H, IP = "www.example.com", "93.184.216.34"
HOME = (b"<html><script src='/static/app.js?v=3'></script><script src='https://cdn.thirdparty.net/lib.js'></script>"
        b"<script src='//www.example.com:8443/other-port.js'></script><script>var base = 'https://sso.example.com/login';</script></html>")
APP = (b"const api = 'https://api-internal.example.com/v1'; fetch('/api/v2/users?id=1'); post(\"/graphql\");"
       b"var docs = 'https://www.example.com.evil.io/x'; route('/about');")


def prober():
    return FakeProber(
        ports={(IP, 443): "open"}, tls={(H, 443): TlsResult("TLSv1.3")},
        http={("https", H, 443, "/"): HttpResult(200, [], HOME), ("https", H, 443, "/static/app.js?v=3"): HttpResult(200, [], APP)},
    )


def test_only_the_services_own_scripts_are_fetched_and_their_api_paths_recorded():
    p = prober()

    svc = fingerprint_service(p, H, IP, 443, config=FingerprintConfig(paths=(), legacy_tls=False, scripts=True))

    fetched = [c[4] for c in p.calls if c[0] == "http" and c[4] not in ("/", "/favicon.ico")]
    assert fetched == ["/static/app.js?v=3"]  # never the third party's or another port's
    assert svc.api_paths == ["/api/v2/users", "/graphql"]
    assert {"api-internal.example.com", "sso.example.com"} <= set(svc.links)


def test_names_in_url_encoded_or_js_escaped_text_are_read_without_the_escape():
    home = (b"<a href='/sso?next=https%3A%2F%2Ftriview.example.com%2Flogin'>x</a>"
            rb"<script>var u = 'https:\u002F\u002Fportal.example.com\x2Fapp';</script>")
    p = FakeProber(ports={(IP, 443): "open"}, tls={(H, 443): TlsResult("TLSv1.3")},
                   http={("https", H, 443, "/"): HttpResult(200, [], home)})

    svc = fingerprint_service(p, H, IP, 443, config=FingerprintConfig(paths=(), legacy_tls=False, scripts=True))

    assert {"triview.example.com", "portal.example.com"} <= set(svc.links)
    assert not [n for n in svc.links if n.startswith(("2f", "u002f", "x2f"))]


def test_without_scripts_nothing_more_is_fetched():
    p = prober()
    svc = fingerprint_service(p, H, IP, 443, config=FingerprintConfig(paths=(), legacy_tls=False))
    assert not [c for c in p.calls if c[0] == "http" and "app.js" in c[4]] and svc.api_paths == []


def test_hostnames_scripts_name_join_the_inventory_resolved_and_api_paths_are_saved(tmp_path):
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", H)])],
        lookup=dns_table({H: Resolution(ips=(IP,)), "api-internal.example.com": Resolution(ips=("93.184.216.99",))}),
        dns=FakeDns({}), prober=prober(),
        fingerprint=FingerprintConfig(ports=(443,), paths=(), rate=None, legacy_tls=False, scripts=True),
    )

    inv = pipeline.run(["example.com"])

    assert inv.hosts["api-internal.example.com"].sources == {"javascript", "dns"} and inv.hosts["api-internal.example.com"].resolves
    assert "cdn.thirdparty.net" not in inv.hosts and "www.example.com.evil.io" not in inv.hosts
    report = write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")
    assert next(r for r in report["fingerprints"] if r["endpoint"] == f"{H}:443")["api_paths"] == ["/api/v2/users", "/graphql"]
    assert "api_paths" in (tmp_path / "fingerprints.csv").read_text().splitlines()[0]


def test_api_paths_are_whole_path_segments():
    from farpoint.fingerprint import _API_PATH

    found = _API_PATH.findall("'/apiary.js' '/authors/list' '/administrator' '/api' '/v2/x' \"/graphql?q=1\"")
    assert sorted(found) == ["/api", "/graphql", "/v2/x"]
