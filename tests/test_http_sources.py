import httpx
import pytest

from conftest import fake_http, pairs, when_params
from easm.sources.base import SourceFailure
from easm.sources.web import (
    CertSpotter,
    CrtSh,
    HackerTarget,
    Otx,
    RapidDns,
    Shodan,
    UrlScan,
    VirusTotal,
    Wayback,
)

D = "example.com"


def test_crtsh_queries_wildcard_and_splits_multi_name_certificates():
    body = [
        {"id": 1, "common_name": "example.com", "name_value": "example.com\nwww.example.com"},
        {"id": 2, "common_name": "*.dev.example.com", "name_value": "*.dev.example.com"},
    ]
    http = fake_http({"crt.sh/": when_params({"q": "%.example.com", "output": "json"}, httpx.Response(200, json=body))})

    got = pairs(CrtSh(http).collect(D))

    assert got == {("example.com", None), ("www.example.com", None), ("*.dev.example.com", None)}


def test_http_source_retries_transient_server_errors():
    http = fake_http({"crt.sh/": [httpx.Response(502), httpx.Response(200, json=[{"name_value": "a.example.com"}])]})

    assert pairs(CrtSh(http, backoff=0).collect(D)) == {("a.example.com", None)}


def test_http_source_retries_after_rate_limit():
    http = fake_http({"crt.sh/": [httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json=[{"name_value": "a.example.com"}])]})

    assert pairs(CrtSh(http, backoff=0).collect(D)) == {("a.example.com", None)}


def test_http_source_gives_up_after_retries_with_failure():
    http = fake_http({"crt.sh/": [httpx.Response(503)] * 5})

    with pytest.raises(httpx.HTTPStatusError):
        list(CrtSh(http, backoff=0).collect(D))


def test_certspotter_pages_with_after_cursor_and_sends_key():
    page1 = [{"id": "100", "dns_names": ["example.com", "www.example.com"]}]
    page2 = [{"id": "200", "dns_names": ["*.api.example.com"]}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer k3y":
            return httpx.Response(401)
        after = request.url.params.get("after")
        return httpx.Response(200, json={None: page1, "100": page2}.get(after, []))

    got = pairs(CertSpotter(fake_http({"api.certspotter.com/v1/issuances": handler}), api_key="k3y").collect(D))

    assert got == {("example.com", None), ("www.example.com", None), ("*.api.example.com", None)}


def test_hackertarget_parses_host_ip_csv():
    text = "www.example.com,93.184.216.34\nmail.example.com,93.184.216.35\n"
    http = fake_http({"api.hackertarget.com/hostsearch/": when_params({"q": D}, httpx.Response(200, text=text))})

    assert pairs(HackerTarget(http).collect(D)) == {
        ("www.example.com", "93.184.216.34"),
        ("mail.example.com", "93.184.216.35"),
    }


def test_hackertarget_quota_message_is_a_failure_not_an_empty_result():
    http = fake_http({"api.hackertarget.com/hostsearch/": httpx.Response(200, text="API count exceeded - Increase Quota with Membership")})

    with pytest.raises(SourceFailure, match="API count exceeded"):
        list(HackerTarget(http).collect(D))


def test_wayback_extracts_hostnames_from_archived_urls():
    text = "https://www.example.com/index.html\nhttp://old.example.com:8080/a?b=c\nhttps://www.example.com/about\n"
    http = fake_http({"web.archive.org/cdx/search/cdx": when_params({"url": "*.example.com"}, httpx.Response(200, text=text))})

    assert pairs(Wayback(http).collect(D)) == {("www.example.com", None), ("old.example.com", None)}


def test_otx_passive_dns_yields_hostname_and_address():
    body = {
        "count": 2,
        "passive_dns": [
            {"hostname": "vpn.example.com", "address": "198.51.100.4", "record_type": "A", "asn": "AS64500", "first": "2024-01-01T00:00:00", "last": "2025-01-01T00:00:00"},
            {"hostname": "shop.example.com", "address": "shops.myshopify.com", "record_type": "CNAME", "asn": None, "first": "2024-01-01T00:00:00", "last": "2025-01-01T00:00:00"},
        ],
    }
    http = fake_http({"otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns": httpx.Response(200, json=body)})

    assert pairs(Otx(http).collect(D)) == {("vpn.example.com", "198.51.100.4"), ("shop.example.com", "shops.myshopify.com")}


def test_urlscan_reads_page_and_task_domains():
    body = {
        "results": [
            {"page": {"domain": "portal.example.com", "ip": "203.0.113.5", "url": "https://portal.example.com/"}, "task": {"domain": "portal.example.com", "url": "https://portal.example.com/"}},
            {"page": {"domain": "login.thirdparty.net", "ip": "192.0.2.1"}, "task": {"domain": "sso.example.com"}},
        ],
        "total": 2,
    }
    http = fake_http({"urlscan.io/api/v1/search/": when_params({"q": "domain:example.com"}, httpx.Response(200, json=body))})

    assert pairs(UrlScan(http).collect(D)) == {
        ("portal.example.com", "203.0.113.5"),
        ("login.thirdparty.net", "192.0.2.1"),
        ("sso.example.com", None),
    }


def test_rapiddns_pairs_hostname_with_ip_from_same_table_row():
    html = """<table><tbody>
    <tr><th>1</th><td>ftp.example.com</td><td><a href="/sameip/192.0.2.10">192.0.2.10</a></td><td>A</td></tr>
    <tr><th>2</th><td>www.example.com</td><td>edge.cdn.net</td><td>CNAME</td></tr>
    </tbody></table>"""
    http = fake_http({"rapiddns.io/subdomain/example.com": httpx.Response(200, text=html)})

    assert pairs(RapidDns(http).collect(D)) == {("ftp.example.com", "192.0.2.10"), ("www.example.com", None)}


def test_shodan_is_unavailable_without_api_key():
    assert Shodan(fake_http({})).available() is False


def test_shodan_dns_maps_subdomain_labels_and_address_records():
    body = {
        "domain": "example.com",
        "subdomains": ["www", "api"],
        "data": [
            {"subdomain": "www", "type": "A", "value": "93.184.216.34", "last_seen": "2025-01-01T00:00:00"},
            {"subdomain": "", "type": "MX", "value": "mx.mailhost.net", "last_seen": "2025-01-01T00:00:00"},
            {"subdomain": "api", "type": "CNAME", "value": "api.herokuapp.com", "last_seen": "2025-01-01T00:00:00"},
        ],
        "more": False,
    }
    http = fake_http({"api.shodan.io/dns/domain/example.com": when_params({"key": "sk"}, httpx.Response(200, json=body))})

    assert pairs(Shodan(http, api_key="sk").collect(D)) == {
        ("www.example.com", "93.184.216.34"),
        ("www.example.com", None),
        ("api.example.com", None),
        ("example.com", None),
    }


def test_virustotal_follows_next_link():
    p1 = {"data": [{"id": "a.example.com", "type": "domain"}], "links": {"next": "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=c2"}}
    p2 = {"data": [{"id": "b.example.com", "type": "domain"}], "links": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-apikey") != "vt":
            return httpx.Response(401)
        return httpx.Response(200, json=p2 if request.url.params.get("cursor") == "c2" else p1)

    http = fake_http({"www.virustotal.com/api/v3/domains/example.com/subdomains": handler})

    assert pairs(VirusTotal(http, api_key="vt").collect(D)) == {("a.example.com", None), ("b.example.com", None)}
