from datetime import date, timedelta

import httpx
import pytest

from farpoint.archive import WaybackArchive
from conftest import fake_http, when_params

HOME = "web.archive.org/web/20260830101500id_/https://www.example.com/"


def wayback(cdx_rows, page=None):
    since = (date.today() - timedelta(days=365)).strftime("%Y%m%d")
    routes = {"web.archive.org/cdx/search/cdx": when_params({"url": "www.example.com/", "limit": "-1", "from": since}, httpx.Response(200, json=cdx_rows))}
    if page is not None:
        routes[HOME] = page
    return WaybackArchive(fake_http(routes))


def test_the_newest_archived_homepage_comes_back_with_the_sites_own_headers():
    page = httpx.Response(200, headers={"server": "Archive.org", "x-archive-orig-server": "nginx/1.14.0", "x-archive-orig-x-powered-by": "PHP/7.2.1"},
                          content=b"<title>Home</title>")

    got = wayback([["timestamp", "original"], ["20260830101500", "https://www.example.com/"]], page).capture("www.example.com")

    assert (got.captured, got.url) == ("2026-08-30", "https://www.example.com/")
    assert dict(got.page.headers) == {"server": "nginx/1.14.0", "x-powered-by": "PHP/7.2.1"}  # never the archive's own
    assert got.page.status == 200 and got.page.body == b"<title>Home</title>"


def test_a_host_with_no_recent_capture_has_none():
    assert wayback([]).capture("www.example.com") is None
    assert wayback([["timestamp", "original"]]).capture("www.example.com") is None


@pytest.mark.network
def test_the_wayback_machine_has_a_recent_copy_of_example_com():
    with httpx.Client(timeout=60, follow_redirects=True) as http:
        got = WaybackArchive(http).capture("example.com")

    assert got is not None and b"Example Domain" in got.page.body
