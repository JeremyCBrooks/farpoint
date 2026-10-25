import socket

import httpx
import pytest

from farpoint.assess import Nvd
from farpoint.enrich import Rdap
from farpoint.fingerprint import FingerprintConfig, fingerprint_service
from farpoint.posture import assess_domain
from farpoint.probe import NetworkProber
from farpoint.resolve import DnsResolver

pytestmark = pytest.mark.network


def test_example_com_https_is_fingerprinted():
    ip = socket.gethostbyname("example.com")
    rec = fingerprint_service(NetworkProber(), "example.com", ip, 443, config=FingerprintConfig(paths=("/robots.txt",)))
    assert rec.service == "https" and rec.status == 200 and rec.title
    assert rec.tls["matches"] and rec.tls["days_left"] > 0 and not rec.tls["self_signed"]


def test_example_com_posture():
    resolver = DnsResolver()
    rdap = Rdap(httpx.Client(timeout=30, follow_redirects=True))
    row = assess_domain(resolver, NetworkProber(), "example.com", lambda h: h.endswith("example.com"), rdap=rdap.domain)
    assert row["spf"] and row["spf_all"] == "-all"  # a domain that sends no mail says so
    assert row["ns"] and row["expires"] and row["registrar"]
    assert row["axfr"] == []  # Cloudflare's nameservers: asked, since customers can open transfers, and refused


def test_nvd_lists_cves_for_an_old_nginx():
    cves = Nvd(httpx.Client(timeout=60)).cves("cpe:2.3:a:f5:nginx:1.18.0")
    assert "CVE-2021-23017" in {c["id"] for c in cves}
