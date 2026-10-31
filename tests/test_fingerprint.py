from datetime import date, datetime, timedelta, timezone

import pytest

from farpoint.fingerprint import (
    DEFAULT_PORTS,
    Evidence,
    FingerprintConfig,
    cpe_for,
    end_of_life,
    favicon_hash,
    fingerprint_service,
    identify,
    murmur3_32,
    parse_ports,
    takeover_platform,
)
from farpoint.probe import HttpResult, SmtpResult, TlsResult, UnsupportedHere, cert_summary


def make_cert(cn="www.example.com", sans=("www.example.com",), days=90, self_signed=False, key_size=2048):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"), x509.NameAttribute(NameOID.COMMON_NAME, "R3")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - timedelta(days=400)).not_valid_after(now + timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class FakeProber:
    """A tiny network: banners per (ip, port), TLS per (host, port), HTTP per (scheme, host, port, path)."""

    def __init__(self, ports=None, banners=None, tls=None, http=None, smtp=None, legacy=()):
        self.ports, self.banners, self.tls_, self.http_, self.smtp_ = ports or {}, banners or {}, tls or {}, http or {}, smtp or {}
        self.legacy = set(legacy)
        self.calls = []

    def connect(self, ip, port):
        self.calls.append(("connect", ip, port))
        return self.ports.get((ip, port), "closed")

    def banner(self, ip, port, wait=3.0):
        self.calls.append(("banner", ip, port))
        return self.banners.get((ip, port), b"")

    def tls(self, host, ip, port, version=None):
        self.calls.append(("tls", host, port, version))
        if version:
            if version == "TLSv1":
                raise UnsupportedHere(version)
            return TlsResult(version) if (host, port, version) in self.legacy else None
        return self.tls_.get((host, port))

    def http(self, scheme, host, ip, port, path="/"):
        self.calls.append(("http", scheme, host, port, path))
        return self.http_.get((scheme, host, port, path), HttpResult(404, [], b"not found") if (scheme, host, port, "/") in self.http_ else None)

    def smtp(self, host, ip, port=25):
        self.calls.append(("smtp", host, port))
        return self.smtp_.get((host, port), SmtpResult())

    def axfr(self, ip, domain):
        self.calls.append(("axfr", ip, domain))
        return 0

    def fetch(self, url):
        return None


def test_murmur3_matches_the_reference_implementation():
    assert murmur3_32(b"hello") == 613153351
    assert murmur3_32(b"foo") == -156908512  # mmh3.hash("foo")
    assert murmur3_32(b"The quick brown fox jumps over the lazy dog") == 0x2E4FF723
    assert favicon_hash(b"\x00" * 10) == murmur3_32(b"AAAAAAAAAAAAAA==\n")


def test_rules_name_products_versions_and_cpes():
    ev = Evidence(
        headers={"server": "nginx/1.18.0 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        cnames=["portal-prod.azurewebsites.net"],
    )
    found = {t.name: t for t in identify(ev)}
    assert found["nginx"].version == "1.18.0" and found["nginx"].cpe == "cpe:2.3:a:f5:nginx:1.18.0"
    assert found["PHP"].version == "7.4.3"
    assert found["OpenSSH"].cpe == "cpe:2.3:a:openbsd:openssh:8.9:p1"  # as NVD lists OpenSSH versions
    assert found["Azure App Service"].category == "platform"
    assert "Apache HTTP Server" not in found


@pytest.mark.parametrize(
    "ev, name",
    [
        (Evidence(location="https://vpn.example.com/remote/login?lang=en"), "FortiGate SSL-VPN"),
        (Evidence(cookies=["SVPNCOOKIE"]), "FortiGate SSL-VPN"),
        (Evidence(body='<a href="/global-protect/login.esp">'), "Palo Alto GlobalProtect"),
        (Evidence(location="https://gw.example.com/logon/LogonPoint/index.html"), "Citrix NetScaler Gateway"),
        (Evidence(cookies=["BIGipServerpool_web"]), "F5 BIG-IP"),
        (Evidence(location="https://vpn.example.com/+CSCOE+/logon.html"), "Cisco ASA / AnyConnect"),
        (Evidence(location="https://ra.example.com/dana-na/auth/url_default/welcome.cgi"), "Ivanti Connect Secure"),
        (Evidence(headers={"x-owa-version": "15.1.2507.6"}), "Microsoft Exchange OWA"),
        (Evidence(generator="WordPress 6.4.2"), "WordPress"),
        (Evidence(headers={"x-jenkins": "2.401.3"}), "Jenkins"),
        (Evidence(headers={"server": "cloudflare", "cf-ray": "8a-LHR"}), "Cloudflare"),
        (Evidence(headers={"server": "Microsoft-IIS/8.5"}), "Microsoft IIS"),
        (Evidence(banner="220 mail.example.com ESMTP Exim 4.94.2 Ubuntu"), "Exim"),
        (Evidence(banner="\x4a\x00\x00\x00\x0a5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1\x00"), "MariaDB"),
        (Evidence(banner="\x4a\x00\x00\x00\x0a8.0.32\x00"), "MySQL"),
        (Evidence(cnames=["acme-mft-traffic.axwaycloud.co"]), "Axway SecureTransport"),
        (Evidence(title="MOVEit Transfer Sign On"), "Progress MOVEit Transfer"),
        (Evidence(location="https://files.example.com/goanywhere/auth/Login.xhtml"), "Fortra GoAnywhere MFT"),
        (Evidence(headers={"server": "Cleo Harmony/5.8.0.21 (Linux)"}), "Cleo Harmony / VLTrader / LexiCom"),
        (Evidence(title="kiteworks"), "Kiteworks"),
    ],
)
def test_attack_surface_rules(ev, name):
    assert name in {t.name for t in identify(ev)}


def test_mariadb_is_not_also_reported_as_mysql():
    names = {t.name for t in identify(Evidence(banner="\x4a\x00\x00\x00\x0a5.5.5-10.6.12-MariaDB\x00"))}
    assert names == {"MariaDB"}


def test_versions_come_from_the_matcher_that_has_one():
    found = {t.name: t for t in identify(Evidence(headers={"x-owa-version": "15.1.2507.6"}, location="https://mail.example.com/owa/"))}
    assert found["Microsoft Exchange OWA"].version == "15.1.2507.6"


def test_end_of_life_follows_version_prefixes_and_dates():
    assert end_of_life("PHP", "7.4.33", date(2026, 1, 1))["eol"] == "2022-11-28"
    assert end_of_life("PHP", "8.3.1", date(2026, 1, 1)) is None
    assert end_of_life("PHP", "8.2.10", date(2026, 1, 1)) is None  # not yet
    assert end_of_life("Microsoft IIS", "8.5", date(2026, 1, 1))["note"] == "Windows Server 2012 R2"
    assert end_of_life("Microsoft Exchange OWA", "15.2.1544.4", date(2026, 1, 1)) is not None
    assert end_of_life("Microsoft Exchange OWA", "15.2.2562.17", date(2026, 1, 1)) is None  # Subscription Edition
    assert end_of_life("nginx", "1.18.0", date(2026, 1, 1)) is None


def test_cpe_versions():
    assert cpe_for("a:f5:nginx", "1.25.3") == "cpe:2.3:a:f5:nginx:1.25.3"
    assert cpe_for("a:f5:nginx", None) is None


def test_port_lists():
    assert parse_ports("22,443") == (22, 443)
    assert set(parse_ports("+8081,9000-9001")) == set(DEFAULT_PORTS) | {8081, 9000, 9001}
    assert parse_ports("none") == ()
    with pytest.raises(ValueError):
        parse_ports("1-65535")
    with pytest.raises(ValueError):
        parse_ports("http")


def test_cert_summary_flags_what_matters():
    good = cert_summary(make_cert(), "www.example.com")
    assert good["matches"] and not good["self_signed"] and good["issuer"] == "Let's Encrypt" and good["key"] == "RSA 2048"
    bad = cert_summary(make_cert(cn="localhost", sans=(), days=-5, self_signed=True, key_size=1024), "www.example.com")
    assert bad["self_signed"] and not bad["matches"] and bad["days_left"] < 0 and bad["key"] == "RSA 1024"
    wildcard = cert_summary(make_cert(sans=("*.example.com",)), "api.example.com")
    assert wildcard["matches"] and wildcard["wildcard"]
    assert not cert_summary(make_cert(sans=("*.example.com",)), "a.b.example.com")["matches"]


HOST, IP = "www.example.com", "192.0.2.10"
HOME = HttpResult(
    200,
    [("server", "nginx/1.18.0"), ("set-cookie", "PHPSESSID=abc; path=/"), ("date", "x"), ("strict-transport-security", "max-age=1")],
    b'<html><head><title>Example &amp; Co</title><meta name="generator" content="WordPress 6.1.1">'
    b'<link rel="icon" href="/static/fav.png"><script src="/wp-content/plugins/contact-form-7/x.js?ver=5.7.1"></script></head>'
    b'<form><input type="password" name="p"></form></html>',
)


def test_a_web_service_is_read_from_headers_page_favicon_and_paths():
    prober = FakeProber(
        tls={(HOST, 443): TlsResult("TLSv1.3", "TLS_AES_128_GCM_SHA256", make_cert())},
        http={
            ("https", HOST, 443, "/"): HOME,
            ("https", HOST, 443, "/static/fav.png"): HttpResult(200, [], b"\x89PNGfake"),
            ("https", HOST, 443, "/.git/HEAD"): HttpResult(200, [], b"ref: refs/heads/main\n"),
            ("https", HOST, 443, "/robots.txt"): HttpResult(200, [], b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"),
        },
        legacy=[(HOST, 443, "TLSv1.1")],
    )

    rec = fingerprint_service(prober, HOST, IP, 443)

    assert (rec.service, rec.status, rec.title, rec.server) == ("https", 200, "Example & Co", "nginx/1.18.0")
    assert rec.cookies == ["PHPSESSID"] and "date" not in rec.headers
    assert rec.favicon == favicon_hash(b"\x89PNGfake")
    assert rec.paths["/robots.txt"]["note"] == "disallows /admin /backup"
    assert rec.paths["/.well-known/security.txt"] == {"status": 404}
    assert {"login-form", "version-disclosure"} <= set(rec.signals)
    assert not any(c[0] == "http" and ".git" in c[4] for c in prober.calls)
    names = {t.name: t for t in rec.tech}
    assert names["WordPress"].version == "6.1.1"
    assert names["WordPress plugin contact-form-7"].version == "5.7.1"
    assert rec.tls["version"] == "TLSv1.3" and rec.tls["matches"]
    assert rec.tls["legacy"] == {"TLSv1": None, "TLSv1.1": True}  # None: this machine can't offer TLS 1.0


def test_an_exposed_git_repository_is_found_when_asked_for():
    prober = FakeProber(
        tls={(HOST, 443): TlsResult("TLSv1.3", "TLS_AES_128_GCM_SHA256", make_cert())},
        http={("https", HOST, 443, "/"): HOME, ("https", HOST, 443, "/.git/HEAD"): HttpResult(200, [], b"ref: refs/heads/main\n")},
    )

    rec = fingerprint_service(prober, HOST, IP, 443, config=FingerprintConfig(paths=("/.git/HEAD",)))

    assert rec.paths["/.git/HEAD"] == {"status": 200, "note": "git repository exposed"}
    assert "git-exposed" in rec.signals


def test_redirects_are_followed_within_the_service_and_recorded_when_they_leave_it():
    prober = FakeProber(http={
        ("http", HOST, 80, "/"): HttpResult(301, [("location", "/en/")], b""),
        ("http", HOST, 80, "/en/"): HttpResult(302, [("location", "https://www.example.com/en/")], b""),
    })

    rec = fingerprint_service(prober, HOST, IP, 80, config=FingerprintConfig(paths=()))

    assert rec.status == 302 and rec.location == "https://www.example.com/en/"
    assert [c for c in prober.calls if c[0] == "http"][:2] == [("http", "http", HOST, 80, "/"), ("http", "http", HOST, 80, "/en/")]


def test_a_banner_service_is_identified_without_any_http():
    prober = FakeProber(banners={(IP, 22): b"SSH-2.0-OpenSSH_7.4\r\n"})

    rec = fingerprint_service(prober, HOST, IP, 22)

    assert rec.service == "ssh" and rec.banner == "SSH-2.0-OpenSSH_7.4"
    assert [t.name for t in rec.tech] == ["OpenSSH"]
    assert not any(c[0] in ("http", "tls") for c in prober.calls)


def test_silent_database_ports_get_no_traffic_beyond_the_sweep():
    prober = FakeProber()
    rec = fingerprint_service(prober, HOST, IP, 3389)
    assert rec.service == "rdp" and prober.calls == []


def test_smtp_reports_starttls_and_the_certificate():
    prober = FakeProber(smtp={(HOST, 25): SmtpResult("mail.example.com ESMTP Postfix (Ubuntu)", ["PIPELINING"], starttls=False)})

    rec = fingerprint_service(prober, HOST, IP, 25)

    assert rec.service == "smtp" and "no-starttls" in rec.signals and [t.name for t in rec.tech] == ["Postfix"]


def test_unknown_ports_try_banner_then_tls_then_http():
    prober = FakeProber(tls={(HOST, 8834): TlsResult("TLSv1.2", "x", make_cert())}, http={("https", HOST, 8834, "/"): HttpResult(200, [("server", "NessusWWW")], b"")})

    rec = fingerprint_service(prober, HOST, IP, 8834, config=FingerprintConfig(paths=(), legacy_tls=False))

    assert rec.service == "https" and rec.server == "NessusWWW"
    assert [c[0] for c in prober.calls] == ["banner", "tls", "http", "http"]  # page, favicon


def test_unclaimed_platform_pages_are_flagged_for_takeover():
    prober = FakeProber(http={("http", HOST, 80, "/"): HttpResult(404, [], b"<p>There isn't a GitHub Pages site here.</p>")})

    rec = fingerprint_service(prober, HOST, IP, 80, cnames=["example.github.io"], config=FingerprintConfig(paths=()))

    assert "takeover:GitHub Pages" in rec.signals
    assert takeover_platform("old-app.azurewebsites.net") == "Azure"
    assert takeover_platform("www.example.com") is None


@pytest.mark.parametrize(
    "ev",
    [
        Evidence(location="https://login.example.com/connect/authorize?client_id=x"),  # OAuth, not Check Point
        Evidence(body="Welcome to our online storefront"),
        Evidence(title="Jenkins & Co Solicitors"),
        Evidence(title="Gitlab tips for beginners - Blog"),
        Evidence(title="Barracuda Networks partner page"),
        Evidence(body='<a href="/ecp/">Our ECP programme</a>'),
        Evidence(title="What the MOVEit Transfer breach taught us - Blog"),
        Evidence(title="Cleo's guide to EDI"),
    ],
)
def test_ordinary_pages_are_not_mistaken_for_products(ev):
    assert {t.category for t in identify(ev)} & {"edge", "file-transfer", "panel", "remote-access", "mail"} == set()


@pytest.mark.parametrize("title, parked", [
    ("Domain registered | Dynadot", True),
    ("example.com is for sale | HugeDomains", True),
    ("Parked Domain name on Hostinger DNS system", True),
    ("This domain is for sale", True),
    ("Register a domain name today - Acme Hosting", False),
    ("1967 Riva Aquarama is for sale - Acme Marine", False),
])
def test_parking_pages_are_recognised(title, parked):
    assert ("Parking page" in {t.name for t in identify(Evidence(title=title))}) is parked


def test_title_rules_still_catch_the_real_products():
    assert {"Jenkins", "GitLab"} <= {t.name for t in identify(Evidence(title="Dashboard [Jenkins]"))} | {t.name for t in identify(Evidence(title="Sign in · GitLab"))}


def test_a_malformed_redirect_port_does_not_lose_the_service():
    prober = FakeProber(http={("http", HOST, 80, "/"): HttpResult(302, [("location", "http://www.example.com:abc/login")], b"")})
    rec = fingerprint_service(prober, HOST, IP, 80, config=FingerprintConfig(paths=()))
    assert rec.status == 302 and rec.location == "http://www.example.com:abc/login"


def test_a_mail_server_that_never_answered_ehlo_is_not_called_cleartext():
    prober = FakeProber(smtp={(HOST, 25): SmtpResult()})  # timed out before EHLO
    assert "no-starttls" not in fingerprint_service(prober, HOST, IP, 25).signals
