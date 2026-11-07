"""What a web service's own answers reveal: products by favicon, cookies sent without Secure, and login
pages any site can frame."""

from farpoint.assess import derive
from farpoint.fingerprint import FingerprintConfig, favicon_hash, fingerprint_service, load_rules
from farpoint.models import Inventory
from farpoint.output import run_report
from farpoint.probe import HttpResult, TlsResult

from test_fingerprint import FakeProber

H, IP = "ci.example.com", "93.184.216.34"
CONFIG = FingerprintConfig(paths=(), legacy_tls=False)
ICON = b"\x00\x00\x01\x00 a product's own icon"


def service(home: HttpResult, icon: bytes | None = None, rules=None):
    http = {("https", H, 443, "/"): home}
    if icon is not None:
        http[("https", H, 443, "/favicon.ico")] = HttpResult(200, [("content-type", "image/x-icon")], icon)
    prober = FakeProber(tls={(H, 443): TlsResult("TLSv1.3")}, http=http)
    return fingerprint_service(prober, H, IP, 443, config=CONFIG, rules=rules)


def findings(svc):
    inv = Inventory(["example.com"])
    inv.services[svc.key] = svc
    return {f["kind"]: f for f in derive(run_report(inv))}


def test_a_product_is_named_by_its_favicon_when_the_page_says_nothing_else():
    rules = load_rules({"rules": [{"name": "Jenkins", "category": "panel", "match": [{"favicon": f"^{favicon_hash(ICON)}$"}]}]})

    svc = service(HttpResult(200, [], b"<html>please wait</html>"), ICON, rules)

    assert [(t.name, t.evidence) for t in svc.tech] == [("Jenkins", f"favicon: {favicon_hash(ICON)}")]
    assert "admin-interface" in findings(svc)
    assert service(HttpResult(200, [], b"<html>please wait</html>"), b"another icon", rules).tech == []


def test_bundled_favicon_rules_match_only_the_exact_hash():
    import re

    from farpoint.fingerprint import bundled_rules

    patterns = {r.name: m.regex.pattern for r in bundled_rules() for m in r.matchers if m.field == "favicon"}
    assert "Jenkins" in patterns
    assert all(re.fullmatch(r"\^-?\d+\$", p) for p in patterns.values())  # unanchored, 81586312 would also match 1815863120


def test_cookies_set_over_https_without_secure_are_named():
    home = HttpResult(200, [("set-cookie", "JSESSIONID=abc; Path=/; HttpOnly"), ("set-cookie", "pref=x; Secure"),
                            ("strict-transport-security", "max-age=1")], b"<title>Home</title>")

    svc = service(home)

    assert "insecure-cookie:JSESSIONID" in svc.signals and not any("pref" in s for s in svc.signals)
    found = findings(svc)["cookie-without-secure"]
    assert found["level"] == "low" and found["evidence"] == ["JSESSIONID"]


def test_a_login_page_any_site_can_frame_is_a_clickjacking_finding_and_a_protected_one_is_not():
    login = b"<form><input type='password' name='p'></form>"

    assert "login-frameable" in findings(service(HttpResult(200, [], login)))
    for header in (("x-frame-options", "DENY"), ("content-security-policy", "default-src 'self'; frame-ancestors 'none'")):
        assert "login-frameable" not in findings(service(HttpResult(200, [header], login)))
    assert "login-frameable" not in findings(service(HttpResult(200, [], b"<title>no login here</title>")))
