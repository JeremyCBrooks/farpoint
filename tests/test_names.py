import pytest

from farpoint.names import extract_hostnames, in_scope, normalize_hostname, normalize_ip, parse_domains


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("WWW.Example.COM", "www.example.com"),
        ("*.example.com", "example.com"),
        ("api.example.com.", "api.example.com"),
        ("  mail.example.com\t", "mail.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("admin@example.com", None),  # crt.sh name_value can contain emails
        ("1.2.3.4", None),
        ("exa mple.com", None),
        ("-bad.example.com", None),
        ("", None),
        ("localhost", None),
    ],
)
def test_normalize_hostname(raw, want):
    assert normalize_hostname(raw) == want


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        (" 1.1.1.1 ", "1.1.1.1"),
        ("999.1.1.1", None),
        ("cname.example.net", None),
        (None, None),
    ],
)
def test_normalize_ip(raw, want):
    assert normalize_ip(raw) == want


@pytest.mark.parametrize(
    ("hostname", "want"),
    [
        ("example.com", True),
        ("a.b.example.com", True),
        ("notexample.com", False),
        ("example.com.evil.net", False),
        ("example.co", False),
    ],
)
def test_in_scope(hostname, want):
    assert in_scope(hostname, "example.com") is want


def test_extract_hostnames_finds_only_in_scope_names_in_free_text():
    text = """
    <tr><td>dev.example.com</td><td>1.2.3.4</td></tr>
    <td>WWW.EXAMPLE.COM</td> https://shop.example.com:8443/cart
    notexample.com  vpn.example.com.evil.net  sentence ends with mx.example.com.
    """
    assert extract_hostnames(text, "example.com") == {
        "dev.example.com",
        "www.example.com",
        "shop.example.com",
        "mx.example.com",
    }


def test_parse_domains_accepts_urls_and_ignores_comments_and_blanks():
    lines = ["# corp domains", "", "Example.com", "https://www.example.org/login", "example.com", "  "]
    assert parse_domains(lines) == ["example.com", "www.example.org"]
