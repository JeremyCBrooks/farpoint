import base64

from easm.posture import assess_domain, check_dkim, check_dmarc, check_spf, dkim_key_bits, hosted, mail_provider, registration
from easm.probe import HttpResult

from test_fingerprint import FakeProber

D = "example.com"


class FakeDns:
    """Zones: name -> {rdtype: [values]}. A name absent from `zones` doesn't exist."""

    def __init__(self, zones):
        self.zones = zones
        self.asked = []

    def records(self, name, rdtype, strict=False):
        self.asked.append((name, rdtype))
        if strict and self.zones.get(name, {}).get(rdtype) == "SERVFAIL":
            raise RuntimeError("SERVFAIL")
        if name not in self.zones:
            return None
        return list(self.zones[name].get(rdtype, []))

    def txt(self, name):
        self.asked.append((name, "TXT"))
        return list(self.zones.get(name, {}).get("TXT", []))


def rsa_record(bits):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    der = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


def test_spf_counts_nested_lookups_and_finds_dead_and_unregistered_includes():
    dns = FakeDns({
        D: {"TXT": ["v=spf1 include:_spf.vendor.com include:spf.gone.com include:spf.lapsed-mailer.net mx a ip4:192.0.2.0/24 -all"]},
        "_spf.vendor.com": {"TXT": ["v=spf1 include:_a.vendor.com include:_b.vendor.com ~all"]},
        "_a.vendor.com": {"TXT": ["v=spf1 ip4:198.51.100.0/24 ~all"]},
        "_b.vendor.com": {"TXT": ["v=spf1 exists:%{i}.x.vendor.com ~all"]},
        "gone.com": {"NS": ["ns1.host.net"]},  # registered, but spf.gone.com has no SPF
    })

    spf = check_spf(dns, D)

    assert spf.all == "-all" and spf.records == 1
    assert spf.lookups == 8  # 3 includes + mx + a, then 2 includes and 1 exists inside the vendor's
    assert spf.missing == ["spf.gone.com", "spf.lapsed-mailer.net"]
    assert spf.unregistered == ["spf.lapsed-mailer.net"]


def test_spf_without_an_all_and_multiple_records():
    spf = check_spf(FakeDns({D: {"TXT": ["v=spf1 include:_spf.google.com", "v=spf1 -all", "google-site-verification=x"]}, "_spf.google.com": {"TXT": ["v=spf1 ~all"]}}), D)
    assert spf.all is None and spf.records == 2


def test_dmarc_policy_and_registered_domain_fallback():
    dns = FakeDns({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:d@example.com"]}})
    assert check_dmarc(dns, D) == {
        "dmarc": "v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:d@example.com",
        "dmarc_from": None, "dmarc_policy": "quarantine", "dmarc_subdomain_policy": "none", "dmarc_pct": 50, "dmarc_reports": True,
    }
    assert check_dmarc(dns, "shop.example.com")["dmarc_from"] == "example.com"
    assert check_dmarc(FakeDns({}), D) == {"dmarc": None, "dmarc_policy": None}


def test_dkim_keys_and_sizes():
    dns = FakeDns({"selector1._domainkey.example.com": {"TXT": [rsa_record(1024)]}, "google._domainkey.example.com": {"TXT": ["v=DKIM1; p="]}})
    assert check_dkim(dns, D, ["selector1", "selector2", "google"]) == {"selector1": 1024, "google": 0}
    assert dkim_key_bits("v=DKIM1; k=ed25519; p=abc") is None


def test_a_wildcard_dkim_record_is_reported_once():
    class Wild(FakeDns):
        def txt(self, name):
            return ["v=DKIM1; p="] if name.endswith("._domainkey.example.com") else []

    assert check_dkim(Wild({}), D, ["selector1", "google"]) == {"*": 0}


def test_a_resolver_that_fails_ds_queries_leaves_dnssec_unknown():
    from easm.posture import check_dns

    row = check_dns(FakeDns({D: {"NS": ["ns1.dnshost.net"], "DS": "SERVFAIL"}}), FakeProber(), D)
    assert row["dnssec"] is None and row["caa"] == []


def test_mail_providers():
    own = lambda h: h.endswith("example.com")
    assert mail_provider(["example-com.mail.protection.outlook.com"], own) == "Microsoft 365"
    assert mail_provider(["mx1.example.com", "aspmx.l.google.com"], own) == "self-hosted, Google Workspace"
    assert mail_provider(["mx.other-isp.net"], own) == "other-isp.net"
    assert mail_provider([], own) is None
    assert hosted("eu-smtp-inbound-1.mimecast.com") and not hosted("mail.example.com")


def test_registration_from_rdap():
    body = {
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
        "status": ["client transfer prohibited", "active"],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}],
    }
    assert registration(body) == {"registrar": "Example Registrar, Inc.", "created": "1995-08-14", "expires": "2027-08-13", "status": ["active", "client transfer prohibited"]}


def test_a_whole_domain():
    dns = FakeDns({
        D: {"MX": ["mx.example.com"], "TXT": ["v=spf1 mx -all"], "NS": ["ns1.example.com", "ns2.dnshost.net"], "CAA": ['0 issue "letsencrypt.org"']},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]},
        "_mta-sts.example.com": {"TXT": ["v=STSv1; id=1"]},
        "ns1.example.com": {"A": ["93.184.216.53"]},
        "ns2.dnshost.net": {"A": ["10.0.0.53"]},  # private: never asked
    })

    class Prober(FakeProber):
        def axfr(self, ip, domain):
            assert ip == "93.184.216.53"
            return 12

        def fetch(self, url):
            assert url == "https://mta-sts.example.com/.well-known/mta-sts.txt"
            return HttpResult(200, [], b"version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n")

    row = assess_domain(dns, Prober(), D, lambda h: h.endswith(D), rdap=lambda d: {"status": ["active"]}, selectors=["selector1"])

    assert row["mail_provider"] == "self-hosted" and row["spf_all"] == "-all" and row["dmarc_policy"] == "reject"
    assert row["mta_sts"] == "testing" and row["tls_rpt"] is False
    assert row["axfr"] == ["ns1.example.com"]
    assert row["ns_providers"] == ["dnshost.net", "example.com"] and row["dnssec"] is False and row["wildcard"] is False
    assert row["status"] == ["active"]


def test_a_failing_check_does_not_lose_the_others():
    class Flaky(FakeDns):
        def txt(self, name):
            if name.endswith("._domainkey.example.com"):
                raise RuntimeError("SERVFAIL")
            return super().txt(name)

    row = assess_domain(Flaky({D: {"TXT": ["v=spf1 -all"]}}), FakeProber(), D, lambda h: False, selectors=["selector1"])
    assert row["spf_all"] == "-all" and "dkim" not in row and row["check_errors"] == ["dkim: RuntimeError: SERVFAIL"]


def test_registration_failure_does_not_lose_the_rest():
    def rdap(domain):
        raise ConnectionError("registry down")

    row = assess_domain(FakeDns({D: {"TXT": ["v=spf1 -all"]}}), FakeProber(), D, lambda h: False, rdap=rdap, selectors=[])
    assert row["spf_all"] == "-all" and row["registration_error"].startswith("ConnectionError")
