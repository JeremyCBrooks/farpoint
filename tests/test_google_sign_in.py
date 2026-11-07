"""How each scan domain signs in to Google Workspace (with --tenants): Google's SAML redirect names the
identity provider a domain federates to, as Microsoft's realm answer does."""

import httpx

from conftest import fake_http
from farpoint.assess import derive
from farpoint.identity import GoogleSignIn
from farpoint.output import run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.tenants import TenantConfig

from test_identity import FakeSignIn
from test_output import read_csv
from test_pipeline import StaticSource, dns_table


def google(redirects):
    """accounts.google.com: a domain in `redirects` answers 302 to its IdP; any other, 400."""

    def handler(request):
        target = redirects.get(request.url.params["domain"])
        return httpx.Response(302, headers={"Location": target}) if target else httpx.Response(400, text="Error 400 (Bad Request)")

    return GoogleSignIn(fake_http({"accounts.google.com/samlredirect": handler}), retries=0)


def scan(domains, redirects):
    return Pipeline(
        sources=[StaticSource("crtsh")], lookup=dns_table({}), tenants=TenantConfig(budget=0, vendors=()), txt=lambda d: [],
        sign_in=FakeSignIn({}), google=google(redirects),
    ).run(domains)


def test_a_domain_federating_google_sign_in_names_its_identity_provider():
    inv = scan(["okta-org.com", "adfs-org.com", "plain.com"], {
        "okta-org.com": "https://acme.okta.com/app/google/abc/sso/saml?SAMLRequest=x",
        "adfs-org.com": "https://sts.adfs-org.com/adfs/ls/?SAMLRequest=x",
    })

    rows = inv.google_identity
    assert (rows["okta-org.com"]["google_sso"], rows["okta-org.com"]["google_sign_in_host"]) == ("Okta", "acme.okta.com")
    assert rows["adfs-org.com"]["google_sso"] == "adfs" and "sts.adfs-org.com" in inv.hosts  # a sign-in host under the scan domains joins
    assert rows["plain.com"]["google_sso"] is None  # no SAML sign-in at Google (or not on Workspace): nothing to say
    findings = {(f["kind"], f["target"]) for f in derive(run_report(inv))}
    assert ("self-hosted-federation", "sts.adfs-org.com") in findings


def test_google_sign_in_shares_identity_csv_with_microsofts(tmp_path):
    inv = scan(["okta-org.com"], {"okta-org.com": "https://acme.okta.com/app/google/abc/sso/saml"})

    write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")

    [row] = read_csv(tmp_path / "identity.csv")
    assert (row["domain"], row["sign_in"], row["google_sso"], row["google_sign_in_host"]) == ("okta-org.com", "none", "Okta", "acme.okta.com")


def test_a_failed_google_lookup_is_unknown_and_keeps_nothing():
    gs = GoogleSignIn(fake_http({"accounts.google.com/samlredirect": httpx.Response(503)}), retries=0)
    inv = Pipeline(sources=[StaticSource("crtsh")], lookup=dns_table({}), tenants=TenantConfig(budget=0, vendors=()), txt=lambda d: [],
                   sign_in=FakeSignIn({}), google=gs).run(["plain.com"])

    assert inv.google_identity == {} and any(e.source == "google-sso" for e in inv.errors)
