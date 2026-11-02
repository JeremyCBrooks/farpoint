import httpx

from conftest import fake_http
from farpoint.identity import MicrosoftSignIn
from farpoint.models import Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution
from farpoint.tenants import TenantConfig, Vendor

from test_output import read_csv
from test_pipeline import StaticSource, dns_table

TENANT = "11111111-2222-3333-4444-555555555555"


def realm(kind, auth_url=None, brand=None):
    body = {"NameSpaceType": kind, "FederationBrandName": brand, "CloudInstanceName": "microsoftonline.com"}
    return {**body, "AuthURL": auth_url} if auth_url else body


class FakeSignIn:
    def __init__(self, realms, openids=None, failing=()):
        self.realms, self.openids, self.failing = realms, openids or {}, set(failing)
        self.asked = []

    def realm(self, domain):
        self.asked.append(domain)
        if domain in self.failing:
            raise httpx.ConnectError("unreachable")
        return self.realms.get(domain, realm("Unknown"))

    def openid(self, domain):
        return self.openids.get(domain)


def scan(sign_in, domains, dns=None):
    return Pipeline(
        sources=[StaticSource("crtsh")], lookup=dns_table(dns or {}), tenants=TenantConfig(budget=0, vendors=()), txt=lambda d: [], sign_in=sign_in,
    ).run(domains)


def test_sign_in_is_classified_per_scan_domain():
    sign_in = FakeSignIn(
        realms={
            "managed.com": realm("Managed", brand="Managed Inc"),
            "adfs.com": realm("Federated", "https://sts.adfs.com/adfs/ls/?username=x"),
            "okta.com.au": realm("Federated", "https://adfsorg.okta.com/app/office365/abc/sso/wsfed/passive"),
            "odd.com": realm("Federated", "https://login.odd-idp.example/sso"),
        },
        openids={"managed.com": {"issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tenant_region_scope": "NA"}},
    )
    inv = scan(sign_in, ["managed.com", "adfs.com", "okta.com.au", "odd.com", "none.com"])

    rows = inv.identity
    assert (rows["managed.com"]["sign_in"], rows["managed.com"]["tenant_id"], rows["managed.com"]["region"], rows["managed.com"]["brand"]) == ("managed", TENANT, "NA", "Managed Inc")
    assert (rows["adfs.com"]["sign_in"], rows["adfs.com"]["provider"], rows["adfs.com"]["sign_in_host"]) == ("federated", "adfs", "sts.adfs.com")
    assert rows["okta.com.au"]["provider"] == "Okta"  # by the sign-in host, not by "adfs" in its name
    assert rows["odd.com"]["provider"] == "other"
    assert (rows["none.com"]["sign_in"], rows["none.com"]["provider"], rows["none.com"]["tenant_id"]) == ("none", None, None)


def test_a_failed_lookup_is_unknown_not_absent():
    inv = scan(FakeSignIn({}, failing={"example.com"}), ["example.com"])

    assert "example.com" not in inv.identity
    assert [(e.source, e.target) for e in inv.errors] == [("entra", "example.com")]


def test_a_self_hosted_sign_in_host_in_scope_joins_the_inventory_and_is_resolved():
    sign_in = FakeSignIn({
        "example.com": realm("Federated", "https://sts.example.com/adfs/ls/"),
        "example.org": realm("Federated", "https://sts.example-corp.net/adfs/ls/"),
    })
    inv = scan(sign_in, ["example.com", "example.org"], dns={"sts.example.com": Resolution(("192.0.2.10",))})

    assert "entra" in inv.hosts["sts.example.com"].sources
    assert inv.hosts["sts.example.com"].resolves is True
    assert "sts.example-corp.net" not in inv.hosts  # not the organisation's scan domains: recorded, not added
    assert inv.identity["example.org"]["sign_in_host"] == "sts.example-corp.net"


def test_sign_in_runs_only_with_tenants():
    sign_in = FakeSignIn({})
    Pipeline(sources=[], lookup=dns_table({}), sign_in=sign_in).run(["example.com"])
    assert sign_in.asked == []


def test_microsoft_sign_in_requests():
    logins = []

    def getuserrealm(request):
        logins.append(request.url.params["login"])
        assert request.url.params["json"] == "1"
        return httpx.Response(200, json=realm("Managed"))

    http = fake_http({
        "login.microsoftonline.com/getuserrealm.srf": getuserrealm,
        "login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration": httpx.Response(200, json={"issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0"}),
        "login.microsoftonline.com/nowhere.com/v2.0/.well-known/openid-configuration": httpx.Response(400, json={"error": "invalid_tenant"}),
    })
    sign_in = MicrosoftSignIn(http, retries=0)

    assert sign_in.realm("example.com")["NameSpaceType"] == "Managed"
    sign_in.realm("example.com")
    assert all(login.endswith("@example.com") for login in logins) and logins[0] != logins[1]  # never a real user
    assert sign_in.openid("example.com")["issuer"].endswith(f"{TENANT}/v2.0")
    assert sign_in.openid("nowhere.com") is None


def test_identity_csv_is_written(tmp_path):
    sign_in = FakeSignIn({"example.com": realm("Federated", "https://sts.example.com/adfs/ls/")})
    write_outputs(scan(sign_in, ["example.com"]), tmp_path, "2026-10-31T00:00:00Z")

    rows = read_csv(tmp_path / "identity.csv")
    assert list(rows[0]) == ["domain", "sign_in", "provider", "sign_in_host", "brand", "tenant_id", "region", "first_seen", "last_seen"]
    assert (rows[0]["domain"], rows[0]["provider"], rows[0]["sign_in_host"]) == ("example.com", "adfs", "sts.example.com")


def test_a_failed_tenant_lookup_keeps_the_sign_in_answer():
    class RateLimited(FakeSignIn):
        def openid(self, domain):
            raise httpx.HTTPStatusError("429", request=httpx.Request("GET", "https://login.microsoftonline.com/"), response=httpx.Response(429))

    inv = scan(RateLimited({"example.com": realm("Federated", "https://sts.example.com/adfs/ls/")}), ["example.com"])

    row = inv.identity["example.com"]
    assert (row["provider"], row["sign_in_host"], row["tenant_id"]) == ("adfs", "sts.example.com", None)
    assert [(e.source, e.target) for e in inv.errors] == [("entra-tenant", "example.com")]


OTHER = "99999999-8888-7777-6666-555555555555"
M365 = [Vendor("Microsoft 365", ("{org}.sharepoint.com", "{org}.onmicrosoft.com"))]


def tenant_scan(openids):
    """example.com signs in to TENANT; the platform has example.onmicrosoft.com and example.sharepoint.com,
    found by name alone. `openids` says which tenant each onmicrosoft.com name is."""
    sign_in = FakeSignIn({"example.com": realm("Managed")}, openids={"example.com": {"issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0"}, **openids})
    found = {"example.onmicrosoft.com": Resolution(("192.0.2.20",)), "example.sharepoint.com": Resolution(("192.0.2.21",))}
    pipeline = Pipeline(
        sources=[StaticSource("crtsh")], lookup=lambda h: found.get(h, Resolution()), txt=lambda d: [],
        tenants=TenantConfig(budget=50, vendors=M365), sign_in=sign_in,
    )
    return pipeline.run(["example.com"]), sign_in


def issuer(tenant):
    return {"issuer": f"https://login.microsoftonline.com/{tenant}/v2.0"}


def test_a_tenant_found_by_name_that_is_someone_elses_is_dropped():
    inv, _ = tenant_scan({"example.onmicrosoft.com": issuer(OTHER)})

    assert "example.onmicrosoft.com" not in inv.tenants
    assert "example.sharepoint.com" not in inv.tenants  # the same tenant's SharePoint


def test_a_tenant_found_by_name_that_is_the_organisations_is_tied_by_its_id():
    inv, _ = tenant_scan({"example.onmicrosoft.com": issuer(TENANT)})

    for name in ("example.onmicrosoft.com", "example.sharepoint.com"):
        assert inv.tenants[name].tie == "records"
        assert "same Microsoft 365 tenant as example.com's sign-in" in inv.tenants[name].evidence


def test_a_tenant_found_by_name_stays_as_it_is_when_the_organisations_tenant_is_unknown():
    sign_in = FakeSignIn({"example.com": realm("Unknown")})  # not on Microsoft 365: nothing to compare with
    found = {"example.onmicrosoft.com": Resolution(("192.0.2.20",))}
    pipeline = Pipeline(sources=[StaticSource("crtsh")], lookup=lambda h: found.get(h, Resolution()), txt=lambda d: [],
                        tenants=TenantConfig(budget=50, vendors=M365), sign_in=sign_in)

    inv = pipeline.run(["example.com"])

    assert inv.tenants["example.onmicrosoft.com"].tie == "name"


def test_a_tenant_later_found_to_be_someone_elses_leaves_the_running_inventory(tmp_path):
    first, _ = tenant_scan({})  # no answer about it this time: kept
    write_outputs(first, tmp_path, "2026-10-01T00:00:00Z")

    later, _ = tenant_scan({"example.onmicrosoft.com": issuer(OTHER)})
    report = write_outputs(later, tmp_path, "2026-10-02T00:00:00Z")

    assert not {t["tenant"] for t in report["tenants"]} & {"example.onmicrosoft.com", "example.sharepoint.com"}
