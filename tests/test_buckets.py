"""Cloud storage buckets named after the organisation (--buckets), and tenants on platforms whose DNS
answers any name, confirmed by asking the platform (--tenants)."""

from farpoint.assess import derive
from farpoint.models import Observation
from farpoint.output import run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution
from farpoint.tenants import TenantConfig, Vendor

from test_pipeline import StaticSource, dns_table

D = "example.com"
LISTING = "<?xml version='1.0'?><ListBucketResult><Name>x</Name><Contents><Key>db.sql.gz</Key></Contents></ListBucketResult>"
DENIED = "<?xml version='1.0'?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
MISSING = "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code></Error>"


class FakeWeb:
    """The platforms' web servers: url -> (status, body); anything else is a missing bucket."""

    def __init__(self, pages):
        self.pages, self.asked = pages, []

    def __call__(self, url):
        self.asked.append(url)
        return self.pages.get(url, (404, MISSING))


def run_buckets(pages, buckets=True):
    web = FakeWeb(pages)
    lookup = dns_table({"assets.example.com": Resolution(ips=("52.216.1.1",), cnames=("example-assets.s3.amazonaws.com",))})
    pipeline = Pipeline(
        sources=[StaticSource("crtsh", [Observation("crtsh", "assets.example.com")])],
        lookup=lookup, web=web, buckets=buckets,
    )
    return pipeline.run([D]), web


def test_buckets_named_after_the_organisation_or_its_cnames_are_found_and_public_ones_are_findings(tmp_path):
    inv, web = run_buckets({
        "https://example-backup.s3.amazonaws.com/": (200, LISTING),
        "https://example.storage.googleapis.com/": (403, DENIED),
        "https://example-assets.s3.amazonaws.com/": (200, LISTING),
    })

    found = {name: (r.vendor, r.tie, r.public) for name, r in inv.tenants.items()}
    assert found == {
        "example-backup.s3.amazonaws.com": ("AWS S3", "name", True),
        "example.storage.googleapis.com": ("Google Cloud Storage", "name", False),
        "example-assets.s3.amazonaws.com": ("AWS S3", "cname", True),  # assets.example.com points at it
    }
    assert all(u.startswith("https://") and (".s3.amazonaws.com/" in u or ".storage.googleapis.com/" in u) for u in web.asked)
    assert len(web.asked) == len(set(web.asked))  # each bucket asked once
    levels = {f["target"]: f["level"] for f in derive(run_report(inv)) if f["kind"] == "public-bucket"}
    assert levels == {"example-assets.s3.amazonaws.com": "high", "example-backup.s3.amazonaws.com": "medium"}  # a name match alone may be someone else's
    report = write_outputs(inv, tmp_path, "2026-11-01T00:00:00Z")
    assert {t["tenant"]: t.get("public") for t in report["tenants"]}["example-backup.s3.amazonaws.com"] is True
    assert "public" in (tmp_path / "tenants.csv").read_text().splitlines()[0]


def test_without_buckets_no_storage_provider_is_asked():
    inv, web = run_buckets({}, buckets=False)
    assert web.asked == [] and inv.tenants == {}


OKTA = Vendor("Okta", ("{org}.okta.com",), verify=("https://{name}/.well-known/openid-configuration", r'"issuer"\s*:\s*"https://{name}"'))


def test_a_tenant_on_a_platform_that_answers_any_name_is_confirmed_by_the_platform_itself():
    wildcard = Resolution(ips=("3.33.1.1",), cnames=("ok12.okta.com",))
    lookup = lambda host: wildcard if host.endswith(".okta.com") else Resolution()  # every name resolves alike
    web = FakeWeb({
        "https://example.okta.com/.well-known/openid-configuration": (200, '{"issuer":"https://example.okta.com","authorization_endpoint":"x"}'),
        "https://example-dev.okta.com/.well-known/openid-configuration": (403, '{"errorCode":"E0000006"}'),
    })
    pipeline = Pipeline(sources=[], lookup=lookup, txt=lambda d: [], tenants=TenantConfig(vendors=(OKTA,)), web=web)

    inv = pipeline.run([D])

    assert set(inv.tenants) == {"example.okta.com"}
    tenant = inv.tenants["example.okta.com"]
    assert tenant.verified and any("openid-configuration" in e for e in tenant.evidence)
    assert web.asked == ["https://example.okta.com/.well-known/openid-configuration"]  # the bare name only: no records name Okta


def test_without_the_platforms_answer_a_wildcard_platforms_name_match_is_not_kept():
    wildcard = Resolution(ips=("3.33.1.1",))
    lookup = lambda host: wildcard if host.endswith(".okta.com") else Resolution()
    web = FakeWeb({})  # 404 for everything: it isn't there

    inv = Pipeline(sources=[], lookup=lookup, txt=lambda d: [], tenants=TenantConfig(vendors=(OKTA,)), web=web).run([D])

    assert inv.tenants == {}


def test_a_website_bucket_named_after_its_host_is_asked_path_style_in_its_region():
    web = FakeWeb({"https://s3.eu-west-1.amazonaws.com/assets.example.com/": (200, LISTING)})
    lookup = dns_table({"assets.example.com": Resolution(ips=("52.218.1.1",), cnames=("assets.example.com.s3-website-eu-west-1.amazonaws.com",)),
                        "files.example.com": Resolution(ips=("34.1.1.1",), cnames=("c.storage.googleapis.com",))})
    pipeline = Pipeline(sources=[StaticSource("crtsh", [Observation("crtsh", h) for h in ("assets.example.com", "files.example.com")])],
                        lookup=lookup, web=web, buckets=True)

    inv = pipeline.run([D])

    record = inv.tenants["assets.example.com.s3.amazonaws.com"]
    assert (record.tie, record.public) == ("cname", True)
    assert "https://storage.googleapis.com/files.example.com/" in web.asked  # GCS's own-domain CNAME names the bucket after the host
    assert not [u for u in web.asked if "//c.storage" in u or "/c/" in u]


def test_a_bucket_in_another_region_exists_though_its_listing_is_unknown():
    from farpoint.buckets import judge

    assert judge(301, "<Error><Code>PermanentRedirect</Code></Error>") == "exists"
