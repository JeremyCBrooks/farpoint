import json

from farpoint.models import Observation
from farpoint.output import write_outputs
from farpoint.pipeline import Pipeline
from farpoint.resolve import Resolution
from farpoint.tenants import TenantConfig, Vendor, bundled_vendors, named_after, plan, registered, spf_includes

from test_pipeline import StaticSource

VENDORS = [
    Vendor("Docs", ("{org}.docs-cloud.net",), txt=("docs-verification",)),
    Vendor("Chat", ("{org}.chat-cloud.net",), spf=("mail.chat-cloud.net",)),
    Vendor("Desk", ("{org}.desk-cloud.net",)),
]
SPF = "v=spf1 include:eu.spf.flowsuite.io include:mail.chat-cloud.net include:_spf.example.com -all"


def test_spf_includes_and_registered_domains():
    assert spf_includes([SPF, "docs-verification=abc"]) == ["eu.spf.flowsuite.io", "mail.chat-cloud.net", "_spf.example.com"]
    assert registered("eu.spf.flowsuite.io") == "flowsuite.io"
    assert registered("spf.mail.example.co.uk") == "example.co.uk"


def test_platforms_the_domains_records_point_to_come_first_and_get_modifiers():
    probes = plan(["example.com"], {"example.com": ["docs-verification=abc", SPF]}, ["shop.store-cloud.net"], VENDORS)
    by_pattern = {p.pattern: p for p in probes}
    assert [p.tie for p in probes] == ["records", "records", "records", "cname", "name"]
    assert by_pattern["{org}.docs-cloud.net"].evidence == "TXT 'docs-verification' on example.com"
    assert by_pattern["{org}.chat-cloud.net"].evidence == "SPF include:mail.chat-cloud.net on example.com"
    assert by_pattern["{org}.flowsuite.io"].expand  # an SPF sender no table entry explains
    assert by_pattern["{org}.store-cloud.net"].evidence == "1 CNAME target under store-cloud.net"
    assert not by_pattern["{org}.desk-cloud.net"].expand
    assert "{org}.example.com" not in by_pattern  # the organisation's own SPF include is not a platform


def test_bundled_table_is_generic():
    vendors = bundled_vendors()
    assert all("{org}" in p for v in vendors for p in v.patterns)
    assert len({p for v in vendors for p in v.patterns}) == sum(len(v.patterns) for v in vendors)


def platform_dns(table, wildcard=None):
    """Lookups: exact names from `table`; other names under a wildcard zone get `wildcard`'s answer."""
    calls = []

    def lookup(host):
        calls.append(host)
        if host in table:
            return table[host]
        for zone, answer in (wildcard or {}).items():
            if host.endswith("." + zone):
                return answer
        return Resolution()

    return lookup, calls


def run(table, txt=None, wildcard=None, budget=800, hosts=("www.example.com",), vendors=VENDORS):
    lookup, calls = platform_dns(table, wildcard)
    src = StaticSource("crtsh", [Observation("crtsh", h) for h in hosts])
    pipeline = Pipeline(
        sources=[src], lookup=lookup, txt=lambda d: (txt or {}).get(d, []), tenants=TenantConfig(budget=budget, vendors=vendors)
    )
    return pipeline.run(["example.com"]), calls


def test_tenants_on_platforms_the_records_point_to_are_found_with_the_organisations_modifiers():
    inv, _ = run(
        {
            "example.docs-cloud.net": Resolution(ips=("192.0.2.10",)),
            "example-dev.docs-cloud.net": Resolution(ips=("192.0.2.11",)),
            "example.flowsuite.io": Resolution(exists=True),  # records but no address (MX only)
        },
        txt={"example.com": ["docs-verification=abc", SPF]},
        hosts=("app.example.com", "app-dev.example.com", "api-dev.example.com"),
    )
    assert set(inv.tenants) == {"example.docs-cloud.net", "example-dev.docs-cloud.net", "example.flowsuite.io"}
    docs = inv.tenants["example.docs-cloud.net"]
    assert (docs.vendor, docs.domain, docs.tie, docs.verified, docs.ips) == ("Docs", "example.com", "records", True, {"192.0.2.10"})
    assert docs.evidence == {"TXT 'docs-verification' on example.com"}


def test_on_a_wildcard_platform_only_a_different_answer_counts():
    star = Resolution(ips=("198.51.100.1",))
    inv, _ = run(
        {"example.chat-cloud.net": Resolution(ips=("198.51.100.1",)), "example.desk-cloud.net": Resolution(ips=("203.0.113.7",))},
        txt={"example.com": [SPF]},
        wildcard={"chat-cloud.net": star, "desk-cloud.net": star},
    )
    chat = inv.tenants["example.chat-cloud.net"]  # same as any name: kept, unverified, because SPF names the platform
    assert (chat.tie, chat.verified) == ("records", False)
    assert inv.tenants["example.desk-cloud.net"].verified  # answers differently from random names
    assert "example-www.chat-cloud.net" not in inv.tenants  # unverifiable variants are not kept


def test_a_name_match_on_a_wildcard_platform_is_not_a_tenant():
    star = Resolution(ips=("198.51.100.1",))
    inv, _ = run({}, wildcard={"desk-cloud.net": star})
    assert inv.tenants == {}


def test_tenant_lookups_stay_within_budget_including_wildcard_checks():
    _, calls = run({}, txt={"example.com": ["docs-verification=abc", SPF]}, budget=10, hosts=("app-dev.example.com", "app-test.example.com"))
    tenant_calls = [c for c in calls if not c.endswith("example.com")]
    assert len(tenant_calls) <= 10


def test_no_tenant_lookups_unless_asked():
    lookup, calls = platform_dns({})
    Pipeline(sources=[], lookup=lookup, txt=lambda d: ["docs-verification=abc"]).run(["example.com"])
    assert calls == ["example.com"]


def test_tenants_are_reported_and_merged_across_runs(tmp_path):
    table = {"example.docs-cloud.net": Resolution(ips=("192.0.2.10",))}
    inv, _ = run(table, txt={"example.com": ["docs-verification=abc"]})
    write_outputs(inv, tmp_path, "2026-01-01T00:00:00Z")
    inv, _ = run(table)  # found again as a name match only: the stronger tie is kept
    report = write_outputs(inv, tmp_path, "2026-01-02T00:00:00Z")
    [row] = report["tenants"]
    assert (row["tenant"], row["tie"], row["verified"]) == ("example.docs-cloud.net", "records", True)
    assert row["evidence"] == ["Docs tenant name pattern", "TXT 'docs-verification' on example.com"]
    assert (row["first_seen"], row["last_seen"]) == ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert "example.docs-cloud.net,Docs,example.com,records,yes" in (tmp_path / "tenants.csv").read_text()
    assert json.loads((tmp_path / "assets.json").read_text())["runs"][-1]["new"]["tenants"] == 0


def test_earlier_runs_hosts_teach_modifiers_and_platforms():
    lookup, _ = platform_dns({"example-qa.docs-cloud.net": Resolution(ips=("192.0.2.12",)), "example.store-cloud.net": Resolution(ips=("192.0.2.13",))})
    known = {"app-qa.example.com": [], "web-qa.example.com": ["shop.store-cloud.net"]}
    config = TenantConfig(vendors=VENDORS, known=known)
    inv = Pipeline(sources=[], lookup=lookup, txt=lambda d: ["docs-verification=abc"], tenants=config).run(["example.com"])
    assert {"example-qa.docs-cloud.net", "example.store-cloud.net"} <= set(inv.tenants)
    assert inv.tenants["example.store-cloud.net"].tie == "cname"


def test_a_domains_records_tie_only_tenants_named_after_it():
    star = Resolution(ips=("198.51.100.1",))
    lookup, _ = platform_dns({"other.docs-cloud.net": Resolution(ips=("192.0.2.20",))}, wildcard={"chat-cloud.net": star})
    txt = {"example.com": ["docs-verification=abc", "v=spf1 include:mail.chat-cloud.net -all"]}
    pipeline = Pipeline(sources=[], lookup=lookup, txt=lambda d: txt.get(d, []), tenants=TenantConfig(vendors=VENDORS))
    inv = pipeline.run(["example.com", "other.org"])
    assert inv.tenants["other.docs-cloud.net"].tie == "name"  # exists, but example.com's record says nothing about it
    assert inv.tenants["other.docs-cloud.net"].evidence == {"Docs tenant name pattern"}
    assert "example.chat-cloud.net" in inv.tenants and "other.chat-cloud.net" not in inv.tenants


def test_a_txt_record_naming_a_tenant_outright_is_tried_as_is():
    vendors = [*VENDORS, Vendor("Mail", ("{org}.mail-cloud.net",))]
    probes = plan(["example.com"], {"example.com": ["EXAMPLECO123.mail-cloud.net", "verify=abc.def", "www.example.com"]}, [], vendors)
    literal = next(p for p in probes if p.literal)
    assert (literal.pattern, literal.vendor, literal.tie) == ("exampleco123.mail-cloud.net", "Mail", "records")
    assert sum(p.literal for p in probes) == 1  # not 'verify=…', not the organisation's own name

    lookup, _ = platform_dns({"exampleco123.mail-cloud.net": Resolution(exists=True)})
    txt = {"example.com": ["EXAMPLECO123.mail-cloud.net"]}
    inv = Pipeline(sources=[], lookup=lookup, txt=lambda d: txt.get(d, []), tenants=TenantConfig(vendors=vendors)).run(["example.com"])
    assert inv.tenants["exampleco123.mail-cloud.net"].verified


def test_a_cname_to_a_name_carrying_the_organisations_is_a_tenant_and_links_back(tmp_path):
    lookup, _ = platform_dns({"mft.example.com": Resolution(ips=("192.0.2.30",), cnames=("example-mft-traffic.vendor.co",))})
    src = StaticSource("crtsh", [Observation("crtsh", "mft.example.com")])
    inv = Pipeline(sources=[src], lookup=lookup, txt=lambda d: [], tenants=TenantConfig(vendors=VENDORS)).run(["example.com"])
    tenant = inv.tenants["example-mft-traffic.vendor.co"]
    assert (tenant.vendor, tenant.tie, tenant.verified, tenant.evidence) == ("vendor.co", "cname", True, {"CNAME of mft.example.com"})
    [row] = write_outputs(inv, tmp_path)["tenants"]
    assert row["hosts"] == ["mft.example.com"]


def test_named_after_matches_whole_words_longest_name_first():
    tokens = {"example": "example.com", "examplecorp": "examplecorp.org"}
    assert named_after("uat-example-mft.vendor.co", tokens) == "example.com"
    assert named_after("examplecorp-x.vendor.co", tokens) == "examplecorp.org"
    assert named_after("examples-x.vendor.co", tokens) is None


def test_cli_seeds_guessing_with_earlier_runs_tried_names_and_tenants():
    from farpoint.cli import _guess_config

    report = {
        "hosts": [{"hostname": "www.example.com", "ips": ["192.0.2.1"]}],
        "guessed": {"api-prod.example.com": "2026-01-01T00:00:00Z"},
        "tenants": [{"tenant": "example-mft.vendor.co", "domain": "example.com", "verified": True}],
    }
    config = _guess_config(100, report, rate=5)
    assert config.tried == {"api-prod.example.com"} and config.rate == 5
    assert config.tenants == {"example-mft.vendor.co": "example.com"}
