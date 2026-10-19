import json
import re

from easm import guess
from easm.guess import GuessConfig, Prior, Taxonomy, bundled_prior, leave_one_out, main
from easm.models import Observation
from easm.pipeline import Pipeline
from easm.resolve import Resolution

from test_pipeline import StaticSource, dns_table

PRIOR = Prior.from_lines(["dev", "test", "mail", "prod", "stage", "uat", "files", "vpn"])


def model(*hosts, domains=("example.com",), cnames=None, weak=()):
    cnames = cnames or {}
    return Taxonomy({h: cnames.get(h, []) for h in hosts}, list(domains), PRIOR, weak)


def rank(candidates, name):
    return candidates.index(name) + 1 if name in candidates else None


def test_labels_split_on_hyphens_digits_and_known_word_plus_modifier():
    m = model("portal.example.com", "crm.example.com")
    assert m.tokenize("portaltest") == (("portal", ""), ("test", ""))
    assert m.tokenize("app2-service-dev") == (("app", ""), ("2", ""), ("service", "-"), ("dev", "-"))
    assert m.tokenize("crmuat") == (("crm", ""), ("uat", ""))
    assert m.tokenize("extranet") == (("extranet", ""),)  # 'extra' is not a known word here


def test_modifiers_that_co_occur_on_other_stems_are_predicted_first():
    m = model(
        "portal-dev.example.com", "portal-prod.example.com",
        "crm-dev.example.com", "crm-prod.example.com",
        "api-dev.example.com",
    )  # fmt: skip
    candidates = m.candidates("example.com")
    assert candidates[0] == "api-prod.example.com"


def test_a_bare_stem_gets_the_modifiers_other_bare_stems_have():
    m = model(
        "crewapp.example.com", "crewapp-stage.example.com",
        "portal.example.com", "portal-stage.example.com",
        "kiosk.example.com",
    )  # fmt: skip
    assert rank(m.candidates("example.com"), "kiosk-stage.example.com") == 1


def test_a_modifier_is_tried_with_the_other_separator():
    m = model("portal.example.com", "portaltest.example.com")
    assert "portal-test.example.com" in m.candidates("example.com")


def test_cname_targets_teach_modifiers_of_known_stems():
    m = model("portal.example.com", "api-dev.example.com", cnames={"portal.example.com": ["portal-prod.azurewebsites.net"]})
    assert m.stem_mods["portal"] >= {"prod"}
    assert rank(m.candidates("example.com"), "api-prod.example.com") <= 2  # 'prod' is now an organisation modifier


def test_numbers_are_varied():
    m = model("appdemo2.example.com")
    assert {"appdemo3.example.com", "appdemo1.example.com"} <= set(m.candidates("example.com"))


def test_numbers_keep_zero_padding_only_where_it_was_used():
    candidates = set(model("app10.example.com", "web07.example.com").candidates("example.com"))
    assert {"app9.example.com", "app11.example.com", "app1.example.com"} <= candidates
    assert {"web06.example.com", "web08.example.com"} <= candidates
    assert "app09.example.com" not in candidates


def test_a_prefix_seen_over_several_names_is_tried_on_the_rest():
    m = model("www.api.example.com", "www.portal.example.com", "api.example.com", "portal.example.com", "crm.example.com")
    assert "www.crm.example.com" in m.candidates("example.com")


def test_names_repeat_across_input_domains():
    m = model("billing.a.com", "vpn.a.com", "billing.b.com", domains=("a.com", "b.com"))
    assert "vpn.b.com" in m.candidates("b.com")


def test_popular_standalone_names_fill_in_where_no_pattern_applies():
    assert {"mail.example.com", "files.example.com"} <= set(model("www.example.com").candidates("example.com"))


def test_known_names_records_and_out_of_scope_names_are_never_candidates():
    m = model("api-dev.example.com", "_dmarc.example.com", "example.com")
    candidates = m.candidates("example.com")
    assert "api-dev.example.com" not in candidates
    assert not any(c.startswith("_") or not c.endswith(".example.com") for c in candidates)


def test_variants_of_names_never_seen_with_an_address_rank_lower():
    hosts = ["junkx.example.com", "realapp.example.com", "other.example.com", "other-stage.example.com"]
    m = model(*hosts, weak={"junkx.example.com"})
    candidates = m.candidates("example.com")
    assert rank(candidates, "realapp-stage.example.com") < rank(candidates, "junkx-stage.example.com")


def test_leave_one_out_recovers_a_hidden_host_from_the_pattern():
    hosts = {f"{s}{m}.example.com": [] for s in ("portal", "crm", "api") for m in ("-dev", "-prod")}
    ranks = leave_one_out(hosts, ["example.com"], prior=PRIOR)
    assert all(r is not None and r <= 3 for r in ranks.values())


def test_leave_one_out_hides_the_host_from_cname_targets_too(monkeypatch):
    seen = []
    real = guess.Taxonomy

    def spy(hosts, *args, **kwargs):
        seen.append({h: list(c) for h, c in hosts.items()})
        return real(hosts, *args, **kwargs)

    monkeypatch.setattr(guess, "Taxonomy", spy)
    hosts = {"www.example.com": ["portal-prod.example.com"], "portal-prod.example.com": [], "portal-dev.example.com": []}
    leave_one_out(hosts, ["example.com"], prior=PRIOR)

    hidden_portal_prod = next(h for h in seen if "portal-prod.example.com" not in h)
    assert hidden_portal_prod["www.example.com"] == []


def test_bundled_prior_loads():
    prior = bundled_prior()
    assert prior.words["www"] < prior.words["files"] < 1000
    assert {"dev", "uat", "staging"} <= prior.dictionary


def test_modifiers_come_only_from_the_organisations_own_names():
    m = model("api-dev.example.com", "portal.example.com")
    assert set(m.mod_stems) == {"dev", ""}  # 'prod' etc. are not assumed
    assert not any(c.startswith(("api-prod", "portal-prod")) for c in m.candidates("example.com"))


def test_evaluation_cli(tmp_path, capsys):
    hosts = [{"hostname": h, "cnames": [], "ips": ["192.0.2.1"]} for h in ("api-dev.example.com", "api-prod.example.com", "crm-dev.example.com")]
    (tmp_path / "assets.json").write_text(json.dumps({"domains": ["example.com"], "hosts": hosts}))
    assert main([str(tmp_path), "--rank", "crm-prod.example.com"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"rank crm-prod.example.com: [1-3] of", out) and "recall@100" in out


# --- pipeline --------------------------------------------------------------------------------------


def guess_pipeline(hosts, table, **config):
    source = StaticSource("s", [Observation("s", h) for h in hosts])
    return Pipeline(sources=[source], lookup=dns_table(table), guess=GuessConfig(prior=PRIOR, **config))


def test_guesses_that_resolve_are_added_and_others_are_not():
    hosts = ["portal-dev.example.com", "portal-prod.example.com", "api-dev.example.com"]
    table = {h: Resolution(("192.0.2.1",)) for h in hosts} | {"api-prod.example.com": Resolution(("192.0.2.9",))}

    inv = guess_pipeline(hosts, table).run(["example.com"])

    found = inv.hosts["api-prod.example.com"]
    assert found.sources == {"guess", "dns"} and found.resolves and found.ips == {"192.0.2.9"}
    assert all(h in hosts + ["example.com", "api-prod.example.com"] for h in inv.hosts)


def test_a_found_guess_teaches_the_next_round():
    table = {"app1.example.com": Resolution(("192.0.2.1",)), "app3.example.com": Resolution(("192.0.2.3",))}
    table["app5.example.com"] = Resolution(("192.0.2.5",))  # app1 suggests up to app3; only app3 suggests app5

    inv = guess_pipeline(["app1.example.com"], table).run(["example.com"])

    assert {"app3.example.com", "app5.example.com"} <= set(inv.hosts)


def test_wildcard_answers_are_not_findings():
    class Wildcard(dict):
        def get(self, host, default=None):
            return super().get(host) or Resolution(("198.51.100.7",), ("lb.cdn.example.net",))

    hosts = ["portal-dev.example.com", "portal-prod.example.com", "api-dev.example.com"]
    table = Wildcard({"api-prod.example.com": Resolution(("192.0.2.9",))})

    inv = guess_pipeline(hosts, table).run(["example.com"])

    assert set(inv.hosts) == {*hosts, "example.com", "api-prod.example.com"}  # answers differently: real


def test_guessing_stays_within_budget_including_wildcard_probes():
    asked = []

    def lookup(host):
        asked.append(host)
        return Resolution()

    source = StaticSource("s", [Observation("s", "api-dev.example.com")])
    Pipeline(sources=[source], lookup=lookup, guess=GuessConfig(budget=5, prior=PRIOR)).run(["example.com"])

    probes = {h for h in asked if re.fullmatch(r"[0-9a-f]{16}\..+", h)}
    guesses = set(asked) - probes - {"example.com", "api-dev.example.com"}
    assert len(probes) == 3 and len(guesses) == 2  # one parent probed, the rest spent on guesses


def test_an_unanswered_wildcard_check_means_no_guesses_there():
    asked = []

    def lookup(host):
        asked.append(host)
        if re.fullmatch(r"[0-9a-f]{16}\..+", host):
            return Resolution(timed_out=True)
        return Resolution(("192.0.2.1",))  # if guesses were tested, all would "resolve"

    source = StaticSource("s", [Observation("s", "api-dev.example.com")])
    inv = Pipeline(sources=[source], lookup=lookup, guess=GuessConfig(prior=PRIOR)).run(["example.com"])

    assert not any("guess" in r.sources for r in inv.hosts.values())
    assert ("guess", "example.com") in {(e.source, e.target) for e in inv.errors}


def test_a_wildcard_rotating_past_the_probes_is_caught_by_how_many_guesses_resolve():
    counter = iter(range(1, 100_000))

    def lookup(host):  # every name resolves, each to a fresh address
        return Resolution((f"198.51.{next(counter) // 250}.{next(counter) % 250}",))

    source = StaticSource("s", [Observation("s", f"{s}-dev.example.com") for s in ("api", "crm", "portal")])
    inv = Pipeline(sources=[source], lookup=lookup, guess=GuessConfig(prior=PRIOR)).run(["example.com"])

    assert not any("guess" in r.sources for r in inv.hosts.values())
    assert any(e.source == "guess" and "wildcard-like" in e.message for e in inv.errors)


def test_under_a_wildcard_a_name_with_an_address_of_its_own_is_kept():
    wildcard = Resolution(("198.51.100.7",))

    def lookup(host):
        return {"api-prod.example.com": Resolution(("198.51.100.7", "192.0.2.9"))}.get(host, wildcard)

    source = StaticSource("s", [Observation("s", h) for h in ("portal-dev.example.com", "portal-prod.example.com", "api-dev.example.com")])
    inv = Pipeline(sources=[source], lookup=lookup, guess=GuessConfig(prior=PRIOR)).run(["example.com"])

    assert [h for h, r in inv.hosts.items() if "guess" in r.sources] == ["api-prod.example.com"]


def test_cname_targets_of_found_guesses_are_resolved_even_if_known_from_earlier_runs():
    table = {
        "api-prod.example.com": Resolution(("192.0.2.9",), ("lb.example.com",)),
        "lb.example.com": Resolution(("192.0.2.9",)),
    }
    earlier = {"portal-dev.example.com": [], "portal-prod.example.com": [], "api-dev.example.com": [], "lb.example.com": []}
    inv = Pipeline(sources=[], lookup=dns_table(table), guess=GuessConfig(prior=PRIOR, known=earlier)).run(["example.com"])

    assert inv.hosts["lb.example.com"].resolves is True


def test_earlier_runs_inventory_is_learned_from_and_not_re_tested():
    asked = []
    table = {"api-prod.example.com": Resolution(("192.0.2.9",))}

    def lookup(host):
        asked.append(host)
        return table.get(host, Resolution())

    earlier = {"portal-dev.example.com": [], "portal-prod.example.com": [], "api-dev.example.com": [], "other.org": []}
    config = GuessConfig(prior=PRIOR, known=earlier)
    inv = Pipeline(sources=[], lookup=lookup, guess=config).run(["example.com"])

    assert "api-prod.example.com" in inv.hosts
    assert not set(earlier) & set(asked)


def test_no_guessing_unless_asked():
    asked = []
    source = StaticSource("s", [Observation("s", "api-dev.example.com")])
    Pipeline(sources=[source], lookup=lambda h: asked.append(h) or Resolution()).run(["example.com"])
    assert sorted(asked) == ["api-dev.example.com", "example.com"]


def test_a_tenants_other_words_are_guessed_first_under_the_domain_it_is_named_after():
    tenants = {"uat-example-mft-traffic.vendor.co": "example.com", "example.docs-cloud.net": "example.com"}
    m = Taxonomy({"www.example.com": [], "portal.example.org": []}, ["example.com", "example.org"], PRIOR, tenants=tenants)
    top = m.candidates("example.com")[:5]
    assert top[:3] == ["mft-traffic.example.com", "mft.example.com", "traffic.example.com"]
    assert set(top[3:]) == {"uat-mft.example.com", "mft-uat.example.com"}
    assert "from tenant uat-example-mft-traffic.vendor.co" in m.explain("example.com")["mft.example.com"]["tenant"][1]
    assert "mft.example.org" not in m.candidates("example.org")[:10]  # named after example.com, not example.org


def test_verified_tenants_feed_guessing_in_the_same_run():
    from easm.tenants import TenantConfig, Vendor

    table = {
        "example-files.vault-cloud.io": Resolution(ips=("192.0.2.40",)),
        "files.example.com": Resolution(ips=("192.0.2.41",), cnames=("example-files.vault-cloud.io",)),
    }
    txt = {"example.com": ["v=spf1 include:spf.vault-cloud.io -all"]}
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com"), Observation("crtsh", "app-files.example.com")])
    inv = Pipeline(
        sources=[src],
        lookup=dns_table(table),
        txt=lambda d: txt.get(d, []),
        tenants=TenantConfig(vendors=[Vendor("Vault", ("{org}.vault-cloud.io",))]),
        guess=GuessConfig(budget=20, prior=PRIOR),
    ).run(["example.com"])
    assert "example-files.vault-cloud.io" in inv.tenants  # an SPF sender, with the organisation's 'files' modifier
    assert "guess" in inv.hosts["files.example.com"].sources


def test_a_tenant_whose_words_the_organisation_already_uses_suggests_nothing():
    m = Taxonomy({"app-dev.example.com": []}, ["example.com"], PRIOR, tenants={"example-dev.vault-cloud.io": "example.com"})
    assert m.tenant_words == {}
    assert not any("tenant" in kinds for kinds in m.explain("example.com").values())


def test_guesses_earlier_runs_tested_are_skipped_so_each_run_goes_deeper():
    src = StaticSource("crtsh", [Observation("crtsh", "api-dev.example.com"), Observation("crtsh", "web-dev.example.com"), Observation("crtsh", "web-prod.example.com")])
    first = Pipeline(sources=[src], lookup=dns_table({}), guess=GuessConfig(budget=8, rounds=1, prior=PRIOR)).run(["example.com"])
    assert len(first.guessed) == 5  # 8 lookups, 3 of them the wildcard check
    second = Pipeline(sources=[src], lookup=dns_table({}), guess=GuessConfig(budget=8, rounds=1, prior=PRIOR, tried=frozenset(first.guessed))).run(["example.com"])
    assert second.guessed and not second.guessed & first.guessed


def test_guess_rate_spaces_lookups_out(monkeypatch):
    from easm import pipeline, runtime

    clock, slept = [0.0], []
    monkeypatch.setattr(pipeline.time, "monotonic", lambda: clock[0])

    def sleep(seconds):
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(runtime, "sleep", sleep)
    paced = pipeline._paced(lambda name: Resolution(), rate=4)
    for name in ("a", "b", "c"):
        paced(name)
    assert slept == [0.25, 0.25]


def test_a_found_guesss_alias_to_a_tenant_teaches_the_next_round():
    from easm.tenants import TenantConfig

    table = {
        "mft.example.com": Resolution(ips=("192.0.2.50",), cnames=("example-mft-traffic.vendor.co",)),
        "traffic.example.com": Resolution(ips=("192.0.2.51",)),
    }
    src = StaticSource("crtsh", [Observation("crtsh", "www.example.com")])
    inv = Pipeline(
        sources=[src],
        lookup=dns_table(table),
        txt=lambda d: [],
        tenants=TenantConfig(vendors=[]),
        guess=GuessConfig(budget=12, rounds=2, prior=Prior.from_lines(["mft"])),
    ).run(["example.com"])
    assert inv.tenants["example-mft-traffic.vendor.co"].tie == "cname"
    assert "guess" in inv.hosts["traffic.example.com"].sources  # 'traffic' came only from the tenant
