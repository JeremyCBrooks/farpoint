import json

from farpoint.corpus import Suffixes, _records, build_stats, org_features
from farpoint.guess import BARE, Corpus, Prior, Taxonomy

PSL = """// ===BEGIN ICANN DOMAINS===
com
co.uk
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
azurewebsites.net
// ===END PRIVATE DOMAINS===
net
"""


def test_registered_domain_and_platforms_are_skipped():
    suffixes = Suffixes(PSL)
    assert suffixes.registered("api-dev.example.com") == "example.com"
    assert suffixes.registered("www.shop.example.co.uk") == "example.co.uk"
    assert suffixes.registered("tenant.azurewebsites.net") is None  # a platform, not an organisation
    assert suffixes.registered("com") is None


def test_org_features_count_modifiers_pairs_and_standalone_names():
    mods, pairs, words = org_features("example.com", ["api.example.com", "api-dev.example.com", "api-prod.example.com", "files.example.com"])
    assert mods == {"dev", "prod"}
    assert {("dev", "prod"), (BARE, "dev"), (BARE, "prod")} <= pairs
    assert {"api", "files", "api-dev"} <= words


def test_each_organisation_counts_once_however_many_names_it_has():
    big = [f"app{i}-dev.big.com" for i in range(50)] + [f"app{i}-prod.big.com" for i in range(50)]
    small = ["api-dev.small.com", "api-prod.small.com", "x.small.com", "y.small.com", "z.small.com"]
    stats = build_stats([("big.com", big), ("small.com", small)], min_orgs=1)
    assert stats["orgs"] == 2
    assert stats["modifiers"]["dev"] == 2
    assert stats["cooccur"]["dev"]["prod"] == 2


def test_single_characters_and_crowded_stems_are_not_shared_habits():
    names = ["web-a.example.com", "web-b.example.com", "api-dev.example.com", "api-prod.example.com"]
    names += [f"cust-{w}.example.com" for w in "alpha bravo delta echo golf hotel india kilo lima mike oscar papa romeo".split()]
    mods, pairs, _ = org_features("example.com", names)
    assert "a" not in mods and "alpha" in mods
    assert ("dev", "prod") in pairs
    assert not any("alpha" in pair for pair in pairs)  # 'cust' has 13 modifiers: a list of customers


def test_rare_features_are_dropped():
    stats = build_stats([("a.com", ["x-qa.a.com", "x-dev.a.com"]), ("b.com", ["y-dev.b.com", "y-prod.b.com"])], min_orgs=2)
    assert stats["modifiers"] == {"dev": 2}


def test_records_skip_excluded_small_and_failed_organisations(tmp_path):
    lines = [
        {"org": "keep.com", "names": [f"h{i}.keep.com" for i in range(5)]},
        {"org": "tiny.com", "names": ["a.tiny.com"]},
        {"org": "target.com", "names": [f"h{i}.target.com" for i in range(5)]},
        {"org": "broken.com", "error": "statement timeout"},
    ]
    (tmp_path / "names.jsonl").write_text("\n".join(json.dumps(line) for line in lines))
    assert [org for org, _ in _records(tmp_path, ["target.com"])] == ["keep.com"]


def test_corpus_teaches_modifiers_this_organisation_has_never_used():
    corpus = Corpus(orgs=10, modifiers={"dev": 8, "apim": 3}, cooccur={"dev": {"apim": 3}, "apim": {"dev": 3}}, words={})
    hosts = {"remit-dev.example.com": [], "portal.example.com": []}
    without = Taxonomy(hosts, ["example.com"], Prior.from_lines(["www"]))
    with_corpus = Taxonomy(hosts, ["example.com"], Prior.from_lines(["www"], corpus))
    assert "remit-apim.example.com" not in without.candidates("example.com")
    assert "remit-apim.example.com" in with_corpus.candidates("example.com")
    why = with_corpus.explain("example.com")["remit-apim.example.com"]["modifier"][1]
    assert "3 of 8 organisations with 'dev'" in why


def test_corpus_standalone_names_are_candidates():
    corpus = Corpus(orgs=4, modifiers={}, cooccur={}, words={"mft": 3})
    m = Taxonomy({"www.example.com": []}, ["example.com"], Prior.from_lines(["www"], corpus))
    assert m.candidates("example.com")[0] == "mft.example.com"
