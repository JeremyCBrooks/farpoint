import pytest

from conftest import fake_http
from farpoint.sources import build_sources, select_sources


@pytest.fixture
def all_sources():
    return build_sources(fake_http({}), env={})


def test_only_keeps_named_sources(all_sources):
    assert [s.name for s in select_sources(all_sources, only=["crtsh", "bbot"])] == ["crtsh", "bbot"]


def test_exclude_drops_named_sources(all_sources):
    names = {s.name for s in select_sources(all_sources, exclude=["dnstwist"])}
    assert "dnstwist" not in names and "crtsh" in names


def test_unknown_source_name_is_rejected_with_valid_choices(all_sources):
    with pytest.raises(ValueError, match="crtsh"):
        select_sources(all_sources, only=["crt.sh"])


def test_api_keys_come_from_environment():
    keyed = {s.name: s for s in build_sources(fake_http({}), env={"SHODAN_API_KEY": "abc"})}
    unkeyed = {s.name: s for s in build_sources(fake_http({}), env={})}

    assert keyed["shodan"].available() and not unkeyed["shodan"].available()


def test_hudsonrock_is_a_default_keyless_source(all_sources):
    (source,) = [s for s in select_sources(all_sources) if s.name == "hudsonrock"]
    assert source.available()


def test_dnstwist_uses_the_scans_resolvers():
    # dnstwist runs as its own process: without them it falls back to the system resolver, which
    # a Droplet's local stub can't keep up with (every lookalike reported as a DNS failure)
    chosen = {s.name: s for s in build_sources(fake_http({}), env={}, nameservers=["1.1.1.1", "8.8.8.8"])}
    system = {s.name: s for s in build_sources(fake_http({}), env={})}

    argv = chosen["dnstwist"].argv("example.com")
    assert argv[argv.index("--nameservers") + 1] == "1.1.1.1,8.8.8.8"
    assert "--nameservers" not in system["dnstwist"].argv("example.com")
