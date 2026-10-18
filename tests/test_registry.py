import pytest

from conftest import fake_http
from easm.sources import build_sources, select_sources


@pytest.fixture
def all_sources():
    return build_sources(fake_http({}), env={})


def test_only_keeps_named_sources(all_sources):
    assert [s.name for s in select_sources(all_sources, only=["crtsh", "amass"])] == ["crtsh", "amass"]


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
