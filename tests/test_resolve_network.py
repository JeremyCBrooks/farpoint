import pytest

from easm.resolve import DnsResolver

pytestmark = pytest.mark.network


def test_resolver_returns_addresses_for_a_real_name():
    res = DnsResolver(["1.1.1.1"]).lookup("one.one.one.one")
    assert "1.1.1.1" in res.ips


def test_resolver_returns_empty_for_nxdomain():
    res = DnsResolver(["1.1.1.1"]).lookup("does-not-exist.invalid")
    assert res.ips == () and res.cnames == ()
