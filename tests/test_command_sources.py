import json

import pytest

from conftest import pairs
from easm.sources.tools import Amass, Bbot, Dnstwist, Subfinder

D = "example.com"


class Recorder:
    """Stands in for subprocess: records argv, returns canned stdout."""

    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.argv: list[str] = []

    def __call__(self, argv):
        self.argv = list(argv)
        return self.stdout


def _contains(argv: list[str], flags: list[str]) -> bool:
    n = len(flags)
    return any(argv[i : i + n] == flags for i in range(len(argv) - n + 1))


# Safety contract: each external tool must be invoked in its passive mode.
@pytest.mark.parametrize(
    ("cls", "flags"),
    [
        (Bbot, ["-rf", "passive"]),
        (Amass, ["-passive"]),
        (Subfinder, ["-d", D]),
    ],
)
def test_external_tools_are_invoked_in_passive_mode(cls, flags):
    rec = Recorder()
    cls(runner=rec).collect(D)
    assert _contains(rec.argv, flags), rec.argv


def test_dnstwist_never_enables_active_probes():
    rec = Recorder("[]")
    Dnstwist(runner=rec).collect(D)
    # --mxcheck talks SMTP, --banners/--lsh/--phash fetch web pages from the lookalike hosts
    dnstwist_args = rec.argv[rec.argv.index("dnstwist") + 1 :]
    assert not {"--mxcheck", "--banners", "--lsh", "--phash", "-m", "-b", "-p"} & set(dnstwist_args)


def test_command_source_unavailable_when_binary_missing():
    assert Amass(runner=Recorder(), which=lambda _: None).available() is False


def test_bbot_parses_dns_name_events_with_resolved_hosts():
    events = [
        {"type": "SCAN", "data": {"name": "x"}},
        {"type": "DNS_NAME", "data": "mail.example.com", "resolved_hosts": ["192.0.2.25"], "scope_distance": 0},
        {"type": "DNS_NAME", "data": "blog.example.com", "scope_distance": 0},
        {"type": "URL", "data": "https://other.example.com/"},
    ]
    stdout = "[INFO] starting\n" + "\n".join(json.dumps(e) for e in events)

    assert pairs(Bbot(runner=Recorder(stdout)).collect(D)) == {
        ("mail.example.com", None),
        ("mail.example.com", "192.0.2.25"),
        ("blog.example.com", None),
    }


def test_amass_extracts_names_from_graph_style_output():
    stdout = (
        "www.example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)\n"
        "example.com (FQDN) --> ns_record --> ns1.dnshost.net (FQDN)\n"
        "dev.example.com\n"
    )
    assert {h for h, _ in pairs(Amass(runner=Recorder(stdout)).collect(D))} == {
        "www.example.com",
        "example.com",
        "dev.example.com",
    }


def test_dnstwist_reports_registered_permutations_as_lookalikes_excluding_original():
    rows = [
        {"fuzzer": "*original", "domain": "example.com", "dns_a": ["93.184.216.34"]},
        {"fuzzer": "homoglyph", "domain": "examp1e.com", "dns_a": ["198.51.100.1"], "dns_aaaa": ["2001:db8::1"], "dns_mx": ["mx.examp1e.com"]},
        {"fuzzer": "addition", "domain": "examplea.com", "dns_ns": ["ns1.parking.net"]},
    ]
    obs = list(Dnstwist(runner=Recorder(json.dumps(rows))).collect(D))

    assert all(o.lookalike for o in obs)
    assert pairs(obs) == {
        ("examp1e.com", "198.51.100.1"),
        ("examp1e.com", "2001:db8::1"),
        ("examplea.com", None),
    }
