import json
import os
import struct

import pytest

from conftest import pairs
from farpoint.sources.base import SourceFailure, run_command
from farpoint.sources.tools import Bbot, Dnstwist, Subfinder

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
        (Subfinder, ["-d", D]),
    ],
)
def test_external_tools_are_invoked_in_passive_mode(cls, flags):
    rec = Recorder('{"type": "SCAN", "data": {}}')
    list(cls(runner=rec).collect(D))
    assert _contains(rec.argv, flags), rec.argv


def test_dnstwist_never_enables_active_probes():
    rec = Recorder("[]")
    list(Dnstwist(runner=rec).collect(D))
    # --mxcheck talks SMTP, --banners/--lsh/--phash fetch web pages from the lookalike hosts
    dnstwist_args = rec.argv[rec.argv.index("dnstwist") + 1 :]
    assert not {"--mxcheck", "--banners", "--lsh", "--phash", "-m", "-b", "-p"} & set(dnstwist_args)


def test_command_source_unavailable_when_binary_missing():
    assert Subfinder(runner=Recorder(), which=lambda _: None).available() is False


def elf(interpreter: str | None) -> bytes:
    """A 64-bit little-endian ELF executable header, with a PT_INTERP program header if dynamically linked."""
    phdrs = b""
    tail = b""
    if interpreter is not None:
        tail = interpreter.encode() + b"\0"
        phdrs = struct.pack("<IIQQQQQQ", 3, 4, 64 + 56, 0, 0, len(tail), len(tail), 1)  # PT_INTERP
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64 if phdrs else 0, 0, 0, 64, 56, len(phdrs) // 56, 64, 0, 0)
    return header + phdrs + tail


def installed(tmp_path, content: bytes) -> Subfinder:
    path = tmp_path / "subfinder"
    path.write_bytes(content)
    return Subfinder(runner=Recorder(), which=lambda _: str(path))


def test_a_binary_whose_loader_is_missing_is_unavailable(tmp_path):
    """subfinder's Alpine build on Debian: the file is there, but exec fails for want of the musl loader."""
    assert installed(tmp_path, elf(str(tmp_path / "ld-musl-x86_64.so.1"))).available() is False


def test_a_binary_whose_loader_exists_or_that_needs_none_is_available(tmp_path):
    loader = tmp_path / "ld-linux-x86-64.so.2"
    loader.write_bytes(b"")
    assert installed(tmp_path, elf(str(loader))).available() is True
    assert installed(tmp_path, elf(None)).available() is True  # statically linked, as Go builds usually are


def test_a_script_whose_interpreter_is_missing_is_unavailable(tmp_path):
    assert installed(tmp_path, b"#!/nonexistent/bin/python3\nprint('hi')\n").available() is False


def test_a_script_run_through_env_whose_interpreter_is_missing_is_unavailable(tmp_path):
    env = tmp_path / "env"
    env.write_bytes(b"")
    assert installed(tmp_path, f"#!{env} no-such-python-here\n".encode()).available() is False


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX permissions, not root")
def test_a_binary_that_can_be_run_but_not_read_is_assumed_available(tmp_path):
    tool = installed(tmp_path, elf(str(tmp_path / "ld-musl-x86_64.so.1")))
    (tmp_path / "subfinder").chmod(0o111)
    assert tool.available() is True


def test_a_tool_that_cannot_be_started_fails_the_source_with_its_path(tmp_path):
    missing = str(tmp_path / "subfinder")
    with pytest.raises(SourceFailure, match="subfinder"):
        run_command([missing, "-d", D])


@pytest.mark.parametrize("stdout", ["", "[ERRR] Setup failed for module \"crt_db\"\n", "1\n[]\n\"warn\"\n"])
def test_bbot_printing_no_events_is_a_failure_not_zero_results(stdout):
    """bbot exits 0 and, with --silent, prints nothing when its module setup fails. A scan that ran
    always emits events (its SCAN event at least), so no events means it never ran."""
    with pytest.raises(SourceFailure, match="bbot"):
        list(Bbot(runner=Recorder(stdout)).collect(D))


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


def test_subfinder_keeps_only_in_scope_names_from_stdout():
    stdout = "www.example.com\nDEV.example.com\nexample.com.attacker.net\n[WRN] rate limited by chaos\n"

    assert pairs(Subfinder(runner=Recorder(stdout)).collect(D)) == {
        ("www.example.com", None),
        ("dev.example.com", None),
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
