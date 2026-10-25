import socket
from pathlib import Path

INNER = '''
import socket

import pytest

import dns.message
import dns.query
import httpx


def test_a_connection_even_if_its_error_is_swallowed():
    try:
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    except Exception:
        pass


def test_a_dns_query():
    dns.query.udp(dns.message.make_query("example.com", "A"), "192.0.2.53", timeout=1)


def test_an_http_request():
    httpx.get("https://example.com/")


def test_an_old_style_lookup():
    socket.gethostbyname("example.org")


def test_an_old_style_lookup_of_every_address():
    socket.gethostbyname_ex("example.net")


@pytest.mark.skipif(not hasattr(socket.socket, "sendmsg"), reason="no sendmsg on this platform")
def test_a_datagram_sent_with_sendmsg():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendmsg([b"x"], [], 0, ("192.0.2.54", 53))


def test_loopback():
    with socket.create_server(("127.0.0.1", 0)) as server:
        socket.create_connection(server.getsockname(), timeout=1).close()
'''


def test_an_offline_test_that_reaches_the_internet_fails_and_nothing_is_sent(pytester):
    pytester.makeconftest((Path(__file__).parent / "conftest.py").read_text(encoding="utf-8"))
    pytester.makepyfile(test_inner=INNER)

    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")

    sendmsg = hasattr(socket.socket, "sendmsg")
    result.assert_outcomes(passed=1, failed=5 + sendmsg, skipped=1 - sendmsg)
    result.stdout.fnmatch_lines_random(["*192.0.2.1*", "*192.0.2.53*", "*example.com*", "*example.org*", "*example.net*", *(["*192.0.2.54*"] if sendmsg else [])])
