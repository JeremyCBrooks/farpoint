import ipaddress
import socket

import httpx
import pytest

from farpoint import runtime
from farpoint.sources import base

pytest_plugins = ["pytester"]


class NetworkBlocked(OSError):
    """An offline test tried to reach a non-loopback address. Raised like any unreachable network."""


_attempts: list[str] = []


def _loopback(host) -> bool:
    if host in (None, "", "localhost"):
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def offline(request, monkeypatch):
    """Refuse every connection, UDP send and name lookup that isn't to loopback, unless the test is marked
    `network`. Attempts are recorded too, so a test still fails when farpoint swallows the error."""
    _attempts.clear()
    if request.node.get_closest_marker("network"):
        return

    def refuse(what):
        _attempts.append(what)
        raise NetworkBlocked(f"offline test tried to reach the network: {what}")

    real_connect, real_connect_ex, real_sendto, real_getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto, socket.getaddrinfo
    real_gethostbyname, real_gethostbyname_ex = socket.gethostbyname, socket.gethostbyname_ex

    def connect(sock, address):
        if isinstance(address, tuple) and not _loopback(address[0]):
            refuse(f"connect to {address[0]}:{address[1]}")
        return real_connect(sock, address)

    def connect_ex(sock, address):
        if isinstance(address, tuple) and not _loopback(address[0]):
            refuse(f"connect to {address[0]}:{address[1]}")
        return real_connect_ex(sock, address)

    def sendto(sock, data, *args):
        if isinstance(args[-1], tuple) and not _loopback(args[-1][0]):
            refuse(f"UDP to {args[-1][0]}:{args[-1][1]}")
        return real_sendto(sock, data, *args)

    def lookup(real):
        def guarded(host, *args, **kwargs):
            if not _loopback(host):
                try:
                    ipaddress.ip_address(str(host).split("%")[0])  # a literal address needs no lookup
                except ValueError:
                    refuse(f"lookup of {host}")
            return real(host, *args, **kwargs)

        return guarded

    def sendmsg(sock, buffers, *args):
        if len(args) == 3 and isinstance(args[2], tuple) and not _loopback(args[2][0]):
            refuse(f"UDP to {args[2][0]}:{args[2][1]}")
        return real_sendmsg(sock, buffers, *args)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket, "getaddrinfo", lookup(real_getaddrinfo))
    monkeypatch.setattr(socket, "gethostbyname", lookup(real_gethostbyname))
    monkeypatch.setattr(socket, "gethostbyname_ex", lookup(real_gethostbyname_ex))
    if real_sendmsg := getattr(socket.socket, "sendmsg", None):  # not on Windows
        monkeypatch.setattr(socket.socket, "sendmsg", sendmsg)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    result = yield
    if _attempts:
        pytest.fail("offline test tried to reach the network (mark it @pytest.mark.network if it must): " + "; ".join(_attempts), pytrace=False)
    return result


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """Record HTTP backoff/pacing sleeps instead of sleeping, advancing the clock the throttle reads."""
    clock = [1000.0]
    recorded: list[float] = []

    def sleep(seconds: float) -> None:
        runtime.check()
        recorded.append(seconds)
        clock[0] += seconds

    runtime.reset()
    monkeypatch.setattr(runtime, "sleep", sleep)
    monkeypatch.setattr(base.time, "monotonic", lambda: clock[0])
    return recorded


def fake_http(routes: dict) -> httpx.Client:
    """A real httpx.Client whose network is a routing table keyed by 'host/path'.

    A value may be an httpx.Response, a callable(request) -> Response, or a list of
    either (served in order, for retry/pagination). Unknown URLs get a 404 so a source
    hitting the wrong endpoint fails loudly instead of returning empty results.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.host + request.url.path
        route = routes.get(key)
        if route is None:
            return httpx.Response(404, text=f"unexpected request {request.url}")
        if isinstance(route, list):
            route = route.pop(0)
        return route(request) if callable(route) else route

    return httpx.Client(transport=httpx.MockTransport(handler))


def when_params(expected: dict, response: httpx.Response):
    """Serve `response` only if the request carries all `expected` query params (else 400)."""

    def handler(request: httpx.Request) -> httpx.Response:
        actual = dict(request.url.params)
        if any(actual.get(k) != v for k, v in expected.items()):
            return httpx.Response(400, text=f"bad params {actual}")
        return response

    return handler


def pairs(observations) -> set[tuple[str, str | None]]:
    return {(o.hostname, o.ip) for o in observations}
