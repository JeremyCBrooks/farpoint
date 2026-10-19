import httpx
import pytest

from easm import runtime
from easm.sources import base


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
