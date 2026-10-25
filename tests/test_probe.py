"""NetworkProber against scripted servers on loopback: the addresses it dials are routed there, so
nothing leaves the machine."""

import datetime
import os
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from farpoint import probe
from farpoint.posture import check_mx
from farpoint.probe import NetworkProber


@pytest.fixture
def routes(monkeypatch):
    """(ip, port) -> loopback port; any other address is unreachable, as from a scanner with no IPv6."""
    table: dict[tuple[str, int], int] = {}
    dialled: list[str] = []
    real = socket.create_connection

    def create_connection(address, *args, **kwargs):
        dialled.append(address[0])
        if (address[0], address[1]) not in table:
            raise OSError("network is unreachable")
        return real(("127.0.0.1", table[(address[0], address[1])]), *args, **kwargs)

    monkeypatch.setattr(probe.socket, "create_connection", create_connection)
    return table, dialled


def smtp_server(replies: list[bytes]) -> int:
    """A one-connection SMTP server: sends replies[0] as the greeting, then one reply per line it reads."""
    listener = socket.create_server(("127.0.0.1", 0))

    def serve():
        conn, _ = listener.accept()
        with conn, conn.makefile("rb") as reader:
            conn.sendall(replies[0])
            for reply in replies[1:]:
                if not reader.readline():
                    return
                conn.sendall(reply)
        listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


def test_an_ehlo_the_server_rejects_leaves_starttls_unknown(routes):
    table, _ = routes
    table[("203.0.113.25", 25)] = smtp_server([b"220 mx.example.com ESMTP\r\n", b"421 4.7.0 too many connections\r\n"])

    mx = check_mx(NetworkProber(timeout=2), "mx.example.com", "203.0.113.25")

    assert mx["starttls"] is None  # it never said what it supports: not "no STARTTLS"


def test_an_ehlo_without_starttls_is_a_definite_no(routes):
    table, _ = routes
    table[("203.0.113.25", 25)] = smtp_server([b"220 mx.example.com ESMTP\r\n", b"250-mx.example.com\r\n250 SIZE 1000\r\n", b"221 bye\r\n"])

    assert check_mx(NetworkProber(timeout=2), "mx.example.com", "203.0.113.25")["starttls"] is False


@pytest.fixture
def https_server(monkeypatch):
    """An HTTPS server on loopback with a certificate for mta-sts.example.com that _context(verify=True) trusts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mta-sts.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("mta-sts.example.com")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)

    class Policy(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"version: STSv1\r\nmode: enforce\r\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
        with open(cert_path, "wb") as fh:
            fh.write(pem)
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Policy)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    real_context = probe._context

    def trusting(verify=False, version=None):
        ctx = real_context(verify, version)
        if verify:
            ctx.load_verify_locations(cadata=pem.decode())
        return ctx

    monkeypatch.setattr(probe, "_context", trusting)
    yield server.server_address[1]
    server.shutdown()


def resolves_to(monkeypatch, *ips):
    """mta-sts.example.com resolves to `ips`, in that order; other names (loopback) resolve as usual."""
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host != "mta-sts.example.com":
            return real(host, port, *args, **kwargs)
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0)) if ":" in ip else (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(probe.socket, "getaddrinfo", getaddrinfo)


def test_a_policy_host_unreachable_over_its_first_address_is_fetched_over_the_next(routes, https_server, monkeypatch):
    table, dialled = routes
    v6, v4 = "2606:4700:4700::1111", "1.1.1.1"  # global addresses; neither is ever really dialled
    resolves_to(monkeypatch, v6, v4)
    table[(v4, 443)] = https_server

    policy = NetworkProber(timeout=2).fetch("https://mta-sts.example.com/.well-known/mta-sts.txt")

    assert policy is not None and policy.status == 200 and b"mode: enforce" in policy.body
    assert dialled == [v6, v4]


def test_a_policy_host_on_a_private_address_is_never_dialled(routes, monkeypatch):
    _, dialled = routes
    resolves_to(monkeypatch, "10.0.0.5")

    assert NetworkProber(timeout=2).fetch("https://mta-sts.example.com/.well-known/mta-sts.txt") is None
    assert dialled == []


@pytest.fixture
def http_server():
    """A plain HTTP server on loopback that records each request's User-Agent: (port, agents)."""
    agents: list[str] = []

    class Record(BaseHTTPRequestHandler):
        def do_GET(self):
            agents.append(self.headers.get("User-Agent", ""))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Record)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], agents
    server.shutdown()
    server.server_close()


def test_requests_to_the_organisations_hosts_carry_the_engagement_id(routes, http_server):
    table, _ = routes
    port, agents = http_server
    table[("203.0.113.80", 80)] = port

    NetworkProber(timeout=2, engagement="ACME-2026-Q4").http("http", "www.example.com", "203.0.113.80", 80)
    NetworkProber(timeout=2).http("http", "www.example.com", "203.0.113.80", 80)

    assert agents == ["farpoint/0.1 (host fingerprinting; engagement ACME-2026-Q4)", "farpoint/0.1 (host fingerprinting)"]


@pytest.mark.parametrize("bad", ["ACME\r\nX-Injected: 1", "a(b)c", "x" * 65, "   ", " ACME", "ACME ", ""])
def test_an_engagement_id_that_cannot_go_in_a_header_is_refused(bad):
    with pytest.raises(ValueError):
        NetworkProber(engagement=bad)
