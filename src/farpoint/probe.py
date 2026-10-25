"""Network primitives for --fingerprint: the only code in farpoint that connects to the organisation's hosts.

Everything here is one short, ordinary exchange: a TCP connect, reading what a server says first, a
TLS handshake, one HTTP GET, an SMTP EHLO/STARTTLS, a zone transfer request. Nothing sends a payload,
logs in, or guesses credentials. The logic that decides what to ask lives in farpoint.fingerprint and
farpoint.posture, behind the Prober protocol, so it can be tested without a network.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import quote, urlsplit

import dns.exception
import dns.query
import dns.zone

from farpoint import runtime

USER_AGENT = "farpoint/0.1 (host fingerprinting)"
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
BODY_LIMIT = 256 * 1024
PER_IP = 2  # connections in flight to one address at a time


@dataclass
class TlsResult:
    version: str | None = None  # TLSv1.3
    cipher: str | None = None
    cert: bytes | None = None  # DER


@dataclass
class HttpResult:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)  # lower-cased names, in order
    body: bytes = b""

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k == name), None)

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]


@dataclass
class SmtpResult:
    banner: str = ""
    ehlo: list[str] = field(default_factory=list)
    starttls: bool = False
    tls: TlsResult | None = None


class Prober(Protocol):
    """What fingerprinting asks the network. Every method may raise on a network error."""

    def connect(self, ip: str, port: int) -> str: ...  # "open", "closed" or "filtered"

    def banner(self, ip: str, port: int, wait: float = 3.0) -> bytes: ...  # what the server sends first (b"" if nothing)

    def tls(self, host: str, ip: str, port: int, version: str | None = None) -> TlsResult | None: ...  # None: no TLS

    def http(self, scheme: str, host: str, ip: str, port: int, path: str = "/") -> HttpResult | None: ...  # None: not HTTP

    def smtp(self, host: str, ip: str, port: int = 25) -> SmtpResult: ...

    def axfr(self, nameserver_ip: str, domain: str) -> int: ...  # records transferred (0: refused)

    def fetch(self, url: str) -> HttpResult | None: ...  # a plain HTTPS GET with certificate checks (MTA-STS policy)


def _context(verify: bool = False, version: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_default_certs()
    if version:  # a legacy-only handshake: does the server still accept it?
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            v = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}[version]
            ctx.minimum_version = ctx.maximum_version = v
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a chosen address with the hostname as SNI and Host, so each virtual host is asked by name."""

    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port, context=context, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), CONNECT_TIMEOUT)
        sock.settimeout(self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), CONNECT_TIMEOUT)
        self.sock.settimeout(self.timeout)


def _sni(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


class NetworkProber:
    """The real network. At most PER_IP connections to one address at a time; every call checks for Ctrl-C."""

    def __init__(self, timeout: float = READ_TIMEOUT) -> None:
        self.timeout = timeout
        self._lock = threading.Lock()
        self._slots: dict[str, threading.BoundedSemaphore] = {}

    def _slot(self, ip: str) -> threading.BoundedSemaphore:
        with self._lock:
            return self._slots.setdefault(ip, threading.BoundedSemaphore(PER_IP))

    def _guard(self, ip: str, fn: Callable):
        runtime.check()
        with self._slot(ip):
            runtime.count_request()
            return fn()

    def connect(self, ip: str, port: int) -> str:
        def go() -> str:
            try:
                with socket.create_connection((ip, port), CONNECT_TIMEOUT):
                    return "open"
            except ConnectionRefusedError:
                return "closed"
            except (TimeoutError, socket.timeout):
                return "filtered"
            except OSError:  # unreachable network/host
                return "filtered"

        return self._guard(ip, go)

    def banner(self, ip: str, port: int, wait: float = 3.0) -> bytes:
        def go() -> bytes:
            try:
                with socket.create_connection((ip, port), CONNECT_TIMEOUT) as sock:
                    sock.settimeout(wait)
                    return sock.recv(4096)
            except OSError:  # refused, timed out or reset: it said nothing first
                return b""

        return self._guard(ip, go)

    def tls(self, host: str, ip: str, port: int, version: str | None = None) -> TlsResult | None:
        def go() -> TlsResult | None:
            try:
                ctx = _context(version=version)
            except (ValueError, ssl.SSLError):  # this OpenSSL can't offer that version at all
                raise UnsupportedHere(version)
            try:
                with socket.create_connection((ip, port), CONNECT_TIMEOUT) as raw:
                    raw.settimeout(self.timeout)
                    with ctx.wrap_socket(raw, server_hostname=_sni(host)) as sock:
                        return TlsResult(sock.version(), (sock.cipher() or (None,))[0], sock.getpeercert(binary_form=True))
            except (ssl.SSLError, OSError):  # not TLS, refused, reset or timed out
                return None

        return self._guard(ip, go)

    def http(self, scheme: str, host: str, ip: str, port: int, path: str = "/") -> HttpResult | None:
        def go() -> HttpResult | None:
            if scheme == "https":
                conn = _PinnedHTTPSConnection(host, ip, port, _context(), self.timeout)
            else:
                conn = _PinnedHTTPConnection(host, ip, port, self.timeout)
            try:
                conn.request("GET", quote(path, safe="/?&=%:@!$'()*+,;~-._"), headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"})
                resp = conn.getresponse()
                headers = [(k.lower(), v) for k, v in resp.getheaders()]
                try:
                    body = resp.read(BODY_LIMIT)
                except http.client.IncompleteRead as exc:
                    body = exc.partial
                except (OSError, http.client.HTTPException):
                    body = b""  # the headers are what matter most
                return HttpResult(resp.status, headers, body)
            except (http.client.HTTPException, ssl.SSLError, OSError, ValueError):
                return None  # something answered, but not HTTP (or hung up): what the port said before stays recorded
            finally:
                conn.close()

        return self._guard(ip, go)

    def smtp(self, host: str, ip: str, port: int = 25) -> SmtpResult:
        def go() -> SmtpResult:
            result = SmtpResult()
            with socket.create_connection((ip, port), CONNECT_TIMEOUT) as raw:
                try:
                    return self._smtp_exchange(raw, host, result)
                except OSError:  # timed out or hung up part-way: keep what it said
                    return result

        return self._guard(ip, go)

    def _smtp_exchange(self, raw: socket.socket, host: str, result: SmtpResult) -> SmtpResult:
        """Greeting, EHLO, and STARTTLS if offered (for the certificate); then QUIT. Never MAIL FROM."""
        raw.settimeout(self.timeout * 2)  # some MTAs delay the greeting on purpose
        reader = raw.makefile("rb")
        _, greeting = _smtp_reply(reader)
        result.banner = " ".join(greeting)
        raw.sendall(b"EHLO farpoint.invalid\r\n")
        code, ehlo = _smtp_reply(reader)
        if code != "250":  # refused (421 busy, 554 rejected): it never said what it supports, so ehlo stays empty
            raw.sendall(b"QUIT\r\n")
            return result
        result.ehlo = ehlo
        result.starttls = any(line.upper().startswith("STARTTLS") for line in result.ehlo)
        if not result.starttls:
            raw.sendall(b"QUIT\r\n")
            return result
        raw.sendall(b"STARTTLS\r\n")
        code, _ = _smtp_reply(reader)
        if code != "220":
            return result
        try:
            with _context().wrap_socket(raw, server_hostname=_sni(host)) as sock:
                result.tls = TlsResult(sock.version(), (sock.cipher() or (None,))[0], sock.getpeercert(binary_form=True))
                sock.sendall(b"QUIT\r\n")
        except (ssl.SSLError, OSError):
            pass
        return result

    def axfr(self, nameserver_ip: str, domain: str) -> int:
        def go() -> int:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain, timeout=self.timeout, lifetime=self.timeout * 2))
            except (dns.exception.DNSException, OSError, EOFError):
                return 0
            return sum(len(node.rdatasets) for node in zone.nodes.values())

        return self._guard(nameserver_ip, go)

    def fetch(self, url: str) -> HttpResult | None:
        """Each of the host's addresses in turn until one connects, so a scanner without IPv6 still
        reaches a dual-stacked host."""
        parts = urlsplit(url)
        host, port = parts.hostname or "", parts.port or 443
        try:
            ips = list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)))
        except OSError:
            return None

        def go(ip: str) -> HttpResult | None:
            conn = _PinnedHTTPSConnection(host, ip, port, _context(verify=True), self.timeout)
            try:
                try:
                    conn.connect()
                except ssl.SSLError:  # reached it: its TLS or certificate is the answer
                    return None
                except OSError:
                    raise _Unreachable from None
                conn.request("GET", parts.path or "/", headers={"User-Agent": USER_AGENT, "Connection": "close"})
                resp = conn.getresponse()
                return HttpResult(resp.status, [(k.lower(), v) for k, v in resp.getheaders()], resp.read(64 * 1024))
            except (OSError, http.client.HTTPException):
                return None
            finally:
                conn.close()

        for ip in ips:
            if not ipaddress.ip_address(ip).is_global:  # never follow the organisation's DNS into a private network
                continue
            try:
                return self._guard(ip, lambda: go(ip))
            except _Unreachable:
                continue
        return None


class _Unreachable(Exception):
    """This address didn't take the connection; another of the host's may."""


class UnsupportedHere(Exception):
    """This machine's OpenSSL refuses to offer the TLS version at all, so the server's answer is unknown."""


def _smtp_reply(reader) -> tuple[str, list[str]]:
    """One (possibly multi-line) SMTP reply: its code and its lines without the code."""
    code, lines = "", []
    for _ in range(100):
        raw = reader.readline(1024)
        if not raw:
            break
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        code = line[:3]
        lines.append(line[4:] if len(line) > 3 else "")
        if len(line) < 4 or line[3] != "-":
            break
    return code, lines


def cert_summary(der: bytes | None, host: str, now: datetime | None = None) -> dict | None:
    """The facts about a certificate that matter for an assessment, as plain JSON values."""
    if not der:
        return None
    try:
        return _cert_summary(der, host, now)
    except Exception as exc:  # noqa: BLE001 - appliances ship odd certificates; never lose the service over one
        return {"error": f"unreadable certificate ({type(exc).__name__})"}


def _cert_summary(der: bytes, host: str, now: datetime | None) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return {"error": "unparseable certificate"}
    now = now or datetime.now(timezone.utc)

    def name_attr(name, oid) -> str | None:
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else None

    try:
        sans = sorted({n.lower() for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)})
    except x509.ExtensionNotFound:
        sans = []
    cn = name_attr(cert.subject, NameOID.COMMON_NAME)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"EC {key.curve.name}"
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_desc = type(key).__name__.removesuffix("PublicKey")
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc = f"DSA {key.key_size}"
    else:
        key_desc = type(key).__name__
    not_after = cert.not_valid_after_utc
    names = sans or ([cn.lower()] if cn else [])
    return {
        "subject": cn or cert.subject.rfc4514_string(),
        "issuer": name_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or name_attr(cert.issuer, NameOID.COMMON_NAME) or cert.issuer.rfc4514_string(),
        "sans": sans[:50],
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_left": (not_after - now).days,
        "self_signed": cert.issuer == cert.subject,
        "matches": any(_name_matches(host, n) for n in names),
        "wildcard": any(n.startswith("*.") for n in names),
        "key": key_desc,
        "signature": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
    }


def _name_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower(), pattern.lower()
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return host == pattern
