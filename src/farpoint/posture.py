"""Per scan domain posture for --fingerprint: how spoofable its mail is, how its DNS is run, when its
registration lapses. Almost all of it is DNS through the recursive resolver; the exceptions are one
zone-transfer request per nameserver the organisation runs itself (managed DNS services never allow one,
see data/dns_providers.json), the MTA-STS policy fetch, and one RDAP query to the registry.

Mail servers are checked separately (check_mx), and only the ones the organisation runs itself: a
hosted provider's (Microsoft 365, Google, a mail gateway) are the provider's, not the target's.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Protocol

from farpoint import runtime
from farpoint.models import describe
from farpoint.probe import Prober, cert_summary
from farpoint.suffixes import registered

MAX_SPF_LOOKUPS = 10  # RFC 7208: more makes the record fail (permerror), so mail is unauthenticated

MAIL_PROVIDERS = (  # MX suffix -> provider
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("mimecast.com", "Mimecast"),
    ("mimecast.co.za", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("messagelabs.com", "Broadcom (MessageLabs)"),
    ("iphmx.com", "Cisco Secure Email"),
    ("trendmicro.com", "Trend Micro"),
    ("trendmicro.eu", "Trend Micro"),
    ("sophos.com", "Sophos"),
    ("hornetsecurity.com", "Hornetsecurity"),
    ("antispamcloud.com", "SpamExperts"),
    ("zoho.com", "Zoho"),
    ("zoho.eu", "Zoho"),
    ("protonmail.ch", "Proton"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "Amazon SES/WorkMail"),
    ("secureserver.net", "GoDaddy"),
    ("emailsrvr.com", "Rackspace"),
    ("arsmtp.com", "AppRiver"),
    ("fireeyecloud.com", "Trellix"),
    ("forcepoint.net", "Forcepoint"),
    ("mailcontrol.com", "Forcepoint"),
    ("cloud-sec-av.com", "Check Point Harmony"),
    ("inbound.mailchannels.net", "MailChannels"),
)


class Dns(Protocol):
    def records(self, name: str, rdtype: str, strict: bool = False) -> list[str] | None: ...  # None: name doesn't exist

    def txt(self, name: str) -> list[str]: ...


@cache
def bundled_selectors() -> tuple[str, ...]:
    text = resources.files("farpoint.data").joinpath("dkim_selectors.txt").read_text(encoding="utf-8")
    return tuple(s.strip() for s in text.splitlines() if s.strip() and not s.startswith("#"))


@cache
def bundled_dns_providers() -> tuple[tuple[str, re.Pattern], ...]:
    data = json.loads(resources.files("farpoint.data").joinpath("dns_providers.json").read_text(encoding="utf-8"))
    return tuple((p["provider"], re.compile(p["ns"], re.IGNORECASE)) for p in data["providers"])


def dns_provider(nameserver: str) -> str | None:
    """The managed DNS service a nameserver belongs to, or None (self-run, or a service not listed)."""
    return next((name for name, pattern in bundled_dns_providers() if pattern.search(nameserver)), None)


def mail_provider(mx: Sequence[str], own: Callable[[str], bool]) -> str | None:
    """Who receives the domain's mail: a known provider, "self-hosted" (its own hosts) or the MX's domain."""
    if not mx:
        return None
    names = []
    for host in mx:
        name = next((p for suffix, p in MAIL_PROVIDERS if host == suffix or host.endswith("." + suffix)), None)
        names.append(name or ("self-hosted" if own(host) else registered(host) or host))
    return ", ".join(dict.fromkeys(names))


def hosted(mx_host: str) -> bool:
    return any(mx_host == s or mx_host.endswith("." + s) for s, _ in MAIL_PROVIDERS)


# --- SPF -----------------------------------------------------------------------------------------


def spf_records(txt: Sequence[str]) -> list[str]:
    return [t for t in txt if t.lower().startswith("v=spf1") and (len(t) == 6 or t[6] == " ")]


@dataclass
class SpfCheck:
    record: str | None = None
    records: int = 0  # more than one is a permerror
    all: str | None = None  # the "all" mechanism's qualifier+all (-all, ~all, ?all, +all), or redirect=...
    lookups: int = 0
    missing: list[str] | None = None  # include/redirect targets with no SPF record
    unregistered: list[str] | None = None  # ...whose domain isn't registered at all: anyone could buy it

    def row(self) -> dict:
        return {
            "spf": self.record,
            "spf_records": self.records,
            "spf_all": self.all,
            "spf_lookups": self.lookups,
            "spf_missing_includes": self.missing or [],
            "spf_unregistered_includes": self.unregistered or [],
        }


def check_spf(dns: Dns, domain: str) -> SpfCheck:
    found = spf_records(dns.txt(domain))
    check = SpfCheck(found[0] if found else None, len(found), missing=[], unregistered=[])
    if not found:
        return check
    terms = found[0].split()[1:]
    for term in terms:
        bare = term.lstrip("+-~?").lower()
        if bare == "all":
            check.all = term if term[0] in "+-~?" else "+all"
    redirect = next((t.split("=", 1)[1] for t in terms if t.lower().startswith("redirect=")), None)
    if check.all is None and redirect:
        check.all = f"redirect={redirect}"
    seen: set[str] = set()
    _count_lookups(dns, terms, check, seen, depth=0)
    return check


def _count_lookups(dns: Dns, terms: Sequence[str], check: SpfCheck, seen: set[str], depth: int) -> None:
    """Count the DNS lookups evaluating `terms` costs, following include/redirect into their records."""
    has_all = any(t.lstrip("+-~?").lower() == "all" for t in terms)
    for term in terms:
        mechanism, _, target = re.split(r"([:=/])", term.lstrip("+-~?").lower() + ":", maxsplit=1)
        target = target.rstrip(":")
        if mechanism in ("a", "mx", "ptr", "exists"):
            check.lookups += 1
        elif mechanism == "redirect" and has_all:
            continue  # RFC 7208 6.1: ignored when the record has an all mechanism
        elif mechanism in ("include", "redirect") and target:
            check.lookups += 1
            if "%{" in target or target in seen or depth > 5 or check.lookups > 30:
                continue
            seen.add(target)
            nested = spf_records(dns.txt(target))
            if nested:
                _count_lookups(dns, nested[0].split()[1:], check, seen, depth + 1)
                continue
            check.missing.append(target)
            reg = registered(target)
            if reg and dns.records(reg, "NS") is None:
                check.unregistered.append(target)


# --- DMARC, DKIM, MTA-STS ---------------------------------------------------------------------------


def tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            out[key.strip().lower()] = value.strip()
    return out


def check_dmarc(dns: Dns, domain: str) -> dict:
    """The domain's DMARC policy, falling back to its registered domain's as receivers do (which
    then apply its sp=, if it has one, rather than its p=)."""
    for name in dict.fromkeys([domain, registered(domain) or domain]):
        records = [t for t in dns.txt(f"_dmarc.{name}") if t.lower().startswith("v=dmarc1")]
        if records:
            t = tags(records[0])
            inherited = name != domain
            return {
                "dmarc": records[0],
                "dmarc_from": name if inherited else None,
                "dmarc_policy": (inherited and t.get("sp", "").lower()) or t.get("p", "").lower() or None,
                "dmarc_subdomain_policy": t.get("sp", "").lower() or None,
                "dmarc_pct": int(t["pct"]) if t.get("pct", "").isdigit() else 100,
                "dmarc_reports": bool(t.get("rua")),
            }
    return {"dmarc": None, "dmarc_policy": None}


def dkim_key_bits(record: str) -> int | None:
    """RSA key size of a DKIM record (0: revoked, empty p=), None if not RSA or unreadable."""
    t = tags(record)
    p = re.sub(r"\s+", "", t.get("p", ""))
    if not p:
        return 0
    if t.get("k", "rsa").lower() != "rsa":
        return None
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        key = load_der_public_key(base64.b64decode(p + "=" * (-len(p) % 4)))
    except ValueError:
        return None
    return key.key_size if isinstance(key, rsa.RSAPublicKey) else None


def check_dkim(dns: Dns, domain: str, selectors: Sequence[str]) -> dict[str, int | None]:
    """Selectors found among the common ones, with their RSA key sizes ("*": a wildcard answers every
    selector, typically an empty key that revokes them all on a domain that sends no mail)."""
    wildcard = [t for t in dns.txt(f"{secrets.token_hex(6)}._domainkey.{domain}") if "p=" in t]
    if wildcard:
        return {"*": dkim_key_bits(wildcard[0])}
    found = {}
    for selector in selectors:
        records = [t for t in dns.txt(f"{selector}._domainkey.{domain}") if "p=" in t]
        if records:
            found[selector] = dkim_key_bits(records[0])
    return found


def check_mta_sts(dns: Dns, prober: Prober, domain: str) -> dict:
    record = next((t for t in dns.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")), None)
    out: dict = {"mta_sts": None}
    if record:
        policy = prober.fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
        if policy is None or policy.status != 200:
            out["mta_sts"] = "broken"  # advertised, but the policy can't be fetched with a valid certificate
        else:
            mode = re.search(r"^mode:\s*(\w+)", policy.body.decode("utf-8", "replace"), re.M | re.I)
            out["mta_sts"] = mode.group(1).lower() if mode else "broken"
    out["tls_rpt"] = any(t.lower().startswith("v=tlsrptv1") for t in dns.txt(f"_smtp._tls.{domain}"))
    out["bimi"] = any(t.lower().startswith("v=bimi1") for t in dns.txt(f"default._bimi.{domain}"))
    return out


# --- DNS -----------------------------------------------------------------------------------------


def check_dns(dns: Dns, prober: Prober, domain: str, axfr: bool = True) -> dict:
    ns = dns.records(domain, "NS") or []
    providers = sorted({registered(n) or n for n in ns})
    transferred, answered, unanswered = [], False, False
    for n in ns if axfr else ():
        if dns_provider(n):  # a managed service: it never will, and asking looks like reconnaissance
            continue
        try:
            public = lambda rdtype: [a for a in dns.records(n, rdtype) or [] if ipaddress.ip_address(a).is_global]  # never into a private network
            address = (public("A") or public("AAAA"))[:1]
        except Exception:  # noqa: BLE001 - this nameserver's address is unknown: skip it
            continue
        for ip in address:
            records = prober.axfr(ip, domain)
            answered |= records is not None
            unanswered |= records is None
            if records:
                transferred.append(n)
    wildcard = dns.records(f"{secrets.token_hex(8)}.{domain}", "A")
    return {
        "ns": ns,
        "ns_providers": providers,
        # nameservers that hand out the whole zone; None: none was asked, or one didn't answer, so it's unknown
        "axfr": transferred or (None if unanswered or not answered else []),
        "dnssec": None if (ds := _strict(dns, domain, "DS")) is None else bool(ds),  # None: the resolver couldn't say
        "caa": _strict(dns, domain, "CAA"),
        "wildcard": bool(wildcard),
    }


def _strict(dns: Dns, name: str, rdtype: str) -> list[str] | None:
    """Records of a type the answer is reported on, or None when the resolver can't tell."""
    try:
        return dns.records(name, rdtype, strict=True) or []
    except Exception:  # noqa: BLE001 - a server failure or timeout: unknown, not "none"
        return None


# --- registration --------------------------------------------------------------------------------


def registration(body: Mapping) -> dict:
    """Registrar, dates and status from an RDAP domain object."""
    events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", []) if isinstance(e, dict)}
    registrar = None
    for entity in body.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = (entity.get("vcardArray") or [None, []])[1]
            registrar = next((p[3] for p in vcard if p and p[0] == "fn"), None) or entity.get("handle")
    return {
        "registrar": registrar,
        "created": (events.get("registration") or "")[:10] or None,
        "expires": (events.get("expiration") or "")[:10] or None,
        "status": sorted(body.get("status", [])),
    }


# --- everything for one domain ---------------------------------------------------------------------


def assess_domain(
    dns: Dns,
    prober: Prober,
    domain: str,
    own: Callable[[str], bool],
    rdap: Callable[[str], Mapping] | None = None,
    selectors: Sequence[str] | None = None,
    axfr: bool = True,
) -> dict:
    errors: list[str] = []

    def part(name: str, fn: Callable[[], dict]) -> dict:
        """One check; if its DNS fails (SERVFAIL, timeout), the others still count."""
        try:
            return fn()
        except runtime.Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {describe(exc)}")
            return {}

    mx = part("mx", lambda: {"mx": dns.records(domain, "MX") or []}).get("mx", [])
    row: dict = {"domain": domain, "mx": mx, "mail_provider": mail_provider(mx, own), "ns": []}
    row.update(part("spf", lambda: check_spf(dns, domain).row()))
    row.update(part("dmarc", lambda: check_dmarc(dns, domain)))
    row.update(part("dkim", lambda: {"dkim": check_dkim(dns, domain, selectors if selectors is not None else bundled_selectors())}))
    row.update(part("mta-sts", lambda: check_mta_sts(dns, prober, domain)))
    row.update(part("dns", lambda: check_dns(dns, prober, domain, axfr)))
    if errors:
        row["check_errors"] = errors
    if rdap:
        try:
            row.update(registration(rdap(registered(domain) or domain)))
        except Exception as exc:  # registration is a nice-to-have: never lose the rest over it
            row["registration_error"] = describe(exc)
    return row


def check_mx(prober: Prober, host: str, ip: str) -> dict:
    """What a self-run mail server says on port 25: product banner, STARTTLS, its certificate."""
    smtp = prober.smtp(host, ip, 25)
    out: dict = {"host": host, "ip": ip, "banner": smtp.banner[:200], "starttls": smtp.starttls if smtp.ehlo else None}  # None: it never answered EHLO
    if smtp.tls:
        out["tls"] = {"version": smtp.tls.version, **(cert_summary(smtp.tls.cert, host) or {})}
    return out
