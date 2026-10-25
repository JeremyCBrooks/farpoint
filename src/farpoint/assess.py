"""Opt-in assessment (--assess): turn the inventory's facts into ranked findings, the way an attacker
picks a soft target. Sends nothing to the organisation's hosts.

Two parts:
  - lookups: the CVEs NVD lists for each product version --fingerprint identified (cached in
    assets.json for a week), and CISA's catalogue of vulnerabilities known to be exploited (KEV);
  - derive(): a pure function over the merged inventory (this run's fingerprints and earlier ones),
    so findings are re-judged from current facts every time and never go stale in the merge.

`level` is attacker interest, not CVSS: high = would be tried first (exposed admin/data services,
edge appliances, known-exploited or end-of-life software, takeovers, spoofable mail); medium =
useful weakness; low = hygiene.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import date, datetime, timedelta, timezone

import httpx

from farpoint import runtime
from farpoint.fingerprint import end_of_life, shared_address
from farpoint.sources.base import HttpSource

LEVELS = ("high", "medium", "low")
CVE_TTL_DAYS = 7
CATEGORY_ORDER = ("edge", "remote-access", "panel", "mail", "database", "cms", "cms-plugin", "framework", "language", "server", "waf", "cdn", "platform")

# Ports that should almost never answer from the internet, and what they are.
EXPOSED = {
    23: ("high", "Telnet"),
    445: ("high", "SMB"),
    1433: ("high", "Microsoft SQL Server"),
    1521: ("high", "Oracle database"),
    2375: ("high", "Docker API (unauthenticated by default)"),
    3306: ("high", "MySQL"),
    3389: ("high", "RDP"),
    5432: ("high", "PostgreSQL"),
    5900: ("high", "VNC"),
    5985: ("high", "WinRM"),
    5986: ("high", "WinRM"),
    6379: ("high", "Redis"),
    6443: ("high", "Kubernetes API"),
    9200: ("high", "Elasticsearch"),
    27017: ("high", "MongoDB"),
    21: ("medium", "FTP (cleartext logins)"),
    389: ("medium", "LDAP"),
    636: ("medium", "LDAPS"),
    110: ("low", "POP3 (cleartext)"),
    143: ("low", "IMAP (cleartext)"),
    22: ("low", "SSH"),
}
HIGH_PANELS = {"Jenkins", "GitLab", "Grafana", "Kibana", "phpMyAdmin", "Portainer", "Webmin", "cPanel / WHM", "Plesk", "SonarQube",
               "Microsoft Exchange OWA", "Microsoft Exchange ECP", "VMware vCenter / ESXi", "Citrix StoreFront", "Microsoft RD Web Access"}
MEDIUM_PANELS = {"Atlassian Jira", "Atlassian Confluence", "Swagger UI", "Zimbra", "Roundcube", "SmarterMail", "Microsoft AD FS",
                 "VMware Horizon", "Guacamole", "Microsoft SharePoint"}
SIGNALS = {
    "git-exposed": ("high", "the site's .git directory is downloadable: source code and often credentials"),
    "bucket-listing": ("high", "a storage bucket lists its contents publicly"),
    "directory-listing": ("medium", "directory listing is on"),
    "default-page": ("medium", "a default server page: often a forgotten, unpatched box"),
    "basic-auth": ("medium", "HTTP Basic authentication prompt: a password-spraying target"),
    "ntlm-auth": ("medium", "NTLM/Negotiate authentication: a password-spraying target that can leak the internal domain name"),
    "error-detail": ("medium", "an error page shows stack traces or debug detail"),
    "cors-any-origin-with-credentials": ("medium", "CORS allows any origin with credentials"),
    "no-starttls": ("medium", "the mail server does not offer STARTTLS: mail to it travels in cleartext"),
    "version-disclosure": ("low", "response headers disclose software versions"),
}
DEV_NAMES = re.compile(r"(^|[.-])(dev|develop|test|testing|tst|stage|staging|stg|uat|qa|preprod|pre-prod|sandbox|demo|old|legacy|backup|bak|temp|tmp|beta)\d*([.-]|$)")
INTERNAL_NAMES = re.compile(r"\.(local|internal|corp|lan|intranet|localdomain|home\.arpa)$")
BACKPORTED = re.compile(r"ubuntu|debian|deb\d|el\d|centos|red ?hat|rhel|amzn|suse", re.I)


# --- lookups (third parties only) ------------------------------------------------------------------


class Nvd(HttpSource):
    """NVD's CVE API: the CVEs whose affected configurations include a product version."""

    name = "nvd"
    max_concurrency = 1
    min_interval = 6.5  # keyless: 5 requests per 30 seconds

    def __init__(self, http: httpx.Client, api_key: str | None = None, **kwargs) -> None:
        super().__init__(http, api_key, **kwargs)
        if api_key:
            self.min_interval = 0.7  # 50 per 30 seconds

    def cves(self, cpe: str) -> list[dict]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        found, start = [], 0
        while True:
            body = self.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start, "noRejected": ""},
                headers=headers,
            ).json()
            for item in body.get("vulnerabilities", []):
                found.append(_cve_row(item.get("cve", {})))
            start += body.get("resultsPerPage", 0) or 2000
            if start >= body.get("totalResults", 0):
                return found


def _cve_row(cve: Mapping) -> dict:
    score, severity = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            if data.get("baseScore") is not None:
                score, severity = data["baseScore"], data.get("baseSeverity") or m.get("baseSeverity")
                break
        if score is not None:
            break
    return {"id": cve.get("id"), "score": score, "severity": (severity or "").lower() or None}


class Kev(HttpSource):
    """CISA's Known Exploited Vulnerabilities catalogue (one download)."""

    name = "cisa-kev"
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def catalogue(self) -> dict[str, dict]:
        body = self.get(self.URL).json()
        return {v["cveID"]: {"name": v.get("vulnerabilityName"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known"} for v in body.get("vulnerabilities", [])}


def wanted_cpes(report: Mapping) -> list[str]:
    return sorted({t["cpe"] for r in report.get("fingerprints", []) for t in r.get("tech", []) if t.get("cpe")})


def lookup_vulns(
    report: Mapping,
    nvd: Nvd | None,
    kev: Kev | None,
    now: datetime | None = None,
    progress: Callable[[int, int, int], None] | None = None,
) -> tuple[list[dict], dict[str, dict], list[dict]]:
    """CVEs per identified product version (NVD, re-fetched after CVE_TTL_DAYS), the KEV catalogue,
    and errors. Lookups that fail keep the previous answer."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    cached = {v["cpe"]: v for v in report.get("vulns", [])}
    fresh_after = (now - timedelta(days=CVE_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: list[dict] = []
    catalogue: dict[str, dict] = {}
    if kev:
        try:
            catalogue = kev.catalogue()
        except (httpx.HTTPError, ValueError, Exception) as exc:  # noqa: BLE001 - one feed must never sink the run
            if isinstance(exc, runtime.Cancelled):
                raise
            errors.append({"source": kev.name, "target": "catalogue", "message": f"{type(exc).__name__}: {exc}"})
    rows = []
    cpes = wanted_cpes(report)
    todo = [c for c in cpes if nvd and cached.get(c, {}).get("checked_at", "") < fresh_after]
    done = failed = 0
    if progress and todo:
        progress(0, len(todo), 0)
    for cpe in cpes:
        row = dict(cached.get(cpe, {"cpe": cpe, "cves": []}))
        if cpe in todo:
            try:
                row = {"cpe": cpe, "cves": nvd.cves(cpe), "checked_at": stamp}
            except runtime.Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001
                failed += 1
                errors.append({"source": nvd.name, "target": cpe, "message": f"{type(exc).__name__}: {exc}"})
            done += 1
            if progress:
                progress(done, len(todo), failed)
        rows.append(row)
    return rows, catalogue, errors


# --- findings ------------------------------------------------------------------------------------


def _finding(level: str, kind: str, target: str, detail: str, evidence: Iterable[str] = (), about: str | None = None) -> dict:
    """`about` tells apart findings of one kind on one target (two edge products, one MX serving two domains)."""
    return {"id": f"{kind}|{target}" + (f"|{about}" if about else ""), "level": level, "kind": kind, "target": target, "detail": detail, "evidence": [e for e in dict.fromkeys(evidence) if e]}


def derive(report: Mapping, kev: Mapping[str, dict] | None = None, today: date | None = None) -> list[dict]:
    """Every finding the inventory's facts support, most interesting first."""
    today = today or date.today()
    kev = kev or {}
    vulns = {v["cpe"]: v.get("cves", []) for v in report.get("vulns", [])}
    out: list[dict] = []
    fingerprints = report.get("fingerprints", [])
    https_hosts = {r["hostname"] for r in fingerprints if r.get("service") == "https" and (r.get("status") or 0) < 500}
    for r in fingerprints:
        out.extend(_endpoint_findings(r, vulns, kev, today, https_hosts))
    out.extend(_host_findings(fingerprints))
    cnames = {h["hostname"]: h.get("cnames", []) for h in report.get("hosts", [])}
    for ip in report.get("ips", []):
        if ip.get("vulns"):
            known = sorted(c for c in ip["vulns"] if c in kev)
            detail = f"Shodan lists {len(ip['vulns'])} CVEs for this address" + (f", {len(known)} known to be exploited" if known else "")
            if shared_address(ip.get("org"), [cnames.get(h, []) for h in ip.get("hostnames", [])], ip.get("tags", [])):
                level, detail = "low", detail + "; it is a shared CDN/SaaS front end, so they are the provider's to fix"
            else:
                level = "high" if known else "medium"
            out.append(_finding(level, "shodan-cves", ip["ip"], detail, (known or sorted(ip["vulns"]))[:20]))
    for d in report.get("dangling", []):
        if d.get("claimable", True):
            out.append(_finding("high", "subdomain-takeover", d["hostname"], d["reason"]))
        else:
            out.append(_finding("low", "dangling-cname", d["hostname"], d["reason"] + ": broken, but nothing known to make it claimable"))
    for p in report.get("posture", []):
        out.extend(_posture_findings(p, today))
    order = {level: i for i, level in enumerate(LEVELS)}
    return sorted(out, key=lambda f: (order[f["level"]], f["kind"], f["target"]))


def _endpoint_findings(r: Mapping, vulns: Mapping, kev: Mapping, today: date, https_hosts: set[str]) -> list[dict]:
    out = []
    ep, port = r["endpoint"], r.get("port")
    if port in EXPOSED:  # Elasticsearch, Docker, WinRM and Kubernetes answer HTTP and are just as exposed
        level, what = EXPOSED[port]
        out.append(_finding(level, "exposed-service", ep, f"{what} answers on port {port} from the internet"))
    for t in r.get("tech", []):
        name, version = t["name"], t.get("version")
        label = f"{name} {version}" if version else name
        if t.get("category") == "edge":
            out.append(_finding("high", "edge-device", ep, f"{label}: VPN/firewall/gateway appliances are the most exploited way in", [t.get("evidence", "")], name))
        elif name in HIGH_PANELS:
            out.append(_finding("high", "admin-interface", ep, f"{label} is reachable from the internet", [t.get("evidence", "")], name))
        elif name in MEDIUM_PANELS:
            out.append(_finding("medium", "admin-interface", ep, f"{label} is reachable from the internet", [t.get("evidence", "")], name))
        if eol := end_of_life(name, version, today):
            note = f" ({eol['note']})" if eol.get("note") else ""
            out.append(_finding("high", "end-of-life", ep, f"{label}{note} has been out of support since {eol['eol']}", about=name))
        if t.get("cpe") and (cves := vulns.get(t["cpe"])):
            out.append(_cve_finding(ep, label, t, cves, kev, r))
        if t.get("category") == "cms-plugin" and version:
            out.append(_finding("low", "plugin-version", ep, f"{label} discloses its version (check it against the plugin's advisories)", about=name))
    for sig in r.get("signals", []):
        if sig in SIGNALS:
            level, what = SIGNALS[sig]
            out.append(_finding(level, sig, ep, what))
    tls = r.get("tls") or {}
    if tls.get("not_after"):
        days = tls.get("days_left")
        if days is not None and days < 0:
            out.append(_finding("high", "certificate-expired", ep, f"the certificate expired on {tls['not_after'][:10]}"))
        elif days is not None and days <= 30:
            out.append(_finding("medium", "certificate-expiring", ep, f"the certificate expires on {tls['not_after'][:10]}"))
        if tls.get("self_signed"):
            out.append(_finding("medium", "certificate-self-signed", ep, f"a self-signed certificate ({tls.get('subject')})"))
        elif tls.get("matches") is False:
            out.append(_finding("medium", "certificate-mismatch", ep, f"the certificate is for {tls.get('subject')}, not {r['hostname']}"))
        if re.match(r"RSA (\d+)", tls.get("key") or "") and int(tls["key"].split()[1]) < 2048:
            out.append(_finding("medium", "weak-certificate-key", ep, f"the certificate key is {tls['key']}"))
        if (tls.get("signature") or "").lower() in ("md5", "sha1"):
            out.append(_finding("medium", "weak-certificate-signature", ep, f"the certificate is signed with {tls['signature'].upper()}"))
        if internal := [n for n in tls.get("sans", []) if INTERNAL_NAMES.search(n)]:
            out.append(_finding("low", "internal-names-in-certificate", ep, "the certificate names internal hosts", internal[:10]))
        if tls.get("wildcard"):
            out.append(_finding("low", "wildcard-certificate", ep, "a wildcard certificate: its key unlocks every name under the domain"))
    legacy = sorted(v for v, ok in (tls.get("legacy") or {}).items() if ok)
    if legacy:
        out.append(_finding("medium", "legacy-tls", ep, f"accepts {' and '.join(legacy)}"))
    headers = r.get("headers") or {}
    status = r.get("status") or 0
    if r.get("service") == "http" and 200 <= status < 300:
        if r["hostname"] not in https_hosts:
            out.append(_finding("medium", "cleartext-http", ep, "serves content over plain HTTP, with no HTTPS alternative"))
        else:
            out.append(_finding("low", "no-https-redirect", ep, "serves content over plain HTTP instead of redirecting to HTTPS"))
    if r.get("service") == "https" and 200 <= status < 300 and "strict-transport-security" not in headers:
        out.append(_finding("low", "no-hsts", ep, "HTTPS without Strict-Transport-Security"))
    return out


def _cve_finding(ep: str, label: str, tech: Mapping, cves: Sequence[Mapping], kev: Mapping, r: Mapping) -> dict:
    known = {c["id"] for c in cves if c.get("kev") or c.get("id") in kev}
    exploited = [c for c in cves if c.get("id") in known]
    worst = max((c.get("score") or 0 for c in cves), default=0)
    level = "high" if exploited or worst >= 9 else "medium" if worst >= 7 else "low"
    backported = BACKPORTED.search(f"{r.get('banner') or ''} {r.get('server') or ''}")
    if backported and level == "high" and not exploited:
        level = "medium"
    ranked = sorted(cves, key=lambda c: (c.get("id") not in known, -(c.get("score") or 0)))
    detail = f"{label}: NVD lists {len(cves)} CVEs for this version (worst CVSS {worst})"
    if exploited:
        detail += f", {len(exploited)} known to be exploited (CISA KEV)"
    if backported:
        detail += "; a distribution package, which may carry backported fixes"
    evidence = [f"{c['id']} {c.get('score') or ''}{' KEV' if c.get('id') in known else ''}".strip() for c in ranked[:15]]
    return _finding(level, "known-vulnerable-version", ep, detail, evidence, tech["name"])


def _host_findings(fingerprints: Sequence[Mapping]) -> list[dict]:
    out = []
    for host in sorted({r["hostname"] for r in fingerprints}):
        if DEV_NAMES.search(host.split(".", 1)[0]) or DEV_NAMES.search(host):
            out.append(_finding("medium", "non-production-exposed", host, "a development/test/old system reachable from the internet: usually less patched and monitored"))
    return out


def _posture_findings(p: Mapping, today: date) -> list[dict]:
    d = p["domain"]
    out = []
    spf_all = p.get("spf_all")
    policy = p.get("dmarc_policy")
    failed = {e.split(":", 1)[0] for e in p.get("check_errors", [])}
    if "spf" in failed:
        pass  # unknown, not missing
    elif not p.get("spf"):
        out.append(_finding("high", "spf-missing", d, "no SPF record: anyone can send mail as this domain"))
    elif spf_all in ("+all",):
        out.append(_finding("high", "spf-allows-all", d, "SPF ends in +all: every server on the internet is authorised to send its mail", [p["spf"]]))
    elif spf_all in ("?all", None):
        out.append(_finding("medium", "spf-neutral", d, f"SPF does not reject unlisted senders ({spf_all or 'no all mechanism'})", [p["spf"]]))
    if (p.get("spf_records") or 0) > 1:
        out.append(_finding("medium", "spf-multiple-records", d, "more than one SPF record: receivers treat SPF as broken"))
    if (p.get("spf_lookups") or 0) > 10:
        out.append(_finding("medium", "spf-too-many-lookups", d, f"SPF needs {p['spf_lookups']} DNS lookups (limit 10): receivers treat it as broken"))
    for inc in p.get("spf_unregistered_includes", []):
        out.append(_finding("high", "spf-include-unregistered", d, f"SPF includes {inc}, whose domain is not registered: whoever registers it can send as this domain"))
    for inc in set(p.get("spf_missing_includes", [])) - set(p.get("spf_unregistered_includes", [])):
        out.append(_finding("medium", "spf-include-missing", d, f"SPF includes {inc}, which has no SPF record"))
    if "dmarc" in failed:
        pass
    elif not p.get("dmarc"):
        level = "high" if spf_all != "-all" else "medium"
        out.append(_finding(level, "dmarc-missing", d, "no DMARC policy: spoofed mail as this domain is not rejected"))
    elif policy == "none":
        out.append(_finding("high" if spf_all != "-all" else "medium", "dmarc-not-enforced", d, "DMARC p=none: spoofed mail is reported but still delivered", [p["dmarc"]]))
    else:
        pct = p.get("dmarc_pct")
        if pct is not None and pct < 100:
            out.append(_finding("medium", "dmarc-partial", d, f"DMARC applies to only {p['dmarc_pct']}% of mail", [p["dmarc"]]))
        if p.get("dmarc_subdomain_policy") == "none":
            out.append(_finding("medium", "dmarc-subdomains-open", d, "DMARC sp=none: mail spoofing its subdomains is delivered", [p["dmarc"]]))
    dkim = p.get("dkim") or {}
    if p.get("mx") and not dkim and "dkim" not in failed:
        out.append(_finding("low", "dkim-not-found", d, "no DKIM key under any common selector (it may use another)"))
    for selector, bits in sorted(dkim.items()):
        if bits and bits < 2048 and selector != "*":
            out.append(_finding("medium", "dkim-weak-key", d, f"DKIM selector {selector} uses a {bits}-bit RSA key"))
    if p.get("mx"):
        if p.get("mta_sts") == "broken":
            out.append(_finding("medium", "mta-sts-broken", d, "MTA-STS is advertised but its policy can't be fetched"))
        elif not p.get("mta_sts") and "mta-sts" not in failed:
            out.append(_finding("low", "mta-sts-missing", d, "no MTA-STS: mail to this domain can be downgraded to cleartext in transit"))
    for mx in p.get("mx_health", []):
        if mx.get("starttls") is False:  # None: it never answered EHLO, so unknown
            out.append(_finding("medium", "mx-no-starttls", mx["host"], f"mail server for {d} does not offer STARTTLS", [mx.get("banner", "")], d))
        tls = mx.get("tls") or {}
        if tls and (tls.get("self_signed") or tls.get("matches") is False or (tls.get("days_left") or 0) < 0):
            out.append(_finding("low", "mx-certificate-invalid", mx["host"], f"mail server for {d} presents an invalid certificate ({tls.get('subject')})", about=d))
    if p.get("axfr"):
        out.append(_finding("high", "zone-transfer", d, "nameservers hand the whole zone to anyone (AXFR)", p["axfr"]))
    if p.get("ns") and p.get("dnssec") is False:
        out.append(_finding("low", "no-dnssec", d, "DNSSEC is not enabled"))
    if p.get("ns") and p.get("caa") == []:
        out.append(_finding("low", "no-caa", d, "no CAA record: any certificate authority may issue for it"))
    if len(p.get("ns_providers", [])) == 1 and len(p.get("ns", [])) < 2:
        out.append(_finding("low", "single-nameserver", d, "only one nameserver"))
    if expires := p.get("expires"):
        try:
            days = (date.fromisoformat(expires) - today).days
        except ValueError:
            days = None
        if days is not None and days <= 30:
            out.append(_finding("high", "domain-expiring", d, f"the registration expires on {expires}"))
    if transfer_locked(p.get("status", [])) is False:
        out.append(_finding("low", "no-transfer-lock", d, "the registration has no transfer lock", [s.lower() for s in p["status"]]))
    return out


def transfer_locked(statuses: Sequence[str]) -> bool | None:
    """Whether RDAP statuses include a transfer lock (None: no statuses to tell from)."""
    if not statuses:
        return None
    return any(re.sub(r"[\s_-]", "", s.lower()) in ("clienttransferprohibited", "servertransferprohibited") for s in statuses)


def merge_findings(prior: Sequence[Mapping], current: Sequence[dict], stamp: str, prior_stamp: str) -> list[dict]:
    """This assessment's findings, keeping when each was first seen."""
    first = {f["id"]: f.get("first_seen", prior_stamp) for f in prior}
    return [{**f, "first_seen": first.get(f["id"], stamp), "last_seen": stamp} for f in current]


def assessed(report: dict, vulns: list[dict], kev: Mapping[str, dict], stamp: str, errors: Sequence[dict] = ()) -> dict:
    """`report` with its findings and CVE cache replaced by this assessment's."""
    if kev:  # remembered on each CVE, so later runs without the catalogue still know
        vulns = [{**v, "cves": [{**c, "kev": True} if c.get("id") in kev else c for c in v.get("cves", [])]} for v in vulns]
    report = {**report, "vulns": vulns}
    today = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").date() if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stamp) else date.today()
    findings = derive(report, kev, today)
    report["findings"] = merge_findings(report.get("findings", []), findings, stamp, report.get("updated_at", stamp))
    report["assessed_at"] = stamp
    if errors:
        report["errors"] = [*report.get("errors", []), *errors]
    return report


def technologies(report: Mapping, today: date | None = None, kev: Mapping | None = None) -> list[dict]:
    """The inventory by technology: what runs where, grouped by product and version, edge devices first."""
    groups: dict[tuple[str, str | None], dict] = {}
    vulns = {v["cpe"]: v.get("cves", []) for v in report.get("vulns", [])}
    for r in report.get("fingerprints", []):
        for t in r.get("tech", []):
            g = groups.setdefault((t["name"], t.get("version")), {
                "category": t.get("category"), "technology": t["name"], "version": t.get("version"), "cpe": t.get("cpe"),
                "endpoints": [], "hosts": set(),
            })
            g["endpoints"].append(r["endpoint"])
            g["hosts"].add(r["hostname"])
    rows = []
    for g in groups.values():
        eol = end_of_life(g["technology"], g["version"], today)
        cves = vulns.get(g["cpe"] or "", [])
        rows.append({
            **g,
            "endpoints": sorted(g["endpoints"]),
            "hosts": sorted(g["hosts"]),
            "count": len(g["hosts"]),
            "eol": eol["eol"] if eol else None,
            "cves": len(cves) if g["cpe"] in vulns else None,
            "kev": sorted(c["id"] for c in cves if c.get("kev") or c.get("id") in (kev or {})) or None,
        })
    rank = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    return sorted(rows, key=lambda r: (rank.get(r["category"], len(rank)), -r["count"], r["technology"], r["version"] or ""))
