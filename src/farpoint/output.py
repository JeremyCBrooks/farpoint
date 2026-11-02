"""Write the inventory as plain lists (for piping), CSVs (for spreadsheets) and JSON (for tooling).

Runs accumulate: assets.json in the output directory is the running inventory, each run is merged
into it, and every other file is regenerated from the merged result.
"""

from __future__ import annotations

import copy
import csv
import ipaddress
import json
import os
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

from farpoint import files
from farpoint.credential_store import CredentialState, attempt_summary, load_credentials, save_credentials
from farpoint.credentials import CredentialBatch
from farpoint.files import now_stamp, stamp as _stamp
from farpoint.guess import RETRY_DAYS
from farpoint.models import Inventory, Observation, describe
from farpoint.names import normalize_ip
from farpoint.related import TIERS as _RELATED_TIERS
from farpoint.tenants import TIES as _TIES


def _ip_key(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def _ips(values: Iterable[str]) -> list[str]:
    """Sorted, and re-normalised: drops what earlier runs recorded that isn't a real address (a block page)."""
    return sorted({ip for v in values if (ip := normalize_ip(v))}, key=_ip_key)


def _resolves(flag: bool | None) -> str:
    return {True: "yes", False: "no", None: ""}[flag]


def _host_rows(inv: Inventory) -> list[dict]:
    return [
        {
            "hostname": h.hostname,
            "resolves": h.resolves,
            "ips": _ips(h.ips),
            "cnames": sorted(h.cnames),
            "sources": sorted(h.sources),
        }
        for h in sorted(inv.hosts.values(), key=lambda h: h.hostname)
    ]


def _ip_rows(inv: Inventory) -> list[dict]:
    return [
        {
            "ip": r.ip,
            "org": r.org,
            "network": r.network,
            "ports": sorted(r.ports),
            "vulns": sorted(r.vulns),
            "hostnames": sorted(r.hostnames),
            "sources": sorted(r.sources),
            **({"tags": sorted(r.tags)} if r.tags else {}),
            **({"open_ports": sorted(r.open_ports)} if r.probed_ports else {}),  # only once swept: else keep the last sweep's
        }
        for r in (inv.ips[ip] for ip in _ips(inv.ips))
    ]


def _fingerprint_rows(inv: Inventory) -> list[dict]:
    rows = []
    for key, s in sorted(inv.services.items(), key=lambda kv: (kv[1].hostname, kv[1].port)):
        row = {
            "endpoint": key,
            "hostname": s.hostname,
            "ip": s.ip,
            "port": s.port,
            "service": s.service,
            "tech": [t.row() for t in s.tech],
            "signals": sorted(set(s.signals)),
            "cookies": s.cookies,
        }
        for name in ("banner", "status", "title", "server", "location", "tls", "favicon"):
            if getattr(s, name) is not None:
                row[name] = getattr(s, name)
        if s.headers:
            row["headers"] = s.headers
        if s.paths:
            row["paths"] = s.paths
        if s.archived:
            row["archived"] = {**s.archived, "tech": [t.row() for t in s.archived["tech"]]}
        rows.append(row)
    return rows


def _tenant_rows(inv: Inventory) -> list[dict]:
    return [
        {
            "tenant": t.hostname,
            "vendor": t.vendor,
            "domain": t.domain,
            "tie": t.tie,
            "verified": t.verified,
            "evidence": sorted(t.evidence),
            "ips": _ips(t.ips),
            "cnames": sorted(t.cnames),
        }
        for t in sorted(inv.tenants.values(), key=lambda t: t.hostname)
    ]


def _related_rows(inv: Inventory) -> list[dict]:
    return [
        {"domain": r.domain, "related_to": r.related_to, "tie": r.tie, "evidence": sorted(r.evidence)}
        for r in sorted(inv.related.values(), key=lambda r: r.domain)
    ]


class ReportError(Exception):
    """The existing assets.json can't be read, so merging into it would lose history."""


_ROW_LISTS = {
    "hosts": ("hostname", ("ips", "cnames", "sources")),
    "ips": ("ip", ("ports", "vulns", "hostnames", "sources", "tags", "open_ports")),
    "lookalikes": ("domain", ("ips", "current_ips", "mx", "ns", "sources")),
    "tenants": ("tenant", ("evidence", "ips", "cnames", "hosts")),
    "related": ("domain", ("evidence",)),
    "fingerprints": ("endpoint", ("tech", "signals", "cookies")),
    "posture": ("domain", ("mx", "ns")),
    "dangling": ("hostname", ()),
    "identity": ("domain", ()),
    "scan_dns": ("domain", ("ns", "mx")),
    "findings": ("id", ("evidence",)),
    "vulns": ("cpe", ("cves",)),
}


def _validate(report) -> None:
    """Reject anything merge_reports can't fold, so a bad file fails before the scan instead of after it."""
    if not isinstance(report, dict):
        raise ValueError("top level is not an object")
    for field in ("domains", "runs", *_ROW_LISTS):
        if not isinstance(report.get(field, []), list):
            raise ValueError(f"'{field}' is not a list")
    guessed = report.get("guessed", {})  # name -> when last tested (a run's own report: a list of names)
    if not (isinstance(guessed, list) and all(isinstance(n, str) for n in guessed)) and not (
        isinstance(guessed, dict) and all(isinstance(n, str) and isinstance(at, str) for n, at in guessed.items())
    ):
        raise ValueError("'guessed' is not a list of names or a map of names to times")
    for field, (key, lists) in _ROW_LISTS.items():
        for i, row in enumerate(report.get(field, [])):
            where = f"{field}[{i}]"
            if not isinstance(row, dict) or not isinstance(row.get(key), str):
                raise ValueError(f"{where} has no '{key}'")
            if any(not isinstance(row.get(f, []), list) for f in lists):
                raise ValueError(f"{where} has a non-list field")
            for ip in [row[key]] if field == "ips" else [*row.get("ips", []), *row.get("current_ips", [])]:
                ipaddress.ip_address(ip)  # ValueError names the bad address


def load_report(out_dir: Path) -> dict | None:
    """The existing inventory in out_dir, or None if there is none yet."""
    path = out_dir / "assets.json"
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        _validate(report)
    except (OSError, ValueError) as exc:
        raise ReportError(f"can't merge into {path}: {exc}. Fix or move it, or choose another --out.") from exc
    if "updated_at" not in report:  # written before runs were merged: date its rows by the file's mtime
        report["updated_at"] = _stamp(datetime.fromtimestamp(path.stat().st_mtime, timezone.utc))
    return report


def _union(*lists: Iterable) -> list:
    return sorted({v for values in lists for v in values})


def _merge_rows(prior: list[dict], current: list[dict], key: str, merge, stamp: str, prior_stamp: str) -> tuple[list[dict], int]:
    """Union rows by `key`; `merge(old, new)` combines a row seen in both. Returns (rows, how many are new)."""
    merged = {row[key]: {"first_seen": prior_stamp, "last_seen": prior_stamp, **row} for row in prior}
    new = 0
    for row in current:
        old = merged.get(row[key])
        if old is None:
            new += 1
            merged[row[key]] = {**row, "first_seen": stamp, "last_seen": stamp}
        else:
            seen = {"first_seen": min(old["first_seen"], stamp), "last_seen": max(old["last_seen"], stamp)}
            merged[row[key]] = {**old, **row, **merge(old, row), **seen}
    return list(merged.values()), new


def _snapshot_rows(prior: list[dict], current: list[dict], key: str, stamp: str, prior_stamp: str, gone: Iterable = ()) -> tuple[list[dict], int]:
    """Rows that describe the latest look: this run's row replaces the old one whole (keeping when it
    was first seen); rows in `gone` (looked at again, no longer there) are dropped."""
    gone = set(gone)
    rows = {r[key]: {"first_seen": prior_stamp, "last_seen": prior_stamp, **r} for r in prior if r[key] not in gone}
    new = 0
    for row in current:
        before = rows.get(row[key])
        new += before is None
        rows[row[key]] = {**row, "first_seen": before["first_seen"] if before else stamp, "last_seen": stamp}
    return list(rows.values()), new


def _keep_axfr(row: dict, before: dict | None) -> dict:
    """A zone transfer not asked for this run (--no-axfr, or no answer) keeps the last answer from the same nameservers."""
    if row.get("axfr") is None and before and before.get("axfr") is not None and sorted(before.get("ns", [])) == sorted(row.get("ns", [])):
        return {**row, "axfr": before["axfr"]}
    return row


def merge_reports(prior: dict | None, current: dict, stamp: str) -> dict:
    """Fold this run's report into the running inventory. Lists are unioned; a host's `resolves` and an
    IP's org/network take this run's value when it has one. Rows gain first_seen/last_seen."""
    prior = prior or {}
    prior_stamp = prior.get("updated_at", stamp)

    def host(old, new):
        return {
            "resolves": new["resolves"] if new["resolves"] is not None else old.get("resolves"),
            **{f: _union(old.get(f, []), new[f]) for f in ("cnames", "sources")},
            "ips": _ips(set(old.get("ips", [])) | set(new["ips"])),
        }

    def ip(old, new):
        return {
            "org": new["org"] or old.get("org"),
            "network": new["network"] or old.get("network"),
            **{f: _union(old.get(f, []), new[f]) for f in ("ports", "vulns", "hostnames", "sources")},
            **({"tags": _union(old.get("tags", []), new.get("tags", []))} if old.get("tags") or new.get("tags") else {}),
        }

    def lookalike(old, new):  # addresses accumulate; what it can do now is this run's look
        looked_up = new.get("registration_checked") == stamp  # else keep the last lookup's answer
        return {
            "ips": _ips(set(old.get("ips", [])) | set(new["ips"])),
            "sources": _union(old.get("sources", []), new["sources"]),
            **({"last_certificate": new.get("last_certificate") or old.get("last_certificate")} if looked_up else
               {f: old.get(f) for f in ("registered_on", "registrar", "registration_checked", "last_certificate")}),
        }

    def tenant(old, new):
        stronger = max(old, new, key=lambda row: _TIES.index(row.get("tie")) if row.get("tie") in _TIES else -1)
        return {
            "vendor": stronger.get("vendor"),
            "tie": stronger.get("tie"),
            "verified": bool(old.get("verified") or new["verified"]),
            **{f: _union(old.get(f, []), new[f]) for f in ("evidence", "cnames")},
            "ips": _ips(set(old.get("ips", [])) | set(new["ips"])),
        }

    hosts, new_hosts = _merge_rows(prior.get("hosts", []), current["hosts"], "hostname", host, stamp, prior_stamp)
    ips, new_ips = _merge_rows(prior.get("ips", []), current["ips"], "ip", ip, stamp, prior_stamp)
    looked_up = [{**r, "registration_checked": stamp if r.get("registration_checked") is True else None} for r in current["lookalikes"]]
    lookalikes, new_lookalikes = _merge_rows(prior.get("lookalikes", []), looked_up, "domain", lookalike, stamp, prior_stamp)
    def related(old, new):  # this run looked again: its verdict replaces the old one
        return {"related_to": new["related_to"], "tie": new["tie"], "evidence": new["evidence"]}

    checked = set(current.get("related_checked", []))  # looked at again and no longer tied: dropped
    found_now = {r["domain"] for r in current.get("related", [])}
    prior_related = [r for r in prior.get("related", []) if r["domain"] not in checked or r["domain"] in found_now]
    related_rows, new_related = _merge_rows(prior_related, current.get("related", []), "domain", related, stamp, prior_stamp)
    rejected = set(current.get("tenants_rejected", []))  # found this run to be another organisation's: dropped
    prior_tenants = [t for t in prior.get("tenants", []) if t["tenant"] not in rejected]
    tenants, new_tenants = _merge_rows(prior_tenants, current.get("tenants", []), "tenant", tenant, stamp, prior_stamp)
    prior_guessed = prior.get("guessed", {})
    if isinstance(prior_guessed, list):
        prior_guessed = dict.fromkeys(prior_guessed, prior_stamp)
    try:
        cutoff = _stamp(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(days=RETRY_DAYS))
    except ValueError:  # not a timestamp farpoint wrote: keep everything
        cutoff = ""
    guessed = {n: at for n, at in prior_guessed.items() if at >= cutoff}  # older ones are tried again
    guessed.update(dict.fromkeys(current.get("guessed", []), stamp))
    fingerprints, new_fingerprints = _snapshot_rows(  # a port found closed now drops its row; one that failed to answer keeps it
        prior.get("fingerprints", []), current.get("fingerprints", []), "endpoint", stamp, prior_stamp, gone=current.get("closed", []),
    )
    before = {r["domain"]: r for r in prior.get("posture", [])}
    posture, _ = _snapshot_rows(prior.get("posture", []), [_keep_axfr(r, before.get(r["domain"])) for r in current.get("posture", [])], "domain", stamp, prior_stamp)
    identity, _ = _snapshot_rows(prior.get("identity", []), current.get("identity", []), "domain", stamp, prior_stamp)
    scan_dns, _ = _snapshot_rows(prior.get("scan_dns", []), current.get("scan_dns", []), "domain", stamp, prior_stamp)
    dangling_now = {r["hostname"] for r in current.get("dangling", [])}
    dangling, _ = _snapshot_rows(
        prior.get("dangling", []), current.get("dangling", []), "hostname", stamp, prior_stamp,
        gone=set(current.get("dangling_checked", [])) - dangling_now,
    )
    pointing: dict[str, list[str]] = {}  # tenant -> the organisation's hosts whose CNAMEs reach it
    for h in hosts:
        for cname in h.get("cnames", []):
            pointing.setdefault(cname, []).append(h["hostname"])
    tenants = [{**t, "hosts": sorted(pointing.get(t["tenant"], []))} for t in tenants]
    run = {
        "at": stamp,
        "domains": current["domains"],
        "interrupted": bool(current.get("interrupted")),
        "new": {"hosts": new_hosts, "ips": new_ips, "lookalikes": new_lookalikes, "tenants": new_tenants, "related": new_related, "fingerprints": new_fingerprints},
        "errors": current["errors"],
        "skipped_sources": current["skipped_sources"],
        **({"credentials": current["credential_run"]} if current.get("credential_run") else {}),
    }
    return {
        "updated_at": max(prior.get("updated_at", stamp), stamp),
        "domains": list(dict.fromkeys([*prior.get("domains", []), *current["domains"]])),
        "hosts": sorted(hosts, key=lambda h: h["hostname"]),
        "ips": sorted(ips, key=lambda r: _ip_key(r["ip"])),
        "lookalikes": sorted(lookalikes, key=lambda r: r["domain"]),
        "tenants": sorted(tenants, key=lambda r: r["tenant"]),
        "related": sorted(related_rows, key=lambda r: (-_RELATED_TIERS.index(r["tie"]) if r.get("tie") in _RELATED_TIERS else 1, r["domain"])),
        "guessed": dict(sorted(guessed.items())),
        **({"fingerprints": sorted(fingerprints, key=lambda r: (r["hostname"], r.get("port", 0)))} if fingerprints else {}),
        **({"posture": sorted(posture, key=lambda r: r["domain"])} if posture else {}),
        **({"dangling": sorted(dangling, key=lambda r: r["hostname"])} if dangling else {}),
        **({"identity": sorted(identity, key=lambda r: r["domain"])} if identity else {}),
        **({"scan_dns": sorted(scan_dns, key=lambda r: r["domain"])} if scan_dns else {}),
        **({"findings": prior["findings"]} if prior.get("findings") else {}),  # re-derived by --assess, kept until then
        **({"vulns": prior["vulns"]} if prior.get("vulns") else {}),
        **({"assessed_at": prior["assessed_at"]} if prior.get("assessed_at") else {}),
        **({"credential_assessment": prior["credential_assessment"]} if prior.get("credential_assessment") else {}),
        "errors": current["errors"],
        "skipped_sources": current["skipped_sources"],
        "runs": sorted([*prior.get("runs", []), run], key=lambda r: r["at"]),
    }


_FILE_MODE = files.FILE_MODE


def run_report(inv: Inventory) -> dict:
    """This run's findings alone, before merging."""
    return {
        "domains": inv.domains,
        "hosts": _host_rows(inv),
        "ips": _ip_rows(inv),
        "lookalikes": [
            {
                "domain": r.domain, "ips": _ips(r.ips), "current_ips": _ips(r.ips), "mx": sorted(r.mx), "ns": sorted(r.ns), "sources": sorted(r.sources),
                "registered_on": (r.registration or {}).get("created"), "registrar": (r.registration or {}).get("registrar"),
                "registration_checked": r.checked, "last_certificate": r.last_certificate,
            }
            for r in sorted(inv.lookalikes.values(), key=lambda r: r.domain)
        ],
        "tenants": _tenant_rows(inv),
        "related": _related_rows(inv),
        "related_checked": sorted(inv.related_checked),
        **({"tenants_rejected": sorted(inv.tenants_rejected)} if inv.tenants_rejected else {}),
        "guessed": sorted(inv.guessed),
        **({"fingerprints": _fingerprint_rows(inv)} if inv.services else {}),
        **({"closed": sorted(inv.closed)} if inv.closed else {}),
        **({"posture": [inv.posture[d] for d in sorted(inv.posture)]} if inv.posture else {}),
        **({"dangling": [{"hostname": h, **d} for h, d in sorted(inv.dangling.items())]} if inv.dangling else {}),
        **({"dangling_checked": sorted(inv.dangling_checked)} if inv.dangling_checked else {}),
        **({"identity": [inv.identity[d] for d in sorted(inv.identity)]} if inv.identity else {}),
        **({"scan_dns": [inv.scan_dns[d] for d in sorted(inv.scan_dns)]} if inv.scan_dns else {}),
        "errors": [{"source": e.source, "target": e.target, "message": e.message} for e in inv.errors],
        "skipped_sources": inv.skipped,
        "interrupted": inv.interrupted,
    }


def _tech_label(t: dict) -> str:
    return f"{t['name']} {t['version']}" if t.get("version") else t["name"]


def _fingerprint_csv_rows(report: dict) -> list[dict]:
    rows = []
    for r in report.get("fingerprints", []):
        tls = r.get("tls") or {}
        archived = r.get("archived")
        rows.append({
            **r,
            "tech": [_tech_label(t) for t in r.get("tech", [])],
            "archived": f"{archived['captured']} {archived['source']}: " + ", ".join(sorted(_tech_label(t) for t in archived["tech"])) if archived else None,
            "cert_subject": tls.get("subject"),
            "cert_issuer": tls.get("issuer"),
            "cert_expires": (tls.get("not_after") or "")[:10] or None,
            "tls_version": tls.get("version"),
            "legacy_tls": sorted(v for v, ok in (tls.get("legacy") or {}).items() if ok),
            "paths": [f"{p} {v['status']}" + (f" ({v['note']})" if v.get("note") else "") for p, v in (r.get("paths") or {}).items()],
        })
    return rows


def _posture_csv_rows(report: dict) -> list[dict]:
    from farpoint.assess import transfer_locked

    rows = []
    for p in report.get("posture", []):
        mx_health = p.get("mx_health", [])
        rows.append({
            **p,
            "dkim": [f"{sel}:{'revoked' if bits == 0 else bits}" if bits is not None else sel for sel, bits in sorted((p.get("dkim") or {}).items())],
            "mx_starttls": [f"{m['host']}:{'yes' if m.get('starttls') else 'no'}" for m in mx_health],
            "caa": None if p.get("caa") is None else bool(p["caa"]),
            "axfr": None if p.get("axfr") is None else (p["axfr"] or "no"),  # blank: not asked, or no answer
            "transfer_lock": transfer_locked(p.get("status", [])),
        })
    return rows


FINGERPRINT_FIELDS = ["endpoint", "hostname", "ip", "port", "service", "tech", "status", "title", "server", "location", "signals",
                      "cert_subject", "cert_issuer", "cert_expires", "tls_version", "legacy_tls", "banner", "favicon", "paths", "cookies", "archived"]
POSTURE_FIELDS = ["domain", "mail_provider", "mx", "spf_all", "spf_lookups", "spf_missing_includes", "dmarc_policy", "dmarc_subdomain_policy",
                  "dmarc_pct", "dkim", "mta_sts", "tls_rpt", "mx_starttls", "ns_providers", "dnssec", "caa", "axfr", "wildcard",
                  "registrar", "created", "expires", "transfer_lock", "spf", "dmarc"]


def _write_all(out_dir: Path, report: dict, mode: int, credentials: CredentialState) -> None:
    seen = ["first_seen", "last_seen"]
    write = lambda name, text: files.write_atomic(out_dir / name, text, mode)
    write("assets.json", json.dumps(report, indent=2))
    write("hosts.txt", "".join(f"{h['hostname']}\n" for h in report["hosts"]))
    write("ips.txt", "".join(f"{r['ip']}\n" for r in report["ips"]))
    write("hosts.csv", files.csv_text(report["hosts"], ["hostname", "resolves", "ips", "cnames", "sources", *seen]))
    write("ips.csv", files.csv_text(report["ips"], ["ip", "org", "network", "ports", "open_ports", "tags", "vulns", "hostnames", "sources", *seen]))
    from farpoint.lookalikes import capable

    flagged = {f["target"]: f["kind"].removeprefix("lookalike-") for f in report.get("findings", []) if f["kind"] in ("lookalike-ready", "lookalike-parked")}
    lookalike_rows = [{**r, "capable": capable(r), "flagged": flagged.get(r["domain"])} for r in report["lookalikes"]]
    write("lookalikes.csv", files.csv_text(lookalike_rows, ["domain", "ips", "mx", "registered_on", "last_certificate", "capable", "flagged", "sources", *seen]))
    if report.get("related"):  # only once --related has found some
        write("related.csv", files.csv_text(report["related"], ["domain", "related_to", "tie", "evidence", *seen]))
    if report.get("tenants"):  # only once --tenants has found some
        write("tenants.csv", files.csv_text(report["tenants"], ["tenant", "vendor", "domain", "tie", "verified", "hosts", "evidence", "ips", "cnames", *seen]))
    if report.get("fingerprints"):  # only once --fingerprint has run
        from farpoint.assess import technologies

        write("fingerprints.csv", files.csv_text(_fingerprint_csv_rows(report), [*FINGERPRINT_FIELDS, *seen]))
        write("technologies.csv", files.csv_text(technologies(report), ["category", "technology", "version", "seen", "count", "eol", "cves", "kev", "cpe", "hosts", "endpoints"]))
    if report.get("identity"):  # only once --tenants has run
        write("identity.csv", files.csv_text(report["identity"], ["domain", "sign_in", "provider", "sign_in_host", "brand", "tenant_id", "region", *seen]))
    if report.get("posture"):
        write("posture.csv", files.csv_text(_posture_csv_rows(report), [*POSTURE_FIELDS, *seen]))
    if "findings" in report:  # only once --assess has run
        block = sorted(d for d, k in flagged.items() if k == "ready") + sorted(d for d, k in flagged.items() if k == "parked")
        write("phishing-block.txt", "".join(f"{d}\n" for d in block))
        write("findings.csv", files.csv_text(report["findings"], ["level", "kind", "target", "detail", "evidence", *seen]))


def write_outputs(inv: Inventory, out_dir: Path, stamp: str | None = None,
                  assess: Callable[[dict, CredentialState], dict] | None = None, credentials: CredentialBatch | None = None) -> dict:
    """Merge this run into out_dir's inventory and rewrite every output file. Returns the merged report.
    `assess`, if given, judges the merged report (farpoint.assess) with the credential sidecar's state before it is written.

    Credentials are saved first, to their own owner-only file, so that an inventory that can't be merged
    never costs the evidence. If the existing inventory can't be merged, this run is saved alongside it
    (never over it) and ReportError says where.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    current = run_report(inv)
    stamp, mode = stamp or now_stamp(), _FILE_MODE
    with files.locked(out_dir):
        if credentials is not None:
            save = save_credentials(out_dir, credentials, stamp)
            state = save.state
            current["credential_run"] = {"new": save.new_exposures, "checks": attempt_summary(credentials)}
            if save.error:
                current["errors"] = [*current["errors"], {"source": "credentials", "target": "credentials.json", "message": save.error}]
        else:
            state = load_credentials(out_dir)
        try:
            report = merge_reports(load_report(out_dir), current, stamp)
        except ReportError as exc:
            unmerged = out_dir / f"assets.unmerged-{stamp.replace(':', '')}.json"
            files.write_atomic(unmerged, json.dumps(current, indent=2), mode)
            raise ReportError(f"{exc} This run was saved to {unmerged}.") from exc
        if assess:
            report = _judged(report, assess, state)
        _write_all(out_dir, report, mode, state)
    return report


def _judged(report: dict, assess: Callable[[dict, CredentialState], dict], credentials: CredentialState) -> dict:
    """`report` assessed; if assessing fails, the scan is still saved, unjudged, with the error recorded."""
    try:
        return assess(report, credentials)
    except Exception as exc:  # noqa: BLE001 - never lose a scan to its assessment
        error = {"source": "assess", "target": "inventory", "message": f"{describe(exc)}; findings not updated"}
        return {**report, "errors": [*report.get("errors", []), error]}


def preview(inv: Inventory | None, out_dir: Path, stamp: str) -> dict:
    """What the merged inventory will be once this run is saved, without saving it (for --assess's lookups)."""
    prior = load_report(out_dir)
    return merge_reports(prior, run_report(inv), stamp) if inv is not None else (prior or {})


def rewrite(out_dir: Path, change: Callable[[dict, CredentialState], dict]) -> dict:
    """Apply `change` to out_dir's inventory and rewrite every output file (no new run is recorded)."""
    with files.locked(out_dir):
        report = load_report(out_dir)
        if report is None:
            raise ReportError(f"no inventory in {out_dir} to assess; run a scan into it first")
        state = load_credentials(out_dir)
        report = change(report, state)
        _write_all(out_dir, report, _FILE_MODE, state)
    return report


class Checkpointer:
    """Saves the run in progress (at most every `interval` seconds) so a hard kill loses little.

    Each run writes its own .checkpoint-<pid>-<random>.json and holds an exclusive lock on the
    matching .lock file while alive; the next run into the directory merges any checkpoint whose lock
    is free (see recover_checkpoints). Locks, not PIDs, decide liveness, since PIDs get reused (a
    container's farpoint is always PID 1). A finished run calls clear().
    """

    def __init__(self, out_dir: Path, interval: float = 5.0) -> None:
        token = f"{os.getpid()}-{secrets.token_hex(4)}"
        self.path = out_dir / f".checkpoint-{token}.json"
        self.lock_path = out_dir / f".checkpoint-{token}.lock"
        self.started = now_stamp()
        self.interval = interval
        self._last: float | None = None
        self._lock_fh = None

    def __call__(self, inv: Inventory, pending: Mapping[tuple[str, str], list[Observation]] | None = None) -> None:
        """Save `inv` plus `pending` (pages from jobs still running), unless saved within `interval`."""
        if self._last is not None and time.monotonic() - self._last < self.interval:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._lock_fh is None:
            self._lock_fh = open(self.lock_path, "w")
            files.lock(self._lock_fh)
        extra = [obs for observations in list((pending or {}).values()) for obs in list(observations)]
        if extra:
            inv = copy.deepcopy(inv)
            for obs in extra:
                inv.add(obs)
        files.write_atomic(self.path, json.dumps({**run_report(inv), "at": self.started, "interrupted": True}), _FILE_MODE)
        self._last = time.monotonic()

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
        if self._lock_fh is not None:
            self._lock_fh.close()  # first: Windows can't delete an open file
            self._lock_fh = None
            self.lock_path.unlink(missing_ok=True)


def _owner_alive(checkpoint: Path) -> bool:
    """Whether the run that wrote `checkpoint` is still running: it holds the lock on its .lock file."""
    with open(checkpoint.with_suffix(".lock"), "a") as fh:
        return not files.lock(fh, wait=False)  # closing the file releases the lock we took


def recover_checkpoints(out_dir: Path) -> list[dict]:
    """Merge checkpoints left by runs that were killed before they could save.

    Returns a summary (at, domains, hosts) of each recovered run."""
    recovered = []
    if not out_dir.is_dir():
        return recovered
    with files.locked(out_dir):
        for path in sorted(out_dir.glob(".checkpoint-*.json")):
            if _owner_alive(path):
                continue
            try:
                checkpoint = json.loads(path.read_text(encoding="utf-8"))
                _validate(checkpoint)
            except (OSError, ValueError) as exc:
                raise ReportError(f"can't recover {path}: {exc}. Move or delete it to continue.") from exc
            stamp = checkpoint.get("at") or now_stamp()
            _write_all(out_dir, merge_reports(load_report(out_dir), checkpoint, stamp), _FILE_MODE, load_credentials(out_dir))
            path.unlink()
            path.with_suffix(".lock").unlink(missing_ok=True)
            recovered.append({"at": stamp, "domains": checkpoint.get("domains", []), "hosts": len(checkpoint.get("hosts", []))})
    return recovered
