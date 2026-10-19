"""Write the inventory as plain lists (for piping), CSVs (for spreadsheets) and JSON (for tooling).

Runs accumulate: assets.json in the output directory is the running inventory, each run is merged
into it, and every other file is regenerated from the merged result.
"""

from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no advisory locking
    fcntl = None

from easm.models import Inventory


def _ip_key(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def _ips(values: Iterable[str]) -> list[str]:
    return sorted(values, key=_ip_key)


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
        }
        for r in (inv.ips[ip] for ip in _ips(inv.ips))
    ]


class ReportError(Exception):
    """The existing assets.json can't be read, so merging into it would lose history."""


def _stamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _stamp(datetime.now(timezone.utc))


_ROW_LISTS = {
    "hosts": ("hostname", ("ips", "cnames", "sources")),
    "ips": ("ip", ("ports", "vulns", "hostnames", "sources")),
    "lookalikes": ("domain", ("ips", "sources")),
}


def _validate(report) -> None:
    """Reject anything merge_reports can't fold, so a bad file fails before the scan instead of after it."""
    if not isinstance(report, dict):
        raise ValueError("top level is not an object")
    for field in ("domains", "runs", *_ROW_LISTS):
        if not isinstance(report.get(field, []), list):
            raise ValueError(f"'{field}' is not a list")
    for field, (key, lists) in _ROW_LISTS.items():
        for i, row in enumerate(report.get(field, [])):
            where = f"{field}[{i}]"
            if not isinstance(row, dict) or not isinstance(row.get(key), str):
                raise ValueError(f"{where} has no '{key}'")
            if any(not isinstance(row.get(f, []), list) for f in lists):
                raise ValueError(f"{where} has a non-list field")
            for ip in [row[key]] if field == "ips" else row.get("ips", []):
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
            merged[row[key]] = {**old, **row, **merge(old, row), "first_seen": old["first_seen"], "last_seen": stamp}
    return list(merged.values()), new


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
        }

    def lookalike(old, new):
        return {"ips": _ips(set(old.get("ips", [])) | set(new["ips"])), "sources": _union(old.get("sources", []), new["sources"])}

    hosts, new_hosts = _merge_rows(prior.get("hosts", []), current["hosts"], "hostname", host, stamp, prior_stamp)
    ips, new_ips = _merge_rows(prior.get("ips", []), current["ips"], "ip", ip, stamp, prior_stamp)
    lookalikes, new_lookalikes = _merge_rows(prior.get("lookalikes", []), current["lookalikes"], "domain", lookalike, stamp, prior_stamp)
    run = {
        "at": stamp,
        "domains": current["domains"],
        "new": {"hosts": new_hosts, "ips": new_ips, "lookalikes": new_lookalikes},
        "errors": current["errors"],
        "skipped_sources": current["skipped_sources"],
    }
    return {
        "updated_at": stamp,
        "domains": list(dict.fromkeys([*prior.get("domains", []), *current["domains"]])),
        "hosts": sorted(hosts, key=lambda h: h["hostname"]),
        "ips": sorted(ips, key=lambda r: _ip_key(r["ip"])),
        "lookalikes": sorted(lookalikes, key=lambda r: r["domain"]),
        "errors": current["errors"],
        "skipped_sources": current["skipped_sources"],
        "runs": [*prior.get("runs", []), run],
    }


@contextlib.contextmanager
def _locked(out_dir: Path) -> Iterator[None]:
    """Serialise read-merge-write so two runs into the same directory can't drop each other's results."""
    with open(out_dir / ".lock", "w") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        yield


def _default_mode() -> int:
    """What open() would give a new file: 0o666 minus the umask (mkstemp alone would give 0o600)."""
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def _write_atomic(path: Path, text: str, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _csv_text(rows: list[dict], fields: list[str]) -> str:
    def flat(value) -> str:
        if isinstance(value, list):
            return " ".join(map(str, value))
        if isinstance(value, bool) or value is None:
            return _resolves(value)
        return str(value)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows({k: flat(row.get(k)) for k in fields} for row in rows)
    return buf.getvalue()


def run_report(inv: Inventory) -> dict:
    """This run's findings alone, before merging."""
    return {
        "domains": inv.domains,
        "hosts": _host_rows(inv),
        "ips": _ip_rows(inv),
        "lookalikes": [
            {"domain": r.domain, "ips": _ips(r.ips), "sources": sorted(r.sources)}
            for r in sorted(inv.lookalikes.values(), key=lambda r: r.domain)
        ],
        "errors": [{"source": e.source, "target": e.target, "message": e.message} for e in inv.errors],
        "skipped_sources": inv.skipped,
    }


def write_outputs(inv: Inventory, out_dir: Path) -> dict:
    """Merge this run into out_dir's inventory and rewrite every output file. Returns the merged report.

    If the existing inventory can't be merged, this run is saved alongside it (never over it) and
    ReportError says where.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    current = run_report(inv)
    stamp, mode = _now(), _default_mode()
    seen = ["first_seen", "last_seen"]
    with _locked(out_dir):
        try:
            report = merge_reports(load_report(out_dir), current, stamp)
        except ReportError as exc:
            unmerged = out_dir / f"assets.unmerged-{stamp.replace(':', '')}.json"
            _write_atomic(unmerged, json.dumps(current, indent=2), mode)
            raise ReportError(f"{exc} This run was saved to {unmerged}.") from exc
        write = lambda name, text: _write_atomic(out_dir / name, text, mode)
        write("assets.json", json.dumps(report, indent=2))
        write("hosts.txt", "".join(f"{h['hostname']}\n" for h in report["hosts"]))
        write("ips.txt", "".join(f"{r['ip']}\n" for r in report["ips"]))
        write("hosts.csv", _csv_text(report["hosts"], ["hostname", "resolves", "ips", "cnames", "sources", *seen]))
        write("ips.csv", _csv_text(report["ips"], ["ip", "org", "network", "ports", "vulns", "hostnames", "sources", *seen]))
        write("lookalikes.csv", _csv_text(report["lookalikes"], ["domain", "ips", "sources", *seen]))
    return report
