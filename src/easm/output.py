"""Write the inventory as plain lists (for piping), CSVs (for spreadsheets) and JSON (for tooling)."""

from __future__ import annotations

import csv
import ipaddress
import json
from collections.abc import Iterable
from pathlib import Path

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


def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    def flat(value) -> str:
        if isinstance(value, list):
            return " ".join(map(str, value))
        if isinstance(value, bool) or value is None:
            return _resolves(value)
        return str(value)

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: flat(row[k]) for k in fields} for row in rows)


def write_outputs(inv: Inventory, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    hosts, ips = _host_rows(inv), _ip_rows(inv)
    lookalikes = [
        {"domain": r.domain, "ips": _ips(r.ips), "sources": sorted(r.sources)}
        for r in sorted(inv.lookalikes.values(), key=lambda r: r.domain)
    ]

    (out_dir / "hosts.txt").write_text("".join(f"{h['hostname']}\n" for h in hosts), encoding="utf-8")
    (out_dir / "ips.txt").write_text("".join(f"{r['ip']}\n" for r in ips), encoding="utf-8")
    _write_csv(out_dir / "hosts.csv", hosts, ["hostname", "resolves", "ips", "cnames", "sources"])
    _write_csv(out_dir / "ips.csv", ips, ["ip", "org", "network", "ports", "vulns", "hostnames", "sources"])
    _write_csv(out_dir / "lookalikes.csv", lookalikes, ["domain", "ips", "sources"])
    report = {
        "domains": inv.domains,
        "hosts": hosts,
        "ips": ips,
        "lookalikes": lookalikes,
        "errors": [{"source": e.source, "target": e.target, "message": e.message} for e in inv.errors],
        "skipped_sources": inv.skipped,
    }
    (out_dir / "assets.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
