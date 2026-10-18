"""Command-line entry point: `uv run easm example.com` or `uv run easm -f domains.txt`."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import httpx

from easm.enrich import InternetDb, Rdap
from easm.names import parse_domains
from easm.pipeline import Pipeline
from easm.output import write_outputs
from easm.resolve import DnsResolver
from easm.sources import build_sources, select_sources

USER_AGENT = "easm/0.1 (passive OSINT discovery)"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="easm", description="Passive external attack surface mapping (discovery only).")
    p.add_argument("domains", nargs="*", help="root domains to map")
    p.add_argument("-f", "--file", type=Path, help="file with one domain per line (# comments allowed)")
    p.add_argument("-o", "--out", type=Path, default=Path("out"), help="output directory (default: ./out)")
    p.add_argument("--only", default="", help="comma-separated sources to run (see --list-sources)")
    p.add_argument("--exclude", default="", help="comma-separated sources to skip")
    p.add_argument("--no-resolve", action="store_true", help="skip DNS resolution of discovered names")
    p.add_argument("--no-enrich", action="store_true", help="skip InternetDB/RDAP lookups for discovered IPs")
    p.add_argument("--nameserver", action="append", help="DNS resolver to use (repeatable; default: system)")
    p.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds (default: 60)")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--list-sources", action="store_true", help="show sources and whether each is usable here")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def load_dotenv(path: Path) -> None:
    """Set KEY=value pairs from `path` (if present) without overriding variables already in the environment."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if not sep or not key or key.startswith("#"):
            continue
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if value:
            os.environ.setdefault(key, value)


def main(argv: list[str] | None = None) -> int:
    load_dotenv(Path(".env"))
    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    http = httpx.Client(timeout=args.timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    all_sources = build_sources(http, os.environ)
    if args.list_sources:
        for s in all_sources:
            print(f"{s.name:<14} {'ready' if s.available() else 'unavailable (missing key or binary)'}")
        return 0

    lines = list(args.domains) + (args.file.read_text(encoding="utf-8").splitlines() if args.file else [])
    domains = parse_domains(lines)
    if not domains:
        parser.error("no valid domains given")
    try:
        sources = select_sources(all_sources, only=_csv(args.only), exclude=_csv(args.exclude))
    except ValueError as exc:
        parser.error(str(exc))

    pipeline = Pipeline(
        sources=sources,
        lookup=None if args.no_resolve else DnsResolver(args.nameserver).lookup,
        enrichers=[] if args.no_enrich else [InternetDb(http), Rdap(http)],
        workers=args.workers,
    )
    inv = pipeline.run(domains)
    write_outputs(inv, args.out)

    live = sum(1 for h in inv.hosts.values() if h.resolves)
    print(f"domains:    {', '.join(inv.domains)}")
    print(f"hostnames:  {len(inv.hosts)} ({live} resolving)")
    print(f"ips:        {len(inv.ips)}")
    print(f"lookalikes: {len(inv.lookalikes)}")
    if inv.skipped:
        print(f"skipped:    {', '.join(inv.skipped)} (no API key / not installed)")
    if inv.errors:
        print(f"errors:     {len(inv.errors)} (see assets.json)")
    print(f"output:     {args.out.resolve()}")
    return 0
