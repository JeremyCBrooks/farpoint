"""Command-line entry point: `uv run easm example.com` or `uv run easm -f domains.txt`."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import traceback
from pathlib import Path

import httpx
from rich.console import Console

from easm import runtime
from easm.enrich import InternetDb, Rdap
from easm.names import parse_domains
from easm.pipeline import Pipeline
from easm.output import Checkpointer, ReportError, load_report, now_stamp, recover_checkpoints, write_outputs
from easm.progress import LiveReporter, NullReporter
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
    p.add_argument("--no-progress", action="store_true", help="no live progress display (implied by -v or when not a terminal)")
    p.add_argument("-v", "--verbose", action="store_true", help="log each result and retry instead of the live display")
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


def _on_interrupt(stop_scan: bool):
    """First Ctrl-C/SIGTERM stops the scan (if `stop_scan`) so results so far get saved; a second exits now."""

    def handler(signum, frame):
        if runtime.cancelled():
            os._exit(130)
        runtime.cancel()
        # os.write, not print: the main thread may be mid-print, and re-entering its buffer raises
        os.write(2, b"\ninterrupted: saving results so far (Ctrl-C again to quit without saving)\n")
        if stop_scan:
            runtime.request_interrupt()

    return handler


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

    try:
        for run in recover_checkpoints(args.out):  # from runs that were killed before they could save
            print(f"recovered an interrupted run from {run['at']} ({', '.join(run['domains'])}: {run['hosts']} hosts)", file=sys.stderr)
        load_report(args.out)  # fail before a long scan, not after it
    except ReportError as exc:
        parser.error(str(exc))

    console = Console(stderr=True)
    live = console.is_terminal and not args.verbose and not args.no_progress
    if live:
        logging.getLogger().setLevel(logging.ERROR)  # failures show on their progress line instead
    checkpoint = Checkpointer(args.out)
    reporter = LiveReporter(console) if live else NullReporter()
    pipeline = Pipeline(
        sources=sources,
        lookup=None if args.no_resolve else DnsResolver(args.nameserver).lookup,
        enrichers=[] if args.no_enrich else [InternetDb(http, retries=2), Rdap(http, retries=2)],  # one per IP: fail fast
        workers=args.workers,
        reporter=reporter,
        checkpoint=checkpoint,
    )
    runtime.reset()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=True))
    if live:
        with reporter:
            inv = pipeline.run(domains)
    else:
        inv = pipeline.run(domains)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=False))  # never abandon a save half-way

    if not inv.interrupted:
        return _save_and_summarise(inv, args.out, checkpoint)
    # Interrupted: worker threads may still be stuck in requests, and a normal return would wait for
    # them at interpreter exit. Whatever happens while saving, leave with os._exit.
    try:
        code = _save_and_summarise(inv, args.out, checkpoint)
    except BaseException:
        traceback.print_exc()
        code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _save_and_summarise(inv, out: Path, checkpoint: Checkpointer) -> int:
    stamp = now_stamp()
    try:
        report = write_outputs(inv, out, stamp)
    except ReportError as exc:  # this run was saved to an assets.unmerged-*.json instead
        checkpoint.clear()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    checkpoint.clear()  # only once saved: any other failure leaves it for the next run to recover

    this_run = next(r for r in reversed(report["runs"]) if r["at"] == stamp)
    new = this_run["new"]
    live = sum(1 for h in report["hosts"] if h["resolves"])
    plural = lambda n, word: f"{n} {word}{'s' if n != 1 else ''}"
    print(f"this run:   {', '.join(inv.domains)}")
    print(f"inventory:  {plural(len(report['domains']), 'domain')}, {plural(len(report['runs']), 'run')} merged")
    print(f"hostnames:  {len(report['hosts'])} ({live} resolving, {new['hosts']} new)")
    print(f"ips:        {len(report['ips'])} ({new['ips']} new)")
    print(f"lookalikes: {len(report['lookalikes'])} ({new['lookalikes']} new)")
    if inv.skipped:
        print(f"skipped:    {', '.join(inv.skipped)} (no API key / not installed)")
    if inv.errors:
        print(f"errors:     {len(inv.errors)} this run (see assets.json)")
    print(f"output:     {out.resolve()}")
    if inv.interrupted:
        print("status:     interrupted, partial results saved; re-run to fill in the rest")
        return 130
    return 0
