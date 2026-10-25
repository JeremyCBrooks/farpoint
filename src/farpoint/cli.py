"""Command-line entry point: `uv run farpoint example.com` or `uv run farpoint -f domains.txt`."""

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

from farpoint import runtime
from farpoint.assess import Kev, Nvd, assessed, lookup_vulns
from farpoint.enrich import InternetDb, Rdap
from farpoint.fingerprint import DEFAULT_PATHS, FingerprintConfig, parse_paths, parse_ports
from farpoint.guess import GuessConfig
from farpoint.names import parse_domains
from farpoint.pipeline import Pipeline
from farpoint.output import Checkpointer, ReportError, load_report, now_stamp, preview, recover_checkpoints, rewrite, write_outputs
from farpoint.probe import NetworkProber
from farpoint.progress import LiveReporter, NullReporter
from farpoint.resolve import DnsResolver
from farpoint.sources import build_sources, select_sources
from farpoint.related import NetworkProbes
from farpoint.tenants import TenantConfig

USER_AGENT = "farpoint/0.1 (passive OSINT discovery)"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="farpoint", description="External attack surface mapping: passive discovery, plus opt-in light probing and assessment.")
    p.add_argument("domains", nargs="*", help="root domains to map")
    p.add_argument("-f", "--file", type=Path, help="file with one domain per line (# comments allowed)")
    p.add_argument("-o", "--out", type=Path, default=Path("out"), help="output directory (default: ./out)")
    p.add_argument("--only", default="", help="comma-separated sources to run (see --list-sources)")
    p.add_argument("--exclude", default="", help="comma-separated sources to skip")
    p.add_argument("--no-resolve", action="store_true", help="skip DNS resolution of discovered names")
    p.add_argument("--no-enrich", action="store_true", help="skip InternetDB/RDAP lookups for discovered IPs")
    p.add_argument("--nameserver", action="append", help="DNS resolver to use (repeatable; default: system)")
    p.add_argument(
        "--guess",
        action="store_true",
        help="also predict unseen names from the naming patterns found and test them in DNS "
        "(not passive: the domain's own nameservers see one query per guess)",
    )
    p.add_argument("--guess-budget", type=int, default=2000, metavar="N", help="DNS lookups per domain for --guess (default: 2000)")
    p.add_argument(
        "--guess-rate", type=float, metavar="N", help="at most N --guess lookups a second, to spread them out (default: no limit)"
    )
    p.add_argument(
        "--tenants",
        action="store_true",
        help="also look for the organisation's tenants on SaaS and cloud platforms (example.sharepoint.com), "
        "chosen from the domains' TXT/SPF records, their CNAMEs and generic name patterns "
        "(not passive: the platforms' nameservers see the lookups)",
    )
    p.add_argument(
        "--related",
        action="store_true",
        help="also look for other domains the organisation owns: its Microsoft 365 tenant's, and its name under "
        "other suffixes (example.de) tied to it by evidence; reported, never scanned "
        "(not passive: registries, the variants and Microsoft see requests)",
    )
    p.add_argument("--tenant-budget", type=int, default=800, metavar="N", help="DNS lookups in all for --tenants (default: 800)")
    p.add_argument(
        "--fingerprint",
        action="store_true",
        help="also fingerprint live hosts: TCP-connect a short list of ports, read banners, TLS certificates and "
        "HTTP headers to name what each runs; check each domain's mail and DNS posture "
        "(not passive: the organisation's hosts see a few connections each)",
    )
    p.add_argument("--ports", default=None, metavar="LIST", help="ports for --fingerprint: 22,443,8000-8010 replaces the defaults, +LIST adds to them, none sweeps only 80,443")
    p.add_argument("--paths", default=",".join(DEFAULT_PATHS), metavar="LIST", help=f"well-known paths --fingerprint requests per web service, or none (default: {','.join(DEFAULT_PATHS)})")
    p.add_argument("--probe-rate", type=float, default=20.0, metavar="N", help="at most N --fingerprint connections a second (default: 20)")
    p.add_argument("--no-legacy-tls", action="store_true", help="skip --fingerprint's TLS 1.0/1.1 handshakes")
    p.add_argument(
        "--assess",
        action="store_true",
        help="judge the inventory: ranked findings (findings.csv), and the CVEs NVD and CISA's known-exploited list "
        "give for each fingerprinted version; sends nothing to the organisation. With no domains, re-assesses --out's inventory",
    )
    p.add_argument("--no-cve", action="store_true", help="--assess without the NVD/CISA lookups")
    p.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds (default: 60)")
    p.add_argument("--workers", type=int, default=16, help="jobs run at once per source or phase (default: 16)")
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


def _guess_config(budget: int, report: dict | None, rate: float | None = None) -> GuessConfig:
    """Guessing also learns from the inventory earlier runs left in the output directory, and skips
    the names they already tested, so each run goes further down the list."""
    hosts = report["hosts"] if report else []
    known = {h["hostname"]: h.get("cnames", []) for h in hosts}
    tenants = {t["tenant"]: t["domain"] for t in (report or {}).get("tenants", []) if t.get("verified") and t.get("domain")}
    guessed = (report or {}).get("guessed", {})
    return GuessConfig(
        budget=budget,
        known=known,
        known_weak=frozenset(h["hostname"] for h in hosts if not h.get("ips")),
        tenants=tenants,
        tried=frozenset(guessed),  # the merge already dropped ones old enough to try again
        rate=rate,
    )


def _tenant_config(budget: int, report: dict | None) -> TenantConfig:
    """Earlier runs' hosts also teach the organisation's modifiers, and their CNAMEs which platforms it uses."""
    hosts = report["hosts"] if report else []
    return TenantConfig(budget=budget, known={h["hostname"]: h.get("cnames", []) for h in hosts})


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
    if not domains and args.assess and not lines:
        return _assess_only(args, http)
    if not domains:
        parser.error("no valid domains given")
    try:
        fingerprint = FingerprintConfig(
            ports=parse_ports(args.ports) if args.ports is not None else FingerprintConfig().ports,
            paths=parse_paths(args.paths),
            rate=args.probe_rate,
            legacy_tls=not args.no_legacy_tls,
        )
    except ValueError as exc:
        parser.error(f"--ports/--paths: {exc}")
    if args.probe_rate <= 0:
        parser.error("--probe-rate must be positive")
    for flag in ("guess", "tenants", "related", "fingerprint"):
        if getattr(args, flag) and args.no_resolve:
            parser.error(f"--{flag} needs DNS resolution; drop --no-resolve")
    if args.guess_budget < 1:
        parser.error("--guess-budget must be at least 1")
    if args.guess_rate is not None and args.guess_rate <= 0:
        parser.error("--guess-rate must be positive")
    if args.tenant_budget < 1:
        parser.error("--tenant-budget must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    try:
        sources = select_sources(all_sources, only=_csv(args.only), exclude=_csv(args.exclude))
    except ValueError as exc:
        parser.error(str(exc))

    try:
        for run in recover_checkpoints(args.out):  # from runs that were killed before they could save
            print(f"recovered an interrupted run from {run['at']} ({', '.join(run['domains'])}: {run['hosts']} hosts)", file=sys.stderr)
        prior_report = load_report(args.out)  # fail before a long scan, not after it
    except ReportError as exc:
        parser.error(str(exc))

    console = Console(stderr=True)
    live = console.is_terminal and not args.verbose and not args.no_progress
    if live:
        logging.getLogger().setLevel(logging.ERROR)  # failures show on their progress line instead
    checkpoint = Checkpointer(args.out)
    reporter = LiveReporter(console) if live else NullReporter()
    resolver = DnsResolver(args.nameserver)
    rdap = Rdap(http, retries=2)
    pipeline = Pipeline(
        sources=sources,
        lookup=None if args.no_resolve else resolver.lookup,
        enrichers=[] if args.no_enrich else [InternetDb(http, retries=2), rdap],  # one per IP: fail fast
        workers=args.workers,
        reporter=reporter,
        checkpoint=checkpoint,
        guess=_guess_config(args.guess_budget, prior_report, args.guess_rate) if args.guess else None,
        tenants=_tenant_config(args.tenant_budget, prior_report) if args.tenants else None,
        txt=resolver.txt,
        related=NetworkProbes(http, resolver.records, lambda ip: rdap.enrich(ip).org) if args.related else None,
        fingerprint=fingerprint if args.fingerprint else None,
        prober=NetworkProber() if args.fingerprint else None,
        dns=resolver,
        rdap_domain=rdap.domain if args.fingerprint else None,
    )
    runtime.reset()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=True))
    stamp = now_stamp()

    def scan():
        inv = pipeline.run(domains)
        judge = None
        if args.assess and not inv.interrupted:
            judge = _prepare_assessment(args, http, reporter, lambda: preview(inv, args.out, stamp), stamp)
        return inv, judge

    if live:
        with reporter:
            inv, judge = scan()
    else:
        inv, judge = scan()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=False))  # never abandon a save half-way
    if runtime.cancelled():
        inv.interrupted = True

    if not inv.interrupted:
        return _save_and_summarise(inv, args.out, checkpoint, stamp, judge)
    # Interrupted: worker threads may still be stuck in requests, and a normal return would wait for
    # them at interpreter exit. Whatever happens while saving, leave with os._exit.
    try:
        code = _save_and_summarise(inv, args.out, checkpoint, stamp, judge)
    except BaseException:
        traceback.print_exc()
        code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _prepare_assessment(args, http: httpx.Client, reporter, report_now, stamp: str):
    """Do --assess's third-party lookups (NVD, CISA KEV) for what the inventory will hold, and return
    the function that judges the report when it is saved. None if the lookups were interrupted."""
    nvd = None if args.no_cve else Nvd(http, os.environ.get("NVD_API_KEY"), retries=3)
    kev = None if args.no_cve else Kev(http, retries=2)
    try:
        current = report_now()
    except ReportError:  # saving will report it, and keep this run's results beside the inventory
        return None
    try:
        vulns, catalogue, errors = lookup_vulns(current, nvd, kev, progress=lambda d, t, f: reporter.phase("vulnerabilities", d, t, f))
    except runtime.Cancelled:
        return None
    return lambda report: assessed(report, vulns, catalogue, stamp, errors)


def _assess_only(args, http: httpx.Client) -> int:
    """`farpoint --assess -o DIR`: re-judge an existing inventory without scanning anything."""
    try:
        report = load_report(args.out)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report is None:
        print(f"error: no inventory in {args.out} to assess; give domains to scan", file=sys.stderr)
        return 2
    stamp = now_stamp()
    runtime.reset()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=False))
    judge = _prepare_assessment(args, http, NullReporter(), lambda: report, stamp)
    if judge is None:
        print("interrupted: nothing changed", file=sys.stderr)
        return 130
    report = rewrite(args.out, judge)
    _summarise_assessment(report)
    print(f"output:     {args.out.resolve()}")
    return 0


def _summarise_assessment(report: dict) -> None:
    from collections import Counter

    from farpoint.assess import technologies

    if report.get("fingerprints"):
        hosts = {r["hostname"] for r in report["fingerprints"]}
        top = Counter()
        for row in technologies(report):
            if row["category"] not in ("cdn", "platform", "language", "framework", "cms-plugin"):
                top[row["technology"]] += row["count"]
        shown = ", ".join(f"{name} {n}" for name, n in top.most_common(6))
        print(f"services:   {len(report['fingerprints'])} on {len(hosts)} hosts" + (f" (top: {shown}; see technologies.csv)" if shown else ""))
    if "findings" in report:
        levels = Counter(f["level"] for f in report["findings"])
        print(f"findings:   {levels['high']} high, {levels['medium']} medium, {levels['low']} low (see findings.csv)")
        for f in [f for f in report["findings"] if f["level"] == "high"][:8]:
            print(f"            {f['target']}: {f['detail']}")


def _save_and_summarise(inv, out: Path, checkpoint: Checkpointer, stamp: str | None = None, judge=None) -> int:
    stamp = stamp or now_stamp()
    try:
        report = write_outputs(inv, out, stamp, assess=judge)
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
    if report["related"]:
        ties = {t: [r["domain"] for r in report["related"] if r["tie"] == t] for t in ("strong", "medium", "weak")}
        print(f"related:    {len(report['related'])} domains ({len(ties['strong'])} strong, {len(ties['medium'])} medium, {len(ties['weak'])} weak; see related.csv)")
        likely = ties["strong"] + ties["medium"]
        if likely:
            shown = ", ".join(likely[:8]) + (f" and {len(likely) - 8} more" if len(likely) > 8 else "")
            print(f"            likely the organisation's, not scanned: {shown}")
    if report["tenants"]:
        verified = sum(1 for t in report["tenants"] if t["verified"])
        print(f"tenants:    {len(report['tenants'])} ({verified} verified in DNS, {new['tenants']} new)")
    if inv.services or judge:
        _summarise_assessment(report)
    if inv.skipped:
        print(f"skipped:    {', '.join(inv.skipped)} (no API key / not installed)")
    if inv.errors:
        print(f"errors:     {len(inv.errors)} this run (see assets.json)")
    print(f"output:     {out.resolve()}")
    if inv.interrupted:
        print("status:     interrupted, partial results saved; re-run to fill in the rest")
        return 130
    return 0
