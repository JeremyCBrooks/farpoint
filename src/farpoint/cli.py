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
from farpoint.credential_assess import credential_status, current_findings
from farpoint.credential_import import CredentialImportError, load_imports
from farpoint.credential_store import SIDECAR, load_credentials
from farpoint.credentials import QUERY_KINDS
from farpoint.enrich import InternetDb, Rdap
from farpoint.fingerprint import DEFAULT_PATHS, FingerprintConfig, parse_paths, parse_ports
from farpoint.guess import GuessConfig
from farpoint.identity import MicrosoftSignIn
from farpoint.lookalikes import LookalikeConfig, NetworkLookalikeLookups, fresh_registrations
from farpoint.models import Inventory
from farpoint.names import parse_domains
from farpoint.pipeline import Pipeline
from farpoint.output import Checkpointer, ReportError, load_report, now_stamp, preview, recover_checkpoints, rewrite, write_outputs
from farpoint.archive import WaybackArchive
from farpoint.probe import NetworkProber, user_agent
from farpoint.progress import LiveReporter, NullReporter
from farpoint.resolve import DnsResolver
from farpoint.sources import build_sources, select_sources
from farpoint.sources.web import CrtSh
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
    p.add_argument("--no-enrich", action="store_true", help="skip InternetDB/RDAP lookups for discovered IPs, and the registration/certificate lookups for lookalikes")
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
        "chosen from the domains' TXT/SPF records, their CNAMEs and generic name patterns; and how each domain signs in "
        "to Microsoft (not passive: the platforms' nameservers and Microsoft's sign-in service see the lookups)",
    )
    p.add_argument(
        "--related",
        action="store_true",
        help="also look for other domains the organisation owns: its Microsoft 365 tenant's, and its name under "
        "other suffixes (example.de) tied to it by evidence; reported, never scanned "
        "(not passive: registries, the variants and Microsoft see requests)",
    )
    p.add_argument(
        "--related-rate", type=float, metavar="N", help="start at most N --related lookups a second, to spread them out (default: no limit)"
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
    p.add_argument("--no-axfr", action="store_true", help="skip --fingerprint's zone-transfer requests")
    p.add_argument("--no-archive", action="store_true", help="don't look up archived copies (Wayback Machine) of web services a bot defence hid from --fingerprint")
    p.add_argument(
        "--engagement",
        metavar="ID",
        help="with --fingerprint: an engagement ID (ticket or client code) added to the User-Agent of its requests, so the "
        "organisation can tell who is probing; the passive sources and --related don't send it",
    )
    p.add_argument(
        "--assess",
        action="store_true",
        help="judge the inventory: ranked findings (findings.csv), and the CVEs NVD and CISA's known-exploited list "
        "give for each fingerprinted version; sends nothing to the organisation. With no domains, re-assesses --out's inventory",
    )
    p.add_argument(
        "--credential-import",
        action="append",
        type=Path,
        metavar="PATH",
        help="add credential-exposure evidence from a provider export (JSON, schema in docs/credential-import/); repeatable. "
        "Offline: nothing is sent anywhere. With no domains, adds it to --out's inventory",
    )
    p.add_argument(
        "--credential-queries",
        default=None,
        metavar="KINDS",
        help="email (default): workforce email-domain exposure; website: credentials for logins to in-scope hosts, including customers' identities",
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

    kinds = _credential_kinds(parser, args)
    lines = list(args.domains) + (args.file.read_text(encoding="utf-8").splitlines() if args.file else [])
    domains = parse_domains(lines)
    if not domains and args.credential_import and not lines:
        return _credentials_only(args, http, kinds)
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
            axfr=not args.no_axfr,
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
    if args.guess_rate is not None and not args.guess_rate > 0:  # NaN too
        parser.error("--guess-rate must be positive")
    if args.related_rate is not None and not args.related_rate > 0:
        parser.error("--related-rate must be positive")
    for rate, stage in (("guess_rate", "guess"), ("related_rate", "related")):
        if getattr(args, rate) is not None and not getattr(args, stage):
            parser.error(f"--{rate.replace('_', '-')} only paces --{stage}; add --{stage}")
    if args.tenant_budget < 1:
        parser.error("--tenant-budget must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.engagement is not None:
        if not args.fingerprint:
            parser.error("--engagement only labels --fingerprint's requests; add --fingerprint")
        try:
            user_agent(args.engagement)
        except ValueError as exc:
            parser.error(f"--engagement: {exc}")
    try:
        sources = select_sources(all_sources, only=_csv(args.only), exclude=_csv(args.exclude))
    except ValueError as exc:
        parser.error(str(exc))

    stamp = now_stamp()
    try:
        batch, rejected = load_imports(args.credential_import, domains, kinds, stamp) if args.credential_import else (None, 0)
    except CredentialImportError as exc:
        parser.error(str(exc))

    try:
        _report_recoveries(args.out)  # from runs that were killed before they could save
        prior_report = load_report(args.out)  # fail before a long scan, not after it
    except ReportError as exc:
        parser.error(str(exc))

    console = Console(stderr=True)
    live = console.is_terminal and not args.verbose and not args.no_progress
    if live:
        logging.getLogger().setLevel(logging.ERROR)  # failures show on their progress line instead
    checkpoint = Checkpointer(args.out, credentials=batch)
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
        sign_in=MicrosoftSignIn(http, retries=2) if args.tenants else None,
        related=NetworkProbes(http, resolver.records, lambda ip: rdap.enrich(ip).org) if args.related else None,
        related_rate=args.related_rate,
        fingerprint=fingerprint if args.fingerprint else None,
        prober=NetworkProber(engagement=args.engagement) if args.fingerprint else None,
        archive=WaybackArchive(http, retries=2) if args.fingerprint and not args.no_archive else None,
        dns=resolver,
        rdap_domain=rdap.domain if args.fingerprint else None,
        lookalikes=None if args.no_enrich else LookalikeConfig(NetworkLookalikeLookups(rdap, CrtSh(http, retries=2)), fresh_registrations(prior_report, now_stamp())),
    )
    runtime.reset()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _on_interrupt(stop_scan=True))

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
        return _save_and_summarise(inv, args.out, checkpoint, stamp, judge, batch, rejected)
    # Interrupted: worker threads may still be stuck in requests, and a normal return would wait for
    # them at interpreter exit. Whatever happens while saving, leave with os._exit.
    try:
        code = _save_and_summarise(inv, args.out, checkpoint, stamp, judge, batch, rejected)
    except BaseException:
        traceback.print_exc()
        code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _credential_kinds(parser: argparse.ArgumentParser, args) -> list[str]:
    """--credential-queries as a list; argument errors are raised before anything is recovered, saved or requested."""
    if args.credential_queries is not None and not args.credential_import:
        parser.error("--credential-queries selects what --credential-import (and, later, --credentials) collect; add one of them")
    kinds = _csv("email" if args.credential_queries is None else args.credential_queries)
    unknown = [k for k in kinds if k not in QUERY_KINDS]
    if unknown or not kinds:
        parser.error(f"--credential-queries: unknown kind(s) {', '.join(unknown) or '(none)'}; choose from {', '.join(QUERY_KINDS)}")
    return kinds


def _report_recoveries(out: Path) -> None:
    for run in recover_checkpoints(out):
        if "warning" in run:
            print(f"warning: {run['warning']}", file=sys.stderr)
            continue
        exposures = run.get("exposures", 0)
        if not run["domains"] and not run["hosts"]:  # only a credential member was left
            print(f"recovered {_plural(exposures, 'credential exposure')} from an interrupted run at {run['at']}", file=sys.stderr)
            continue
        extra = f", {_plural(exposures, 'credential exposure')}" if exposures else ""
        print(f"recovered an interrupted run from {run['at']} ({', '.join(run['domains'])}: {run['hosts']} hosts{extra})", file=sys.stderr)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def _this_run(report: dict, stamp: str) -> dict:
    return next((r for r in reversed(report["runs"]) if r["at"] == stamp), {})


def _credential_save_failed(report: dict, stamp: str) -> bool:
    """Warn when this run's credential evidence didn't reach credentials.json; value-free, names the fallback."""
    run = _this_run(report, stamp).get("credentials", {})
    if not run.get("error"):
        return False
    kept = f"; kept in {run['fallback']}" if run.get("fallback") else ""
    print(f"warning: credential evidence not saved ({run['error']}){kept}", file=sys.stderr)
    return True


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
    return lambda report, credentials: assessed(report, vulns, catalogue, stamp, errors, credentials)


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
    _summarise_assessment(report, args.out)
    _summarise_credentials(args.out, report)
    print(f"output:     {args.out.resolve()}")
    return 0


def _credentials_only(args, http: httpx.Client, kinds: list[str]) -> int:
    """`farpoint --credential-import FILE -o DIR`: add evidence to an existing inventory without scanning.
    Everything is validated before anything is changed."""
    try:
        report = load_report(args.out)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report is None:
        print(f"error: no inventory in {args.out} to add credential evidence to; scan into it first", file=sys.stderr)
        return 2
    stamp = now_stamp()
    try:
        batch, rejected = load_imports(args.credential_import, report["domains"], kinds, stamp)
    except CredentialImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"credential scope: {', '.join(report['domains'])}", file=sys.stderr)
    try:
        _report_recoveries(args.out)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    judge = None
    if args.assess:
        runtime.reset()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, _on_interrupt(stop_scan=False))
        judge = _prepare_assessment(args, http, NullReporter(), lambda: report, stamp)
        if judge is None:
            print("interrupted: nothing changed", file=sys.stderr)
            return 130
    try:
        saved = write_outputs(Inventory(report["domains"]), args.out, stamp, assess=judge, credentials=batch)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _summarise_assessment(saved, args.out)
    _summarise_credentials(args.out, saved, rejected, _this_run(saved, stamp).get("credentials", {}).get("new", 0))
    print(f"output:     {args.out.resolve()}")
    return 1 if _credential_save_failed(saved, stamp) else 0


def _summarise_credentials(out: Path, report: dict, rejected: int = 0, new: int = 0) -> None:
    """Counts only: identities never reach the terminal."""
    from collections import Counter

    state = load_credentials(out)
    if not (out / SIDECAR).exists() and not rejected and not report.get("credential_assessment"):
        return
    data = state.data or {}
    checks = Counter(c["status"] for c in data.get("checks", []))
    shown = ", ".join(f"{n} {status}" for status, n in sorted(checks.items())) or "none"
    print(f"credentials: {len(data.get('exposures', []))} exposures ({new} new), {len(data.get('summaries', []))} summaries; checks: {shown}")
    if rejected:
        print(f"            {rejected} import rows outside scope were dropped")
    status = credential_status(report, state)
    note = {"stale": " (run --assess to update)", "unavailable": f": {state.error}"}.get(status, "")
    print(f"            assessment: {status}{note}")


def _summarise_assessment(report: dict, out: Path) -> None:
    from collections import Counter

    from farpoint.assess import technologies

    if report.get("fingerprints"):
        hosts = {r["hostname"] for r in report["fingerprints"]}
        top = Counter()
        for row in technologies(report):
            if row["seen"] == "live" and row["category"] not in ("cdn", "platform", "language", "framework", "cms-plugin"):
                top[row["technology"]] += row["count"]
        shown = ", ".join(f"{name} {n}" for name, n in top.most_common(6))
        print(f"services:   {len(report['fingerprints'])} on {len(hosts)} hosts" + (f" (top: {shown}; see technologies.csv)" if shown else ""))
        from farpoint.visibility import summarise, summary_line

        if line := summary_line(summarise(report)):
            print(f"            {line}")
    if "findings" in report:
        findings = current_findings(report, load_credentials(out))
        levels = Counter(f["level"] for f in findings)
        print(f"findings:   {levels['high']} high, {levels['medium']} medium, {levels['low']} low (see findings.csv)")
        for f in [f for f in findings if f["level"] == "high"][:8]:
            print(f"            {f['target']}: {f['detail']}")


def _save_and_summarise(inv, out: Path, checkpoint: Checkpointer, stamp: str | None = None, judge=None, batch=None, rejected: int = 0) -> int:
    stamp = stamp or now_stamp()
    try:
        report = write_outputs(inv, out, stamp, assess=judge, credentials=batch)
    except ReportError as exc:  # this run was saved to an assets.unmerged-*.json instead
        checkpoint.clear(keep_credentials=True)  # credential persistence may also have failed
        print(f"error: {exc}", file=sys.stderr)
        return 1
    this_run = _this_run(report, stamp)
    credential_run = this_run.get("credentials", {})
    checkpoint.clear(keep_credentials=bool(credential_run.get("error") and not credential_run.get("fallback")))

    new = this_run["new"]
    new_credentials = this_run.get("credentials", {}).get("new", 0)
    live = sum(1 for h in report["hosts"] if h["resolves"])
    plural = _plural
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
        _summarise_assessment(report, out)
    _summarise_credentials(out, report, rejected, new_credentials)
    if inv.skipped:
        print(f"skipped:    {', '.join(inv.skipped)} (no API key / not installed)")
    if inv.errors:
        print(f"errors:     {len(inv.errors)} this run (see assets.json)")
    print(f"output:     {out.resolve()}")
    if _credential_save_failed(report, stamp):
        return 1
    if inv.interrupted:
        print("status:     interrupted, partial results saved; re-run to fill in the rest")
        return 130
    return 0
