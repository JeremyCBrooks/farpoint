"""How much of a scan's web the scan actually saw, and which bot defences hid the rest.

    uv run python -m farpoint.visibility out

A challenge (`bot-challenge:<vendor>`) could be passed by a browser; a block (`bot-block:<vendor>`) can't
be passed by any client, only from another network. Compare the numbers before and after a change to
how farpoint asks, on the same organisations, rather than judging it on one site.
"""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from pathlib import Path

from farpoint.fingerprint import turned_away
from farpoint.probe import HttpResult

WEB = ("http", "https")


def _defence(record: dict) -> tuple[str, str] | None:
    for signal in record.get("signals", []):
        if signal.startswith(("bot-challenge", "bot-block")):
            kind, _, vendor = signal.partition(":")
            return kind.removeprefix("bot-"), vendor or "unknown"
    # Recorded before farpoint marked bot defences: read again from the status, headers and title it kept.
    # The page itself wasn't kept, so a block that only its page names reads as a challenge or not at all.
    title = html.escape(record.get("title") or "")
    return turned_away(HttpResult(record.get("status") or 0, list((record.get("headers") or {}).items()), f"<title>{title}</title>".encode()))


def summarise(report: dict) -> dict:
    """Web services in the report: how many were seen, and per vendor how many were challenged or blocked."""
    web = [r for r in report.get("fingerprints", []) if r.get("service") in WEB]
    hidden = {"challenge": Counter(), "block": Counter()}
    for record in web:
        if defence := _defence(record):
            hidden[defence[0]][defence[1]] += 1
    return {
        "web": len(web),
        "seen": len(web) - sum(hidden["challenge"].values()) - sum(hidden["block"].values()),
        "challenged": dict(hidden["challenge"].most_common()),
        "blocked": dict(hidden["block"].most_common()),
    }


def _vendors(counts: dict, sep: str = ", ") -> str:
    return sep.join(f"{vendor} {n}" for vendor, n in counts.items())


def summary_line(summary: dict) -> str | None:
    """One line for the run summary, or None when nothing was hidden."""
    hidden = sum(summary["challenged"].values()) + sum(summary["blocked"].values())
    if not hidden:
        return None
    parts = [f"{label}: {_vendors(summary[key])}" for key, label in (("challenged", "challenged"), ("blocked", "blocked")) if summary[key]]
    them = "them" if hidden != 1 else "it"
    return f"{hidden} web service{'s' if hidden != 1 else ''} turned the scan away ({'; '.join(parts)}): what runs behind {them} wasn't seen"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m farpoint.visibility", description="How much of a scan's web was hidden by bot defences.")
    parser.add_argument("out", nargs="?", default="out", help="a scan's output directory (default ./out)")
    args = parser.parse_args(argv)
    summary = summarise(json.loads((Path(args.out) / "assets.json").read_text(encoding="utf-8")))
    print(f"{'web services':<14}{summary['web']}")
    print(f"{'seen':<14}{summary['seen']}")
    for key in ("challenged", "blocked"):
        n = sum(summary[key].values())
        print(f"{key:<14}{n}" + (f"  ({_vendors(summary[key])})" if n else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
