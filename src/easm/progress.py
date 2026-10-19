"""Live progress: one line per (source, domain) job plus counters for the DNS and enrichment phases."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field, replace
from typing import Protocol

from rich.console import Console, Group
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

Key = tuple[str, str]


class ProgressReporter(Protocol):
    def job_queued(self, key: Key) -> None: ...

    def job_started(self, key: Key) -> None: ...

    def job_status(self, key: Key, text: str) -> None: ...

    def job_request(self, key: Key) -> None: ...

    def job_finished(self, key: Key, count: int, error: str | None) -> None: ...

    def phase(self, name: str, done: int, total: int, failed: int = 0) -> None: ...

    def interrupted(self) -> None: ...


class NullReporter:
    def job_queued(self, key: Key) -> None: ...

    def job_started(self, key: Key) -> None: ...

    def job_status(self, key: Key, text: str) -> None: ...

    def job_request(self, key: Key) -> None: ...

    def job_finished(self, key: Key, count: int, error: str | None) -> None: ...

    def phase(self, name: str, done: int, total: int, failed: int = 0) -> None: ...

    def interrupted(self) -> None: ...


@dataclass
class _Row:
    state: str = "queued"  # queued | running | done | failed | interrupted
    status: str = ""
    requests: int = 0
    count: int = 0
    error: str | None = None
    started: float | None = None
    ended: float | None = None

    def elapsed(self, now: float) -> str:
        if self.started is None:
            return ""
        seconds = int((self.ended or now) - self.started)
        return f"{seconds // 60}m{seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


@dataclass
class _Phase:
    done: int = 0
    total: int = 0
    failed: int = 0
    finished: bool = False


@dataclass
class LiveReporter:
    """Renders job rows with a braille spinner, refreshed in place. Use as a context manager."""

    console: Console = field(default_factory=lambda: Console(stderr=True))
    _rows: dict[Key, _Row] = field(default_factory=dict)
    _phases: dict[str, _Phase] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _spinner: Spinner = field(default_factory=lambda: Spinner("dots", style="cyan"))
    _final: bool = False
    _live: Live | None = None

    def __enter__(self) -> LiveReporter:
        self._live = Live(console=self.console, get_renderable=self.render, refresh_per_second=8, transient=False, vertical_overflow="visible")
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        self._final = True
        if self._live:
            self._live.__exit__(*exc)

    # --- ProgressReporter ---------------------------------------------------------------
    def job_queued(self, key: Key) -> None:
        with self._lock:
            self._rows[key] = _Row()

    def job_started(self, key: Key) -> None:
        with self._lock:
            row = self._rows.setdefault(key, _Row())
            row.state, row.started = "running", time.monotonic()

    def job_status(self, key: Key, text: str) -> None:
        with self._lock:
            if key in self._rows:
                self._rows[key].status = text

    def job_request(self, key: Key) -> None:
        with self._lock:
            if key in self._rows:
                self._rows[key].requests += 1

    def job_finished(self, key: Key, count: int, error: str | None) -> None:
        with self._lock:
            row = self._rows.setdefault(key, _Row())
            row.state = "failed" if error else "done"
            row.count, row.error, row.ended = count, error, time.monotonic()
            if row.started is None:
                row.started = row.ended

    def phase(self, name: str, done: int, total: int, failed: int = 0) -> None:
        with self._lock:
            for other, p in self._phases.items():  # starting a phase finishes the one before it
                if other != name:
                    p.finished = True
            p = self._phases.setdefault(name, _Phase())
            p.done, p.total, p.failed = done, total, failed
            p.finished = total > 0 and done >= total

    def interrupted(self) -> None:
        now = time.monotonic()
        with self._lock:
            for row in self._rows.values():
                if row.state in ("queued", "running"):
                    row.state, row.ended = "interrupted", now
            for p in self._phases.values():
                p.finished = True

    # --- rendering ----------------------------------------------------------------------
    def _icon(self, state: str, now: float) -> Text:
        if state == "running":
            return self._spinner.render(now)
        icon, style = {"queued": ("·", "dim"), "done": ("✓", "green"), "failed": ("✗", "red")}.get(state, ("■", "yellow"))
        return Text(icon, style=style)

    def _cells(self, key: Key, row: _Row, now: float) -> tuple:
        name, target = key
        icon = self._icon(row.state, now)
        label = Text.assemble(icon, " ", (name, "dim" if row.state == "queued" else "bold"))
        if row.state == "queued":
            return label, Text(target, style="dim"), Text("queued", style="dim"), ""
        if row.state == "running":
            detail = row.status or "running"
            if row.requests > 1:
                detail += f" · {row.requests} requests"
            return label, target, Text(detail, style="cyan"), row.elapsed(now)
        if row.state == "done":
            return label, target, f"{row.count} results", row.elapsed(now)
        if row.state == "failed":
            kept = f"{row.count} results, then " if row.count else ""
            return label, target, Text(f"{kept}failed: {row.error}", style="red"), row.elapsed(now)
        return label, target, Text("interrupted", style="yellow"), row.elapsed(now)

    def render(self) -> Group:
        now = time.monotonic()
        with self._lock:  # copy the rows themselves, not just the list: workers update them in place
            rows = [(key, replace(row)) for key, row in self._rows.items()]
            phases = [(name, replace(p)) for name, p in self._phases.items()]
        order = {"running": 0, "failed": 1, "interrupted": 1, "done": 2, "queued": 3}
        shown = rows
        hidden: dict[str, int] = {}
        room = max(self.console.height - len(phases) - 4, 5)
        if not self._final and len(rows) > room:
            ranked = sorted(rows, key=lambda kv: order[kv[1].state])
            keep = {key for key, _ in ranked[: room - 1]}
            shown = [kv for kv in rows if kv[0] in keep]  # original order among those shown
            for _, row in ranked[room - 1 :]:
                hidden[row.state] = hidden.get(row.state, 0) + 1

        # Names and domains keep their full width; only the status text is truncated to fit.
        name_w = max((len(k[0]) for k, _ in shown), default=0) + 2  # + icon
        target_w = min(max((len(k[1]) for k, _ in shown), default=0), 40)
        table = Table.grid(padding=(0, 1))
        table.add_column(no_wrap=True, min_width=name_w)
        table.add_column(no_wrap=True, min_width=target_w, overflow="ellipsis")
        table.add_column(no_wrap=True, overflow="ellipsis", ratio=1)
        table.add_column(justify="right", style="dim", no_wrap=True, min_width=6)
        for key, row in shown:
            table.add_row(*self._cells(key, row, now))
        parts: list = [table]
        if hidden:
            parts.append(Text("  … " + ", ".join(f"{n} more {state}" for state, n in hidden.items()), style="dim"))
        for name, p in phases:
            icon = Text("✓", style="green") if p.finished else self._spinner.render(now)
            failures = (f" · {p.failed} failed (see assets.json)", "red") if p.failed else ""
            parts.append(Text.assemble(icon, " ", (f"{name} {p.done}/{p.total}", "bold"), failures))
        return Group(*parts)
