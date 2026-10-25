import io
import json
import os
import subprocess
import sys
import threading
import time

import httpx
import pytest
from rich.console import Console

from conftest import fake_http
from farpoint import runtime
from farpoint.models import Inventory, Observation
from farpoint.output import Checkpointer, merge_reports, recover_checkpoints, run_report, write_outputs
from farpoint.pipeline import Pipeline
from farpoint.progress import LiveReporter
from farpoint.sources.base import SourceFailure, run_command
from farpoint.sources.web import CrtSh

D = "example.com"


class Recorder:
    def __init__(self):
        self.events = []

    def job_queued(self, key):
        self.events.append(("queued", key))

    def job_started(self, key):
        self.events.append(("started", key))

    def job_status(self, key, text):
        self.events.append(("status", key, text))

    def job_request(self, key):
        self.events.append(("request", key))

    def job_finished(self, key, count, error):
        self.events.append(("finished", key, count, error))

    def phase(self, name, done, total, failed=0):
        self.events.append(("phase", name, done, total, failed))

    def interrupted(self):
        self.events.append(("interrupted",))


def test_retries_are_reported_on_the_jobs_progress_line():
    http = fake_http({"crt.sh/": [httpx.Response(502), httpx.Response(200, json=[{"name_value": "a.example.com"}])]})
    rec = Recorder()

    Pipeline(sources=[CrtSh(http)], reporter=rec).run([D])

    key = ("crtsh", D)
    statuses = [e[2] for e in rec.events if e[0] == "status"]
    assert any(s.startswith("HTTP 502, retrying in") and s.endswith("(2/5)") for s in statuses)
    assert sum(1 for e in rec.events if e == ("request", key)) == 2
    assert ("finished", key, 1, None) in rec.events
    assert rec.events[0] == ("queued", key)


def test_final_failure_says_how_many_attempts_were_made():
    http = fake_http({"crt.sh/": [httpx.Response(502)] * 5})
    rec = Recorder()

    inv = Pipeline(sources=[CrtSh(http)], reporter=rec).run([D])

    (finished,) = [e for e in rec.events if e[0] == "finished"]
    assert "HTTP 502 Bad Gateway after 5 attempts" in finished[3]
    assert "after 5 attempts" in inv.errors[0].message


def test_dns_and_enrichment_phases_count_up():
    rec = Recorder()
    src_obs = [Observation("crtsh", f"h{i}.example.com") for i in range(3)]

    class Src:
        name = "crtsh"

        def available(self):
            return True

        def collect(self, domain):
            return src_obs

    from farpoint.resolve import Resolution

    Pipeline(sources=[Src()], lookup=lambda h: Resolution(), reporter=rec).run([D])

    phases = [e for e in rec.events if e[0] == "phase"]
    assert phases[-1] == ("phase", "resolving", 4, 4, 0)  # 3 found + the input domain


def test_phase_failures_are_counted():
    from farpoint.resolve import Resolution

    rec = Recorder()

    def lookup(host):
        if host.startswith("bad"):
            raise TimeoutError("boom")
        return Resolution()

    class Src:
        name = "crtsh"

        def available(self):
            return True

        def collect(self, domain):
            return [Observation("crtsh", f"bad.{domain}"), Observation("crtsh", f"ok.{domain}")]

    Pipeline(sources=[Src()], lookup=lookup, reporter=rec).run([D])

    assert [e for e in rec.events if e[0] == "phase"][-1] == ("phase", "resolving", 3, 3, 1)


def test_live_display_shows_phase_failures():
    r = LiveReporter(Console(file=io.StringIO(), width=120, height=40, color_system=None))
    r.phase("enriching", 158, 158, 12)

    assert "enriching 158/158 · 12 failed" in rendered(r)


# --- CLI tools -------------------------------------------------------------------------


def py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_command_output_is_streamed_as_progress():
    rec = Recorder()
    runtime.bind(rec, ("subfinder", D))
    try:
        out = run_command(py("for i in range(3): print(f'h{i}.example.com', flush=True)"), unit="names")
    finally:
        runtime.bind(None, None)

    assert out.splitlines() == ["h0.example.com", "h1.example.com", "h2.example.com"]
    assert [e[2] for e in rec.events if e[0] == "status"] == ["running", "1 names", "2 names", "3 names"]


def test_command_timeout_and_failure_are_reported():
    with pytest.raises(SourceFailure, match="timed out after 0s"):
        run_command(py("import time; time.sleep(30)"), timeout=0.2)
    with pytest.raises(SourceFailure, match="exited 3: boom"):
        run_command(py("import sys; print('boom', file=sys.stderr); sys.exit(3)"))


def test_cancelling_terminates_running_commands_and_keeps_their_output():
    result = {}

    def run():
        result["out"] = run_command(py("import time; print('found.example.com', flush=True); time.sleep(30)"))

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.5)
    started = time.monotonic()
    runtime.cancel()
    t.join(timeout=5)

    assert result == {"out": "found.example.com\n"}
    assert time.monotonic() - started < 5


def test_interrupted_tool_keeps_parsed_results_and_reports_cancellation():
    from farpoint.sources.tools import Subfinder

    runtime.cancel()
    source = Subfinder(runner=lambda argv: "a.example.com\nb.example.com\n")
    got = []

    with pytest.raises(runtime.Cancelled):
        for obs in source.collect(D):
            got.append(obs.hostname)

    assert sorted(got) == ["a.example.com", "b.example.com"]  # parse order follows a set


# --- interrupting ----------------------------------------------------------------------


class Quick:
    """Finishes as soon as `after` is set (so a Stuck source's first page is in hand by then)."""

    name = "quick"

    def __init__(self, after: threading.Event):
        self.after = after

    def available(self):
        return True

    def collect(self, domain):
        self.after.wait(5)
        return [Observation(self.name, f"quick.{domain}")]


class Stuck:
    """Yields one page, then blocks until the run is cancelled (like a source mid-pagination)."""

    name = "stuck"
    max_concurrency = 1

    def __init__(self):
        self.first_page_kept = threading.Event()

    def available(self):
        return True

    def collect(self, domain):
        yield Observation(self.name, f"page1.{domain}")
        self.first_page_kept.set()  # resumed: the caller has stored page 1
        if runtime._cancel.wait(10):
            raise runtime.Cancelled()
        yield Observation(self.name, f"never.{domain}")


def test_interrupt_keeps_finished_and_partial_results_and_returns_promptly():
    rec = Recorder()

    def interrupt_after_first_result(inv, pending):
        raise KeyboardInterrupt

    started = time.monotonic()
    stuck = Stuck()
    inv = Pipeline(sources=[stuck, Quick(after=stuck.first_page_kept)], reporter=rec, checkpoint=interrupt_after_first_result).run([D])

    assert time.monotonic() - started < 5
    assert inv.interrupted
    assert {"quick.example.com", "page1.example.com"} <= set(inv.hosts)
    assert "never.example.com" not in inv.hosts
    assert ("interrupted",) in rec.events
    assert runtime.cancelled()


def test_an_interrupted_run_is_marked_in_the_history(tmp_path):
    inv = Inventory([D])
    inv.add(Observation("crtsh", "a.example.com"))
    inv.interrupted = True

    report = write_outputs(inv, tmp_path)

    assert report["runs"][-1]["interrupted"] is True


# --- checkpoints -----------------------------------------------------------------------


def test_checkpoint_is_throttled_and_cleared(tmp_path):
    inv = Inventory([D])
    inv.add(Observation("crtsh", "a.example.com"))
    cp = Checkpointer(tmp_path, interval=3600)

    cp(inv)
    inv.add(Observation("crtsh", "b.example.com"))
    cp(inv)  # within the interval: not rewritten

    saved = json.loads(cp.path.read_text())
    assert [h["hostname"] for h in saved["hosts"]] == ["a.example.com"]
    assert "b.example.com" in inv.hosts
    assert saved["interrupted"] is True
    cp.clear()
    assert not cp.path.exists()


def test_checkpoints_from_dead_runs_are_merged_and_live_ones_left_alone(tmp_path):
    def inventory(host):
        inv = Inventory([D])
        inv.add(Observation("crtsh", host))
        return inv

    alive = Checkpointer(tmp_path)  # holds its lock, like a run still scanning
    alive(inventory("alive.example.com"))
    dead = Checkpointer(tmp_path)
    dead(inventory("killed.example.com"))
    dead._lock_fh.close()  # what the OS does when the process dies; the files stay behind
    dead._lock_fh = None

    recovered = recover_checkpoints(tmp_path)

    assert recovered == [{"at": dead.started, "domains": [D], "hosts": 1}]
    report = json.loads((tmp_path / "assets.json").read_text())
    assert {h["hostname"] for h in report["hosts"]} == {"killed.example.com"}
    assert report["runs"][-1]["interrupted"] is True
    assert not dead.path.exists() and not dead.lock_path.exists()
    assert alive.path.exists()
    alive.clear()


def test_a_reused_pid_does_not_hide_a_dead_runs_checkpoint(tmp_path):
    """In a container farpoint is always PID 1: liveness must come from the lock, not the PID."""
    inv = Inventory([D])
    inv.add(Observation("crtsh", "killed.example.com"))
    stale = tmp_path / f".checkpoint-{os.getpid()}-deadbeef.json"  # same PID as this live process
    stale.write_text(json.dumps({**run_report(inv), "at": "2026-10-19T00:00:00Z", "interrupted": True}))

    assert [r["hosts"] for r in recover_checkpoints(tmp_path)] == [1]
    assert not stale.exists()


def test_merging_an_older_run_never_moves_timestamps_backwards():
    def rep(*hosts):
        inv = Inventory([D])
        for h in hosts:
            inv.add(Observation("crtsh", h))
        return run_report(inv)

    newer = merge_reports(None, rep("a.example.com"), "2026-10-19T10:00:00Z")
    merged = merge_reports(newer, rep("a.example.com", "b.example.com"), "2026-10-19T09:00:00Z")

    hosts = {h["hostname"]: h for h in merged["hosts"]}
    assert hosts["a.example.com"]["last_seen"] == "2026-10-19T10:00:00Z"
    assert hosts["a.example.com"]["first_seen"] == "2026-10-19T09:00:00Z"
    assert merged["updated_at"] == "2026-10-19T10:00:00Z"
    assert [r["at"] for r in merged["runs"]] == ["2026-10-19T09:00:00Z", "2026-10-19T10:00:00Z"]


# --- display ---------------------------------------------------------------------------


def rendered(reporter: LiveReporter) -> str:
    reporter.console.print(reporter.render())
    return reporter.console.file.getvalue()


def test_live_display_shows_each_jobs_state():
    r = LiveReporter(Console(file=io.StringIO(), width=120, height=40, color_system=None))
    for key in [("crtsh", D), ("otx", D), ("virustotal", D), ("shodan", D)]:
        r.job_queued(key)
    r.job_started(("crtsh", D))
    r.job_finished(("crtsh", D), 35, None)
    r.job_started(("otx", D))
    r.job_finished(("otx", D), 3, "SourceFailure: HTTP 502 Bad Gateway after 5 attempts")
    r.job_started(("virustotal", D))
    r.job_status(("virustotal", D), "rate limit: next request in 15s")
    r.phase("resolving", 3, 10)

    text = rendered(r)

    assert "✓ crtsh" in text and "35 results" in text
    assert "✗ otx" in text and "3 results, then failed: SourceFailure: HTTP 502" in text
    assert "rate limit: next request in 15s" in text
    assert "· shodan" in text and "queued" in text
    assert "resolving 3/10" in text


def test_live_display_summarises_rows_that_do_not_fit():
    r = LiveReporter(Console(file=io.StringIO(), width=120, height=12, color_system=None))
    for i in range(30):
        r.job_queued(("crtsh", f"d{i}.example"))
    r.job_started(("crtsh", "d29.example"))

    text = rendered(r)

    assert "d29.example" in text  # running rows always shown
    assert "more queued" in text


def test_names_stay_readable_on_a_narrow_terminal_with_long_errors():
    r = LiveReporter(Console(file=io.StringIO(), width=80, height=40, color_system=None))
    r.job_queued(("virustotal", "example-co.org"))
    r.job_finished(("virustotal", "example-co.org"), 0, "SourceFailure: HTTP 502 Bad Gateway after 5 attempts: https://crt.sh/?q=%25.example.com&output=json")
    r.job_queued(("crtsh", D))
    r.job_finished(("crtsh", D), 12, None)

    lines = rendered(r).splitlines()

    assert lines[0].startswith("✗ virustotal example-co.org failed: SourceFailure: HTTP 502")
    assert lines[1].startswith("✓ crtsh      example.com    12 results")
    assert all(len(line) <= 80 for line in lines)


def test_checkpoints_include_pages_from_jobs_still_running(tmp_path):
    saved = []

    def checkpoint(inv, pending):
        cp = Checkpointer(tmp_path / str(len(saved)))
        cp(inv, pending)
        saved.append(json.loads(cp.path.read_text()))

    stuck = Stuck()
    Pipeline(sources=[stuck, Quick(after=stuck.first_page_kept)], checkpoint=lambda inv, pending: (checkpoint(inv, pending), runtime.cancel())).run([D])

    hosts = {h["hostname"] for h in saved[0]["hosts"]}
    assert {"quick.example.com", "page1.example.com"} <= hosts


# --- thread/signal safety --------------------------------------------------------------


def test_saving_never_touches_the_process_umask(monkeypatch, tmp_path):
    from farpoint import output

    def forbidden(_):
        raise AssertionError("os.umask() changes process-wide state that subprocesses inherit")

    monkeypatch.setattr(output.os, "umask", forbidden)
    inv = Inventory([D])
    inv.add(Observation("crtsh", "a.example.com"))

    Checkpointer(tmp_path)(inv)
    write_outputs(inv, tmp_path)


def test_interrupt_is_deferred_until_the_main_thread_is_waiting():
    runtime.request_interrupt()  # e.g. Ctrl-C while a result is being applied: nothing raised here

    with pytest.raises(KeyboardInterrupt):
        with runtime.interruptible():
            pass
    with runtime.interruptible():  # delivered once
        pass
    with pytest.raises(KeyboardInterrupt):
        with runtime.interruptible():
            runtime.request_interrupt()  # while waiting: raised immediately


def test_ctrl_c_while_applying_a_result_stops_at_the_next_wait():
    stuck = Stuck()

    def ctrl_c_mid_processing(inv, pending):
        runtime.request_interrupt()  # the handler's path; must not raise inside this callback

    inv = Pipeline(sources=[stuck, Quick(after=stuck.first_page_kept)], checkpoint=ctrl_c_mid_processing).run([D])

    assert inv.interrupted
    assert {"quick.example.com", "page1.example.com"} <= set(inv.hosts)


def test_signal_handler_writes_without_print_and_second_signal_exits(monkeypatch):
    from farpoint import cli

    writes, exits = [], []
    monkeypatch.setattr(cli.os, "write", lambda fd, data: writes.append(fd))
    def fake_exit(code):
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(cli.os, "_exit", fake_exit)
    monkeypatch.setattr("builtins.print", lambda *a, **k: pytest.fail("print() in a signal handler can re-enter stdio"))
    handler = cli._on_interrupt(stop_scan=False)

    handler(2, None)
    with pytest.raises(SystemExit):
        handler(2, None)

    assert writes == [2] and runtime.cancelled()
    assert exits == [130]


def test_a_deferred_interrupt_is_not_lost_after_the_last_wait():
    """Ctrl-C lands while the final result is being applied (no wait follows, e.g. --no-resolve
    --no-enrich): the run must still come back marked interrupted."""

    def ctrl_c(inv, pending):
        runtime.cancel()  # what the signal handler does first
        runtime.request_interrupt()  # deferred: the main thread isn't waiting

    ready = threading.Event()
    ready.set()
    inv = Pipeline(sources=[Quick(after=ready)], checkpoint=ctrl_c).run([D])

    assert inv.interrupted


def test_cancelled_jobs_are_shown_as_interrupted_not_done():
    rec = Recorder()
    stuck = Stuck()

    def ctrl_c(inv, pending):
        runtime.cancel()
        runtime.request_interrupt()

    Pipeline(sources=[stuck, Quick(after=stuck.first_page_kept)], reporter=rec, checkpoint=ctrl_c).run([D])

    finished = {e[1][0] for e in rec.events if e[0] == "finished"}
    assert "stuck" not in finished
    assert ("interrupted",) in rec.events


def test_rdap_falls_back_to_rdap_org_when_the_bootstrap_registry_is_down():
    from farpoint.enrich import Rdap

    body = {"name": "EXAMPLE-NET", "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}]}
    http = fake_http({"data.iana.org/rdap/ipv4.json": [httpx.Response(503)] * 3, "rdap.org/ip/192.0.2.1": httpx.Response(200, json=body)})

    details = Rdap(http, retries=2).enrich("192.0.2.1")

    assert (details.org, details.network) == ("EXAMPLE-NET", "192.0.2.0/24")
