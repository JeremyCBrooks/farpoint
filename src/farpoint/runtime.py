"""Per-run shared state: which job a worker thread is on (for progress), and cancellation.

Sources call status()/count_request()/sleep() without knowing who is listening; the pipeline binds
each worker thread to its job and a Reporter. Cancelling wakes every runtime.sleep() and terminates
tracked subprocesses so an interrupted run can save and exit promptly.

Interrupts (Ctrl-C) are only delivered to the main thread while it is idle in an interruptible()
block, waiting for the next job; arriving at any other moment they are deferred to the next wait, so
a result is never half-applied to the inventory.

This is per-process state: one scan per process.
"""

from __future__ import annotations

import contextlib
import subprocess
import threading
from collections.abc import Iterator
from typing import Protocol


class Cancelled(Exception):
    """The run was interrupted; the job should stop without recording an error."""


class Reporter(Protocol):
    def job_status(self, key: tuple[str, str], text: str) -> None: ...

    def job_request(self, key: tuple[str, str]) -> None: ...


_local = threading.local()
_cancel = threading.Event()
_interrupt = {"pending": False, "open": False}  # main thread only (signal handlers run there)
_procs: set[subprocess.Popen] = set()
_procs_lock = threading.Lock()


def bind(reporter: Reporter | None, key: tuple[str, str] | None) -> None:
    _local.reporter, _local.key = reporter, key


def status(text: str) -> None:
    """Describe what the current job is doing right now (e.g. 'retrying in 7s')."""
    reporter, key = getattr(_local, "reporter", None), getattr(_local, "key", None)
    if reporter and key:
        reporter.job_status(key, text)


def count_request() -> None:
    reporter, key = getattr(_local, "reporter", None), getattr(_local, "key", None)
    if reporter and key:
        reporter.job_request(key)


def check() -> None:
    if _cancel.is_set():
        raise Cancelled()


def sleep(seconds: float) -> None:
    """time.sleep that returns early, raising Cancelled, when the run is cancelled."""
    if seconds > 0 and _cancel.wait(seconds):
        raise Cancelled()
    check()


def cancelled() -> bool:
    return _cancel.is_set()


def cancel() -> None:
    _cancel.set()
    with _procs_lock:
        procs = list(_procs)
    for proc in procs:
        proc.terminate()


def reset() -> None:
    """Clear cancellation and any deferred interrupt; call before starting a scan (and its signal handlers)."""
    _cancel.clear()
    _interrupt["pending"] = False


def request_interrupt() -> None:
    """Called from a signal handler: raise KeyboardInterrupt now if the main thread is idle, else at its next wait."""
    _interrupt["pending"] = True
    if _interrupt["open"]:
        _interrupt["pending"] = False
        raise KeyboardInterrupt


@contextlib.contextmanager
def interruptible() -> Iterator[None]:
    """Mark a main-thread wait as a safe point to deliver a (possibly deferred) interrupt."""
    if _interrupt["pending"]:
        _interrupt["pending"] = False
        raise KeyboardInterrupt
    _interrupt["open"] = True
    try:
        yield
    finally:
        _interrupt["open"] = False


def track(proc: subprocess.Popen) -> None:
    with _procs_lock:
        _procs.add(proc)
    if _cancel.is_set():
        proc.terminate()


def untrack(proc: subprocess.Popen) -> None:
    with _procs_lock:
        _procs.discard(proc)
