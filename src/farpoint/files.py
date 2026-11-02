"""File primitives shared by the report writers: locking, atomic writes, formula-safe CSVs, timestamps."""

from __future__ import annotations

import contextlib
import csv
import io
import os
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: msvcrt's byte-range locks instead
    fcntl = None
    import msvcrt


def stamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_stamp() -> str:
    return stamp(datetime.now(timezone.utc))


def lock(fh, wait: bool = True) -> bool:
    """Take an exclusive lock on open file `fh`, held until it is closed or its process dies.
    With wait=False, returns False at once if someone else holds it."""
    if fcntl:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            return False
        return True
    fh.seek(0)
    while True:
        try:  # LK_LOCK itself retries for about 10 seconds before giving up
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK if wait else msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            if not wait:
                return False


@contextlib.contextmanager
def locked(out_dir: Path) -> Iterator[None]:
    """Serialise read-merge-write so two runs into the same directory can't drop each other's results."""
    with open(out_dir / ".lock", "w") as fh:
        lock(fh)
        yield


def _read_umask() -> int:
    """os.umask() can only be read by setting it, which would briefly hand any subprocess started
    meanwhile a umask of 0, so it is read once, at import, before any worker thread exists."""
    umask = os.umask(0o077)
    os.umask(umask)
    return umask


FILE_MODE = 0o666 & ~_read_umask()  # what open() gives a new file (mkstemp alone would give 0o600)
OWNER_MODE = 0o600


def write_atomic(path: Path, text: str, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:  # closed before any unlink: Windows can't delete open files
            if hasattr(os, "fchmod"):
                os.fchmod(fd, mode)
            else:  # Windows before Python 3.13
                os.chmod(tmp, mode)
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _guard(cell: str) -> str:
    """A spreadsheet runs a cell that starts with one of these as a formula, so quote it."""
    return "'" + cell if cell[:1] in ("=", "+", "-", "@", "\t", "\r") else cell


def csv_text(rows: list[dict], fields: list[str]) -> str:
    def flat(value) -> str:
        if isinstance(value, list):  # phrases (evidence) are separated so they stay readable
            items = [_guard(str(v)) for v in value]
            return ("; " if any(" " in v for v in items) else " ").join(items)
        if isinstance(value, bool) or value is None:
            return {True: "yes", False: "no", None: ""}[value]
        return _guard(str(value))

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows({k: flat(row.get(k)) for k in fields} for row in rows)
    return buf.getvalue()
