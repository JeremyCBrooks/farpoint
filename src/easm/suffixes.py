"""Registered domains, by the Public Suffix List's ICANN rules (bundled in easm/data/public_suffixes.txt)."""

from __future__ import annotations

from functools import cache
from importlib import resources


@cache
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(exact suffixes, parents of *. wildcards, ! exceptions)."""
    lines = resources.files("easm.data").joinpath("public_suffixes.txt").read_text(encoding="utf-8").splitlines()
    rules = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    exact = frozenset(r for r in rules if r[0] not in "*!")
    wild = frozenset(r[2:] for r in rules if r.startswith("*."))
    exceptions = frozenset(r[1:] for r in rules if r.startswith("!"))
    return exact, wild, exceptions


def public_suffix(hostname: str) -> str | None:
    """The longest public suffix `hostname` ends in (www.example.co.uk -> co.uk), None if none."""
    exact, wild, exceptions = _rules()
    labels = hostname.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1 :])
        if candidate in exact or (i + 1 < len(labels) and ".".join(labels[i + 1 :]) in wild):
            return candidate
    return None


def registered(hostname: str) -> str | None:
    """The registered domain `hostname` is under (www.example.co.uk -> example.co.uk), None if
    `hostname` is itself a public suffix or under none."""
    suffix = public_suffix(hostname)
    host = hostname.lower().rstrip(".")
    if not suffix or host == suffix:
        return None
    return ".".join(host[: -len(suffix) - 1].split(".")[-1:] + [suffix])
