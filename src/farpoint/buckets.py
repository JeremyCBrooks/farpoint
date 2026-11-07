"""Opt-in cloud storage discovery (--buckets): S3 and Google Cloud Storage buckets named after the
organisation, or that its own CNAMEs point at.

Each candidate gets one unauthenticated GET to the storage provider (never to the organisation), and
the provider's answer says which of three things is true: no such bucket (404 NoSuchBucket), a bucket
that exists but isn't public (403), or one that lists its contents to anyone (200 ListBucketResult).
Nothing is downloaded beyond that first page of the listing, and nothing is written.

A bucket found by name alone may be someone else's: bucket names are global, first come first served.
One the organisation's CNAMEs point at is tied by the CNAME.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

PROVIDERS = {  # vendor -> (bucket hostname template, URL template)
    "AWS S3": ("{name}.s3.amazonaws.com", "https://{name}.s3.amazonaws.com/"),
    "Google Cloud Storage": ("{name}.storage.googleapis.com", "https://{name}.storage.googleapis.com/"),
}
MODIFIERS = (
    "backup", "backups", "assets", "static", "media", "uploads", "files", "data", "logs", "dev", "prod", "staging",
    "test", "public", "www", "images", "web", "cdn", "docs", "archive",
)
LIMIT = 200  # requests per scan in all: a few dozen names on two providers
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")  # names tried by guess: no dots
_DOTTED = re.compile(r"^(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$")  # a CNAME's bucket may be named after the host (a website bucket)
_S3_CNAME = re.compile(r"^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$")
_S3_REGION = re.compile(r"\.s3[.-](?:website[.-])?([a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com$")
_GCS_CNAME = re.compile(r"^([a-z0-9][a-z0-9._-]*[a-z0-9])\.storage\.googleapis\.com$")
_GCS_OWN_DOMAIN = "c.storage.googleapis.com"  # a CNAME here serves the bucket named exactly like the host


@dataclass(frozen=True)
class Candidate:
    name: str
    vendor: str
    domain: str  # the scan domain it is named after or whose host points at it
    tie: str  # "name" or "cname"
    evidence: str
    region: str | None = None  # an S3 bucket's region, when its CNAME says

    @property
    def hostname(self) -> str:
        return PROVIDERS[self.vendor][0].format(name=self.name)

    @property
    def url(self) -> str:
        if "." not in self.name:
            return PROVIDERS[self.vendor][1].format(name=self.name)
        # Dotted names don't match the provider's wildcard certificate, so they are asked path-style.
        if self.vendor == "AWS S3":
            return f"https://s3.{self.region}.amazonaws.com/{self.name}/" if self.region else f"https://s3.amazonaws.com/{self.name}/"
        return f"https://storage.googleapis.com/{self.name}/"


def candidates(tokens: Mapping[str, str], modifiers: Sequence[str], cnames: Mapping[str, Iterable[str]], scope_of) -> list[Candidate]:
    """Buckets the organisation's CNAMEs point at first (tie cname), then its name with common and its own
    modifiers on each provider (tie name), at most LIMIT."""
    found: dict[tuple[str, str], Candidate] = {}
    for host, targets in sorted(cnames.items()):
        for target in sorted(targets):
            if target == _GCS_OWN_DOMAIN:
                if _DOTTED.match(host):
                    found.setdefault(("Google Cloud Storage", host), Candidate(host, "Google Cloud Storage", scope_of(host), "cname", f"CNAME of {host}"))
                continue
            for vendor, pattern in (("AWS S3", _S3_CNAME), ("Google Cloud Storage", _GCS_CNAME)):
                if (m := pattern.match(target)) and _DOTTED.match(m.group(1)):
                    region = (r.group(1) if (r := _S3_REGION.search(target)) else None) if vendor == "AWS S3" else None
                    found.setdefault((vendor, m.group(1)), Candidate(m.group(1), vendor, scope_of(host), "cname", f"CNAME of {host}", region))
    words = list(dict.fromkeys([*MODIFIERS, *modifiers]))
    for token, domain in tokens.items():
        for name in [token, *(f"{token}-{w}" for w in words)]:
            if _NAME.match(name):
                for vendor in PROVIDERS:
                    found.setdefault((vendor, name), Candidate(name, vendor, domain, "name", f"{vendor} bucket named after {domain}"))
    return list(found.values())[:LIMIT]


def judge(status: int, body: str) -> str | None:
    """"public", "private", "exists" (in another region: whether it lists is unknown) or "absent" from the
    provider's answer; None when it says nothing either way."""
    if status == 301 and "PermanentRedirect" in body:
        return "exists"
    if status == 404 and "NoSuchBucket" in body:
        return "absent"
    if status == 200 and "<ListBucketResult" in body:
        return "public"
    if status == 403:
        return "private"
    return None
