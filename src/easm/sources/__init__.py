"""Source registry. To add a source: implement collect()/available() and list it here."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import httpx

from easm.sources.base import Source
from easm.sources.tools import Amass, Bbot, Dnstwist, Subfinder
from easm.sources.web import CertSpotter, CrtSh, HackerTarget, Otx, RapidDns, Shodan, UrlScan, VirusTotal, Wayback


def build_sources(http: httpx.Client, env: Mapping[str, str]) -> list[Source]:
    return [
        CrtSh(http),
        CertSpotter(http, env.get("CERTSPOTTER_API_KEY")),
        HackerTarget(http, env.get("HACKERTARGET_API_KEY")),
        Wayback(http),
        Otx(http, env.get("OTX_API_KEY")),
        UrlScan(http, env.get("URLSCAN_API_KEY")),
        RapidDns(http),
        Shodan(http, env.get("SHODAN_API_KEY")),
        VirusTotal(http, env.get("VIRUSTOTAL_API_KEY")),
        Subfinder(),
        Amass(),
        Bbot(),
        Dnstwist(),
    ]


def select_sources(sources: Sequence[Source], only: Sequence[str] = (), exclude: Sequence[str] = ()) -> list[Source]:
    known = [s.name for s in sources]
    unknown = [n for n in [*only, *exclude] if n not in known]
    if unknown:
        raise ValueError(f"unknown source(s) {', '.join(unknown)}; choose from: {', '.join(known)}")
    by_name = {s.name: s for s in sources}
    chosen = [by_name[n] for n in only] if only else list(sources)
    return [s for s in chosen if s.name not in exclude]
