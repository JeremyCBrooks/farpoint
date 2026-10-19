"""Build the cross-organisation naming corpus that easm.guess learns its priors from.

    uv run --group corpus python -m easm.corpus orgs  -d corpus --count 2000   # organisations, from OV/EV certificates in CT logs
    uv run --group corpus python -m easm.corpus fetch -d corpus                # every name crt.sh has under each (resumable)
    uv run --group corpus python -m easm.corpus stats -d corpus --exclude example.com
    uv run --group corpus python -m easm.corpus evaluate -d corpus      # cross-validated: with vs without corpus

Organisations are the registered domains on organisation-validated certificates (the subject names an
organisation), sampled at random positions in public CT logs: businesses rather than hobby sites, and
nothing to do with any scan target. Their names come from crt.sh's public database, one query at a time.
Statistics count each organisation once per feature, so one with thousands of names weighs no more than
one with ten, and `--exclude` keeps organisations you will evaluate on out of the corpus.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import socket
import sys
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

import httpx

from easm.guess import BARE, Corpus, Prior, Taxonomy, bundled_prior, leave_one_out, render
from easm.names import normalize_hostname

LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
PSL = "https://publicsuffix.org/list/public_suffix_list.dat"
CRTSH = "host=crt.sh port=5432 dbname=certwatch user=guest"
USER_AGENT = "easm-corpus (cross-organisation naming statistics)"
MIN_NAMES = 5  # organisations with fewer names say little about naming
MIN_ORGS = 3  # features seen in fewer organisations are dropped
BATCH = 256  # CT entries asked for per request (logs may return fewer)
PAUSE = 0.5  # seconds between CT requests to one log
FEATURE_NAMES = 5000  # names sampled per organisation for its features: platforms have hundreds of thousands
STEM_MODIFIERS = 12  # stems with more modifiers than this (customer or device names) say nothing about pairs
QUERY_TIMEOUT = 120  # seconds before we cancel a query ourselves (crt.sh also cancels its own after ~30 s)

_NAMES_SQL = """SELECT DISTINCT lower(cai.name_value) FROM certificate_and_identities cai
                 WHERE plainto_tsquery('certwatch', %s) @@ identities(cai.certificate)
                   AND cai.name_type IN ('2.5.4.3', 'san:dNSName')"""


# --- public suffixes ----------------------------------------------------------------------------


class Suffixes:
    """Registered domains per the Public Suffix List. Platform suffixes (its private section, e.g.
    azurewebsites.net) are not organisations: names under them are skipped."""

    def __init__(self, text: str) -> None:
        self.icann: set[str] = set()
        self.platforms: set[str] = set()
        section = self.icann
        for line in text.splitlines():
            line = line.strip()
            if "===BEGIN PRIVATE DOMAINS===" in line:
                section = self.platforms
            if line and not line.startswith("//"):
                section.add(line.lstrip("!").removeprefix("*."))

    def registered(self, hostname: str) -> str | None:
        labels = hostname.split(".")
        for i in range(len(labels)):
            if ".".join(labels[i:]) in self.platforms:
                return None
        for i in range(1, len(labels)):
            if ".".join(labels[i:]) in self.icann:
                return ".".join(labels[i - 1 :])
        return None


def load_suffixes(directory: Path, http: httpx.Client) -> Suffixes:
    path = directory / "public_suffix_list.dat"
    if not path.exists():
        path.write_text(http.get(PSL).raise_for_status().text, encoding="utf-8")
    return Suffixes(path.read_text(encoding="utf-8"))


# --- step 1: organisations from CT logs ---------------------------------------------------------


def _logs(http: httpx.Client) -> list[str]:
    """Usable logs that serve the classic RFC 6962 API."""
    listing = http.get(LOG_LIST).raise_for_status().json()
    return [log["url"] for op in listing["operators"] for log in op.get("logs", []) if "usable" in log.get("state", {})]


def _certificate(entry: dict) -> bytes:
    leaf, extra = base64.b64decode(entry["leaf_input"]), base64.b64decode(entry["extra_data"])
    if int.from_bytes(leaf[10:12], "big") == 0:  # x509_entry: the certificate is in the leaf
        return leaf[15 : 15 + int.from_bytes(leaf[12:15], "big")]
    return extra[3 : 3 + int.from_bytes(extra[0:3], "big")]  # precert_entry: the pre-certificate


def _validated_domains(der: bytes) -> tuple[str, list[str]] | None:
    """(organisation, DNS names) of an organisation-validated certificate, else None."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_der_x509_certificate(der)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not org:
            return None
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return str(org[0].value), san.get_values_for_type(x509.DNSName)
    except Exception:  # malformed or unusual certificates are common in CT; skip them
        return None


def sample_orgs(directory: Path, count: int, seed: int) -> None:
    http = httpx.Client(timeout=60, headers={"User-Agent": USER_AGENT})
    suffixes = load_suffixes(directory, http)
    out_path = directory / "orgs.tsv"
    rows = [line.split("\t") for line in out_path.read_text(encoding="utf-8").splitlines() if line] if out_path.exists() else []
    seen = {row[0] for row in rows}
    owners = {row[1].casefold() for row in rows}  # one domain per certificate organisation: cloud giants issue millions
    rng = random.Random(seed + len(seen))
    logs = _logs(http)
    sizes: dict[str, int] = {}
    with out_path.open("a", encoding="utf-8") as out:
        while len(seen) < count:
            log = rng.choice(logs)
            try:
                if log not in sizes:
                    sizes[log] = http.get(log + "ct/v1/get-sth").raise_for_status().json()["tree_size"]
                start = rng.randrange(0, max(sizes[log] - BATCH, 1))
                entries = http.get(log + "ct/v1/get-entries", params={"start": start, "end": start + BATCH - 1}).raise_for_status().json()["entries"]
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                print(f"skipping {log}: {exc}", file=sys.stderr)
                logs.remove(log)
                if not logs:
                    raise SystemExit("no usable CT logs answered")
                continue
            before = len(seen)
            for entry in entries:
                found = _validated_domains(_certificate(entry))
                if not found or found[0].casefold() in owners:
                    continue
                for name in found[1]:
                    host = normalize_hostname(name)
                    domain = suffixes.registered(host) if host else None
                    if domain and domain not in seen and len(seen) < count:
                        seen.add(domain)
                        owners.add(found[0].casefold())
                        out.write(f"{domain}\t{found[0].replace(chr(9), ' ')}\n")
                        break
            out.flush()
            if len(seen) != before:
                print(f"{len(seen)}/{count} organisations", file=sys.stderr, flush=True)
            time.sleep(PAUSE)


# --- step 2: every name under each organisation --------------------------------------------------


def _connect():
    """A crt.sh database session over IPv4 (its IPv6 address is often unreachable). If crt.sh can't be
    reached at all, stop: the run resumes from where it was."""
    import psycopg

    last: Exception | None = None
    for attempt in range(3):
        try:
            address = socket.getaddrinfo("crt.sh", 5432, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            return psycopg.connect(CRTSH, hostaddr=address, autocommit=True, connect_timeout=30, prepare_threshold=None)
        except (OSError, psycopg.OperationalError) as exc:
            last = exc
            time.sleep(10 * (attempt + 1))
    raise SystemExit(f"cannot reach crt.sh ({str(last).splitlines()[0]}); re-run to resume")


def fetch_names(directory: Path) -> None:
    """Every name crt.sh has under each organisation, appended to names.jsonl. An organisation whose
    query times out or keeps being dropped (too many names) is recorded with its error and not retried."""
    import psycopg

    orgs = [line.split("\t")[0] for line in (directory / "orgs.tsv").read_text(encoding="utf-8").splitlines() if line]
    out_path = directory / "names.jsonl"
    done = {json.loads(line)["org"] for line in out_path.read_text(encoding="utf-8").splitlines()} if out_path.exists() else set()
    todo = [o for o in orgs if o not in done]
    conn = None
    with out_path.open("a", encoding="utf-8") as out:
        for i, org in enumerate(todo, 1):
            for attempt in range(2):
                conn = conn or _connect()
                guard = threading.Timer(QUERY_TIMEOUT, conn.cancel_safe)  # crt.sh ignores a session statement_timeout
                guard.start()
                try:
                    rows = conn.execute(_NAMES_SQL, (org,)).fetchall()
                except psycopg.errors.QueryCanceled:  # by crt.sh's own limit or our guard: too many names
                    conn, record = None, {"org": org, "error": "query timed out"}
                    break
                except psycopg.OperationalError as exc:  # dropped mid-query: crt.sh sheds very large ones
                    conn, record = None, {"org": org, "error": str(exc).splitlines()[0][:200]}
                    time.sleep(5)
                    continue
                except psycopg.Error as exc:
                    conn, record = None, {"org": org, "error": str(exc).splitlines()[0][:200]}
                    break
                finally:
                    guard.cancel()
                names = sorted({h for (n,) in rows if (h := normalize_hostname(n)) and (h == org or h.endswith("." + org))})
                record = {"org": org, "names": names}
                break
            out.write(json.dumps(record) + "\n")
            out.flush()
            print(f"{len(done) + i}/{len(orgs)} organisations fetched ({org}{': ' + record['error'] if 'error' in record else ''})", file=sys.stderr, flush=True)


# --- step 3: statistics --------------------------------------------------------------------------


def org_features(org: str, names: Iterable[str]) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    """What one organisation's names say: modifiers it uses, modifier pairs that share a stem (BARE for
    the stem alone), and standalone first labels directly under its domain. Single characters (web-a,
    app-b) are an organisation's own enumeration, not a habit organisations share, so they are left out."""
    names = sorted(names)
    if len(names) > FEATURE_NAMES:
        names = random.Random(org).sample(names, FEATURE_NAMES)
    model = Taxonomy({n: [] for n in names}, [org], bundled_prior(corpus=False))
    mods = {m for m in model.mod_stems if len(m) > 1}
    pairs = {
        (a, b)
        for stem_mods in model.stem_mods.values()
        if len(stem_mods) <= STEM_MODIFIERS
        for a in stem_mods & (mods | {BARE})
        for b in stem_mods & mods
        if a != b
    }
    words = {render(name.labels[0]) for name in model.names if len(name.labels) == 1}
    return mods, pairs, words


def _records(directory: Path, exclude: Iterable[str]) -> Iterator[tuple[str, list[str]]]:
    excluded = tuple(exclude)
    for line in (directory / "names.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        org = record["org"]
        if "names" in record and len(record["names"]) >= MIN_NAMES and not any(org == e or org.endswith("." + e) for e in excluded):
            yield org, record["names"]


Features = tuple[set[str], set[tuple[str, str]], set[str]]


def build_stats(records: Iterable[tuple[str, list[str]]], min_orgs: int = MIN_ORGS) -> dict:
    return _tally((org_features(org, names) for org, names in records), min_orgs)


def _tally(features: Iterable[Features], min_orgs: int = MIN_ORGS) -> dict:
    n = 0
    modifiers: Counter[str] = Counter()
    pairs: Counter[tuple[str, str]] = Counter()
    words: Counter[str] = Counter()
    for mods, org_pairs, org_words in features:
        n += 1
        modifiers.update(mods)
        pairs.update(org_pairs)
        words.update(org_words)
    cooccur: dict[str, dict[str, int]] = defaultdict(dict)
    for (a, b), count in pairs.items():
        if count >= min_orgs:
            cooccur[a][b] = count
    keep = lambda counts: {k: v for k, v in counts.most_common() if v >= min_orgs}
    return {"orgs": n, "modifiers": keep(modifiers), "cooccur": dict(cooccur), "words": keep(words)}


def evaluate(records: Iterable[tuple[str, list[str]]], folds: int = 5, names_per_org: int = 300, hidden_per_org: int = 20,
             ks: tuple[int, ...] = (100, 500, 2000), seed: int = 0) -> dict[str, dict[int, float]]:
    """Cross-validation: corpus statistics from the other folds' organisations, then leave-one-out on
    each held-out organisation (a random subset of its names, as a scan would find), with and without
    the corpus. Returns recall@k per variant, averaged over hidden hosts."""
    rng = random.Random(seed)
    records = list(records)
    rng.shuffle(records)
    features = [org_features(org, names) for org, names in records]  # once, not once per fold
    base = bundled_prior(corpus=False)
    hits = {"without corpus": Counter(), "with corpus": Counter()}
    total = 0
    for fold in range(folds):
        test = records[fold::folds]
        train = [f for i, f in enumerate(features) if i % folds != fold]
        priors = {"without corpus": base, "with corpus": Prior(base.words, Corpus.from_json(_tally(train)))}
        for org, names in test:
            sample = rng.sample(names, min(len(names), names_per_org))
            hosts = {n: [] for n in sample}
            for variant, prior in priors.items():
                ranks = leave_one_out(hosts, [org], hidden_per_org, prior)
                hits[variant].update(k for r in ranks.values() for k in ks if r and r <= k)
                if variant == "with corpus":
                    total += len(ranks)
        print(f"fold {fold + 1}/{folds}: {total} hidden hosts so far", file=sys.stderr, flush=True)
    return {variant: {k: counts[k] / max(total, 1) for k in ks} for variant, counts in hits.items()}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m easm.corpus", description=__doc__.split("\n\n")[0])
    p.add_argument("step", choices=["orgs", "fetch", "stats", "evaluate"])
    p.add_argument("-d", "--dir", type=Path, default=Path("corpus"), help="working directory (default: ./corpus)")
    p.add_argument("--count", type=int, default=2000, help="orgs: organisations to sample (default: 2000)")
    p.add_argument("--seed", type=int, default=0, help="orgs: random seed")
    p.add_argument("--exclude", action="append", default=[], help="stats/evaluate: leave out this domain's organisation (repeatable)")
    p.add_argument("--folds", type=int, default=5, help="evaluate: cross-validation folds (default: 5)")
    p.add_argument("--out", type=Path, help="stats: where to write (default: <dir>/corpus.json)")
    args = p.parse_args(argv)
    args.dir.mkdir(parents=True, exist_ok=True)
    if args.step == "orgs":
        sample_orgs(args.dir, args.count, args.seed)
    elif args.step == "fetch":
        fetch_names(args.dir)
    elif args.step == "evaluate":
        for variant, recall in evaluate(_records(args.dir, args.exclude), args.folds).items():
            print(f"{variant:15}", "  ".join(f"recall@{k}: {r:.0%}" for k, r in recall.items()))
    else:
        stats = build_stats(_records(args.dir, args.exclude))
        out = args.out or args.dir / "corpus.json"
        out.write_text(json.dumps(stats, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        print(f"{stats['orgs']} organisations -> {out} ({len(stats['modifiers'])} modifiers, {len(stats['words'])} words)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
