"""Opt-in guessing: learn how an organisation names its hosts, then predict names no dataset has seen.

Learning and ranking are offline. Testing a guess is an ordinary DNS lookup through the recursive
resolver, but unlike the rest of easm, each guess reaches the domain's authoritative nameservers, which
can see (and log) a burst of queries for names that mostly don't exist.

Every known name is split into labels and each label into tokens (`portaltest` -> portal + test,
`app2-service-dev` -> app 2 -service -dev). A label's first token is its stem; later word tokens
are modifiers. Candidates for a domain come from:
  - modifiers a stem lacks, scored by how often they co-occur with the stem's own modifiers on other
    stems and how common they are in this organisation (api-dev -> api-prod, once some other name or
    CNAME target here uses 'prod')
  - joining a modifier the other way (portaltest -> portal-test), dropping one, nearby numbers
  - the organisation's tenants on other platforms, found by easm.tenants: their words besides its
    name (example-mft-traffic.vendor.co -> mft, mft-traffic), tried before anything else
  - prefixes reused over many names (www.), names repeated across the input domains
  - popular standalone names from a cross-organisation ranking, for hosts no pattern predicts
Each kind of evidence contributes its best score once; a candidate's rank is the sum.

Nothing here is specific to an organisation, and no list of words is hand-picked: the taxonomy is
learned from the names being scanned. The only outside data is a popularity ranking of subdomain
labels across many organisations, used as standalone guesses and as the dictionary that splits
run-together labels.

Measure it offline with `python -m easm.guess OUT_DIR`: each known host is hidden in turn and ranked
by a model learned from the others.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache, cached_property
from importlib import resources
from pathlib import Path

from easm.names import normalize_hostname

Token = tuple[str, str]  # (text, separator before it: "-" or "")
Label = tuple[Token, ...]
BARE = ""  # pseudo-modifier: the stem seen on its own (portal)

# Weight of each kind of evidence (tuned with leave-one-out runs on unrelated inventories).
W_COOC, W_POPULAR = 0.3, 0.3
W_FLIP, W_DROP, W_NUMBER, W_PREFIX, W_ACROSS = 0.3, 0.3, 0.25, 0.5, 0.8
W_WORD, WORD_SCALE = 0.15, 100  # the standalone word at rank r scores W_WORD / (1 + r / WORD_SCALE)
W_WEAK = 0.4  # variants of a name never seen with an address (often a source's junk) count for less
W_TENANT = 1.0  # names taken from the organisation's tenants on other platforms: real names, tried first
TENANT_NAMES = 10  # most guesses one tenant suggests
W_CORPUS, W_CORPUS_WORD = 0.05, 0.3 # cross-organisation evidence, when a corpus is available
CORPUS_SMOOTHING = 10  # a corpus share is n / (organisations + this): a modifier seen at 3 of 4 is no certainty
MODS_PER_STEM = 40
RETRY_DAYS = 90  # a guess that didn't exist is tried again after this long

_RUN_RE = re.compile(r"[a-z]+|[0-9]+|[^a-z0-9]+")
_WORD_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


@dataclass(frozen=True)
class GuessConfig:
    budget: int = 2000  # DNS lookups per input domain, over all rounds
    rounds: int = 3  # names found in one round teach the next; 0: no guessing
    follow_up: float = 0.1  # share of the budget kept for one more round, on what the last regular round found
    prior: Prior | None = None  # None: the bundled one
    known: Mapping[str, Sequence[str]] = field(default_factory=dict)  # earlier runs' hosts -> CNAMEs: learned from, never re-tested
    known_weak: frozenset[str] = frozenset()  # those of them never seen with an address
    tenants: Mapping[str, str] = field(default_factory=dict)  # earlier runs' verified tenants -> the scan domain each is named after
    tried: frozenset[str] = frozenset()  # guesses earlier runs tested lately: skipped, so each run goes deeper
    rate: float | None = None  # at most this many lookups a second (None: as fast as the workers go)


@dataclass(frozen=True)
class Corpus:
    """Naming statistics across many organisations, built by easm.corpus: how many organisations use
    each modifier, use two modifiers on one stem (BARE: the stem also exists alone), or have a
    standalone name."""

    orgs: int
    modifiers: Mapping[str, int]
    cooccur: Mapping[str, Mapping[str, int]]
    words: Mapping[str, int]

    @staticmethod
    def from_json(data: Mapping) -> Corpus:
        return Corpus(data["orgs"], data["modifiers"], data["cooccur"], data["words"])

    def follows(self, own: Iterable[str]) -> dict[str, tuple[float, str]]:
        """Modifiers organisations use on a stem that has `own`: mod -> (best share of organisations
        with one of `own` that also use it on the same stem, smoothed towards zero; which one)."""
        best: dict[str, tuple[float, str]] = {}
        for o in own:
            base = self.orgs if o == BARE else self.modifiers.get(o, 0)
            for mod, n in self.cooccur.get(o, {}).items() if base else ():
                if n / (base + CORPUS_SMOOTHING) > best.get(mod, (0.0, ""))[0]:
                    best[mod] = (n / (base + CORPUS_SMOOTHING), o)
        return best


@dataclass(frozen=True)
class Prior:
    """Naming habits shared across organisations: a popularity ranking of subdomain labels and,
    when built, a corpus of how organisations combine them."""

    words: Mapping[str, int]  # popular standalone label -> rank, 0 = most common
    corpus: Corpus | None = None

    @staticmethod
    def from_lines(lines: Iterable[str], corpus: Corpus | None = None) -> Prior:
        """`lines`: labels, most popular first."""
        ranked: dict[str, int] = {}
        for word in _clean(lines):
            ranked.setdefault(word, len(ranked))
        return Prior(ranked, corpus)

    @cached_property
    def dictionary(self) -> frozenset[str]:
        """Words a run-together label may end in (athenauat = athena + uat)."""
        corpus_mods = self.corpus.modifiers if self.corpus else {}
        return frozenset(w for w in [*self.words, *corpus_mods] if w.isalpha() and len(w) >= 2)


def _clean(lines: Iterable[str]) -> list[str]:
    words = (line.strip().lower() for line in lines)
    return [w for w in words if w and not w.startswith("#") and _WORD_RE.fullmatch(w)]


@cache
def bundled_prior(corpus: bool = True) -> Prior:
    data = resources.files("easm.data")
    built = data.joinpath("corpus.json")
    stats = Corpus.from_json(json.loads(built.read_text(encoding="utf-8"))) if corpus and built.is_file() else None
    return Prior.from_lines(data.joinpath("subdomains.txt").read_text(encoding="utf-8").splitlines(), stats)


def render(label: Label) -> str:
    return "".join(sep + text for text, sep in label)


@dataclass(frozen=True)
class _Name:
    root: str
    labels: tuple[Label, ...]  # left of the root, leftmost first
    weak: bool = False


class Taxonomy:
    """What a set of known hostnames says about how their organisation names hosts."""

    def __init__(
        self,
        hosts: Mapping[str, Iterable[str]],
        domains: Sequence[str],
        prior: Prior | None = None,
        weak: Iterable[str] = (),
        tenants: Mapping[str, str] | None = None,
    ) -> None:
        """`hosts` maps each known hostname to its CNAME targets, which often carry the organisation's
        internal names (portal.example.com -> portal-prod.azurewebsites.net). `weak` names have never had
        an address: they still teach the taxonomy, but their own variants are tried later. `tenants` maps
        the organisation's tenants on other platforms to the scan domain each is named after
        (example-mft-traffic.vendor.co -> example.com): their other words are likely host names."""
        self.prior = prior or bundled_prior()
        self.domains = list(domains)
        self.known = set(hosts)
        weak = set(weak)
        lefts = []
        for host in hosts:
            root = root_of(host, self.domains)
            labels = host[: -len(root) - 1].split(".") if root and host != root else []
            if labels and not any(label.startswith("_") for label in labels):  # skip _dmarc and other records
                lefts.append((root, labels, host in weak))
        runs = lambda label: re.findall("[a-z]+", label)
        self.words = {run for _, labels, _ in lefts for label in labels for run in runs(label)}
        self.words |= {d.split(".")[0] for d in self.domains}
        hyphenated = {run for _, labels, _ in lefts for label in labels for part in label.split("-")[1:] for run in runs(part)[:1]}
        self.modifier_vocab = hyphenated | self.prior.dictionary
        self.names = [_Name(root, tuple(self.tokenize(label) for label in labels), w) for root, labels, w in lefts]

        own = {text for name in self.names for label in name.labels for text, _ in label}
        self.tenant_words = {}  # tenant -> (domain, words before the organisation's name, new words after it)
        for t, d in (tenants or {}).items():
            before, after = tenant_words(t, d)
            if any(w not in own for w in after):  # example-dev teaches nothing its own names don't
                self.tenant_words[t] = (d, before, after)
        self.words |= {w for _, _, after in self.tenant_words.values() for w in after}
        evidence = [label for name in self.names for label in name.labels]
        evidence += [self.tokenize("-".join(after)) for _, _, after in self.tenant_words.values()]
        stems = {label[0][0] for label in evidence}
        for targets in hosts.values():
            for target in targets:
                label = self.tokenize(target.split(".")[0])
                if label[0][0] in stems:
                    evidence.append(label)
        self._learn(evidence)

    def tokenize(self, label: str) -> Label:
        tokens: list[Token] = []
        for i, part in enumerate(label.split("-")):
            sep = "-" if i else ""
            for run in _RUN_RE.findall(part):
                for piece in self._split(run) if run.isalpha() else [run]:
                    tokens.append((piece, sep))
                    sep = ""
        return tuple(tokens) or (("", ""),)

    def _split(self, run: str) -> list[str]:
        """portaltest -> [portal, test]: a known word followed by a modifier, longest word first. Both
        parts have at least three letters, or ordinary words split (testing -> test + ing)."""
        for i in range(len(run) - 3, 2, -1):
            if run[:i] in self.words and run[i:] in self.modifier_vocab:
                return [run[:i], run[i:]]
        return [run]

    def _learn(self, labels: Iterable[Label]) -> None:
        self.stem_mods: dict[str, set[str]] = defaultdict(set)
        self.seps: Counter[str] = Counter()
        self.stem_seps: dict[str, Counter[str]] = defaultdict(Counter)
        for label in labels:
            stem = label[0][0]
            mods = [(text, sep) for text, sep in label[1:] if not text.isdigit()]
            self.stem_mods[stem].update(text for text, _ in mods) if mods else self.stem_mods[stem].add(BARE)
            for _, sep in mods:
                self.seps[sep] += 1
                self.stem_seps[stem][sep] += 1
        self.mod_stems = Counter(m for mods in self.stem_mods.values() for m in mods)  # modifier -> stems using it
        self.cooc: dict[str, Counter[str]] = defaultdict(Counter)
        for mods in self.stem_mods.values():
            for a in mods:
                self.cooc[a].update(b for b in mods if b != a)
        self.n_modified = sum(1 for mods in self.stem_mods.values() if mods - {BARE}) or 1
        self._mod_cache: dict[str, list[tuple[str, float, str]]] = {}

    def modifier_scores(self, stem: str) -> list[tuple[str, float, str]]:
        """Modifiers `stem` has not been seen with, best first, each with why it scored as it did."""
        if stem not in self._mod_cache:
            own = self.stem_mods.get(stem, {BARE})
            follows = self.prior.corpus.follows(own) if self.prior.corpus else {}
            pool = (set(self.mod_stems) | set(follows)) - own - {BARE, stem}
            scored = []
            for mod in pool:
                cooc, via = max(((self.cooc[o][mod] / self.mod_stems[o], o) for o in own if self.mod_stems[o]), default=(0.0, ""))
                popular = self.mod_stems[mod] / self.n_modified
                share, after = follows.get(mod, (0.0, ""))
                score = W_COOC * cooc + W_POPULAR * popular + W_CORPUS * share
                seen = f"with '{via}'" if via else "that exist alone"
                why = [f"{self.cooc[via][mod]}/{self.mod_stems[via]} stems {seen} also have it"] if cooc else []
                why += [f"used by {self.mod_stems[mod]}/{self.n_modified} modified stems"] if popular else []
                if share:
                    corpus = self.prior.corpus
                    base = corpus.modifiers[after] if after != BARE else corpus.orgs
                    elsewhere = f"'{after}'" if after else "a stem that exists alone"
                    why.append(f"{corpus.cooccur[after][mod]} of {base} organisations with {elsewhere} use it on the same stem")
                scored.append((mod, score, "; ".join(why)))
            scored.sort(key=lambda ms: (-ms[1], ms[0]))
            self._mod_cache[stem] = scored[:MODS_PER_STEM]
        return self._mod_cache[stem]

    def sep_weights(self, stem: str) -> dict[str, float]:
        """How likely this stem (or else the organisation) joins a modifier with '-' versus directly."""
        counts = self.stem_seps.get(stem) or self.seps
        total = sum(counts.values())
        return {sep: (counts[sep] + 0.5) / (total + 1) for sep in ("-", "")}

    def candidates(self, domain: str) -> list[str]:
        """Unknown names under `domain`, most likely first."""
        return list(self._scored(domain, explain=False))

    def explain(self, domain: str) -> dict[str, dict[str, tuple[float, str]]]:
        """Unknown names under `domain`, most likely first, each with its best evidence of every kind:
        kind -> (score, why). A name's score is the sum over its kinds."""
        return self._scored(domain, explain=True)

    def _scored(self, domain: str, explain: bool) -> dict[str, dict[str, tuple[float, str]]]:
        scores: dict[str, dict[str, tuple[float, str]]] = defaultdict(dict)

        def add(labels: Sequence[Label], kind: str, score: float, why: str) -> None:
            name = normalize_hostname(".".join([*(render(label) for label in labels), domain]))
            if name and name not in self.known and root_of(name, self.domains) == domain:
                if score > scores[name].get(kind, (0.0, ""))[0]:
                    scores[name][kind] = (score, why)

        for name in self.names:
            if name.root == domain:
                weight, note = (W_WEAK, " (never seen with an address)") if name.weak else (1.0, "")
                source = f"{_render_name(name)}{note}"
                self._variants(name, lambda labels, kind, score, why: add(labels, kind, score * weight, f"from {source}: {why}"))
        self._from_tenants(domain, add)
        self._prefixes(domain, add)
        self._across(domain, add)
        for word, rank in self.prior.words.items():  # most of the candidates: explained only on request
            add([((word, ""),)], "word", W_WORD / (1 + rank / WORD_SCALE), f"#{rank + 1} most popular subdomain name" if explain else "")
        corpus = self.prior.corpus
        for word, n in corpus.words.items() if corpus else ():
            why = f"standalone name at {n}/{corpus.orgs} organisations" if explain else ""
            add([((word, ""),)], "corpus-word", W_CORPUS_WORD * n / corpus.orgs, why)
        totals = {name: sum(score for score, _ in kinds.values()) for name, kinds in scores.items()}
        return {name: scores[name] for name in sorted(totals, key=lambda name: (-totals[name], name))}

    def _variants(self, name: _Name, add: Callable[[Sequence[Label], str, float, str], None]) -> None:
        first, parent = name.labels[0], name.labels[1:]
        stem = first[0][0]
        mod_at = [i for i, (text, _) in enumerate(first) if i and not text.isdigit()]
        seps = self.sep_weights(stem)
        for mod, score, why in self.modifier_scores(stem):
            if mod_at:  # swap the last modifier: api-dev -> api-prod
                i = mod_at[-1]
                add([first[:i] + ((mod, first[i][1]),) + first[i + 1 :], *parent], "modifier", score, f"swap '{first[i][0]}' for '{mod}' ({why})")
            else:  # attach one: portal -> portal-test, portaltest
                for sep, weight in seps.items():
                    joined = f"'{sep}'" if sep else "nothing"
                    add([first + ((mod, sep),), *parent], "modifier", score * weight, f"add '{mod}' joined by {joined} ({why})")
        for i in mod_at:
            flipped = "" if first[i][1] else "-"
            joined = "'-'" if flipped else "nothing"
            add([first[:i] + ((first[i][0], flipped),) + first[i + 1 :], *parent], "flip", W_FLIP * seps[flipped], f"join '{first[i][0]}' by {joined} instead")
        if mod_at:
            i = mod_at[-1]
            add([first[:i] + first[i + 1 :], *parent], "drop", W_DROP, f"drop '{first[i][0]}'")
        for i, (text, sep) in enumerate(first):
            if text.isdigit() and len(text) <= 3:
                n = int(text)
                for k in sorted({n - 1, n + 1, n + 2, 1, 2} - {n}):
                    if k >= 0:
                        number = str(k).zfill(len(text)) if text.startswith("0") else str(k)  # app07 -> app08, app10 -> app9
                        add([first[:i] + ((number, sep),) + first[i + 1 :], *parent], "number", W_NUMBER, f"number {text} -> {number}")

    def _from_tenants(self, domain: str, add: Callable[[Sequence[Label], str, float, str], None]) -> None:
        """A tenant's words besides the organisation's name, as names under the domain it is named after:
        example-mft-traffic -> mft-traffic, mft, traffic; uat-example-mft -> also uat-mft, mft-uat."""
        for tenant, (named_after, before, after) in self.tenant_words.items():
            if named_after == domain:
                names = ["-".join(after), *after, *(n for p in before for n in (f"{p}-{after[0]}", f"{after[0]}-{p}"))]
                for i, name in enumerate(list(dict.fromkeys(names))[:TENANT_NAMES]):
                    add([self.tokenize(name)], "tenant", W_TENANT * (1 - i / 100), f"from tenant {tenant}")

    def _prefixes(self, domain: str, add: Callable[[Sequence[Label], str, float, str], None]) -> None:
        """A leftmost label seen over several parents (www.) is tried over the others."""
        parents: dict[Label, set[tuple[str, tuple[Label, ...]]]] = defaultdict(set)
        for name in self.names:
            if len(name.labels) > 1:
                parents[name.labels[0]].add((name.root, name.labels[1:]))
        here = [name for name in self.names if name.root == domain]
        for prefix, seen in parents.items():
            if len(seen) < 2:
                continue
            share = min(1.0, len(seen) / max(len(here), 1))
            for name in here:
                if name.labels[0] != prefix and (domain, name.labels) not in seen:
                    add([prefix, *name.labels], "prefix", W_PREFIX * share, f"'{render(prefix)}.' is on {len(seen)} other names")

    def _across(self, domain: str, add: Callable[[Sequence[Label], str, float, str], None]) -> None:
        """Names under another input domain, weighted by how many of its names this one already has."""
        by_root: dict[str, set[tuple[Label, ...]]] = defaultdict(set)
        for name in self.names:
            by_root[name.root].add(name.labels)
        here = by_root.get(domain, set())
        for root, lefts in by_root.items():
            if root != domain and lefts:
                share = len(lefts & here) / len(lefts)
                for labels in lefts - here:
                    why = f"exists under {root}, {len(lefts & here)}/{len(lefts)} of whose names also exist here"
                    add(labels, "across", W_ACROSS * share, why)


def tenant_words(tenant: str, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The words of a tenant's first label before and after the organisation's name (the domain's first
    label): uat-example-mft-traffic -> (uat,), (mft, traffic). Nothing if the name isn't in it."""
    org, parts = domain.split(".")[0], tenant.split(".")[0].split("-")
    for i, part in enumerate(parts):
        if part.startswith(org):
            after = ([part[len(org) :]] if part != org else []) + parts[i + 1 :]
            words = lambda ps: tuple(p for p in ps if p.isalpha() and len(p) > 1)
            return words(parts[:i]), words(after)
    return (), ()


def _render_name(name: _Name) -> str:
    return ".".join([*(render(label) for label in name.labels), name.root])


def root_of(hostname: str, domains: Sequence[str]) -> str | None:
    """The most specific input domain `hostname` is equal to or under."""
    matches = [d for d in domains if hostname == d or hostname.endswith("." + d)]
    return max(matches, key=len, default=None)


def parent_of(hostname: str) -> str:
    return hostname.partition(".")[2]


def leave_one_out(
    hosts: Mapping[str, Iterable[str]],
    domains: Sequence[str],
    sample: int = 300,
    prior: Prior | None = None,
    weak: Iterable[str] = (),
) -> dict[str, int | None]:
    """Hide each known host in turn and return its rank among candidates learned from the rest (None: not generated)."""
    targets = sorted(h for h in hosts if h not in domains and root_of(h, domains) and not h.startswith("_"))
    if len(targets) > sample:
        targets = sorted(random.Random(0).sample(targets, sample))
    ranks: dict[str, int | None] = {}
    for host in targets:
        rest = {h: [c for c in cnames if c != host] for h, cnames in hosts.items() if h != host}  # hidden as a CNAME target too
        ranked = Taxonomy(rest, domains, prior, weak).candidates(root_of(host, domains))
        ranks[host] = ranked.index(host) + 1 if host in ranked else None
    return ranks


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m easm.guess", description="Offline evaluation of easm's guesser on an inventory.")
    p.add_argument("out", type=Path, help="an easm output directory (reads its assets.json)")
    p.add_argument("--k", default="100,500,2000", help="budgets to report recall at (default: 100,500,2000)")
    p.add_argument("--sample", type=int, default=300, help="hide at most this many hosts (default: 300)")
    p.add_argument("--rank", action="append", default=[], help="also report where this hostname ranks (repeatable)")
    p.add_argument("--show", type=int, default=0, help="print the top N candidates per domain")
    p.add_argument("--no-corpus", action="store_true", help="ignore the cross-organisation corpus, for comparison")
    p.add_argument("-v", "--verbose", action="store_true", help="print every hidden host's rank")
    args = p.parse_args(argv)
    prior = bundled_prior(corpus=not args.no_corpus)

    report = json.loads((args.out / "assets.json").read_text(encoding="utf-8"))
    hosts = {h["hostname"]: h.get("cnames", []) for h in report["hosts"]}
    domains = report["domains"]
    weak = {h["hostname"] for h in report["hosts"] if not h.get("ips")}
    model = Taxonomy(hosts, domains, prior, weak)
    for name in args.rank:
        ranked = model.explain(root_of(name, domains) or "")
        order = list(ranked)
        print(f"rank {name}: {order.index(name) + 1 if name in ranked else 'not generated'} of {len(order)}")
        for kind, (score, why) in sorted(ranked.get(name, {}).items(), key=lambda kv: -kv[1][0]):
            print(f"  {kind:<8} {score:.3f}  {why}")
    for domain in domains if args.show else []:
        print(f"top {args.show} for {domain}:", *model.candidates(domain)[: args.show], sep="\n  ")

    ranks = leave_one_out(hosts, domains, args.sample, prior, weak)
    if args.verbose:
        for host, rank in sorted(ranks.items(), key=lambda hr: (hr[1] is None, hr[1] or 0, hr[0])):
            print(f"  {rank if rank else '-':>6}  {host}")
    print(f"leave-one-out over {len(ranks)} hosts:")
    for k in (int(k) for k in args.k.split(",")):
        hits = sum(1 for r in ranks.values() if r and r <= k)
        print(f"  recall@{k}: {hits}/{len(ranks)} = {hits / max(len(ranks), 1):.0%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
