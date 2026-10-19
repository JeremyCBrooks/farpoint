# easm: passive external attack surface mapping

Give it your root domains and it returns the **hostnames** and **IP addresses** that public OSINT
sources associate with them. Each IP gets an owner/network (RDAP) and Shodan's pre-collected port
and CVE data. Registered **lookalike domains** are reported separately.

**Discovery only.** Nothing here scans, probes or sends traffic to your hosts or the lookalike
hosts. Every query goes to a third-party dataset (CT logs, passive DNS, archives) or to a recursive
DNS resolver. The one exception is opt-in: `--guess` (below) looks up predicted names, and those
lookups reach the domain's own nameservers.

## Quick start

```bash
uv run easm example.com example.org          # results in ./out/
uv run easm -f domains.txt -o out/acme -v    # one domain (or URL) per line, '#' comments ok
uv run easm --list-sources                   # what's usable on this machine
uv run easm example.com --only crtsh,certspotter --no-enrich
uv run easm example.com --exclude dnstwist   # dnstwist is the slowest source (several minutes)
uv run easm example.com --guess              # also predict unseen names and test them in DNS (not passive)
```

## Guessing unseen names (`--guess`)

Public datasets miss names that never got their own certificate (a wildcard cert covers them) and
that no passive-DNS sensor happened to see. `--guess` learns how the organisation names its hosts from
everything known (this run, the inventory already in `--out`, and the CNAME targets, which often carry
internal names like `portal-prod.azurewebsites.net`), then predicts and tests names it hasn't seen:

- modifiers a base name lacks, ranked by how often they appear together on the organisation's other
  names: `api-dev` → `api-prod`, `portal` + `portal-stage` → `kiosk-stage`
- the other way of joining (`portaltest` → `portal-test`), dropping a modifier, nearby numbers
- prefixes the organisation reuses (`www.`), names repeated across the input domains
- popular standalone names (`files`, `sftp`, `vpn`), from a cross-organisation ranking

Names found in one round teach the next (3 rounds). `--guess-budget N` caps the lookups per domain,
wildcard probes included (default 2000, a minute or two). Before testing names under a parent, three
random names there are looked up. If those resolve (wildcard DNS), a guess only counts if it has an
address or alias of its own. If they get no answer, no guesses are tested there. If most guesses under
a parent resolve anyway (a wildcard rotating addresses), they are all discarded. Skipped and discarded
parents are listed in `assets.json` errors. Found names are listed with source `guess`.

**Not passive:** the domain's authoritative nameservers see every guess, mostly for names that don't
exist. Only use it where that is acceptable.

Nothing in the model is specific to one organisation. Everything is learned from the names being
scanned, except a weak prior: `src/easm/data/subdomains.txt`, a popularity ranking of subdomain labels
from SecLists (MIT). Popular labels are tried as standalone names (`files`), and the most popular
1000 are also candidate modifiers, weighted by rank (`dev` #18 far above `uat` #685). To measure it on an
inventory without any DNS traffic, `uv run python -m easm.guess out` hides each known host in turn and
reports how often a model learned from the rest ranks it within 100/500/2000 guesses.

## Progress and stopping a scan

In a terminal, easm shows one live line per source and domain: a spinner while it runs, what it is
doing (requesting, waiting on a rate limit, `HTTP 502, retrying in 7s (2/5)`, names found so far
for subfinder/bbot), then `✓ N results` or `✗ failed: …`, followed by DNS/enrichment counters.
`-v` logs the same events as plain lines instead (also used when output is not a terminal);
`--no-progress` turns the display off.

**Ctrl-C (or SIGTERM) stops the scan and saves what it has**, including pages already fetched by
sources still running, and marks the run `interrupted` in the history; press Ctrl-C again to quit
without saving. While scanning, results are also checkpointed (every few seconds, as sources
finish) to `.checkpoint-<pid>.json`, so even a hard kill or closed terminal loses little: the next
run into the same `--out` merges it automatically. Re-running fills in whatever was missed.

## Output (`--out`, default `./out`)

Runs **accumulate**: each run is merged into the inventory already in the output directory, so you
can scan domains one at a time, re-run a source that failed, or re-scan weekly into the same folder.
Hosts, IPs and lookalikes are de-duplicated across runs and their IPs/CNAMEs/sources/ports/CVEs
unioned; `resolves` and IP owner take the latest run's answer when it has one. Every row carries
`first_seen`/`last_seen` (UTC), so `first_seen` = the latest `updated_at` means "new this run".
To start fresh, use a new `--out` or delete the directory.

| File | Contents |
|---|---|
| `hosts.txt` / `ips.txt` | Plain sorted lists, good for piping into other tools |
| `hosts.csv` | hostname, resolves (yes/no/blank = unchecked), ips, cnames, sources, first/last seen |
| `ips.csv` | ip, org, network, ports, vulns, hostnames, sources, first/last seen |
| `lookalikes.csv` | Registered typosquat/homoglyph domains and their IPs |
| `assets.json` | The inventory itself: everything above, plus `runs` (per-run domains, errors, skipped sources) |

`assets.json` is the source of truth; the other files are regenerated from it on every run. Writes
are atomic, and on Linux/macOS locked so concurrent runs into one folder don't lose results (on
Windows, don't run two scans into the same folder at once). A run refuses to start if the existing
`assets.json` can't be read; if it becomes unreadable mid-scan, the run is saved beside it as
`assets.unmerged-<time>.json` instead.

`resolves=no` with IPs listed means a **historical** record: the name was in CT/passive DNS but no
longer resolves. These are worth checking for dangling DNS. `sources` shows which datasets
corroborate each finding.

## Sources

| Source | Kind | Key (env var) |
|---|---|---|
| crt.sh | Certificate transparency | none |
| CertSpotter | Certificate transparency | optional `CERTSPOTTER_API_KEY` |
| HackerTarget | Passive DNS (host, ip) | optional `HACKERTARGET_API_KEY` |
| Wayback Machine | Archived URLs | none |
| AlienVault OTX | Passive DNS | optional `OTX_API_KEY` (strongly recommended: anonymous use is rate-limited hard) |
| urlscan.io | Existing scan search (never submits) | optional `URLSCAN_API_KEY` |
| RapidDNS | Subdomain/IP table | none |
| Shodan DNS | Subdomains + records | **required** `SHODAN_API_KEY` |
| VirusTotal | Subdomain relations | **required** `VIRUSTOTAL_API_KEY` (free tier) |
| subfinder | CLI, passive by design | binary on PATH |
| bbot | CLI, `-p subdomain-enum -rf passive` | binary on PATH (Linux/macOS/WSL) |
| dnstwist | Lookalike domains, DNS only (no `--mxcheck/--banners/--lsh/--phash`) | bundled |
| dnspython | A/AAAA/CNAME resolution of every discovered name | none |
| guess (opt-in) | Names predicted from the organisation's naming patterns, kept if they resolve | none |
| Shodan InternetDB | Ports/CVEs/hostnames per IP | none |
| RDAP (IANA bootstrap → RIR) | IP owner and network | none |

Keys are read from the environment or from a `.env` file in the current directory (shell wins).
Sources with no key or binary are skipped and listed in the summary. A source that errors or hits
a rate limit is recorded in `assets.json` (with any pages it returned first kept) and the rest of the run
continues. HTTP calls are throttled per service (VirusTotal is paced to the free tier's 4 requests/minute,
Shodan to 1/second) and retry transport errors, 5xx and 429 with exponential backoff and jitter
(honouring `Retry-After`). DNS timeouts are retried once; a name that still times out is left
blank in `resolves` rather than reported as `no`.

Optional tools: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`,
`uv tool install bbot`.

## Development

```bash
uv run pytest               # offline suite
uv run pytest -m network    # real-DNS smoke tests
uv run python -m easm.guess out --rank api-prod.example.com   # offline guesser evaluation
```

Layout: `names.py` (normalize/scope), `models.py` (Observation → Inventory), `sources/` (one class
per source behind the `Source` protocol: `available()` + `collect(domain)`), `resolve.py`,
`guess.py`, `enrich.py`, `pipeline.py`, `output.py`, `cli.py`.

To add a source, subclass `HttpSource` (you get retries) or `CommandSource` (you get availability
checks), yield `Observation`s, and register it in `sources/__init__.py`. Scoping, normalization and
de-duplication happen centrally in `Inventory`, so sources stay dumb.

## Scope and limits

- Only names equal to or under an input domain are kept. Third-party CNAME targets (CDNs, SaaS)
  are recorded on the host but not expanded.
- No wildcard-DNS detection outside `--guess`, and no ASN/netblock expansion yet. Those are good next steps toward
  commercial ASM parity, along with reverse-whois/org-name pivoting to discover unknown root
  domains, and diffing runs over time.
- Only use it on domains you own or are authorised to assess.
