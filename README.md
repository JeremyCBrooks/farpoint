# farpoint: external attack surface mapping

farpoint maps what an organisation exposes to the internet, starting from nothing but its root domains.
It finds the organisation's **hostnames** and **IP addresses** in public data sources, resolves them,
and records who owns each address. Two optional stages go further. `--fingerprint` identifies what
each live host runs, and `--assess` ranks the weaknesses an attacker would look at first.

By default a scan is **passive**: every query goes to a third-party dataset or a DNS resolver, and
nothing is sent to the organisation's hosts. The options that send traffic elsewhere are opt-in and
are marked **not passive** below. Only use farpoint on domains you own or are authorised to assess.

## Quick start

You need Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                     # install
uv run farpoint example.com                 # passive scan; results in ./out/
```

Open `out/hosts.csv` for the hostnames found and `out/ips.csv` for their addresses. Running again
into the same folder adds to the inventory instead of replacing it.

Common next steps:

```bash
uv run farpoint -f domains.txt -o out/acme  # several domains, one per line, into their own folder
uv run farpoint example.com --guess --tenants --related   # find more names, tenants and domains (not passive)
uv run farpoint example.com --fingerprint --assess        # what each host runs, ranked findings (not passive)
uv run farpoint --assess -o out/acme        # re-assess an existing inventory without scanning
uv run farpoint --list-sources              # which data sources are usable on this machine
```

The ranked list is in `findings.csv`, and `technologies.csv` groups hosts by what they run.

API keys make several sources return much more. Put them in a `.env` file in the directory you run
from (see [Sources](#sources) for the names):

```bash
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
OTX_API_KEY=...
```

## Approach

- **Start from root domains and widen.** Hostnames come from many independent datasets: certificate
  logs, passive DNS, web archives and search engines of past scans. Optional phases widen further,
  to sister domains, SaaS tenants and names predicted from the organisation's naming habits.
- **Verify, and keep the evidence.** Every name is checked in DNS, and each records which sources
  reported it, so names several sources agree on stand out from one-off sightings.
- **Keep to scope.** Only names under the scan domains are kept and probed. Related domains, tenants
  and lookalikes are reported for you to review, never scanned.
- **Escalate contact one step at a time.** Passive datasets come first, then DNS lookups, then light
  probing of the organisation's own hosts. Each step beyond passive is a separate opt-in.
- **Use the lightest touch that answers the question.** Fingerprinting asks each service who it is
  the way any client would. It never logs in, guesses passwords or sends exploits.
- **Separate facts from judgments.** Discovery, enrichment and fingerprinting add facts to an
  inventory that builds up across scans. Assessment derives findings from those facts afresh each
  time, so findings always reflect the latest look.
- **Rank like an attacker.** Findings are ordered by what an attacker choosing a soft target would
  try first, such as exposed VPN appliances, admin panels and spoofable mail, not by CVSS score.
- **Never report unknown as absent.** When a check fails, its answer is recorded as unknown, never as
  a missing control.

## How a scan works

A scan runs these phases in order. Each phase works on what the earlier ones found.

| Phase | What it does | Who sees traffic | Enabled by |
|---|---|---|---|
| Discovery | Collects hostnames from certificate logs, passive DNS, archives and other datasets | The data sources | always |
| Related domains | Finds other registered domains the organisation owns | Registries, the domains found, Microsoft | `--related` |
| Resolution | Looks up every name's addresses and CNAMEs | Your DNS resolver | always (`--no-resolve` skips) |
| Tenants | Finds the organisation's accounts on SaaS and cloud platforms | The platforms' nameservers | `--tenants` |
| Guessing | Predicts unseen names from the naming patterns found and tests them in DNS | The domain's nameservers | `--guess` |
| Enrichment | Adds each address's owner, network, and Shodan's port and CVE history | RDAP registries, Shodan | always (`--no-enrich` skips) |
| Fingerprinting | Identifies what each live host runs, and each domain's mail and DNS posture | **The organisation's hosts** | `--fingerprint` |
| Assessment | Turns the inventory into ranked findings and matches versions to CVEs | NVD, CISA | `--assess` |

Results are then merged into the inventory in the output folder, and every output file is rewritten.

## Options

| Option | Meaning |
|---|---|
| `domains` | Root domains to map. A URL is accepted and reduced to its hostname. |
| `-f, --file FILE` | Read domains from a file, one per line. Lines starting with `#` are ignored. |
| `-o, --out DIR` | Output folder and inventory (default `./out`). |
| `--only LIST` | Run only these discovery sources, comma-separated. |
| `--exclude LIST` | Skip these discovery sources. `dnstwist` is the slowest (several minutes). |
| `--list-sources` | Show every source and whether it is usable here (key or binary present). |
| `--no-resolve` | Skip DNS resolution. Cannot be combined with `--guess`, `--tenants`, `--related` or `--fingerprint`. |
| `--no-enrich` | Skip the RDAP and Shodan InternetDB lookups for addresses. |
| `--nameserver IP` | DNS resolver to use instead of the system's. Repeat for several. |
| `--related` | Look for other domains the organisation owns. **Not passive.** |
| `--tenants` | Look for the organisation's tenants on SaaS and cloud platforms. **Not passive.** |
| `--tenant-budget N` | DNS lookups `--tenants` may make in total (default 800). |
| `--guess` | Predict unseen hostnames and test them in DNS. **Not passive.** |
| `--guess-budget N` | DNS lookups `--guess` may make per domain (default 2000). |
| `--guess-rate N` | At most N `--guess` lookups a second (default: no limit). |
| `--fingerprint` | Probe live hosts and check each domain's mail and DNS posture. **Not passive.** |
| `--ports LIST` | Ports `--fingerprint` checks. `22,443,8000-8010` replaces the defaults, `+8081` adds to them, `none` checks only 80 and 443. |
| `--paths LIST` | Paths `--fingerprint` requests on each web service, or `none` (default `/robots.txt,/.well-known/security.txt,/.git/HEAD`). |
| `--probe-rate N` | At most N `--fingerprint` connections a second across the scan (default 20). |
| `--no-legacy-tls` | Skip `--fingerprint`'s TLS 1.0 and 1.1 handshakes. |
| `--assess` | Rank findings and look up CVEs. With no domains, re-assesses the inventory in `--out` without scanning. |
| `--no-cve` | Assess without the NVD and CISA lookups. |
| `--timeout SECONDS` | HTTP timeout for data sources (default 60). |
| `--workers N` | Jobs run at once per source or phase (default 16). |
| `--no-progress` | No live progress display. |
| `-v, --verbose` | Log each result and retry as plain lines instead of the live display. |

## Discovery

Each source is queried once per domain. Only names equal to or under a scan domain are kept, and
each host records which sources reported it.

| Source | Kind | Key (environment variable) |
|---|---|---|
| crt.sh | Certificate transparency | none |
| CertSpotter | Certificate transparency | optional `CERTSPOTTER_API_KEY` |
| HackerTarget | Passive DNS | optional `HACKERTARGET_API_KEY` |
| Wayback Machine | Archived URLs | none |
| AlienVault OTX | Passive DNS | optional `OTX_API_KEY` (recommended: anonymous use is heavily rate-limited) |
| urlscan.io | Existing scans (never submits one) | optional `URLSCAN_API_KEY` |
| RapidDNS | Subdomain table | none |
| Shodan | Subdomains and records | required `SHODAN_API_KEY` |
| VirusTotal | Subdomain relations | required `VIRUSTOTAL_API_KEY` (free tier works) |
| subfinder | Passive subdomain tool | `subfinder` on PATH |
| bbot | Passive subdomain-enum preset | `bbot` on PATH (Linux, macOS, WSL) |
| dnstwist | Registered lookalike domains, DNS only | bundled |

Install the optional tools with `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
and `uv tool install bbot`. Keys are read from the environment or from `.env` in the current
directory; the environment wins. Sources without their key or binary are skipped and listed in the
summary.

Requests are throttled per service: VirusTotal to its free tier's 4 a minute, Shodan to 1 a second.
Transport errors, 5xx and 429 responses are retried with exponential backoff, honouring
`Retry-After`. A source that fails is recorded in `assets.json` with any pages it returned first,
and the scan continues.

Lookalike domains (typosquats and homoglyphs registered by anyone) go to `lookalikes.csv` and are
never scanned.

## Related domains (`--related`)

Finds other registered domains the organisation owns: brands, country domains, defensive
registrations. Two methods:

- **Microsoft 365.** The domains verified in the Microsoft 365 tenant each scan domain belongs to.
  Only an owner can verify a domain, so these are the organisation's. Subdomains of the scan domains
  it lists join the inventory with source `m365`.
- **Suffix swap.** Each scan domain's name under every other suffix in `src/farpoint/data/suffixes.txt`
  (all top-level domains plus common second levels such as `com.au`). Registered ones are tied to the
  organisation by evidence. One signal alone is at most `medium`, because nameservers, parking
  addresses and redirects can each be shared or faked:
  - `strong`: signals that agree, such as the organisation's own nameservers plus a shared mail host,
    address or redirect home, or the same nameservers plus a redirect home or the organisation's own
    mail host
  - `medium`: its own nameservers, a direct redirect home, or its own mail host
  - `weak`: the same nameservers at an outside provider, a shared address or generic mail host, or a
    redirect home through someone else's host

  Registered variants with no tie go to lookalikes.

Results go to `related.csv`, and the summary lists the strong and medium ones. **Related domains are
never scanned**: owning a domain doesn't mean you're authorised to scan it, so add the ones you are
to your domain list yourself. A domain looked at again and no longer tied leaves the list.

**Not passive:** about 1,800 lookups per scan domain go to the registries, 8 at a time. Each
registered variant gets a few DNS lookups and one HTTP request to see where it redirects, and
Microsoft gets one request per scan domain.

## Resolution

Every discovered name is looked up for A, AAAA and CNAME records. In-scope CNAME targets join the
inventory and are resolved too. `hosts.csv` shows `resolves` as yes, no, or blank when the lookup
timed out after a retry. A name with `resolves=no` but addresses listed is a historical record: it
was seen in passive DNS but no longer resolves.

## Tenants (`--tenants`)

Finds the organisation's accounts on other companies' platforms, such as `example.sharepoint.com` or
`example.my.salesforce.com`. Platforms are tried in this order:

1. tenant names the scan domains' TXT records give outright (`EXAMPLE123.onmicrosoft.com`)
2. platforms the domains' records say they use: verification strings and SPF includes. Here the
   organisation's common name modifiers are tried too (`example-dev`, `example-test`)
3. zones the organisation's CNAMEs point into, from this scan and earlier ones in `--out`
4. every platform in `src/farpoint/data/tenants.json`

Tenant names are built from each scan domain's first label. Each pattern is first checked with
three random names. On a platform that answers any name, a tenant counts only if it answers
differently. Where DNS can't tell, the name is kept as **unverified**, and only when the domain's own
records name the platform. A tenant's `tie` says what links it to the organisation: `records` (its
own TXT or SPF), `cname`, or `name` (a name match only, which may be another organisation).

A CNAME target outside the scan domains that carries the organisation's name is recorded as a
tenant too, with the organisation's hosts that point at it.

**Not passive:** the platforms' nameservers see the lookups, and the organisation's nameservers see
one TXT query per domain. Results go to `tenants.csv`.

## Guessing (`--guess`)

Finds names that public datasets missed by learning how the organisation names its hosts from
everything known: this scan, the inventory in `--out`, and CNAME targets such as
`portal-prod.azurewebsites.net`. It then tests names it hasn't seen:

- modifiers a name lacks, ranked by how often they appear together elsewhere (`api-dev` → `api-prod`)
- the other way of joining (`portaltest` → `portal-test`), dropping a modifier, nearby numbers
- prefixes the organisation reuses (`www.`), and names repeated across the scan domains
- popular standalone names (`files`, `sftp`, `vpn`) from `src/farpoint/data/subdomains.txt`
- with `--tenants`, the words in the organisation's verified tenant names (`example-mft.vendor.co` → `mft`)

The budget is spread over three rounds plus a small final round, so names found in one round have
their variants tried in the next. Every name tested is remembered in `assets.json`, and later scans
into the same `--out` skip it until 90 days have passed, so each scan goes further down the list.

Before guessing under a parent name, three random names there are looked up. If they resolve
(wildcard DNS), a guess counts only if it has an address or alias of its own. If they time out, no
guesses are made there. If most guesses under a parent resolve anyway, they are all discarded.
Skipped parents are listed in the errors in `assets.json`. Found names have source `guess`.

**Not passive:** the domain's authoritative nameservers see every guess, mostly for names that don't
exist. `--guess-rate` spreads them out; 2000 lookups at 5 a second take about 7 minutes.

To measure the guesser on an inventory without any DNS traffic:
`uv run python -m farpoint.guess out` hides each known host in turn and reports how often the rest
rank it within 100, 500 and 2000 guesses.

### Cross-organisation corpus (optional)

`farpoint.corpus` builds naming statistics from many organisations' certificates, to teach patterns one
organisation's names can't. When `src/farpoint/data/corpus.json` exists, `--guess` uses it. None is
bundled.

```bash
uv sync --group corpus
uv run python -m farpoint.corpus orgs  -d corpus --count 2000 # sample organisations (minutes)
uv run python -m farpoint.corpus fetch -d corpus              # fetch their names (hours; resumable)
uv run python -m farpoint.corpus evaluate -d corpus           # compare guessing with and without it
uv run python -m farpoint.corpus stats -d corpus --exclude example.com --out src/farpoint/data/corpus.json
```

Use `--exclude` for any organisation you will evaluate on, so its own names don't leak into the
statistics.

## Enrichment

Each public address is looked up in RDAP for its owner and network, and in Shodan's free
InternetDB for the ports, CVEs, hostnames and tags (such as `cdn`) Shodan has seen. Neither contacts
the address itself. In-scope hostnames InternetDB reports join the inventory.

## Fingerprinting (`--fingerprint`)

Identifies what each live host runs, with the lightest touch that answers the question. It only
contacts in-scope hosts that resolve now to a public address. It never contacts lookalikes, related
domains, tenants, private addresses, or addresses a name had in the past.

- **Ports.** One TCP connect per port per address. The default 43 ports cover remote access
  (22, 3389, 5900, 5985), databases (1433, 3306, 5432, 6379, 9200, 27017), mail, directory services,
  container APIs, and web and appliance ports (80, 443, 8443, 10443...). Ports Shodan has seen open
  on the address are added. Addresses that belong to a CDN or SaaS front end, such as Cloudflare,
  CloudFront, Azure Front Door or Shopify, only get 80 and 443, because the machine is the provider's.
- **Services.** Each open port is asked who it is in the ordinary way:
  - servers that speak first (SSH, FTP, MySQL, VNC) have their greeting read
  - mail ports get SMTP `EHLO` and `STARTTLS`, never `MAIL FROM`
  - TLS ports get a handshake for the certificate and version, plus two handshakes to see whether
    TLS 1.0 and 1.1 are still accepted
  - web services get `GET /` (following redirects within the service), the favicon (hashed the way
    Shodan does, to search for in Shodan) and the `--paths`
  - database and RDP ports get nothing past the connect

  Web ports are checked per hostname, since virtual hosts differ. Other services are checked once
  per address and recorded for each hostname on it.
- **Technologies.** The answers are matched against `src/farpoint/data/fingerprints.json`, which covers
  VPN and firewall appliances (FortiGate, GlobalProtect, NetScaler, BIG-IP, Cisco ASA, Ivanti,
  SonicWall, Check Point), remote access gateways, mail (Exchange with its build number), CDNs and
  WAFs, web servers, languages, CMSs (WordPress with plugin and theme versions), admin panels and
  hosting platforms. Each match carries a version and CPE where the answer gives one. Add a rule to
  that file to recognise more.
- **Domain posture**, for each scan domain:
  - mail: provider, SPF (its `all`, DNS lookups against the limit of 10, includes that don't exist or
    whose domain is unregistered), DMARC (`p`, `sp`, `pct`), DKIM keys under 32 common selectors with
    their sizes, MTA-STS, TLS-RPT and BIMI
  - mail servers under the organisation's own domains get one SMTP connection for their banner,
    STARTTLS and certificate. Hosted providers such as Microsoft 365 or Google are left alone
  - DNS: nameservers, a zone transfer (`AXFR`) request to each, DNSSEC, CAA and wildcard DNS
  - registration: registrar, creation and expiry dates, and transfer lock, from RDAP
- **Dangling DNS.** For each name that doesn't resolve, its CNAME and the CNAME's target are looked
  up. A target that doesn't exist on a platform where names can be claimed (Azure, Elastic
  Beanstalk), or under an unregistered domain, is a takeover risk. So is a live host serving a
  platform's "nothing configured here" page (`src/farpoint/data/takeover.json`). A target that doesn't
  exist anywhere else is reported as a broken record.

Connections are paced by `--probe-rate`, with at most 2 at a time to one address, and identify
themselves with the user agent `farpoint/0.1 (host fingerprinting)`. A scan of about 100 hosts makes a
few thousand connections over a few minutes. Results go to `fingerprints.csv`, `technologies.csv`
and `posture.csv`.

**Not passive:** the organisation's hosts see the connections, and a port sweep or `AXFR` request
may be logged as reconnaissance. Some DNS resolvers can't answer DNSSEC (DS) queries. DNSSEC then
shows as unknown, with an error suggesting `--nameserver 1.1.1.1`.

## Assessment (`--assess`)

Turns the inventory into `findings.csv`, ranked by how interesting each finding is to an attacker
choosing a soft target, not by CVSS. Assessment sends nothing to the organisation.

| Level | Examples |
|---|---|
| high | RDP, SMB, databases, Docker or Kubernetes APIs open to the internet; VPN and firewall appliances; Jenkins, GitLab, Grafana, Kibana, phpMyAdmin, Exchange; end-of-life software (PHP 7, IIS 8.5, Exchange 2016); versions with a CVE CISA lists as exploited, or scoring 9 or more; an exposed `.git`; expired certificates; subdomain takeovers; no SPF; DMARC missing or `p=none` without SPF `-all`; SPF includes on unregistered domains; zone transfers; a domain expiring within 30 days |
| medium | self-signed or mismatched certificates, TLS 1.0/1.1, plain HTTP with no HTTPS, directory listings, default server pages, Basic or NTLM login prompts, stack traces, dev/test/staging hosts on the internet, DMARC `pct` below 100 or `sp=none`, mail servers without STARTTLS, weak DKIM keys, SPF over 10 lookups |
| low | missing HSTS, wildcard certificates, internal names in certificates, broken CNAMEs, no DNSSEC, no CAA, no MTA-STS, no transfer lock, version-revealing headers, SSH open |

For each product version fingerprinting identified, assessment asks NVD which CVEs affect it and
checks them against CISA's Known Exploited Vulnerabilities catalogue. NVD answers are cached in
`assets.json` for a week. Without a key NVD allows about one request every 6 seconds, so set
`NVD_API_KEY` for large inventories.

Some matches are discounted:
- a version from a distribution package (`OpenSSH_8.9p1 Ubuntu`) is capped at medium unless the CVE
  is known to be exploited, since distributions backport fixes
- CVEs Shodan lists for a shared CDN or SaaS address are low, since they are the provider's to fix
- a check that failed (a DNS error, a mail server that never answered) is reported as unknown, never
  as a missing control

Findings are derived from the whole inventory each time, so they reflect the latest look at each
host. `first_seen` records when a finding was first reported. `technologies.csv` lists each product
and version with how many hosts run it, its end-of-life date and its CVE counts, edge devices first.

## Output (`--out`, default `./out`)

Each scan is **merged** into the inventory already in the folder. Scan domains one at a time, re-run
a source that failed, or re-scan regularly into the same folder. To start fresh, use a new folder.

| File | Contents |
|---|---|
| `hosts.txt`, `ips.txt` | Sorted plain lists, for piping into other tools |
| `hosts.csv` | hostname, resolves, ips, cnames, sources |
| `ips.csv` | ip, org, network, ports (Shodan's history), open_ports (found by fingerprinting), tags, vulns, hostnames, sources |
| `lookalikes.csv` | Registered lookalike domains and their addresses |
| `related.csv` | With `--related`: domain, the scan domain it relates to, tie, evidence |
| `tenants.csv` | With `--tenants`: tenant, vendor, domain, tie, verified, hosts pointing at it, evidence, ips, cnames |
| `fingerprints.csv` | With `--fingerprint`: one row per open host and port: service, technologies, status, title, server, redirect, signals, certificate, TLS versions, banner, favicon hash, paths |
| `technologies.csv` | With `--fingerprint`: each technology and version, host count, end-of-life date, CVE and known-exploited counts, hosts |
| `posture.csv` | With `--fingerprint`: one row per scan domain: mail provider, SPF, DMARC, DKIM, MTA-STS, mail server STARTTLS, nameservers, DNSSEC, CAA, AXFR, registration |
| `findings.csv` | With `--assess`: level, kind, target, detail, evidence |
| `assets.json` | The inventory: everything above in full, plus each scan's domains, errors and skipped sources |

Every row has `first_seen` and `last_seen` (UTC). `assets.json` is the source of truth, and the other
files are regenerated from it after every scan.

How rows merge:
- hosts, addresses and lookalikes are combined across scans. Their addresses, CNAMEs, sources,
  ports and CVEs are unioned, and `resolves` and the address owner take the latest answer
- fingerprints and posture describe the latest look. A host and port fingerprinted again replaces its
  old row. One that now refuses connections is removed. One that timed out or wasn't checked keeps
  its row and its old `last_seen`
- findings are re-derived from the whole inventory by each assessment
- if assessment fails, the scan is still saved and the error recorded

Writes are atomic. On Linux and macOS they are also locked, so two scans into one folder don't lose
each other's results; on Windows, don't run two at once. A scan refuses to start if the existing
`assets.json` can't be read. If it becomes unreadable during a scan, the scan is saved beside it as
`assets.unmerged-<time>.json`.

## Progress and stopping

In a terminal, farpoint shows a live line per source and domain with what it is doing (requesting,
waiting on a rate limit, retrying), then its result count or error. Counters follow for each later
phase. `-v` prints the same events as plain lines, which is also what happens when output isn't a
terminal. `--no-progress` turns the display off.

**Ctrl-C (or SIGTERM) stops the scan and saves what it has**, including pages already fetched by
sources still running, and marks the scan as interrupted. Press Ctrl-C again to quit without saving.
Progress is also saved every few seconds to a checkpoint file in the output folder, so after a hard
kill the next scan into the same folder merges it automatically.

## Scope and limits

- Only names equal to or under a scan domain are kept. CNAME targets outside them are recorded on the
  host but not followed.
- Fingerprinting covers the hosts found live in the current scan, not hosts known only from earlier
  scans in `--out`.
- Technology rules match what services reveal. Products that hide their name or version are missed.
  CVE matches are by version, so treat them as leads to confirm.
- Favicon hashes are recorded but not matched against known products.
- DKIM is checked under common selectors only, so "not found" can mean "uses another selector".

## Development

```bash
uv run pytest               # offline test suite
uv run pytest -m network    # smoke tests against real DNS, example.com and NVD
```

Code layout, in `src/farpoint/`:

| Module | Role |
|---|---|
| `cli.py` | Command line |
| `pipeline.py` | Runs the phases in order |
| `sources/` | One class per discovery source |
| `names.py`, `models.py` | Normalising and scoping names; the inventory |
| `resolve.py`, `enrich.py` | DNS resolution; RDAP and InternetDB |
| `related.py`, `tenants.py`, `guess.py` | The discovery opt-ins |
| `probe.py` | The only code that connects to the organisation's hosts |
| `fingerprint.py`, `posture.py` | What fingerprinting asks, and what the answers mean |
| `assess.py` | Findings, NVD and CISA lookups |
| `output.py` | Merging and writing the output files |

To add a discovery source, subclass `HttpSource` (retries included) or `CommandSource` (binary
checks included), yield `Observation`s, and register it in `sources/__init__.py`. Scoping,
normalisation and de-duplication happen centrally in the inventory.
