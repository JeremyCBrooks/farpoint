# farpoint: external attack surface mapping

farpoint maps what an organisation exposes to the internet, starting from nothing but its root domains.
It finds the organisation's **hostnames** and **IP addresses** in public data sources, resolves them,
and records who owns each address. Two optional stages go further. `--fingerprint` identifies what
each live host runs, and `--assess` ranks the weaknesses an attacker would look at first.

By default a scan is **passive**: every query goes to a third-party dataset or a DNS resolver, and
nothing is sent to the organisation's hosts. The options that send traffic elsewhere are opt-in and
are marked **not passive** below. Only use farpoint on domains you own or are authorised to assess.

## Quick start

You need Python 3.11+ and [uv](https://docs.astral.sh/uv/), or Docker (see [Docker](#docker)).

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
from (see [Discovery](#discovery) for the names):

```bash
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
OTX_API_KEY=...
```

## How it works

farpoint collects hostnames from many independent public datasets, checks each in live DNS, and keeps
a record of which sources reported it. Optional stages then widen the search, to sister domains, SaaS
tenants and names predicted from the organisation's own naming habits. Further optional stages
fingerprint what is live and rank what an attacker would try first. Each stage that makes more contact
than the one before is a separate opt-in. Only names under the scan domains are ever probed: related
domains, tenants and lookalikes are reported for you to review. Findings are worked out afresh from the
whole inventory on every assessment. A check that fails is recorded as unknown, never as a missing
control.

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
[ARCHITECTURE.md](ARCHITECTURE.md) has the methodology behind each phase and a system diagram.

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
| `--related-rate N` | Start at most N `--related` lookups a second (default: no limit). Needs `--related`. |
| `--tenants` | Look for the organisation's tenants on SaaS and cloud platforms. **Not passive.** |
| `--tenant-budget N` | DNS lookups `--tenants` may make in total (default 800). |
| `--guess` | Predict unseen hostnames and test them in DNS. **Not passive.** |
| `--guess-budget N` | DNS lookups `--guess` may make per domain (default 2000). |
| `--guess-rate N` | At most N `--guess` lookups a second (default: no limit). Needs `--guess`. |
| `--fingerprint` | Probe live hosts and check each domain's mail and DNS posture. **Not passive.** |
| `--ports LIST` | Ports `--fingerprint` checks. `22,443,8000-8010` replaces the defaults, `+8081` adds to them, `none` checks only 80 and 443. |
| `--paths LIST` | Paths `--fingerprint` requests on each web service, or `none` (default `/robots.txt,/.well-known/security.txt`). |
| `--probe-rate N` | At most N `--fingerprint` connections a second across the scan (default 20). |
| `--no-legacy-tls` | Skip `--fingerprint`'s TLS 1.0 and 1.1 handshakes. |
| `--no-axfr` | Skip `--fingerprint`'s zone-transfer (`AXFR`) requests. |
| `--engagement ID` | With `--fingerprint`, add an engagement ID (a ticket or client code: up to 64 letters, digits, spaces and `.-_:@+/=`, not starting or ending with a space) to the user agent of its requests, so the organisation can tell who is probing. The passive sources and `--related` don't send it. Plain-HTTP probes send it unencrypted. |
| `--assess` | Rank findings and look up CVEs. With no domains, re-assesses the inventory in `--out` without scanning. |
| `--no-cve` | Assess without the NVD and CISA lookups. |
| `--timeout SECONDS` | HTTP timeout for data sources (default 60). |
| `--workers N` | Jobs run at once per source or phase (default 16). |
| `--no-progress` | No live progress display. |
| `-v, --verbose` | Log each result and retry as plain lines instead of the live display. |

## Discovery

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
| bbot | Passive subdomain-enum preset | `bbot` on PATH (Linux, macOS, WSL), or the [Docker](#docker) image |
| dnstwist | Registered lookalike domains, DNS only | bundled |

Install the optional tools with `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
and `uv tool install bbot`. Keys are read from the environment or from `.env` in the current
directory; the environment wins. Sources without their key or binary are skipped and listed in the
summary, as is a tool that can't start here, such as a binary built for Alpine on a glibc system. A
source that fails is recorded in `assets.json` with any pages it returned first, and the scan
continues. A bbot run that prints no events, which is what bbot does when it can't set up its
modules, counts as failed, not as finding nothing.

Lookalike domains (typosquats and homoglyphs registered by anyone) go to `lookalikes.csv` and are
never scanned.

## Related domains (`--related`)

Finds other registered domains the organisation owns, such as brands, country domains and defensive
registrations. They come from the scan domains' Microsoft 365 tenant, and from the scan domains' names
under every other suffix (`example.de`, `example.com.au`). Each is given a `tie` of `strong`, `medium`
or `weak` by the evidence linking it to the organisation. Registered variants with no tie go to
lookalikes.

Results go to `related.csv`, and the summary lists the strong and medium ones. **Related domains are
never scanned**: owning a domain doesn't mean you're authorised to scan it, so add the ones you are
to your domain list yourself.

**Not passive:** about 1,800 lookups per scan domain go to the registries, 8 at a time (fewer with
`--workers`). Each registered variant gets a few DNS lookups and one HTTP request to see where it
redirects, and Microsoft gets one request per scan domain. `--related-rate` spreads all of these
lookups out: at 10 a second, one domain takes about 3 minutes. A lookup can be more than one packet
(a DNS lookup that times out is retried, and a redirect check follows each hop), so the network sees
a little more. Unpaced, a burst of this size can overwhelm a small NAT or home router.

## Resolution

`hosts.csv` shows `resolves` as yes, no, or blank when the lookup timed out after a retry. A name with
`resolves=no` but addresses listed is a historical record: it was seen in passive DNS but no longer
resolves.

## Tenants (`--tenants`)

Finds the organisation's accounts on other companies' platforms, such as `example.sharepoint.com` or
`example.my.salesforce.com`. Platforms the organisation's own DNS records point to are tried first,
then a bundled table of common ones. Platforms that answer any name are allowed for.

In `tenants.csv`, a tenant's `tie` says what links it to the organisation: `records` (its own TXT or
SPF), `cname` (its hosts point there), or `name` (a name match only, which may be another
organisation). `verified=no` means the platform answers any name, so DNS can't confirm the tenant
exists.

**Not passive:** the platforms' nameservers see the lookups, and the organisation's nameservers see
one TXT query per domain.

## Guessing (`--guess`)

Finds names that public datasets missed by learning how the organisation names its hosts
(`api-dev` → `api-prod`, `portaltest` → `portal-test`) and testing names it hasn't seen in DNS. It
learns from this scan, the inventory in `--out` and, with `--tenants`, the organisation's tenant
names. Every name tested is remembered, and later scans into the same `--out` skip it for 90 days, so
each scan goes further down the list. Found names have source `guess`. Parents skipped because of
wildcard DNS are listed in the errors in `assets.json`.

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

## Fingerprinting (`--fingerprint`)

Identifies what each live host runs. It only contacts in-scope hosts that resolve now to a public
address. It never contacts lookalikes, related domains, tenants, private addresses, or addresses a name
had in the past. It never logs in, guesses passwords or sends exploits.

- **Ports**: 43 by default, covering remote access, databases, mail, directory services, container
  APIs, and web and appliance ports. Addresses belonging to a CDN or SaaS front end only get 80 and 443.
- **Services**: each open port is asked who it is the ordinary way: its greeting, a TLS handshake,
  `GET /`, the favicon and the `--paths`. Mail ports get `EHLO` and `STARTTLS`, never `MAIL FROM`.
- **Technologies**: the answers are matched against `src/farpoint/data/fingerprints.json`, which covers
  VPN and firewall appliances (FortiGate, GlobalProtect, NetScaler, BIG-IP, Cisco ASA, Ivanti,
  SonicWall, Check Point), remote access gateways, mail (Exchange with its build number), CDNs and
  WAFs, web servers, languages, CMSs (WordPress with plugin and theme versions), admin panels and
  hosting platforms. Add a rule to that file to recognise more.
- **Domain posture**, per scan domain: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, the STARTTLS of mail
  servers the organisation runs itself, nameservers, zone transfers, DNSSEC, CAA and registration.
  A zone transfer isn't requested from managed DNS services whose customers can't open one to the
  internet (Route 53, Azure DNS, Google Cloud DNS and others in `src/farpoint/data/dns_providers.json`).
  Every other nameserver is asked, including Cloudflare's, since some services let customers allow
  transfers to whole address ranges. In `posture.csv`, `axfr` lists the nameservers that handed over the zone, `no` if
  none did, and is blank when it's unknown: none was asked (`--no-axfr`, or only such services) or one
  didn't answer. A scan that gets no answer keeps the last one while the nameservers stay the same.
- **Dangling DNS**: CNAMEs pointing at names that don't exist, flagged as takeover risks where the
  name could be claimed.

Connections are paced by `--probe-rate` and identify themselves with the user agent
`farpoint/0.1 (host fingerprinting)`, or `farpoint/0.1 (host fingerprinting; engagement ID)` with
`--engagement`. A scan of about 100 hosts makes a few thousand connections over a
few minutes. Results go to `fingerprints.csv`, `technologies.csv` and `posture.csv`.

**Not passive:** the organisation's hosts see the connections, and a port sweep or `AXFR` request
may be logged as reconnaissance (`--ports none` and `--no-axfr` drop both). Some DNS resolvers can't answer DNSSEC (DS) queries. DNSSEC then
shows as unknown, with an error suggesting `--nameserver 1.1.1.1`.

## Assessment (`--assess`)

Turns the inventory into `findings.csv`, ranked by how interesting each finding is to an attacker
choosing a soft target, not by CVSS. Assessment sends nothing to the organisation.

| Level | Examples |
|---|---|
| high | RDP, SMB, databases, Docker or Kubernetes APIs open to the internet; VPN and firewall appliances; Jenkins, GitLab, Grafana, Kibana, phpMyAdmin, Exchange; end-of-life software (PHP 7, IIS 8.5, Exchange 2016); versions with a CVE CISA lists as exploited, or scoring 9 or more; an exposed `.git`; expired certificates; subdomain takeovers; no SPF; DMARC missing or `p=none` without SPF `-all`; SPF includes on unregistered domains; zone transfers; a domain expiring within 30 days |
| medium | self-signed or mismatched certificates, TLS 1.0/1.1, plain HTTP with no HTTPS, directory listings, default server pages, Basic or NTLM login prompts, stack traces, dev/test/staging hosts on the internet, DMARC `pct` below 100 or `sp=none`, mail servers without STARTTLS, weak DKIM keys, SPF over 10 lookups |
| low | missing HSTS, wildcard certificates, internal names in certificates, broken CNAMEs, no DNSSEC, no CAA, no MTA-STS, no transfer lock, version-revealing headers, SSH open |

Each product version fingerprinting identified is checked against NVD for CVEs and against CISA's
Known Exploited Vulnerabilities catalogue. NVD answers are cached in `assets.json` for a week. Without
a key NVD allows about one request every 6 seconds, so set `NVD_API_KEY` for large inventories.
Distribution package versions and CVEs on shared CDN addresses are discounted.

`first_seen` records when a finding was first reported. `technologies.csv` lists each product and
version with how many hosts run it, its end-of-life date and its CVE counts, edge devices first.

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
files are regenerated from it after every scan. Discovered facts accumulate across scans, while
fingerprints, posture and findings describe the latest look (see
[ARCHITECTURE.md](ARCHITECTURE.md#9-merge-and-output) for the exact rules).

Writes are atomic and locked, so two scans into one folder don't lose each other's results. A scan refuses to start if the existing
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

## Docker

The image bundles farpoint with every discovery source, subfinder and bbot included, so it is also
the way to run bbot on Windows. It reads `.env` and writes `./out` in the current directory:

```bash
mkdir -p out                                # first: Docker would create it owned by root
docker compose run --rm farpoint example.com --fingerprint --assess
docker compose run --rm farpoint --list-sources
```

Without compose, build and run it directly:

```bash
docker build -t farpoint .                  # --target slim: no subfinder or bbot, about 350 MB instead of 1.4 GB
docker run --rm -it --init --env-file .env -v "$PWD/out:/work/out" farpoint example.com
```

- **`--init`** (compose sets `init: true`) lets Ctrl-C stop subfinder and bbot. `docker stop` saves
  results like Ctrl-C does.
- **The scan runs as uid 1000.** On a Linux host where your uid differs, make `out` writable by
  uid 1000.
- **subfinder and bbot keys** are in their own config, not `.env`. Mount
  `~/.config/subfinder/provider-config.yaml` and `~/.config/bbot/secrets.yml` under `/home/scan/`
  (commented out in `compose.yaml`).
- **DNS is slower in a container**, because Docker bypasses the host's caching resolver. That slows
  `--guess`, `--tenants` and `--related`. On Linux, use `--network host` (`network_mode: host`), or
  point `--nameserver` at a fast resolver.
- **IPv6** addresses show as unreachable unless the Docker network has IPv6 enabled.
- `docker build --target test .` builds an image that runs the offline test suite.

## Development

```bash
uv run pytest               # offline test suite
uv run pytest -m network    # smoke tests against real DNS, example.com and NVD
```

[ARCHITECTURE.md](ARCHITECTURE.md) covers the code layout, the methodology of each stage, a system
diagram, and how to add sources, technology rules, tenant platforms and findings.
