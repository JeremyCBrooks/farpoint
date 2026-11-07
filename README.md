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
than the one before is a separate opt-in.

Only names under the scan domains are ever probed. Related domains, tenants and lookalikes are
reported for you to review, never scanned. Findings are worked out afresh from the whole inventory on
every assessment, and a check that fails is recorded as unknown, never as a missing control.

A scan runs these phases in order. Each phase works on what the earlier ones found.

| Phase | What it does | Who sees traffic | Enabled by |
|---|---|---|---|
| Discovery | Collects hostnames from certificate logs, passive DNS, archives and other datasets | The data sources | always |
| Related domains | Finds other registered domains the organisation owns | Registries, the domains found, Microsoft | `--related` |
| Resolution | Looks up every name's addresses and CNAMEs | Your DNS resolver | always (`--no-resolve` skips) |
| Tenants | Finds the organisation's accounts on SaaS and cloud platforms, and how each domain signs in to Microsoft | The platforms' nameservers, Microsoft | `--tenants` |
| Guessing | Predicts unseen names from the naming patterns found and tests them in DNS | The domain's nameservers | `--guess` |
| Enrichment | Adds each address's owner, network, and Shodan's port and CVE history; dates the lookalikes that could be used for phishing | RDAP registries, Shodan, crt.sh | always (`--no-enrich` skips) |
| Fingerprinting | Identifies what each live host runs, and each domain's mail and DNS posture | **The organisation's hosts** | `--fingerprint` |
| Assessment | Turns the inventory into ranked findings and matches versions to CVEs | NVD, CISA | `--assess` |

Credential evidence (`--credentials`) is collected from its providers before the scan starts. Results
are then merged into the inventory in the output folder, and every output file is rewritten.
[ARCHITECTURE.md](ARCHITECTURE.md) has the methodology behind each phase and a system diagram.

## Options

| Option | Meaning |
|---|---|
| `domains` | Root domains to map. A URL is accepted and reduced to its hostname. |
| `-f, --file FILE` | Read domains from a file, one per line. Lines starting with `#` are ignored. |
| `-o, --out DIR` | Output folder and inventory (default `./out`). |
| `--only LIST` | Run only these discovery sources, comma-separated, by the names in the [Discovery](#discovery) table. |
| `--exclude LIST` | Skip these discovery sources. `dnstwist` is the slowest (several minutes). |
| `--list-sources` | Show every source and whether it is usable here (key or binary present). |
| `--no-resolve` | Skip DNS resolution. Cannot be combined with `--guess`, `--tenants`, `--related` or `--fingerprint`. |
| `--no-enrich` | Skip the RDAP and Shodan InternetDB lookups for addresses, and the registration and certificate lookups for lookalikes. |
| `--nameserver IP` | DNS resolver to use instead of the system's, dnstwist included. Repeat for several. |
| `--related` | Look for other domains the organisation owns. **Not passive.** |
| `--related-rate N` | Start at most N `--related` lookups a second (default: no limit). Needs `--related`. |
| `--tenants` | Look for the organisation's tenants on SaaS and cloud platforms, and ask Microsoft how each domain signs in. **Not passive.** |
| `--tenant-budget N` | DNS lookups `--tenants` may make in total (default 800). |
| `--guess` | Predict unseen hostnames and test them in DNS. **Not passive.** |
| `--guess-budget N` | DNS lookups `--guess` may make per domain (default 2000). |
| `--guess-rate N` | At most N `--guess` lookups a second (default: no limit). Needs `--guess`. |
| `--fingerprint` | Probe live hosts and check each domain's mail and DNS posture. **Not passive.** |
| `--ports LIST` | Ports `--fingerprint` checks. `22,443,8000-8010` replaces the defaults, `+8081` adds to them, `none` checks only 80 and 443. |
| `--paths LIST` | Paths `--fingerprint` requests on each web service, or `none` (default `/robots.txt,/.well-known/security.txt`). |
| `--probe-rate N` | Start at most N `--fingerprint` port checks and service checks a second across the scan (default 20). A service check makes several connections. |
| `--no-legacy-tls` | Skip `--fingerprint`'s TLS 1.0 and 1.1 handshakes. |
| `--no-axfr` | Skip `--fingerprint`'s zone-transfer (`AXFR`) requests. |
| `--no-archive` | Don't look up archived copies (Wayback Machine) of the web services a bot defence hid from `--fingerprint`. |
| `--engagement ID` | With `--fingerprint`, add an engagement ID (a ticket or client code: up to 64 letters, digits, spaces and `.-_:@+/=`, not starting or ending with a space) to the user agent of its requests, so the organisation can tell who is probing. The passive sources and `--related` don't send it. Plain-HTTP probes send it unencrypted. |
| `--assess` | Rank findings and look up CVEs. With no domains, re-assesses the inventory in `--out` without scanning. |
| `--no-cve` | Assess without the NVD and CISA lookups. |
| `--credentials PROVIDERS` | Collect credential-exposure evidence from free providers, comma-separated: `hudsonrock-osint`, `hibp-public`. No "all": name each one. Sends each root domain to the provider; never contacts the organisation. With no domains, collects for the inventory in `--out`, within that inventory's domains. See [Credential exposure](#credential-exposure---credentials). |
| `--credential-queries KINDS` | Which kinds of evidence `--credentials` collects: `email` (default; workforce email-domain exposure) and `website` (credentials for logins to in-scope hosts, which includes customers' identities). Needs `--credentials`. Rows of a kind that isn't enabled are dropped. |
| `--timeout SECONDS` | HTTP timeout for data sources, RDAP, NVD, CISA and Microsoft (default 60). |
| `--workers N` | Jobs run at once per source or phase (default 16). |
| `--no-progress` | No live progress display. |
| `-v, --verbose` | Log each result and retry as plain lines instead of the live display. |

## Discovery

| Source | Name for `--only` / `--exclude` | Kind | Key (environment variable) |
|---|---|---|---|
| crt.sh | `crtsh` | Certificate transparency | none |
| CertSpotter | `certspotter` | Certificate transparency | optional `CERTSPOTTER_API_KEY` |
| HackerTarget | `hackertarget` | Passive DNS | optional `HACKERTARGET_API_KEY` |
| Wayback Machine | `wayback` | Archived URLs | none |
| AlienVault OTX | `otx` | Passive DNS | optional `OTX_API_KEY` (recommended: anonymous use is heavily rate-limited) |
| urlscan.io | `urlscan` | Existing scans (never submits one) | optional `URLSCAN_API_KEY` |
| RapidDNS | `rapiddns` | Subdomain table | none |
| Hudson Rock | `hudsonrock` | Hosts of login URLs seen in infostealer logs | none |
| Shodan | `shodan` | Subdomains and records | required `SHODAN_API_KEY` |
| VirusTotal | `virustotal` | Subdomain relations | required `VIRUSTOTAL_API_KEY` (free tier works) |
| subfinder | `subfinder` | Passive subdomain tool | `subfinder` on PATH |
| bbot | `bbot` | Passive subdomain-enum preset | `bbot` on PATH (Linux, macOS, WSL), or the [Docker](#docker) image |
| dnstwist | `dnstwist` | Registered lookalike domains, DNS only | bundled |

Install the optional tools with `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
and `uv tool install bbot`. Keys are read from the environment or from `.env` in the current
directory; the environment wins.

Sources without their key or binary are skipped and listed in the summary, as is a tool that is
installed but can't start on this system. A source that fails is recorded in `assets.json` with any
results it returned first, and the scan continues.

Lookalike domains (typosquats and homoglyphs registered by anyone) go to `lookalikes.csv` and are
never scanned. See [Lookalike triage](#lookalike-triage).

## Related domains (`--related`)

Finds other registered domains the organisation owns, such as brands, country domains and defensive
registrations. They come from the scan domains' Microsoft 365 tenant, and from the scan domains' names
under other suffixes (`example.de`, `example.com.au`). Each is given a `tie` of `strong`, `medium`
or `weak` by the evidence linking it to the organisation. Registered variants with no tie are reported
as lookalikes.

Results go to `related.csv`. The summary counts each tie and names the first few strong and medium
domains. **Related domains are never scanned**: owning a domain doesn't mean you're authorised to scan
it, so add the ones you are to your domain list yourself.

**Not passive:** about 1,800 lookups per scan domain go to the registries, 8 at a time (fewer with
`--workers`). Each registered variant gets a few DNS lookups and an HTTP request (HTTPS, then plain
HTTP if that fails) to see where it redirects, and Microsoft gets one request per scan domain.
`--related-rate` spreads all of these out: at 10 a second, one domain takes about 3 minutes. Unpaced,
a burst of this size can overwhelm a small NAT or home router.

## Resolution

`hosts.csv` shows `resolves` as `yes`, `no`, or blank when the answer is unknown: the lookup timed out
after a retry, the DNS servers failed to answer (SERVFAIL), or your resolver answered only with a block
page (a filtering resolver such as Cisco Umbrella). A blank answer keeps the previous scan's `yes` or `no`. A name with `resolves=no` but
addresses listed is a historical record: it was seen in passive DNS but no longer resolves.

## Tenants (`--tenants`)

Finds the organisation's accounts on other companies' platforms, such as `example.sharepoint.com` or
`example.my.salesforce.com`. Platforms the organisation's own DNS records point to are tried first,
then a bundled table of common ones. Platforms that answer any name are allowed for.

In `tenants.csv`, a tenant's `tie` says what links it to the organisation: `records` (its own TXT or
SPF), `cname` (its hosts point there), or `name` (a name match only, which may be another
organisation). `verified=no` means the platform answers any name, so DNS can't confirm the tenant
exists.

It also asks Microsoft how each scan domain signs in (`identity.csv`): `managed` (passwords in Entra),
`federated` (to the identity provider in `provider` and `sign_in_host`), or `none` (not in Microsoft),
with the tenant ID and region. That's two requests per domain to `login.microsoftonline.com`, with a
made-up username, never a real one. A Microsoft 365 tenant found by its name alone
(`example.onmicrosoft.com`) is checked against the scan domains' tenant ID: someone else's is dropped,
from earlier runs' inventory too, and the organisation's own gets tie `records`. Federation to a
self-hosted ADFS server is a finding, and a sign-in host under the scan domains joins the inventory.

**Not passive:** the platforms' nameservers and Microsoft's sign-in service see the lookups, and the
organisation's nameservers see one TXT query per domain.

## Guessing (`--guess`)

Finds names that public datasets missed by learning how the organisation names its hosts
(`api-dev` → `api-prod`, `portaltest` → `portal-test`) and testing names it hasn't seen in DNS. It
learns from this scan, the inventory in `--out` and the organisation's verified tenant names (from
this scan's `--tenants`, or earlier ones in `--out`). Found names have source `guess`.

Every name tested is remembered, and later scans into the same `--out` skip it for about 90 days, so
each scan goes further down the list. Names under a wildcard count only if they answer differently
from it. Parents where the wildcard check got no answer, or where most guesses resolved, are skipped
and listed in the errors in `assets.json`.

**Not passive:** the domain's authoritative nameservers see every guess, mostly for names that don't
exist. `--guess-rate` spreads them out; 2000 lookups at 5 a second take about 7 minutes.

### Measuring the guesser

`uv run python -m farpoint.guess out` measures the guesser on an inventory without any DNS traffic. It
hides known hosts one at a time (up to 300, sampled) and reports how often the rest rank each one
within 100, 500 and 2000 guesses.

| Option | Meaning |
|---|---|
| `--k LIST` | Budgets to report (default `100,500,2000`) |
| `--sample N` | Hide at most N hosts (default 300) |
| `--rank HOST` | Also show where this host ranks and why. Repeatable. |
| `--show N` | Print the top N candidates per domain |
| `--no-corpus` | Ignore the cross-organisation corpus, for comparison |
| `-v` | Print every hidden host's rank |

### Cross-organisation corpus (optional)

`farpoint.corpus` builds naming statistics from many organisations' certificates, to teach patterns one
organisation's names can't. When `src/farpoint/data/corpus.json` exists, `--guess` uses it. None is
bundled.

```bash
uv sync --group corpus
uv run python -m farpoint.corpus orgs     -d corpus --count 2000   # sample organisations (minutes; resumable)
uv run python -m farpoint.corpus fetch    -d corpus                # fetch their names (hours; resumable)
uv run python -m farpoint.corpus evaluate -d corpus                # compare guessing with and without it
uv run python -m farpoint.corpus stats    -d corpus --exclude example.com --out src/farpoint/data/corpus.json
```

`-d` defaults to `./corpus`. Without `--out`, `stats` writes `corpus/corpus.json`, which `--guess`
doesn't read. Use `--exclude` (repeatable) for any organisation you will evaluate on, so its own names
don't leak into the statistics. `orgs --seed` changes the sample and `evaluate --folds` (default 5) the
cross-validation.

## Lookalike triage

Most registered lookalikes are someone else's business. To find the few worth blocking, enrichment
looks up when each lookalike that has mail servers (MX) or an address was registered (RDAP). For those
registered within the last year it also fetches the newest certificate (crt.sh). Dates are reused for
30 days. Many country registries (`.io`, `.de`, `.eu`, `.me`, `.us` and others) publish no
registration data, so their lookalikes' dates stay unknown; the run records one error naming those
TLDs. Nothing is sent to the lookalikes' own servers, apart from a few DNS lookups of random names to
spot wildcard DNS. `--no-enrich` skips all of this.

With `--assess`, two kinds of lookalike are flagged:

- `lookalike-ready` (high): registered within the last year and able to receive mail (it has MX) or
  serve a site now.
- `lookalike-parked` (medium): recently registered but showing a parking service and nothing else.
  Probably a speculator, but able to start sending mail at any time. The parking services recognised
  are in `src/farpoint/data/parking.json`.

Both go into `phishing-block.txt`, ready ones first, for the mail gateway. Review it before you block:
a new, legitimate business with a similar name can still appear.

Never flagged: a lookalike with no known registration date, one registered over a year ago, one that
only had an address in an earlier scan, and the organisation's own variants. A variant counts as the
organisation's when it is in `related.csv`, has mail servers or nameservers under its domains, shares
a mail server named after the organisation, or uses the same set of nameservers as one of its domains
(registrars' shared defaults excepted). The scan domains' own nameservers and mail servers are looked
up for this, one query each, through your resolver. If they can't be looked up, no lookalike is
flagged, since the organisation's own variants can't be told apart; the error is in `assets.json`, and
the next scan tries again.

## Fingerprinting (`--fingerprint`)

Identifies what each live host runs. It only contacts in-scope hosts that resolve now to a public
address. It never contacts lookalikes, related domains, tenants, private addresses, or addresses a name
had in the past. It never logs in, guesses passwords or sends exploits.

- **Ports**: 43 by default, covering remote access, databases, mail, directory services, container
  APIs, and web and appliance ports, plus any ports Shodan has seen open. Addresses belonging to a CDN
  or SaaS front end only get 80 and 443.
- **Services**: each open port is asked who it is the ordinary way: its greeting, a TLS handshake,
  `GET /`, the favicon and the `--paths`. SMTP ports (25, 587) get `EHLO` and `STARTTLS`, never
  `MAIL FROM`.
- **Technologies**: the answers are matched against `src/farpoint/data/fingerprints.json`, which covers
  VPN and firewall appliances (FortiGate, GlobalProtect, NetScaler, BIG-IP, Cisco ASA, Ivanti,
  SonicWall, Check Point), remote access gateways, mail (Exchange with its build number), CDNs and
  WAFs, web servers, languages, CMSs (WordPress with plugin and theme versions), admin panels and
  hosting platforms. Add a rule to that file to recognise more.
- **Domain posture**, per scan domain: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, the STARTTLS of mail
  servers the organisation runs itself, nameservers, zone transfers, DNSSEC, CAA and registration.
  Zone transfers aren't requested from managed DNS services that can't allow one
  (`src/farpoint/data/dns_providers.json`).
- **Dangling DNS**: CNAMEs pointing at names that don't exist, flagged as takeover risks where the
  name could be claimed.

Results go to `fingerprints.csv`, `technologies.csv` and `posture.csv`. A few `posture.csv` values
need reading carefully:

- `axfr` lists the nameservers that handed over the zone, `no` if none did, and is blank when it's
  unknown: none was asked (`--no-axfr`, or only managed services) or one didn't answer. A scan that gets
  no answer keeps the last one while the nameservers stay the same.
- `mta_sts` is the policy's mode, `broken` when it's advertised but missing or invalid, and `unknown`
  when its host turned the scan away (a bot challenge, HTTP 429 or 5xx). No MTA-STS finding is made
  when it's unknown.
- `dnssec` is blank when your resolver can't answer DNSSEC queries; the error suggests
  `--nameserver 1.1.1.1`.

Port checks and service checks are paced by `--probe-rate`. A service check makes several connections
(handshakes, `GET /` and its redirects, the favicon, the paths), and the domain posture checks aren't
paced, so the connection rate can be several times the setting. Web requests identify themselves with
the user agent `farpoint/0.1 (host fingerprinting)`, or `farpoint/0.1 (host fingerprinting; ID)` with
`--engagement ID`. A scan of about 100 hosts makes a few thousand connections over a few minutes.

**Not passive:** the organisation's hosts see the connections, and a port sweep or `AXFR` request may
be logged as reconnaissance. `--ports none` reduces the sweep to ports 80 and 443, and `--no-axfr`
drops the zone-transfer requests.

### Bot defences

A bot defence may answer the scan instead of the site. Such a service gets the signal
`bot-challenge:<vendor>` (a page a browser could get past, such as Cloudflare's "Just a moment...")
or `bot-block:<vendor>` (a refusal no client gets past, such as Cloudflare's "Sorry, you have been
blocked" or an Akamai "Access Denied"). Nothing on the defence's page is taken as the site's, no
finding is made from it, and the run summary counts them by vendor: what runs behind them wasn't seen.
The vendors recognised are in `src/farpoint/data/bot_defences.json`. A block is usually of the scan's
network, such as a cloud provider's: scan from a network the site accepts, or ask the organisation to
allowlist the scan's address for the run.

For each host a bot defence hid, farpoint fetches the newest Wayback Machine copy of its homepage from
the last year and matches the same rules against it (`--no-archive` turns this off). This is passive:
only archive.org is asked. What a copy shows is recorded apart from what the scan saw: in the
`archived` column of `fingerprints.csv` (with the capture date) and as `seen` `archive` rows in
`technologies.csv`. It makes no findings, because the copy may be months old.

`uv run python -m farpoint.visibility out` reports how many web services a scan saw, how many each
vendor challenged or blocked, and how many of those an archived copy identified. Use it to compare a
change to how farpoint asks across the same organisations, rather than judging it on one site. For
scans made before these signals existed it works from the status, headers and title they kept, so
there a block can read as a challenge.

## Assessment (`--assess`)

Turns the inventory into `findings.csv`, ranked by how interesting each finding is to an attacker
choosing a soft target, not by CVSS. Assessment sends nothing to the organisation. Every finding kind
is listed in [Finding kinds](#finding-kinds).

| Level | Examples |
|---|---|
| high | RDP, SMB, Telnet, VNC, WinRM, databases, Docker or Kubernetes APIs open to the internet; VPN and firewall appliances; managed file transfer (MOVEit, GoAnywhere, Cleo, Axway, Kiteworks); admin panels such as Jenkins, GitLab, Grafana, vCenter and Exchange; end-of-life software (PHP 7, IIS 8.5, Exchange 2016); versions with a CVE CISA lists as exploited, or scoring 9 or more; an exposed `.git` (add `/.git/HEAD` to `--paths` to check); a public bucket listing; expired certificates; subdomain takeovers; no SPF, or SPF `+all`; DMARC missing or `p=none` without SPF `-all`; SPF includes on unregistered domains; zone transfers; a domain expiring within 30 days; a scan domain with no nameservers (it may be free to register); a parked scan domain still listed in the organisation's Microsoft 365 tenant; a recently registered lookalike that can handle mail or serve a site |
| medium | Jira, Confluence, Swagger UI and webmail open to the internet; FTP and LDAP; self-signed, mismatched, weak-key or SHA-1 certificates; certificates expiring within 30 days (7 for certificates that live 100 days or less, which renew themselves); TLS 1.0/1.1; plain HTTP with no HTTPS; directory listings; default server pages; Basic or NTLM login prompts; stack traces; CORS open to any origin with credentials; dev/test/staging hosts on the internet; SPF that doesn't reject, is duplicated or needs over 10 lookups; DMARC `pct` below 100 or `sp=none`; a broken MTA-STS policy; mail servers without STARTTLS; weak DKIM keys; BGP open to the internet; a parked scan domain; a recently registered lookalike that is only parked; sign-in federated to a self-hosted ADFS server |
| low | missing HSTS, or HTTP not redirecting to HTTPS; wildcard certificates covering the organisation's names; a provider's own certificate on a name pointed at that provider (an Intune or App Proxy name never set up for HTTPS); SPF at exactly 10 lookups; internal names in certificates; broken CNAMEs; no DNSSEC, CAA, MTA-STS or DKIM found; a single nameserver; no transfer lock; version-revealing headers or plugin versions; POP3, IMAP and SSH open |

Each product version fingerprinting identified is checked against NVD for CVEs and against CISA's
Known Exploited Vulnerabilities catalogue. NVD answers are cached in `assets.json` for a week. Without
a key NVD allows about one request every 6.5 seconds, so set `NVD_API_KEY` for large inventories.

Some findings are deliberately ranked lower to avoid confident false positives: CVEs on distribution
packages (which backport fixes), CVEs Shodan lists for shared CDN addresses, and CVEs for addresses the
latest scan didn't see in live DNS. A provider's own certificate on a name that points at the provider
is the provider's to renew, so it is never reported as expiring, though it is reported once it has
expired.

`first_seen` records when a finding was first reported, and `last_seen` when the evidence behind it
was last observed: a finding from fingerprints or posture keeps the date of the last `--fingerprint`
run, even when a later scan without it re-assesses the inventory. `technologies.csv` lists each product
and version with how many hosts run it, its end-of-life date, its CVE count and the known-exploited
ones, edge devices first.

## Credential exposure (`--credentials`)

Adds evidence that the organisation's accounts appear in breaches or infostealer logs, and ranks it with
the rest of the findings. Name the providers to ask; farpoint fetches, normalises and stores their answers.

```bash
# Collect alongside a normal scan of example.com
uv run farpoint example.com --credentials hudsonrock-osint --assess

# Add evidence to an existing inventory and judge it, without scanning
uv run farpoint --credentials hudsonrock-osint,hibp-public --credential-queries email,website --assess --no-cve -o out/acme

# Re-judge what is stored, without new evidence
uv run farpoint --assess --no-cve -o out/acme
```

With no domains, `--credentials` needs an existing inventory and is scoped to *its* domains: the terminal
prints `credential scope: ...` first so you can check it matches your authorisation. A missing inventory
is an error. Rows outside the scope are dropped and counted. Secret values (passwords, hashes, cookies,
tokens) are never stored; only the *type* of secret is kept, and paths, query strings and credentials in
URLs are stripped.

### Providers

| Provider | What it reports | `--credential-queries` kind |
|---|---|---|
| `hudsonrock-osint` | [Hudson Rock](https://www.hudsonrock.com/free-tools)'s free search by domain: login URLs on the domain's hosts found in infostealer logs, how often each was seen, and domain-wide counts (infected employees, users and third parties, stealer families, the latest compromise dates) | `email` for employees' logins and most counts; `website` adds users' (customers') logins and the infected-user count |
| `hibp-public` | [Have I Been Pwned](https://haveibeenpwned.com)'s breach list: breaches of the organisation's own site, with date and data classes. Data from haveibeenpwned.com, licensed CC BY 4.0 | `website` only, so it needs `--credential-queries email,website` |

Each sends only the root domain, once per run, to that provider; neither contacts the organisation.
Both are free and need no key. Collection runs before the scan, and the evidence is saved with it. A
provider that fails prints `warning: <provider> <domain>: <category>`, is recorded as a failed check,
and doesn't change the exit status. Ctrl-C during collection exits without saving any new evidence.

The `hudsonrock` hostname source reads the same answer, so with `--credentials hudsonrock-osint` a
domain is requested once. The source runs by default like the other sources (`--exclude hudsonrock`
turns it off, without affecting `--credentials`).

What the free data can't do:

- **It names no accounts.** Findings point at hosts ("identities not reported by provider"), so they
  tell you where to look and whether a paid provider is worth buying, not whose password to reset.
- **It has no per-login date.** Hudson Rock's dates are domain-wide, so its findings are medium at most.
- **Zero means no data.** Hudson Rock answers a domain it knows nothing about with zeros, exactly like
  a clean one. Such a check is shown as `no data`, never as clean, and makes no finding.
- **It is a sample.** Hudson Rock lists at most about a hundred URLs. Only rows from a provider's latest
  complete check make findings; older rows stay in `credentials.json` and the exports as history
  (`in_latest_snapshot` is `no`). A later failed check retires nothing.

### How it is judged

Each finding covers one scope domain and one service, and carries counts, never identities. Evidence
counts as tied to the organisation only when it matches something the scan found: the exact host and
port, a sign-in host, or a tenant with records or CNAME evidence. A shared IP, a common SaaS provider,
a name resemblance or a shared identity provider's own sign-in page (such as `accounts.google.com`)
doesn't count. When the provider names a port the scan never saw open, the finding names `host:port`,
says "reported port not observed", and stays medium.

| Level | Evidence |
|---|---|
| high | Infostealer or phishing evidence with a known theft or capture date within 90 days, tied to a service, sign-in host or tenant that a scan observed within the last 90 days. Needs a positive observation, so a name that only resolves in DNS stays medium (run `--fingerprint`). |
| medium | The same theft evidence with an unknown or older date, or without a strong match to a service; account-specific password or hash records. |
| low | Email-only breach membership and dataset-level exposure; aggregate counts (reported as summaries, never as confirmed accounts). |

Breach publication dates never count as theft dates. Evidence is historical: it is not proof that an
account can be accessed now, that a password is still valid or that the organisation is compromised,
and absence from a later check does not mean remediation. A check that was partial or failed is shown
next to the finding and never reads as a clean result.

### Freshness

Credential findings are tied to the version of `credentials.json` they judged. Collecting new evidence
without `--assess`, or an unreadable `credentials.json`, leaves them out of `findings.csv` and the
terminal totals until you run `--assess`. The terminal prints one of:

- `assessment: current`
- `assessment: stale (run --assess to update)`
- `assessment: unavailable: credentials.json can't be read (<reason>)`
- `assessment: none` (evidence is stored but has never been assessed)

If the evidence can't be saved to `credentials.json` (it is unreadable, read-only or the disk is
full), the batch is kept in an owner-only `credentials.unmerged-<time>.json`, the terminal prints
`warning: credential evidence not saved (<reason>); kept in <file>` and farpoint exits with status 1.
The rest of the scan is saved as usual. To recover, fix `credentials.json` (or move it aside) and re-run
the same `--credentials` command; then delete the `credentials.unmerged-*.json` file. If even that
fallback can't be written, the evidence stays in a checkpoint in the output folder and the next run
into it recovers the evidence.

### Sensitive data

- Identities (email addresses and other account identifiers) are stored whole in `credentials.json`
  and the `credential-*.csv` exports, and **only** there. `assets.json`, `findings.csv` and the other
  files carry no identities. `credential-exposures.csv` also keeps the stealer log and malware names a
  provider reported, which findings leave out because they can name a victim's user or machine.
- No secret values are stored anywhere: not in the files, checkpoints, fallbacks or messages.
- These files are written owner-only (mode 0600) on POSIX. On Windows file modes give no such
  guarantee, so the output folder itself must be private.
- You are responsible for having a lawful basis and authorisation to process the identities you
  collect. farpoint applies no retention expiry.
- To delete credential evidence, remove `credentials.json`, `credentials.unmerged-*.json`,
  `.credential-checkpoint-*` and `credential-*.csv` from the output folder, then run `--assess` to
  re-derive the findings.

## Output (`--out`, default `./out`)

Each scan is **merged** into the inventory already in the folder. Scan domains one at a time, re-run
a source that failed, or re-scan regularly into the same folder. To start fresh, use a new folder.

| File | Contents |
|---|---|
| `hosts.txt`, `ips.txt` | Sorted plain lists, for piping into other tools |
| `hosts.csv` | hostname, resolves, ips, cnames, sources |
| `ips.csv` | ip, org, network, ports (Shodan's history), open_ports (found by fingerprinting), tags, vulns, hostnames, sources |
| `lookalikes.csv` | Registered lookalike domains: domain, addresses, mail servers, registration date, newest certificate, `capable` (mail, web: what it can do now), `flagged` (ready, parked), sources |
| `phishing-block.txt` | With `--assess`: the flagged lookalikes, one per line, ready ones first, for the mail gateway |
| `identity.csv` | With `--tenants`: one row per scan domain: sign_in, provider, sign_in_host, brand, tenant_id, region |
| `related.csv` | With `--related`: domain, the scan domain it relates to, tie, evidence |
| `tenants.csv` | With `--tenants`: tenant, vendor, domain, tie, verified, hosts pointing at it, evidence, ips, cnames |
| `fingerprints.csv` | With `--fingerprint`: one row per open host and port: endpoint, hostname, ip, port, service, technologies, status, title, server, redirect, signals, certificate subject, issuer and expiry, TLS versions, banner, favicon hash, paths, cookies, and for a service a bot defence hid, what an archived copy showed |
| `technologies.csv` | With `--fingerprint`: each technology's category, name and version, whether the scan saw it (`live`) or only an archived copy (`archive`), host count, end-of-life date, CVE count, known-exploited CVEs, CPE, hosts and endpoints |
| `posture.csv` | With `--fingerprint`: one row per scan domain: mail provider, MX, SPF (record, `all`, lookups, missing includes), DMARC (record, policy, subdomain policy, pct), DKIM, MTA-STS, TLS-RPT, mail server STARTTLS, nameserver providers, DNSSEC, CAA, AXFR, wildcard DNS, registrar, created, expires, transfer lock |
| `findings.csv` | With `--assess`: level, kind, target, detail, evidence |
| `credentials.json` | With `--credentials`: the credential evidence (identities included; owner-only). The source of truth for it |
| `credential-exposures.csv` | Each exposure: its ID, provider, scope domain, kind, identity, relationship, service host and port, how it matched the inventory, type, source and malware names, secret types, occurrences, event date and basis, reference, and whether it is in its provider's latest snapshot. Contains identities |
| `credential-summary.csv` | Aggregate counts a provider reported |
| `credential-checks.csv` | What each provider/domain/kind/operation check covered, its status and error, and `no data` when a complete check returned nothing |
| `assets.json` | The inventory: everything above in full, plus each scan's domains, errors and skipped sources |
| `assets.unmerged-<time>.json`, `credentials.unmerged-<time>.json` | Only after a failed save: this run's results, kept beside the file that couldn't be updated |

Every row except in `technologies.csv` and `credential-checks.csv` has `first_seen` and `last_seen`
(UTC); a credential check has `started_at`, `completed_at` and `last_complete_at` instead.
`assets.json` and `credentials.json` are the sources of truth; every other file is regenerated from
them after every scan, so edit neither the CSVs nor the lists by hand. Discovered facts accumulate
across scans, while fingerprints and posture describe the latest look. Findings describe the latest
`--assess`: a scan without it leaves them as they were.

The folder also holds hidden working files: `.lock` while a scan saves, and `.checkpoint-*` and
`.credential-checkpoint-*` files while a scan runs (see below). Two scans into one folder don't lose
each other's results. A scan refuses to start if the existing `assets.json` can't be read.

## Progress, stopping and exit status

In a terminal, farpoint shows a live line per source and domain with what it is doing (requesting,
waiting on a rate limit, retrying), then its result count or error. Counters follow for each later
phase. `-v` prints the same events as plain lines instead. When output isn't a terminal, or with
`--no-progress`, there is no display, and only failures are printed unless you add `-v`.

**Ctrl-C (or SIGTERM) stops the scan and saves what it has**, including results already fetched by
sources still running, and marks the scan as interrupted. Press Ctrl-C again to quit without saving.
Progress is also saved every few seconds to a checkpoint file in the output folder, so after a hard
kill the next scan into the same folder merges it automatically.

| Exit status | Meaning |
|---|---|
| 0 | Done |
| 1 | Credential evidence couldn't be saved to `credentials.json` (see [Freshness](#freshness)) |
| 2 | Invalid options, or `--assess` / `--credentials` without domains and no readable inventory in `--out` |
| 130 | Interrupted: partial results saved; re-run to fill in the rest |

## Scope and limits

- Only names equal to or under a scan domain are kept. CNAME targets outside them are recorded on the
  host but not followed.
- Fingerprinting covers the hosts found live in the current scan, not hosts known only from earlier
  scans in `--out`.
- Technology rules match what services reveal. Products that hide their name or version are missed.
  CVE matches are by version, so treat them as leads to confirm.
- Favicon hashes are recorded but not matched against known products.
- DKIM is checked under common selectors only, so "not found" can mean "uses another selector".
- BGP (port 179) isn't in the default ports; it is only checked when Shodan saw it open or you add it
  with `--ports`.

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
  results like Ctrl-C does; compose allows 30 seconds for it (`stop_grace_period`).
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

## Finding kinds

The `kind` column of `findings.csv`, by area. Where a kind can take more than one level, the
[Assessment](#assessment---assess) table and ARCHITECTURE.md say when.

| Area | Kinds |
|---|---|
| Exposed services | `exposed-service` (high, medium or low by port), `edge-device`, `file-transfer`, `admin-interface` (high or medium by product), `non-production-exposed` |
| Software | `end-of-life`, `known-vulnerable-version` (by CVSS and exploitation), `shodan-cves`, `plugin-version` |
| Web | `git-exposed`, `bucket-listing`, `directory-listing`, `default-page`, `basic-auth`, `ntlm-auth`, `error-detail`, `cors-any-origin-with-credentials`, `version-disclosure`, `cleartext-http`, `no-https-redirect`, `no-hsts` |
| Certificates and TLS | `certificate-expired`, `certificate-expiring`, `certificate-self-signed`, `certificate-mismatch`, `weak-certificate-key`, `weak-certificate-signature`, `wildcard-certificate`, `internal-names-in-certificate`, `legacy-tls` |
| Mail | `spf-missing`, `spf-allows-all`, `spf-neutral`, `spf-multiple-records`, `spf-too-many-lookups`, `spf-at-lookup-limit`, `spf-include-unregistered`, `spf-include-missing`, `dmarc-missing`, `dmarc-not-enforced`, `dmarc-partial`, `dmarc-subdomains-open`, `dkim-not-found`, `dkim-weak-key`, `mta-sts-missing`, `mta-sts-broken`, `mx-no-starttls`, `no-starttls` (an SMTP port the scan probed), `mx-certificate-invalid` |
| DNS and domains | `subdomain-takeover`, `dangling-cname`, `zone-transfer`, `no-dnssec`, `no-caa`, `single-nameserver`, `domain-unregistered`, `domain-expiring`, `no-transfer-lock`, `parked-domain` |
| Phishing and identity | `lookalike-ready`, `lookalike-parked`, `self-hosted-federation` |
| Credentials | `credential-theft`, `credential-breach`, `credential-summary` |

## Development

```bash
uv run pytest               # offline test suite
uv run pytest -m network    # smoke tests against real DNS, example.com and NVD
```

[ARCHITECTURE.md](ARCHITECTURE.md) covers the code layout, the methodology of each stage, a system
diagram, and how to add sources, technology rules, tenant platforms and findings.
