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
than the one before is a separate opt-in. Only names under the scan domains are ever probed, apart
from a zone-transfer request to the scan domains' nameservers: related domains, tenants and
lookalikes are reported for you to review. Findings are worked out afresh from the
whole inventory on every assessment. A check that fails is recorded as unknown, never as a missing
control.

A scan runs these phases in order. Each phase works on what the earlier ones found.

| Phase | What it does | Who sees traffic | Enabled by |
|---|---|---|---|
| Discovery | Collects hostnames from certificate logs, passive DNS, archives and other datasets | The data sources | always |
| Related domains | Finds other registered domains the organisation owns | Registries, the domains found, Microsoft | `--related` |
| Resolution | Looks up every name's addresses and CNAMEs | Your DNS resolver | always (`--no-resolve` skips) |
| Tenants | Finds the organisation's accounts on SaaS and cloud platforms, and how each domain signs in to Microsoft | The platforms' nameservers, Microsoft | `--tenants` |
| Guessing | Predicts unseen names from the naming patterns found and tests them in DNS | The domain's nameservers | `--guess` |
| Enrichment | Adds each address's owner, network, and Shodan's port and CVE history; when each lookalike that can handle mail or serve a site was registered | RDAP registries, Shodan, crt.sh | always (`--no-enrich` skips) |
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
| `--no-enrich` | Skip the RDAP and Shodan InternetDB lookups for addresses, and the registration and certificate lookups for lookalikes. |
| `--nameserver IP` | DNS resolver to use instead of the system's. Repeat for several. |
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
| `--credential-import PATH` | Add credential-exposure evidence from a provider export (schema: [docs/credential-import/schema.json](docs/credential-import/schema.json)). Repeatable. Offline: nothing is sent anywhere. With no domains, adds it to the inventory in `--out`, within that inventory's domains. See [Credential exposure](#credential-exposure---credential-import). |
| `--credentials PROVIDERS` | Collect credential-exposure evidence from free providers, comma-separated: `hudsonrock-osint`, `hibp-public`. No "all": name each one. Sends each root domain to the provider; never contacts the organisation. With no domains, collects for the inventory in `--out`. See [Free providers](#free-providers---credentials). |
| `--credential-queries KINDS` | Which kinds of evidence an import or `--credentials` may hold: `email` (default; workforce email-domain exposure) and `website` (credentials for logins to in-scope hosts, which includes customers' identities). Needs `--credential-import` or `--credentials`. An import with a disabled kind is rejected whole. |
| `--timeout SECONDS` | HTTP timeout for data sources, RDAP, NVD, CISA and Microsoft (default 60). |
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
| Hudson Rock | Hosts of login URLs seen in infostealer logs | none |
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
`--workers`). Each registered variant gets a few DNS lookups and an HTTP request (HTTPS, then plain HTTP if
that fails) to see where it redirects, and Microsoft gets one request per scan domain. `--related-rate` spreads all of these
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

It also asks Microsoft how each scan domain signs in (`identity.csv`): `managed` (passwords in Entra),
`federated` (to the identity provider in `provider` and `sign_in_host`), or `none` (not in Microsoft),
with the tenant ID and region. That's two requests per domain to `login.microsoftonline.com`, with a
made-up username, never a real one. A Microsoft 365 tenant found by its name alone
(`example.onmicrosoft.com`, `example.sharepoint.com`) gets one more request for its tenant ID: if it
is not the tenant a scan domain signs in to, it is someone else's and is dropped, from earlier runs'
inventory too; if it is, its tie
becomes `records`. Federation to a self-hosted ADFS server (a sign-in URL under
`/adfs/`) is a finding; a sign-in host under the scan domains joins the inventory. Identity providers
are recognised from `src/farpoint/data/identity_providers.json`.

**Not passive:** the platforms' nameservers and Microsoft's sign-in service see the lookups, and the
organisation's nameservers see one TXT query per domain.

## Lookalike triage

Most registered lookalikes are someone else's business. To find the few worth blocking, enrichment
looks up when each lookalike that has mail servers (MX) or an address was registered (RDAP), and for
those registered within the last year, its newest certificate (crt.sh). A name under someone else's
domain (`ex.ample.com`, dnstwist's dot insertion) is dated by that registered domain, unless the domain
answers any name the same way (wildcard DNS: three lookups of random names under it), when its date
says nothing about the organisation and the name is left undated (also with `--no-resolve`, with an
error per name, since the check needs DNS). Registration dates are
reused for 30 days. Many country registries (`.io`, `.de`, `.eu`, `.me`, `.us` and others) run no RDAP
service: their lookalikes' dates are unknown, and the run records one error naming those TLDs. MX and nameservers come from dnstwist and `--related`, which already look them up.
Nothing is sent to the lookalikes' own servers except those wildcard DNS lookups, which their
nameservers see. `--no-enrich` skips the lookups.

With `--assess`, a lookalike registered within the last year that can receive mail (it has MX) or serve
a site now is `lookalike-ready` (high). One that shows a parking service and nothing else (all its nameservers are the
service's parking nameservers, or all its addresses its parked-page addresses, and any mail server is
the service's too; see `src/farpoint/data/parking.json`) is `lookalike-parked` (medium). Registrars'
default nameservers and forwarding addresses don't count, since they serve live sites too:
probably a speculator, but able to start sending mail at any time. Both go into `phishing-block.txt`,
ready ones first, for the mail gateway. Review it before you block: a new, legitimate business with a
similar name can still appear.

Never flagged: a lookalike with no known registration date (many country registries don't publish
one), one registered over a year ago, one that only had an address in an earlier scan, and the
organisation's own variants: in `related.csv`, with mail servers or nameservers under its domains,
on the same mail server as one of its domains (a host named after the organisation, not a provider's
shared one), or on the same set of nameservers as one of its domains. The scan domains' own
nameservers and mail servers are looked up for this (one query each, through your resolver).
Registrars' and DNS hosts' default nameservers, which every customer shares, don't count
(`shared_nameservers` in `src/farpoint/data/parking.json`). If a scan domain's own nameservers and
mail servers couldn't be looked up, no lookalike is flagged, since its own variants can't be told
apart; the error is in `assets.json`, and the next scan tries again.

## Guessing (`--guess`)

Finds names that public datasets missed by learning how the organisation names its hosts
(`api-dev` → `api-prod`, `portaltest` → `portal-test`) and testing names it hasn't seen in DNS. It
learns from this scan, the inventory in `--out` and the organisation's verified tenant names (from
this scan's `--tenants`, or earlier ones in `--out`). Every name tested is remembered, and later scans
into the same `--out` skip it for 90 days, so each scan goes further down the list. Found names have
source `guess`. Under a wildcard, a guess counts only if it answers differently. Parents where the
wildcard check got no answer, or where most guesses resolved, are skipped and listed in the errors in
`assets.json`.

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
  `GET /`, the favicon and the `--paths`. SMTP ports (25, 587) get `EHLO` and `STARTTLS`, never
  `MAIL FROM`.
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
  `mta_sts` is the policy's mode, `broken` when it's advertised but missing or invalid, and `unknown`
  when its host turned the scan away (a bot challenge, HTTP 429 or 5xx): no MTA-STS finding is made
  then, and the error says what it answered. A plain 401 or 403 refuses sending servers too, so it is
  `broken`.
- **Dangling DNS**: CNAMEs pointing at names that don't exist, flagged as takeover risks where the
  name could be claimed.

Port checks and service checks are paced by `--probe-rate`, and a service check makes several
connections (handshakes, `GET /` and its redirects, the favicon, the paths). The domain posture
checks aren't paced. Web requests identify themselves with the user agent
`farpoint/0.1 (host fingerprinting)`, or `farpoint/0.1 (host fingerprinting; engagement ID)` with
`--engagement`. A scan of about 100 hosts makes a few thousand connections over a
few minutes. Results go to `fingerprints.csv`, `technologies.csv` and `posture.csv`.

A bot defence may answer the scan instead of the site. Such a service gets the signal
`bot-challenge:<vendor>` (a page a browser could get past, such as Cloudflare's "Just a moment...")
or `bot-block:<vendor>` (a refusal no client gets past, such as Cloudflare's "Sorry, you have been
blocked" or an Akamai "Access Denied"). Nothing on the defence's page is taken as the site's, its
favicon and paths aren't requested, no finding is made from it, and the run summary counts them by
vendor: what runs behind them wasn't seen. The vendors recognised are in
`src/farpoint/data/bot_defences.json`. The scan's TLS handshake leaves out session tickets, because
Cloudflare challenges Python's default handshake on that alone. A block is usually of the scan's
network, such as a cloud provider's: scan from a network the site accepts, or ask the organisation to
allowlist the scan's address for the run.

For each host a bot defence hid, farpoint fetches the newest Wayback Machine copy of its homepage from
the last year and matches the same rules against it (`--no-archive` turns this off). This is passive:
only archive.org is asked, once per host. What a copy shows is recorded apart from what the scan saw:
in the `archived` column of `fingerprints.csv` (with the capture date) and as `seen` `archive` rows in
`technologies.csv`. It makes no findings, because the copy may be months old. A copy the archive
itself was turned away from is ignored.

`uv run python -m farpoint.visibility out` reports how many web services a scan saw and how many each
vendor challenged or blocked, and how many of those an archived copy identified. It reads scans made before these signals existed from the status,
headers and title they kept, so there a block can read as a challenge. Use it to compare a change to
how farpoint asks across the same organisations, rather than judging it on one site.

**Not passive:** the organisation's hosts see the connections, and a port sweep or `AXFR` request
may be logged as reconnaissance (`--ports none` and `--no-axfr` drop both). Some DNS resolvers can't answer DNSSEC (DS) queries. DNSSEC then
shows as unknown, with an error suggesting `--nameserver 1.1.1.1`.

## Assessment (`--assess`)

Turns the inventory into `findings.csv`, ranked by how interesting each finding is to an attacker
choosing a soft target, not by CVSS. Assessment sends nothing to the organisation.

| Level | Examples |
|---|---|
| high | RDP, SMB, databases, Docker or Kubernetes APIs open to the internet; VPN and firewall appliances; managed file transfer (MOVEit, GoAnywhere, Cleo, Axway, Kiteworks); Jenkins, GitLab, Grafana, Kibana, phpMyAdmin, Exchange; end-of-life software (PHP 7, IIS 8.5, Exchange 2016); versions with a CVE CISA lists as exploited, or scoring 9 or more; an exposed `.git` (add `/.git/HEAD` to `--paths` to check); expired certificates; subdomain takeovers; no SPF; DMARC missing or `p=none` without SPF `-all`; SPF includes on unregistered domains; zone transfers; a domain expiring within 30 days; a scan domain with no nameservers (it may be free to register); a parked scan domain still listed in the organisation's Microsoft 365 tenant; a lookalike registered within the last year that can handle mail or serve a site (see Lookalike triage) |
| medium | self-signed or mismatched certificates, certificates expiring within 30 days (7 for certificates that live 100 days or less, which renew themselves), TLS 1.0/1.1, plain HTTP with no HTTPS, directory listings, default server pages, Basic or NTLM login prompts, stack traces, dev/test/staging hosts on the internet, DMARC `pct` below 100 or `sp=none`, mail servers without STARTTLS, weak DKIM keys, SPF over 10 lookups, BGP open to the internet, a parked scan domain, a recently registered lookalike that is only parked, sign-in federated to a self-hosted ADFS server |
| low | missing HSTS, wildcard certificates covering the organisation's names (one finding per certificate), a provider's own certificate on a name pointed at that provider (an Intune or App Proxy name never set up for HTTPS), SPF at exactly 10 lookups, internal names in certificates, broken CNAMEs, no DNSSEC, no CAA, no MTA-STS, no transfer lock, version-revealing headers (not on a CDN's or SaaS front end: those are the provider's), SSH open |

Each product version fingerprinting identified is checked against NVD for CVEs and against CISA's
Known Exploited Vulnerabilities catalogue. NVD answers are cached in `assets.json` for a week. Without
a key NVD allows about one request every 6 seconds, so set `NVD_API_KEY` for large inventories.
Distribution package versions, CVEs on shared CDN addresses, and CVEs on addresses the latest scan
didn't see in live DNS are discounted. A provider's own certificate on a name that points at the
provider is the provider's to renew, so it is never reported as expiring.

`first_seen` records when a finding was first reported, and `last_seen` when the evidence behind it
was last observed: a finding from fingerprints or posture keeps the date of the last `--fingerprint`
run, even when a later scan without it re-assesses the inventory. `technologies.csv` lists each product and
version with how many hosts run it, its end-of-life date, its CVE count and the known-exploited
ones, edge devices first.

## Credential exposure (`--credential-import`)

Adds evidence that the organisation's accounts appear in breaches, infostealer logs or phishing
captures, and ranks it with the rest of the findings. This release reads **normalised exports that
you obtained yourself** from an intelligence provider, which sends nothing anywhere, and collects from
two free providers with `--credentials` (below).

```bash
# Add an export to an existing inventory and judge it (no scan, no network)
uv run farpoint --credential-import evidence.json --assess --no-cve -o out/acme

# Also accept website-login records (these hold customers' identities)
uv run farpoint --credential-import evidence.json --credential-queries email,website --assess --no-cve -o out/acme

# Import alongside a normal scan of example.com
uv run farpoint example.com --credential-import evidence.json --assess

# Re-judge what is stored, without new evidence
uv run farpoint --assess --no-cve -o out/acme
```

With no domains, the import needs an existing inventory and is scoped to *its* domains: the terminal
prints `credential scope: ...` first so you can check it matches your authorisation. A missing
inventory is an error. Rows outside the scope are dropped and counted. An invalid import, or one
with a disabled query kind, is rejected before anything is saved or recovered.

The format is in [docs/credential-import/schema.json](docs/credential-import/schema.json), with a
worked file in [docs/credential-import/example.json](docs/credential-import/example.json). Secret
values (passwords, hashes, cookies, tokens) must not be in the file; only the *type* of secret is
kept, and paths, query strings and credentials in URLs are stripped.

### Free providers (`--credentials`)

```bash
uv run farpoint example.com --credentials hudsonrock-osint --assess
uv run farpoint --credentials hudsonrock-osint,hibp-public --credential-queries email,website --assess --no-cve -o out/acme
```

| Provider | What it reports | Kind |
|---|---|---|
| `hudsonrock-osint` | [Hudson Rock](https://www.hudsonrock.com/free-tools)'s free search by domain: login URLs on the domain's hosts found in infostealer logs, how often each was seen, and domain-wide counts (infected employees, users and third parties, stealer families, the latest compromise dates) | `email` for employees' logins; `website` for users' (customers') logins and counts |
| `hibp-public` | [Have I Been Pwned](https://haveibeenpwned.com)'s breach list: breaches of the organisation's own site, with date and data classes. Data from haveibeenpwned.com, licensed CC BY 4.0 | `website` only, so it needs `--credential-queries email,website` |

Each sends only the root domain, once per run, to that provider; neither contacts the organisation.
Both are free and need no key. Collection runs before the scan, and the evidence is saved like an
import. A provider that fails prints `warning: <provider> <domain>: <category>`, is recorded as a
failed check, and doesn't change the exit status. Ctrl-C during collection changes nothing.

What the free data can't do:

- **It names no accounts.** Findings point at hosts ("identities not reported by provider"), so they
  tell you where to look and whether a paid provider is worth buying, not whose password to reset.
- **It has no per-login date.** Hudson Rock's dates are domain-wide, so its findings are medium at most.
- **Zero means no data.** Hudson Rock answers a domain it knows nothing about with zeros, exactly like
  a clean one. Such a check is shown as `no data`, never as clean, and makes no finding.
- **It is a sample.** Hudson Rock lists at most about a hundred URLs. Only rows from a provider's latest
  complete check make findings; older rows stay in `credentials.json` and the exports as history
  (`in_latest_snapshot` is `no`). A later failed check retires nothing. Imports keep the usual rule, even
  under these providers' names: absence from a later import is not remediation.

Hudson Rock's URLs are unmasked and can hold password-reset tokens: only the host and an explicit port
are kept. The `hudsonrock` hostname source reads the same answer, so with `--credentials
hudsonrock-osint` a domain is requested once; it runs by default like the other sources
(`--exclude hudsonrock` turns it off, without affecting `--credentials`).

### How it is judged

Findings are grouped by scope domain, kind, relationship and matched service, and carry counts, never
identities. A finding's ID is `kind|target|scope domain|relationship` (for example
`credential-theft|vpn.example.com:443|example.com|workforce-associated`), and its detail names the scope
domain, so two of the organisation's domains with exposures on one service stay two findings. Evidence
is correlated with the inventory (exact host and port, a sign-in host, a tenant with records or CNAME
evidence); a shared IP, a common SaaS provider or a name resemblance is not a match. A shared identity
provider's own sign-in page (such as `accounts.google.com`) is context, never a strong match, even when
the organisation's sign-in is federated to it. When the provider names a port that no fingerprint saw
open, other services or hostname-only sign-in/tenant evidence cannot confirm that port. The match is `host-port-unobserved`: the finding names
`host:port`, says "reported port not observed", and stays medium. Infostealer and phishing log names
are left out of findings, since they can name a victim's user or machine; breach names are kept.

| Level | Evidence |
|---|---|
| high | Infostealer or phishing evidence with a known theft or capture date within 90 days, tied to a service, sign-in host or tenant that a scan observed within the last 90 days. Needs a positive observation, so a name that only resolves in DNS stays medium (run `--fingerprint`). |
| medium | The same theft evidence with an unknown or older date, or without a strong match to a service; account-specific password or hash records. |
| low | Email-only breach membership and dataset-level exposure; aggregate counts (reported as summaries, never as confirmed accounts). |

Breach publication dates never count as theft dates. The theft-date clauses ("theft date unknown",
"older than 90 days") appear only on credential-theft findings. Evidence is historical: it is not
proof that an account can be accessed now, that a password is still valid or that the organisation is
compromised, and absence from a later import does not mean remediation. A check that was partial or
failed is shown next to the finding and never reads as a clean result.
When several imported files contain checks for the same operation, the newest check wins by its
observation time, regardless of file order, and the latest successful completion is retained.

### Freshness

Credential findings are tied to the version of the credential file they judged. Importing new
evidence, or an unreadable `credentials.json`, makes them **stale** or **unavailable**: they are then
left out of `findings.csv` and the terminal totals (the stored snapshot stays in `assets.json`) until
you run `--assess`. The terminal prints `assessment: current`, `stale (run --assess to update)` or the
reason it is unavailable.
Reassessment also regenerates the three credential CSVs from the current valid sidecar, recreating
missing exports and removing stale rows if the sidecar was replaced with empty evidence.

If the evidence can't be saved to `credentials.json` (it is unreadable, read-only or the disk is
full), the batch is kept in an owner-only `credentials.unmerged-<time>.json`, the terminal prints
`warning: credential evidence not saved (<reason>); kept in <file>` and farpoint exits with status 1.
The rest of the scan is saved as usual. To recover, fix `credentials.json` (or move it aside) and re-run
the original import; then delete the `credentials.unmerged-*.json` file.
If both the sidecar and fallback writes fail, an existing credential checkpoint is retained for
automatic recovery on the next run after the write problem is fixed.

### Sensitive data

- Identities (email addresses and other account identifiers) are stored whole in `credentials.json`
  and the `credential-*.csv` exports, and **only** there. `assets.json`, `findings.csv` and the other
  files carry no identities.
- No secret values are stored anywhere: not in the files, checkpoints, fallbacks or messages.
- These files are written owner-only (mode 0600) on POSIX. On Windows file modes give no such
  guarantee, so the output folder itself must be private.
- You are responsible for having a lawful basis and authorisation to process the identities you
  import. farpoint applies no retention expiry.
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
| `lookalikes.csv` | Registered lookalike domains: addresses, mail servers, registration date, newest certificate, `capable` (mail, web: what it can do now), `flagged` (ready, parked) |
| `phishing-block.txt` | With `--assess`: the flagged lookalikes, one per line, ready ones first, for the mail gateway |
| `identity.csv` | With `--tenants`: one row per scan domain: sign_in, provider, sign_in_host, brand, tenant_id, region |
| `related.csv` | With `--related`: domain, the scan domain it relates to, tie, evidence |
| `tenants.csv` | With `--tenants`: tenant, vendor, domain, tie, verified, hosts pointing at it, evidence, ips, cnames |
| `fingerprints.csv` | With `--fingerprint`: one row per open host and port: service, technologies, status, title, server, redirect, signals, certificate, TLS versions, banner, favicon hash, paths, and for a service a bot defence hid, what an archived copy showed |
| `technologies.csv` | With `--fingerprint`: each technology's category, name and version, whether the scan saw it (`live`) or only an archived copy (`archive`), host count, end-of-life date, CVE count, known-exploited CVEs, CPE, hosts and endpoints |
| `posture.csv` | With `--fingerprint`: one row per scan domain: mail provider, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, mail server STARTTLS, nameserver providers, DNSSEC, CAA, AXFR, wildcard DNS, registration |
| `findings.csv` | With `--assess`: level, kind, target, detail, evidence |
| `credentials.json` | With `--credential-import` or `--credentials`: the credential evidence (identities included; owner-only). The source of truth for it |
| `credential-exposures.csv` | Each exposure: its stable ID, provider, identity, relationship, matched service, type, secret types, occurrences, event date and basis, reference, and whether it is in its provider's latest snapshot. Contains identities |
| `credential-summary.csv` | Aggregate counts a provider reported |
| `credential-checks.csv` | What each provider/domain/kind/operation check covered, its status, and `no data` when a complete check returned nothing |
| `credentials.unmerged-<time>.json` | Evidence that couldn't be saved to `credentials.json` (it is unreadable or the save failed), kept owner-only |
| `assets.json` | The inventory: everything above in full, plus each scan's domains, errors and skipped sources |

Every row except in `technologies.csv` and `credential-checks.csv` has `first_seen` and `last_seen`
(UTC); a credential check has `started_at`, `completed_at` and `last_complete_at` instead. `assets.json` is the
source of truth for the infrastructure and `credentials.json` for credential evidence; the other files are regenerated from them after every scan. Discovered facts
accumulate across scans, while fingerprints and posture describe the latest look. Findings describe
the latest `--assess`: a scan without it leaves them as they were (see
[ARCHITECTURE.md](ARCHITECTURE.md#9-merge-and-output) for the exact rules).

Writes are atomic and locked, so two scans into one folder don't lose each other's results. A scan refuses to start if the existing
`assets.json` can't be read. If it becomes unreadable during a scan, the scan is saved beside it as
`assets.unmerged-<time>.json`.

## Progress and stopping

In a terminal, farpoint shows a live line per source and domain with what it is doing (requesting,
waiting on a rate limit, retrying), then its result count or error. Counters follow for each later
phase. `-v` prints the same events as plain lines instead. When output isn't a terminal, or with
`--no-progress`, there is no display, and only failures are printed unless you add `-v`.

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
