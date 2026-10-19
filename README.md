# easm: passive external attack surface mapping

Give it your root domains and it returns the **hostnames** and **IP addresses** that public OSINT
sources associate with them. Each IP gets an owner/network (RDAP) and Shodan's pre-collected port
and CVE data. Registered **lookalike domains** are reported separately.

**Discovery only.** Nothing here scans, probes or sends traffic to your hosts or the lookalike
hosts. Every query goes to a third-party dataset (CT logs, passive DNS, archives) or to a recursive
DNS resolver.

## Quick start

```bash
uv run easm example.com example.org          # results in ./out/
uv run easm -f domains.txt -o out/acme -v    # one domain (or URL) per line, '#' comments ok
uv run easm --list-sources                   # what's usable on this machine
uv run easm example.com --only crtsh,certspotter --no-enrich
uv run easm example.com --exclude dnstwist   # dnstwist is the slowest source (several minutes)
```

## Output (`--out`, default `./out`)

| File | Contents |
|---|---|
| `hosts.txt` / `ips.txt` | Plain sorted lists, good for piping into other tools |
| `hosts.csv` | hostname, resolves (yes/no), ips, cnames, sources |
| `ips.csv` | ip, org, network, ports, vulns, hostnames, sources |
| `lookalikes.csv` | Registered typosquat/homoglyph domains and their IPs |
| `assets.json` | Everything above, plus per-source errors and skipped sources |

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
```

Layout: `names.py` (normalize/scope), `models.py` (Observation → Inventory), `sources/` (one class
per source behind the `Source` protocol: `available()` + `collect(domain)`), `resolve.py`,
`enrich.py`, `pipeline.py`, `output.py`, `cli.py`.

To add a source, subclass `HttpSource` (you get retries) or `CommandSource` (you get availability
checks), yield `Observation`s, and register it in `sources/__init__.py`. Scoping, normalization and
de-duplication happen centrally in `Inventory`, so sources stay dumb.

## Scope and limits

- Only names equal to or under an input domain are kept. Third-party CNAME targets (CDNs, SaaS)
  are recorded on the host but not expanded.
- No wildcard-DNS detection or ASN/netblock expansion yet. Those are good next steps toward
  commercial ASM parity, along with reverse-whois/org-name pivoting to discover unknown root
  domains, and diffing runs over time.
- Only use it on domains you own or are authorised to assess.
