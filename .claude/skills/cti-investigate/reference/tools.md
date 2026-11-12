# intel.py reference (all external lookups)

`python scripts/intel.py <CASE> <service> <action> [target] [options]`. The output is a summary of at most 25 lines plus a `STUB {...}` provenance line.
- Exit 0: ok.
- Exit 2: UNKNOWN. Record it as an UNKNOWN entry using the printed STUB.
- Raw output goes to `Investigation Records/<CASE>/raw/`, with one line per call in `audit.log`.
- Rate limits are handled across parallel agents. VT has a 15 s gap (4/min public key) and crt.sh a 12 s gap.

| Need | Command |
|---|---|
| Redirect chain | `urlscan result <uuid>` (redirects) and `vt url <url>` (redirection_chain). WhereGoes has no API and rejects scripted use: `wheregoes trace <url>` prints a user step for a "Needs you" row |
| Existing urlscan captures | `urlscan search "page.domain:X OR domain:X"` (also `page.ip:IP`, `page.asn:AS123`, `hash:<sha256>`, `page.url:"path"`, `date:>now-30d`, `filename:x.js`) |
| Capture details (requests, XHR/POST, exfil, domains, IPs, verdict) | `urlscan result <uuid>` |
| Forms, scripts, tokens in the DOM | `urlscan dom <uuid>` |
| Screenshot (brand impersonated) | `urlscan shot <uuid>` (view the PNG with the Read tool) |
| Related sites by shared kit resources | `urlscan hashpivot <uuid> [--max 8]` |
| Fresh scan, always for every artifact URL (urlscan fetches) | `urlscan submit <url> --country il --mobile --compare <newest earlier uuid>` (default `--visibility unlisted`) |
| What changed between scans | `urlscan diff <old_uuid> <new_uuid>`: NEW domains, IPs, backend/XHR/POST calls, final page, hosting, certs, resource hashes |
| Subdomains (passive DB) | `viewdns subdomains <d>`. Free alternatives: crt.sh names and `vt domain <d> --rel subdomains` |
| Past IPs, co-hosted domains, same registrant, same NS or MX | `viewdns iphistory <d>`, `viewdns reverseip <ip>` (non-CDN only), `viewdns reversewhois "<email or name>"`, `viewdns reversens <ns>`, `viewdns reversemx <mx>` |
| Historical paths (second source) | `commoncrawl paths <d>` (latest index) |
| Quota | `urlscan quotas` |
| VT reputation and relations | `vt domain|ip|url|file X --rel resolutions,subdomains,communicating_files,referrer_files,historical_ssl_certificates,historical_whois,siblings` |
| VT URL submission (VT fetches) | `vt submit-url <url>` |
| Registration | `rdap domain X`, `rdap ip X`, `rdap asn AS123` |
| DNS (resolver query) | `dns lookup X` |
| Certificates | `crtsh domain X [--wildcard]`, then `python scripts/cert_pivot.py D1=<raw1> D2=<raw2>` |
| IP reputation | `abuseipdb check IP` |
| Malware and phishing feeds | `urlhaus host|url X`, `threatfox ioc X`, `otx domain|ip|url|file X` |
| Historical paths | `wayback cdx DOMAIN` |
| Bulk enrichment | `enrich all [--only vt,urlhaus,threatfox,otx,abuseipdb]` |

**Keys:** stored encrypted with DPAPI by the user, in their own terminal: `python scripts\keystore.py set NAME`. Names: VT_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_KEY, ABUSECH_KEY (URLhaus/ThreatFox), VIEWDNS_KEY, OTX_KEY (optional). Environment variables work only as a fallback.
- Never ask the user to paste a key into chat.
- Never run keystore code yourself; the hook denies it.
- ViewDNS: a trial key gives 250 queries in total, so spend them on decisive pivots. Its active tools (port scan, ping, traceroute, HTTP headers) are deliberately not wrapped.

**No route?** If a service is blocked or has no key, write a "Needs you" row with a command the user can run themselves (PowerShell, key read from their env var). For example:
`curl.exe -s -H "x-apikey: $env:VT_API_KEY" https://www.virustotal.com/api/v3/domains/DOMAIN -o vt_DOMAIN.json`
The user saves the output into `Investigation Records/<CASE>/raw/`, and the entry is recorded with `by: user`.

**Not available by default:** Shodan, Censys, SecurityTrails and DNSdumpster need keys or paid tiers. Use them only through the user, and treat them as UNKNOWN otherwise.

# ioc_index.py — cross-case IOC gateway

`python scripts/ioc_index.py <command>`. No network; reads/writes the vault-level graph `_index/ioc-index.json` (v2: Case → Observation → Finding; strong-class IOCs only; each observation has its own CONFIRMED/INFERRED label and active/superseded/retracted status, tombstoned never deleted) and `_index/cards/<CASE>.md`. Only active CONFIRMED observations score. The graph is derived and refreshed automatically (ingest / `phase DONE --confirmed` / `reopen`); a failed refresh prints a WARNING. A cross-case match is an **INFERRED** lead, never attribution; cases are never auto-merged (see core-policy and CLAUDE.md invariant 8).

| Need | Command |
|---|---|
| Check a case's current leads against every prior case | `match <CASE>` — prints linked candidate cases (score ≥ 2: a `hash`/`phone`/`secret` match scores 2, a `domain`/`ip` scores 1), the shared IOCs, and the path to load next: **Tier 1** the prior case's `report.md`, or (if `report: null`, case still open) its card + `case.py status`. Each hit also prints a machine `MATCH {...}` line. Never loads another case's working files — that's Tier 2, user-gated. Also prints `context:` lines (INFERRED/tombstoned overlaps, unscored), `B also links to C — indirect, not loaded` (one hop, informational, no Tier 1 path), and `index stale for: ...` if any case drifted. |
| Rebuild one case's observations | `index <CASE>` — full per-case rebuild (normally automatic via refresh; use after a manual repair). |
| Detect stale / unindexed / orphan cases | `verify` — compares sha256(state.json+evidence.json) with each case node; exit 2 if drift (repair: `reindex-all --include-open`). |
| (Re)generate the thin Obsidian case card | `card <CASE> [--alias "NAME"]` — frontmatter + a link to the report + anchor IOCs (active CONFIRMED) as `[[wikilinks]]` plus a `Context (not scored)` section in plain text; `--alias` binds a memorable campaign name (e.g. "CASA MAYA") to the folder id. |
| Backfill the whole vault | `reindex-all [--include-open]` — index + card every case folder (closed only, or add open cases). |
| Single-IOC query across the index | `lookup <type> <value>` (e.g. `lookup domain shemesh.me`). |

- Attacker-owned keys/tokens are indexable IOCs: add one as a pivot with `case.py add <value> --type secret` (the `secret` type is case-preserving and near-unique); once it's cited in a CONFIRMED entry it enters the index, shown masked in the card. The user's own keys are never indexed.
- `url` and `other` IOCs are never indexed (the host/domain is; URLs carry per-victim tokens). Shortener hosts are classed `shared` and never link cases.
