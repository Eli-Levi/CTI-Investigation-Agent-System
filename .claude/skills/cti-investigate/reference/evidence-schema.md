# Evidence fragments and entries

Nobody edits `evidence.json`, `findings.json`, `evidence.md` or `diagram.mmd` by hand. Write a **fragment** to `Investigation Records/<CASE>/work/<TASK_ID>.json`; `evidence_ingest.py` is the only writer.

## Fragment
```json
{"task_id": "WEB-001",
 "entries": [ENTRY, ...],
 "updates": [{"id": "E-004", "label": "CONFIRMED", "note": "WEB-001-02 shows the same backend in a second scan"}],
 "nodes": [{"id": "PAY", "label": "pay-il[.]xyz\nphishing landing", "kind": "confirmed"}],
 "edges": [{"from": "SHORT", "to": "PAY", "technique": "WhereGoes", "confidence": "confirmed"}]}
```
- Local ids are `<TASK_ID>-NN` (e.g. `WEB-001-01`). You may reference them anywhere in the fragment (`superseded_by`, update notes). Ingest maps them to `E-xxx`.
- `updates` change existing E-entries. Allowed fields: `label`, `status` (active | superseded | retracted) and `superseded_by`. A `note` is required and is appended to the entry's history. Entries are never deleted.
- `nodes` and `edges` are proposals that ingest merges by id: a suspect node is upgraded when evidence confirms it, and inferred edges are upgraded to confirmed. Reuse existing node ids (check `findings.json` with Grep) when you mean the same thing.

## ENTRY (copy `found_in`, `reconfirm`, `raw_file` and `sha256` from the `STUB` line intel.py printed)
```json
{"id": "WEB-001-01", "claim": "Landing page POSTs card fields to a Telegram bot", "label": "CONFIRMED",
 "value": "verbatim text exactly as found (NOT defanged)",
 "found_in": {"tool": "urlscan.io result API", "query": "<exact request from STUB>", "location": "data.requests[14].request.url",
              "observed_at": "2026-11-06T10:22:31Z", "by": "claude"},
 "reconfirm": {"link": "https://urlscan.io/result/UUID/", "steps": "HTTP tab, request 14", "stability": "stable"},
 "nodes": ["PAY", "PAY>TGBOT"], "raw_file": "raw/urlscan_result_UUID_20261106T102231Z.json", "sha256": "<from STUB>"}
```
Every entry answers three questions:
- **WHAT** it is: `claim` (one line, no raw URLs), `value` (verbatim) and `label`.
- **WHERE** it was found: the `found_in` fields. Set `location` to the JSON path, hop number or line. `by` is `claude`, or `user` if the user pasted it (second-hand).
- **HOW to reconfirm it**: `reconfirm.link`, `steps` or `none_reason`, plus `stability`, which is one of `stable` (a permanent record), `volatile` (live DNS, WHOIS, reputation or page), `user-only` (needs the user's login) or `none`. Never invent a link. If you built a URL from a documented pattern without opening it, say so in `steps`.

**Uncensored means verbatim.** `value` holds the exact text found: full URLs (not defanged), domains, IPs, attacker phone numbers and display names, tokens or keys in the attacker's own client code, headers, JSON and Hebrew text. Never shorten, mask or paraphrase it. For long output, keep the full raw file and put the relevant excerpt in `value`. Only three things are held back:
1. Victim PII is never collected. Record the endpoint and field names only.
2. The user's own secrets.
3. Invisible, bidi and control characters, which the renderer shows as `<U+XXXX>`.

**UNKNOWN entries:** if intel.py prints `UNKNOWN: ...` plus a STUB, record an entry with `label: UNKNOWN`, `value` set to the error text, and that STUB's provenance.

**Labels:** CONFIRMED means directly observed in a cited source. INFERRED means a reasoned link, with its corroboration still missing; say what would confirm it in `claim` or in `reconfirm.steps`. UNKNOWN means it could not be determined.

`evidence.md` contains live attacker indicators. It is not safe to forward or publish as is, and `Investigation Records/` must stay out of Git.
