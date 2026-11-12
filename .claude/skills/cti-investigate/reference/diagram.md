# Attack-chain diagram

Propose nodes and edges in fragments. Ingest merges them into `findings.json` and regenerates `diagram.mmd`, using `scripts/cti_diagram.py`. Never hand-edit the .mmd file.

- **Node kinds:**
  - `confirmed` (blue): confirmed indicators.
  - `infra` (purple): hosting or infrastructure.
  - `leak` (red): data exposure, e.g. an RLS leak.
  - `suspect` (orange, dashed): founded but unconfirmed attribution.
- **Node ids:** letters, digits and underscore only, e.g. `SMS`, `SHORT`, `PAY`, `CF_IP`, `TGBOT`. Ids starting with `LEGEND` are reserved.
- **Labels:** defang URLs and domains (`pay-il[.]xyz`). Never include victim PII or full phone numbers. Don't name a real company outside a suspect node.
- **Edges:** every edge needs a `technique`, the method that produced it (WhereGoes, urlscan, urlscan hash pivot, RDAP, DNS, crt.sh shared cert, VirusTotal relation, AbuseIPDB, reverse-IP, Wayback, ...).
  - Unconfirmed links use `confidence: "inferred"`, drawn as a dotted arrow.
  - Shared-certificate and shared-hash links default to inferred.
- **Coverage:** every node and edge must be cited by an active evidence entry, through that entry's `nodes` field (`"PAY"` or `"SHORT>PAY"`). Ingest prints the gaps.
- **Legend:** the script adds the legend under the diagram. Wherever the diagram is shown as code, also print this line beneath it:
  `Legend: blue = confirmed indicators | purple = hosting/infra | red = data leak (e.g. RLS) | orange dashed = founded-but-unconfirmed attribution | arrow label = technique | dotted arrow = inferred link`
- **Rendering:** if `mmdc` exists, you can optionally render a PNG. Otherwise give the Mermaid code for mermaid.live.

## Reading shared-certificate results (cert_pivot.py)
- `SHARED-BETWEEN-TARGETS` with a small SAN list is a strong lead. It stays INFERRED until a second independent link turns up (registrar, IP, backend, hash).
- `OTHER-NAMES` gives candidate domains. Add them as suspect nodes with dashed edges, then pivot on them if they're worth it.
- `LARGE-SAN` means a shared platform or CDN, which is a weak link. The same CA alone proves nothing.
