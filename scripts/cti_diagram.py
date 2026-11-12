#!/usr/bin/env python3
# usage: cti_diagram.py findings.json [-o out.mmd]
import argparse, json, re, sys
KINDS = {"confirmed", "infra", "leak", "suspect"}
CONF = {"confirmed", "inferred"}
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,40}$")
MAX_BYTES = 1_000_000
CLASSDEFS = (
    "classDef confirmed fill:#dbeafe,stroke:#2563eb,color:#0b2a6b;",
    "classDef infra fill:#ede9fe,stroke:#7c3aed,color:#3b0d6b;",
    "classDef suspect fill:#fff7ed,stroke:#ea580c,color:#7a2e0b,stroke-dasharray:5 3;",
    "classDef leak fill:#fee2e2,stroke:#dc2626,color:#7f1d1d;",
)
LEGEND = (("confirmed", "Confirmed indicator"), ("infra", "Hosting / infrastructure"),
          ("leak", "Data leak / exposure"), ("suspect", "Founded, unconfirmed attribution"))
class FindingsError(ValueError): pass

def esc(t, f):
    if not isinstance(t, str) or not t.strip():
        raise FindingsError(f"{f} must be a non-empty string")
    for a, b in (("&", "#amp;"), ('"', "#quot;"), ("<", "#lt;"), (">", "#gt;"),
                 ("`", "#96;"), ("|", "#124;")):
        t = t.replace(a, b)
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", t)
    return t.replace("\n", "<br/>")

def validate(d):
    if not isinstance(d, dict): raise FindingsError("top level must be an object")
    nodes, edges = d.get("nodes"), d.get("edges", [])
    if not isinstance(nodes, list) or not nodes: raise FindingsError("'nodes' must be a non-empty list")
    if not isinstance(edges, list): raise FindingsError("'edges' must be a list")
    ids = set()
    for n in nodes:
        if not isinstance(n, dict): raise FindingsError("each node must be an object")
        i = n.get("id")
        if not isinstance(i, str) or not ID_RE.match(i) or i.upper().startswith("LEGEND"):
            raise FindingsError(f"invalid node id: {i!r}")
        if i in ids: raise FindingsError(f"duplicate node id: {i}")
        if n.get("kind") not in KINDS: raise FindingsError(f"node {i}: kind must be one of {sorted(KINDS)}")
        ids.add(i)
    for e in edges:
        if not isinstance(e, dict): raise FindingsError("each edge must be an object")
        for end in ("from", "to"):
            if e.get(end) not in ids: raise FindingsError(f"edge references unknown node: {e.get(end)!r}")
        if not isinstance(e.get("technique"), str) or not e["technique"].strip():
            raise FindingsError(f"edge {e['from']}->{e['to']}: technique is required")
        if e.get("confidence", "confirmed") not in CONF:
            raise FindingsError(f"edge {e['from']}->{e['to']}: bad confidence")

def deepest(d):
    """Node at the greatest depth, so the legend lands below the whole chart (cycle-safe)."""
    depth = {n["id"]: 0 for n in d["nodes"]}
    for _ in range(len(depth)):
        for e in d.get("edges", []):
            depth[e["to"]] = max(depth[e["to"]], min(depth[e["from"]] + 1, len(depth)))
    return max(reversed(d["nodes"]), key=lambda n: depth[n["id"]])["id"]  # ties: last node

def build(d, legend=True):
    validate(d)
    o = ["flowchart TB"]
    for n in d["nodes"]:
        o.append(f'  {n["id"]}["{esc(n["label"], "label of " + n["id"])}"]')
    for e in d.get("edges", []):
        a = "-.->" if e.get("confidence", "confirmed") == "inferred" else "-->"
        o.append(f'  {e["from"]} {a}|"{esc(e["technique"], "technique")}"| {e["to"]}')
    o += ["  " + c for c in CLASSDEFS]
    for k in ("confirmed", "infra", "leak", "suspect"):
        m = [n["id"] for n in d["nodes"] if n["kind"] == k]
        if m: o.append(f'  class {",".join(m)} {k};')
    if legend:
        o.append(f"  {deepest(d)} ~~~ LEGEND_title")
        o.append('  LEGEND_title["Legend"]')
        for k, t in LEGEND: o.append(f'  {deepest(d)} ~~~ LEGEND_{k}\n  LEGEND_{k}["{t}"]')
        o.append('  LEGEND_arrows["Arrow label = technique used<br/>Dotted arrow = inferred link"]')
        o.append(f"  {deepest(d)} ~~~ LEGEND_arrows")
        o.append("  classDef legendnote fill:#f8fafc,stroke:#94a3b8,color:#334155;")
        o.append("  classDef legendtitle fill:none,stroke:none,color:#334155,font-weight:bold;")
        o.append("  class LEGEND_arrows legendnote;\n  class LEGEND_title legendtitle;")
        for k, _ in LEGEND: o.append(f"  class LEGEND_{k} {k};")
    return "\n".join(o) + "\n"

def load(p):
    with open(p, "rb") as fh: raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise FindingsError("findings file too large")
    try: return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as x: raise FindingsError(f"cannot parse JSON: {x}") from x

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("findings"); ap.add_argument("-o", "--output")
    ap.add_argument("--no-legend", action="store_true")
    a = ap.parse_args(argv)
    try: mmd = build(load(a.findings), legend=not a.no_legend)
    except (FindingsError, OSError) as x:
        print(f"error: {x}", file=sys.stderr); return 1
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh: fh.write(mmd)
    else: sys.stdout.write(mmd)
    return 0

if __name__ == "__main__": sys.exit(main())
