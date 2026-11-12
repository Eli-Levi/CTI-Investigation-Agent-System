#!/usr/bin/env python3
"""Cross-case IOC gateway: a derived, continuously refreshed graph (Case -> Observation -> Finding).

The index (`Investigation Records/_index/ioc-index.json`, version 2) has three parts:
  nodes         case nodes (`case:<CASE>`) and finding nodes (`<type>:<value>`, strong-class only)
  observations  one per (case, finding): that case's evidence-backed sighting, with its own
                confidence label (CONFIRMED/INFERRED), lifecycle status (active/superseded/retracted)
                and a per-evidence map. Retracted/superseded ones are tombstoned, never deleted.
Only ACTIVE + CONFIRMED observations score toward a cross-case match. INFERRED observations,
tombstones and indirect (2-hop) links are context only, never a candidate. A match is an INFERRED
lead (never attribution) that loads the prior case's report, not its working record.
Case evidence stays authoritative; the graph is rebuildable (`reindex-all`), except the human
metadata on case nodes (aliases / cluster / verdict). See CLAUDE.md invariant 8, core-policy.md.

usage:
  ioc_index.py index CASE                 # full per-case rebuild of CASE's observations
  ioc_index.py match CASE                 # check CASE's leads against the graph -> cross-case leads
  ioc_index.py card CASE [--alias NAME]   # (re)index + regenerate the thin Obsidian case card
  ioc_index.py reindex-all [--include-open]
  ioc_index.py lookup TYPE VALUE          # single-IOC query: observations with label/status/E-ids
  ioc_index.py verify                     # detect stale / unindexed / orphan cases (exit 2 if any)
refresh(case) is called automatically by evidence_ingest, `case.py phase DONE --confirmed`, `reopen`.
exit: 0 ok, 1 usage/error, 2 verify found drift
"""
import argparse, hashlib, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctilib import (CTIError, INDEX_DIR, INVESTIGATIONS, Lock, case_dir, ioc_class, normalize,
                    read_json, undefang, utc, write_json)

# Match scoring: near-unique IOCs score 2 (one is enough to flag), reusable-but-dedicated ones 1
# (need two). shared/exclude never score. A prior case is a linked candidate at score >= 2.
WEIGHT = {"hash": 2, "phone": 2, "secret": 2, "domain": 1, "ip": 1}
THRESHOLD = 2
LEAD_NOTE = "cross-case overlap = INFERRED lead, not attribution (see core-policy)"
REPAIR = "ioc_index.py reindex-all --include-open"
RANK = {"CONFIRMED": 2, "INFERRED": 1}


def index_path():
    return os.path.join(INDEX_DIR, "ioc-index.json")


def _skeleton():
    return {"version": 2, "updated": utc(), "nodes": {}, "observations": {}}


def load_index():
    idx = read_json(index_path(), None)
    if idx is None:
        return _skeleton()
    if idx.get("version") == 2:
        idx.setdefault("nodes", {})
        idx.setdefault("observations", {})
        return idx
    # v1 -> v2: keep the human metadata (aliases/cluster/verdict), drop the derived iocs map.
    out = _skeleton()
    for case, meta in (idx.get("cases") or {}).items():
        out["nodes"][f"case:{case}"] = {
            "kind": "case", "case": case, "aliases": meta.get("aliases", []),
            "verdict": meta.get("verdict", "CONFIRMED"), "cluster": meta.get("cluster", ""),
            "report": meta.get("report"), "card": meta.get("card") or f"_index/cards/{case}.md"}
    return out


def _split(key):
    typ, _, val = key.partition(":")
    return typ, val


def _cited(typ, val, entry):
    """True if an evidence entry references this IOC value (verbatim working record). Domains and
    IPs match on token boundaries, so `a0r.me` is not cited by `xa0r.me` nor `ran.shemesh.me`
    citing `shemesh.me`."""
    hay = (entry.get("value", "") or "") + "\n" + (entry.get("claim", "") or "")
    if typ == "secret":
        return val in hay  # keys are case-sensitive; no undefang/lowercase
    hay = undefang(hay).lower()
    v = val.lower()
    if typ == "phone":
        digits = re.sub(r"\D", "", hay)
        vd = re.sub(r"\D", "", val)
        return len(vd) >= 9 and vd in digits
    if typ == "domain":
        return re.search(r"(?<![a-z0-9.-])" + re.escape(v) + r"(?![a-z0-9-]|\.[a-z0-9])", hay) is not None
    if typ == "ip":
        return re.search(r"(?<!\d)(?<!\d\.)" + re.escape(v) + r"(?!\d|\.\d)", hay) is not None
    return v in hay


def _defang(typ, val):
    if typ in ("domain", "url", "ip"):
        return re.sub(r"(?i)^http", "hxxp", val.replace(".", "[.]"))
    if typ == "secret":
        return (val[:6] + "…" + val[-4:]) if len(val) > 12 else "…"
    return val


def _secret_ref(val):
    return "secret-" + hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]


def _read_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return b""


def _fingerprint(d):
    """sha256 over state.json + evidence.json; one check catches failed refreshes and manual edits."""
    h = hashlib.sha256()
    for name in ("state.json", "evidence.json"):
        b = _read_bytes(os.path.join(d, name))
        h.update(name.encode() + b"\0" + b)
    return h.hexdigest()


def _derive(citers):
    """citers: {eid: {label, status, ...}} -> (label, status). Current evidence beats historical."""
    for want in ("CONFIRMED", "INFERRED"):
        if any(c["status"] == "active" and c["label"] == want for c in citers.values()):
            return want, "active"
    status = "retracted" if any(c["status"] == "retracted" for c in citers.values()) else "superseded"
    label = max((c["label"] for c in citers.values()), key=lambda l: RANK[l])
    return label, status


def _build_case(case):
    """Read the authoritative files once; return (state, source fingerprint, observations)."""
    d = case_dir(case)
    sb, eb = _read_bytes(os.path.join(d, "state.json")), _read_bytes(os.path.join(d, "evidence.json"))
    h = hashlib.sha256()
    for name, b in (("state.json", sb), ("evidence.json", eb)):
        h.update(name.encode() + b"\0" + b)
    s = json.loads(sb.decode("utf-8"))
    ev = json.loads(eb.decode("utf-8")) if eb else {"entries": []}
    entries = [e for e in ev.get("entries", []) if e.get("label") in RANK]  # UNKNOWN = not observed
    obs = {}
    for key, meta in s.get("seen", {}).items():
        typ, val = _split(key)
        if ioc_class(typ, val) != "strong":
            continue
        hits = [e for e in entries if e.get("id") and _cited(typ, val, e)]
        if not hits:
            continue
        citers = {}
        for e in hits:
            c = {"label": e["label"], "status": e.get("status", "active")}
            if e.get("superseded_by"):
                c["superseded_by"] = e["superseded_by"]
            citers[e["id"]] = c
        label, status = _derive(citers)
        det = [e for e in hits if e["label"] == label
               and (citers[e["id"]]["status"] == "active") == (status == "active")] or hits
        times = [e.get("found_in", {}).get("observed_at") for e in hits if e.get("found_in", {}).get("observed_at")]
        obs[key] = {
            "case": f"case:{case}", "finding": key, "label": label, "status": status,
            "evidence": citers,
            "nodes": sorted({n for e in hits for n in e.get("nodes", [])}),
            "first_seen": min(times) if times else meta.get("at", ""),
            "role": (det[0].get("claim", "") or "")[:80],
        }
    return s, h.hexdigest(), obs


def _case_node(case, s, source, prev):
    d = case_dir(case)
    closed = s.get("phase") in ("REPORT", "DONE")
    has_report = closed and os.path.isfile(os.path.join(d, "report.md"))
    return {
        "kind": "case", "case": case,
        "aliases": prev.get("aliases", []), "verdict": prev.get("verdict", "CONFIRMED"),
        "cluster": prev.get("cluster", ""), "phase": s.get("phase"),
        "closed_at": s.get("close_confirmed"),
        "report": f"{case}/report.md" if has_report else None,
        "card": f"_index/cards/{case}.md", "source": source, "indexed_at": utc(),
    }


def _strip_case(idx, case):
    cid = f"case:{case}"
    for oid in [o for o, v in idx["observations"].items() if v["case"] == cid]:
        del idx["observations"][oid]


def _gc_findings(idx):
    used = {v["finding"] for v in idx["observations"].values()}
    for nid in [n for n, v in idx["nodes"].items() if v.get("kind") == "finding" and n not in used]:
        del idx["nodes"][nid]


def _index_tx(case, new_aliases=()):
    """Full per-case rebuild in one transaction under the index lock. Returns the written index."""
    s, source, obs = _build_case(case)
    os.makedirs(INDEX_DIR, exist_ok=True)
    with Lock(os.path.join(INDEX_DIR, ".index.lock")):
        idx = load_index()
        _strip_case(idx, case)
        prev = idx["nodes"].get(f"case:{case}", {})
        node = _case_node(case, s, source, prev)
        node["aliases"] = list(dict.fromkeys(list(node["aliases"]) + list(new_aliases or [])))
        idx["nodes"][f"case:{case}"] = node
        for key, o in obs.items():
            typ, val = _split(key)
            idx["nodes"].setdefault(key, {"kind": "finding", "type": typ, "value": val, "class": ioc_class(typ, val)})
            idx["observations"][f"obs:{case}|{key}"] = o
        _gc_findings(idx)
        idx["version"] = 2
        idx["updated"] = utc()
        write_json(index_path(), idx)
    return idx


def _case_obs(idx, case):
    cid = f"case:{case}"
    return [o for o in idx["observations"].values() if o["case"] == cid]


def _scored(o):
    return o["status"] == "active" and o["label"] == "CONFIRMED"


def _write_card(case, idx):
    node = idx["nodes"].get(f"case:{case}", {})
    d = case_dir(case)
    s = read_json(os.path.join(d, "state.json"))
    aliases = node.get("aliases", [])
    obs = sorted(_case_obs(idx, case), key=lambda o: o["finding"])
    anchors = [o for o in obs if _scored(o)]
    context = [o for o in obs if not _scored(o)]
    date = (s.get("created", "") or "")[:10]
    report = node.get("report")
    report_line = (f"[Report](../../{case}/report.md)"
                   + (f" · [HE](../../{case}/report.he.md)" if os.path.isfile(os.path.join(d, "report.he.md")) else "")
                   ) if report else "_report pending (case still open)_"
    verdict = node.get("verdict", "CONFIRMED")
    lines = ["---", f"case: {case}"]
    if aliases:
        lines.append("aliases:")
        lines += [f"  - {al}" for al in aliases]
    lines += [f"date: {date}", f"verdict: {verdict}", f"cluster: {node.get('cluster', '')}", "tags: [cti/case]",
              "---", "", f"# {case}" + (f" (aka {', '.join(aliases)})" if aliases else ""), "",
              f"**Source of truth:** {report_line}", "",
              f"**Verdict:** {verdict}" + (" · CLOSED" if s.get("phase") in ("REPORT", "DONE") else f" · phase {s.get('phase')}"),
              "", "## Anchor IOCs (gateway)", ""]
    if anchors:
        for o in anchors:
            typ, val = _split(o["finding"])
            link, shown = (_secret_ref(val), _defang(typ, val)) if typ == "secret" else (_defang(typ, val),) * 2
            eids = ", ".join(sorted(o["evidence"]))
            lines.append(f"- `{typ}` [[{link}]] — {shown} ({o['label']}" + (f", {eids}" if eids else "") + ")")
    else:
        lines.append("_no CONFIRMED strong IOCs yet_")
    lines += ["", "## Context (not scored)", ""]
    if context:
        for o in context:  # plain defanged text, NO wikilinks: the graph must not connect on these
            typ, val = _split(o["finding"])
            lines.append(f"- `{typ}` {_defang(typ, val)} — {o['label']} {o['status']} ({', '.join(sorted(o['evidence']))})")
    else:
        lines.append("_none_")
    lines += ["", "## Links", "", "_cross-case ties, confirmed by the operator, go here_", ""]
    os.makedirs(os.path.join(INDEX_DIR, "cards"), exist_ok=True)
    card_path = os.path.join(INDEX_DIR, "cards", f"{case}.md")
    tmp = card_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    os.replace(tmp, card_path)
    return card_path, len(anchors), len(context)


def refresh(case):
    """Best-effort index + card refresh. Never raises, never changes the caller's exit code."""
    try:
        _write_card(case, _index_tx(case))
        return True
    except Exception as e:  # noqa: BLE001 - deliberately broad: must never block the main operation
        print(f"WARNING: IOC index refresh failed for {case}: {e} — index is stale for this case; run {REPAIR}")
        return False


def _case_folders():
    if not os.path.isdir(INVESTIGATIONS):
        return []
    return [n for n in sorted(os.listdir(INVESTIGATIONS)) if not n.startswith(("_", "."))
            and os.path.isfile(os.path.join(INVESTIGATIONS, n, "state.json"))]


def _drift(idx):
    """-> (stale, unindexed, orphan) comparing each case node's fingerprint with the live files."""
    folders = _case_folders()
    stale, unindexed = [], []
    for n in folders:
        node = idx["nodes"].get(f"case:{n}")
        if node is None:
            unindexed.append(n)
        elif node.get("source") != _fingerprint(os.path.join(INVESTIGATIONS, n)):
            stale.append(n)
    orphan = [v["case"] for k, v in idx["nodes"].items() if v.get("kind") == "case" and v["case"] not in folders]
    return stale, unindexed, orphan


def _scores(idx, keys, exclude):
    """Score `keys` (finding ids) against active CONFIRMED observations, plus unscored context."""
    by_finding = {}
    for o in idx["observations"].values():
        by_finding.setdefault(o["finding"], []).append(o)
    scores, ctx = {}, {}
    for key in keys:
        typ, _ = _split(key)
        for o in by_finding.get(key, []):
            oc = o["case"].split(":", 1)[1]
            if oc in exclude:
                continue
            if _scored(o):
                row = scores.setdefault(oc, {"score": 0, "shared": []})
                row["score"] += WEIGHT.get(typ, 0)
                row["shared"].append((typ, _split(key)[1], o["label"]))
            else:
                c = ctx.setdefault(oc, {})
                tag = "INFERRED" if o["status"] == "active" else o["status"]
                c[tag] = c.get(tag, 0) + 1
    return scores, ctx


def _ctx_line(oc, c):
    order = ("INFERRED", "retracted", "superseded")
    parts = ", ".join(f"{c[t]} {t}" for t in order if t in c)
    return f"context: {parts} overlap(s) with {oc} (not scored)"


def _aka(idx, oc):
    al = idx["nodes"].get(f"case:{oc}", {}).get("aliases")
    return (" aka " + ", ".join(al)) if al else ""


def cmd_index(a):
    case_dir(a.case)  # validates id + existence
    idx = _index_tx(a.case)
    n = len([o for o in _case_obs(idx, a.case) if _scored(o)])
    total = len(_case_obs(idx, a.case))
    print(f"indexed {a.case}: {n} active CONFIRMED / {total} observation(s)"
          + ("; report linked" if idx["nodes"][f"case:{a.case}"]["report"] else "; report pending (case open)"))


def cmd_match(a):
    case = a.case
    s = read_json(os.path.join(case_dir(case), "state.json"))
    idx = load_index()
    stale, unindexed, _ = _drift(idx)
    bad = [c for c in stale + unindexed if c != case]
    if bad:
        print(f"index stale for: {', '.join(bad)} → run {REPAIR}")
    scores, ctx = _scores(idx, s.get("seen", {}), {case})
    candidates = {oc: v for oc, v in scores.items() if v["score"] >= THRESHOLD}
    if not candidates:
        print(f"match {case}: no strong cross-case overlap ({len(scores)} case(s) shared <{THRESHOLD}-weight)")
        for oc in sorted(ctx):
            print(f"  {_ctx_line(oc, ctx[oc])}")
        return
    print(f"match {case}: {len(candidates)} linked candidate case(s) [{LEAD_NOTE}]")
    for oc in sorted(candidates, key=lambda k: -candidates[k]["score"]):
        row, node = candidates[oc], idx["nodes"].get(f"case:{oc}", {})
        shared = "; ".join(f"{t}:{_defang(t, v)} ({lbl})" for t, v, lbl in row["shared"])
        report = node.get("report")
        load = (f"Tier 1 -> Read {report}" if report else
                f"Tier 1 pending (case open) -> Read {node.get('card') or 'card'} + `case.py status {oc}`")
        print(f"  {oc}{_aka(idx, oc)}  score {row['score']}  shared: {shared}")
        print(f"     {load}")
        print("     " + json.dumps({"MATCH": {"case": oc, "score": row["score"], "report": report,
                                              "card": node.get("card"),
                                              "shared": [[t, v] for t, v, _ in row["shared"]]}},
                                    ensure_ascii=False))
        if oc in ctx:
            print(f"     {_ctx_line(oc, ctx[oc])}")
    # indirect (2-hop): exactly one hop beyond the direct candidates, graph only, never recursive
    for oc in sorted(candidates):
        keys = [o["finding"] for o in _case_obs(idx, oc) if _scored(o)]
        s2, _ = _scores(idx, keys, {case, *candidates})
        for c2 in sorted(s2, key=lambda k: -s2[k]["score"]):
            if s2[c2]["score"] >= THRESHOLD:
                print(f"  {oc} also links to {c2}{_aka(idx, c2)} (score {s2[c2]['score']}) — indirect, not loaded")
    for oc in sorted(set(ctx) - set(candidates)):
        print(f"  {_ctx_line(oc, ctx[oc])}")


def cmd_card(a):
    case_dir(a.case)
    idx = _index_tx(a.case, a.alias or [])
    path, n, c = _write_card(a.case, idx)
    print(f"card -> {os.path.relpath(path, INVESTIGATIONS)} ({n} anchor IOC(s), {c} context)")


def cmd_reindex_all(a):
    done = []
    for name in _case_folders():
        s = read_json(os.path.join(INVESTIGATIONS, name, "state.json"))
        if s.get("phase") not in ("REPORT", "DONE") and not a.include_open:
            continue
        _write_card(name, _index_tx(name))
        done.append(name)
    print(f"reindexed {len(done)} case(s): {', '.join(done) or 'none'}")


def cmd_lookup(a):
    val, typ = normalize(a.value, a.type)
    key = f"{typ}:{val}"
    idx = load_index()
    obs = [o for o in idx["observations"].values() if o["finding"] == key]
    if not obs:
        print(f"lookup {key}: not in index")
        return
    print(f"lookup {key} (class {idx['nodes'].get(key, {}).get('class')}): {len(obs)} observation(s)")
    for o in obs:
        oc = o["case"].split(":", 1)[1]
        print(f"  {oc}{_aka(idx, oc)}: {o['label']} {o['status']} {', '.join(sorted(o['evidence']))}".rstrip())


def cmd_verify(a):
    stale, unindexed, orphan = _drift(load_index())
    for name, lst in (("stale", stale), ("unindexed", unindexed), ("orphan", orphan)):
        if lst:
            print(f"{name}: {', '.join(lst)}")
    print(f"verify: {len(stale)} stale / {len(unindexed)} unindexed / {len(orphan)} orphan")
    if stale or unindexed or orphan:
        print(f"repair: {REPAIR}")
        return 2
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ("index", "match"):
        sp.add_parser(name).add_argument("case")
    p = sp.add_parser("card"); p.add_argument("case")
    p.add_argument("--alias", action="append", help="memorable campaign name; repeatable")
    p = sp.add_parser("reindex-all"); p.add_argument("--include-open", action="store_true")
    p = sp.add_parser("lookup"); p.add_argument("type"); p.add_argument("value")
    sp.add_parser("verify")
    a = ap.parse_args(argv)
    fn = {"index": cmd_index, "match": cmd_match, "card": cmd_card, "reindex-all": cmd_reindex_all,
          "lookup": cmd_lookup, "verify": cmd_verify}[a.cmd]
    try:
        return fn(a) or 0
    except CTIError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
