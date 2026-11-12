#!/usr/bin/env python3
"""Single writer for evidence.json / findings.json. Merges agent fragments from work/*.json.

usage: evidence_ingest.py CASE [--dry-run]

Fragment format (work/<TASK_ID>.json, written by an agent or the orchestrator):
{
  "task_id": "WEB-001",
  "entries": [ {evidence entry exactly as in evidence.json, but "id": "WEB-001-01" (local id)} ],
  "updates": [ {"id": "E-004", "label": "CONFIRMED", "status": "superseded", "superseded_by": "WEB-001-02",
                "note": "why (required)"} ],
  "nodes":   [ {"id": "PAY", "label": "pay-il[.]xyz\\nlanding", "kind": "confirmed|infra|leak|suspect"} ],
  "edges":   [ {"from": "SHORT", "to": "PAY", "technique": "urlscan", "confidence": "confirmed|inferred"} ]
}
- Local ids are mapped to the next free E-xxx (also inside superseded_by / history notes / claims).
- raw_file paths are relative to the case dir; sha256 is computed if missing, verified if present.
- Nodes merge by id (suspect -> other kind upgrades; label replaced only on upgrade); edges merge by from>to
  (inferred -> confirmed upgrades; techniques are combined).
- Invalid fragments are left in work/ with the error printed (exit 2); valid ones move to work/ingested/.
- Afterwards evidence.md is regenerated. diagram.mmd is NOT written here: it is generated only at case close,
  after the user confirms the investigation is complete (python scripts/cti_diagram.py findings.json -o diagram.mmd).
"""
import argparse, copy, glob, os, re, shutil, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctilib import CTIError, Lock, case_dir, read_json, sha256_file, utc, write_json
import evidence_doc
import cti_diagram
import ioc_index

LOCAL_RE = re.compile(r"\b[A-Z]{2,8}-\d{3}-\d{2,3}\b")
KIND_RANK = {"suspect": 0, "infra": 1, "confirmed": 1, "leak": 2}


class FragmentError(ValueError):
    pass


def next_num(entries):
    return max((int(e["id"][2:]) for e in entries if re.fullmatch(r"E-\d+", str(e.get("id")))), default=0) + 1


def remap(obj, idmap):
    if isinstance(obj, str):
        return LOCAL_RE.sub(lambda m: idmap.get(m.group(), m.group()), obj)
    if isinstance(obj, list):
        return [remap(x, idmap) for x in obj]
    if isinstance(obj, dict):
        return {k: (v if k in ("value", "query") else remap(v, idmap)) for k, v in obj.items()}  # never alter verbatim data
    return obj


def apply_fragment(frag, doc, fnd, base, num):
    if not isinstance(frag, dict) or not isinstance(frag.get("entries", []), list):
        raise FragmentError("fragment must be an object with an 'entries' list")
    idmap, new = {}, []
    for e in frag.get("entries", []):
        lid = e.get("id")
        if not isinstance(lid, str) or not LOCAL_RE.fullmatch(lid):
            raise FragmentError(f"entry id {lid!r} must be a local id like WEB-001-01")
        if lid in idmap:
            raise FragmentError(f"duplicate local id {lid}")
        idmap[lid] = f"E-{num:03d}"
        num += 1
    for e in frag.get("entries", []):
        e = remap(dict(e), idmap)  # local id -> E-xxx (also in superseded_by / history / claim)
        e.setdefault("status", "active")
        e.setdefault("history", [])
        rf = e.get("raw_file")
        if rf:
            p = os.path.realpath(os.path.join(base, rf))
            if not p.startswith(os.path.realpath(base) + os.sep) or not os.path.isfile(p):
                raise FragmentError(f"{e['id']}: raw_file {rf!r} missing or outside the case dir")
            now = sha256_file(p)
            if e.get("sha256") and e["sha256"].lower() != now:
                raise FragmentError(f"{e['id']}: HASH MISMATCH for {rf} (recorded {e['sha256'][:12]}.., now {now[:12]}..)")
            e["sha256"] = now
        new.append(e)
    doc["entries"].extend(new)
    by_id = {e["id"]: e for e in doc["entries"]}
    for u in frag.get("updates", []):
        u = remap(dict(u), idmap)
        tgt = by_id.get(u.get("id"))
        if not tgt:
            raise FragmentError(f"update targets unknown id {u.get('id')!r}")
        if not isinstance(u.get("note"), str) or not u["note"].strip():
            raise FragmentError(f"update of {u['id']} needs a 'note' explaining the new evidence")
        changes = []
        for k in ("label", "status", "superseded_by"):
            if k in u and u[k] != tgt.get(k):
                changes.append(f"{k} {tgt.get(k, '-')}->{u[k]}")
                tgt[k] = u[k]
        tgt.setdefault("history", []).append({"at": utc(), "note": f"{'; '.join(changes) or 'note'}: {u['note']}"})
    nodes = {n["id"]: n for n in fnd["nodes"]}
    for n in frag.get("nodes", []):
        old = nodes.get(n.get("id"))
        if old is None:
            fnd["nodes"].append(dict(n)); nodes[n["id"]] = fnd["nodes"][-1]
        elif KIND_RANK.get(n.get("kind"), 0) > KIND_RANK.get(old.get("kind"), 0) or (old.get("kind") == "suspect" and n.get("kind") != "suspect"):
            old.update(kind=n["kind"], label=n.get("label", old["label"]))
    edges = {(e["from"], e["to"]): e for e in fnd["edges"]}
    for e in frag.get("edges", []):
        old = edges.get((e.get("from"), e.get("to")))
        if old is None:
            fnd["edges"].append(dict(e)); edges[(e["from"], e["to"])] = fnd["edges"][-1]
        else:
            if e.get("confidence", "confirmed") == "confirmed":
                old["confidence"] = "confirmed"
            techs = [t.strip() for t in old["technique"].split("+")]
            if e.get("technique") and e["technique"] not in techs:
                old["technique"] = " + ".join(techs + [e["technique"]])
    return idmap, num, len(new), len(frag.get("updates", []))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case"); ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    try:
        d = case_dir(a.case)
    except CTIError as x:
        print(f"error: {x}", file=sys.stderr); return 1
    work, done = os.path.join(d, "work"), os.path.join(d, "work", "ingested")
    os.makedirs(done, exist_ok=True)
    rc = 0
    with Lock(os.path.join(d, "evidence.lock")):
        doc = read_json(os.path.join(d, "evidence.json"), {"title": a.case, "entries": []})
        fnd = read_json(os.path.join(d, "findings.json"), {"nodes": [], "edges": []})
        frags = sorted(glob.glob(os.path.join(work, "*.json")), key=lambda p: (os.path.getmtime(p), os.path.basename(p)))
        if not frags:
            print("no fragments to ingest")
        num = next_num(doc["entries"])
        for fp in frags:
            name = os.path.basename(fp)
            snapshot = copy.deepcopy((None, doc["entries"], fnd["nodes"], fnd["edges"]))
            try:
                frag = read_json(fp)
                idmap, num2, n_new, n_upd = apply_fragment(frag, doc, fnd, d, num)
                if doc["entries"]:
                    evidence_doc.validate(doc)
                if fnd["nodes"]:
                    cti_diagram.validate(fnd)
            except (FragmentError, evidence_doc.EvidenceError, cti_diagram.FindingsError, ValueError, KeyError, TypeError) as x:
                doc["entries"] = snapshot[1]; fnd["nodes"] = snapshot[2]; fnd["edges"] = snapshot[3]
                print(f"REJECTED {name}: {x}  (left in work/; fix and rerun)")
                rc = 2
                continue
            num = num2
            print(f"{name}: +{n_new} entries, {n_upd} updates; ids " + (", ".join(f"{k}={v}" for k, v in idmap.items()) or "-"))
            if not a.dry_run:
                shutil.move(fp, os.path.join(done, name))
        if a.dry_run:
            print("dry run: nothing written"); return rc
        write_json(os.path.join(d, "evidence.json"), doc)
        write_json(os.path.join(d, "findings.json"), fnd)
    # keep the cross-case IOC graph current (best-effort, outside the evidence lock, never changes rc)
    ioc_index.refresh(a.case)
    # regenerate working outputs (the Mermaid diagram is NOT written here; only at case close, after user confirmation)
    if doc["entries"]:
        md = evidence_doc.render(doc, d, fnd if fnd["nodes"] else None)
        with open(os.path.join(d, "evidence.md"), "w", encoding="utf-8") as fh:
            fh.write(md)
        if fnd["nodes"]:
            bad, gaps = evidence_doc.coverage(doc, fnd)
            print(f"coverage gaps: {', '.join(gaps) or 'none'}" + (f" | refs to unknown diagram items: {', '.join(bad)}" if bad else ""))
        if any(s in md for s in ("HASH MISMATCH", "FILE MISSING", "REJECTED (outside")):
            print("warning: raw-file problems, see evidence.md")
    print(f"total: {len(doc['entries'])} evidence entries, {len(fnd['nodes'])} nodes, {len(fnd['edges'])} edges")
    return rc


if __name__ == "__main__":
    sys.exit(main())
