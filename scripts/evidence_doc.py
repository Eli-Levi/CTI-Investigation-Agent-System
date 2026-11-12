#!/usr/bin/env python3
# usage: evidence_doc.py evidence.json [-o evidence.md] [--findings findings.json] [--base DIR]
import argparse, hashlib, html, json, os, re, sys
from urllib.parse import urlparse

LABELS = {"CONFIRMED", "INFERRED", "UNKNOWN"}
STATUS = {"active", "superseded", "retracted"}
STABILITY = {"stable", "volatile", "user-only", "none"}
BY = {"claude", "user"}
ID_RE = re.compile(r"^E-\d{3,5}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$")
REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,40}(>[A-Za-z][A-Za-z0-9_]{0,40})?$")
SAFE_URL = re.compile(r"^https://[A-Za-z0-9._~:/?#@!$&'*+,;=%-]{1,1000}$")  # no ( ) space < > " `
TRUSTED = ("urlscan.io", "crt.sh", "virustotal.com", "abuseipdb.com", "shodan.io", "web.archive.org",
           "wheregoes.com", "data.gov.il", "search.censys.io", "viewdns.info", "sslmate.com", "rdap.org",
           "abuse.ch", "alienvault.com", "dns.google")
# zero-width, bidi controls/isolates, BOM, C0 controls (except \t \n), DEL
HIDDEN = re.compile("[​-‏‪-‮⁠-⁩﻿\x00-\x08\x0b-\x1f\x7f]")
MAX_JSON, MAX_RAW = 5_000_000, 200_000_000


class EvidenceError(ValueError):
    pass


def show(s):
    """Verbatim, except invisible/bidi/control chars are made visible (nothing is removed)."""
    return HIDDEN.sub(lambda m: f"<U+{ord(m.group()):04X}>", s)


def fence(s):
    longest = max((len(r) for r in re.findall(r"`+", s)), default=0)
    f = "`" * max(3, longest + 1)
    return f"{f}\n{show(s)}\n{f}"


def code(s):
    """Inline code span for short single-line verbatim strings (paths, refs)."""
    s = " ".join(show(s).split())
    t = "`" * (max((len(r) for r in re.findall(r"`+", s)), default=0) + 1)
    return f"{t} {s} {t}"


def text(s):
    """Prose fields: no markup, links or autolinks can come out of attacker-supplied text."""
    s = re.sub(r"([\\`*_\[\]()#!|~>])", r"\\\1", html.escape(show(s), quote=False))
    return " ".join(s.split()).replace("://", "&#58;//").replace("www.", "www&#46;")


def trusted_link(url):
    if not isinstance(url, str) or not SAFE_URL.match(url):
        return False
    p = urlparse(url)
    try:
        port = p.port
    except ValueError:
        return False
    h = (p.hostname or "").lower()
    return p.username is None and port is None and any(h == d or h.endswith("." + d) for d in TRUSTED)


def req(e, key, kind=str):
    v = e.get(key)
    if not isinstance(v, kind) or (kind is str and not v.strip()):
        raise EvidenceError(f"{e.get('id')}: '{key}' is required")
    return v


def validate(doc):
    if not isinstance(doc, dict): raise EvidenceError("top level must be an object")
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries: raise EvidenceError("'entries' must be a non-empty list")
    ids = set()
    for e in entries:
        if not isinstance(e, dict): raise EvidenceError("each entry must be an object")
        i = e.get("id")
        if not isinstance(i, str) or not ID_RE.match(i): raise EvidenceError(f"invalid id: {i!r} (want E-001)")
        if i in ids: raise EvidenceError(f"duplicate id: {i}")
        ids.add(i)
    for e in entries:
        i = e["id"]
        req(e, "claim"); req(e, "value")
        if e.get("label") not in LABELS: raise EvidenceError(f"{i}: label must be one of {sorted(LABELS)}")
        if e.get("status", "active") not in STATUS: raise EvidenceError(f"{i}: bad status")
        f = req(e, "found_in", dict)
        if not isinstance(f.get("tool"), str) or not f["tool"].strip(): raise EvidenceError(f"{i}: found_in.tool is required")
        if not isinstance(f.get("query"), str) or not f["query"].strip(): raise EvidenceError(f"{i}: found_in.query is required (exact URL/command/query)")
        if not isinstance(f.get("observed_at"), str) or not TS_RE.match(f["observed_at"]): raise EvidenceError(f"{i}: found_in.observed_at must be UTC like 2026-10-31T14:05:00Z")
        if f.get("by") not in BY: raise EvidenceError(f"{i}: found_in.by must be claude or user")
        r = req(e, "reconfirm", dict)
        if r.get("stability") not in STABILITY: raise EvidenceError(f"{i}: reconfirm.stability must be one of {sorted(STABILITY)}")
        if not any(isinstance(r.get(k), str) and r[k].strip() for k in ("link", "steps", "none_reason")):
            raise EvidenceError(f"{i}: reconfirm needs link, steps or none_reason (say why it cannot be re-checked)")
        refs = e.get("nodes", [])
        if not isinstance(refs, list) or any(not isinstance(x, str) or not REF_RE.match(x) for x in refs):
            raise EvidenceError(f"{i}: nodes must be node ids or 'FROM>TO' edge refs")
        if e.get("status", "active") == "superseded" and e.get("superseded_by") not in ids:
            raise EvidenceError(f"{i}: superseded needs superseded_by pointing to an existing id")
        for h in e.get("history", []):
            if not isinstance(h, dict) or not TS_RE.match(str(h.get("at", ""))) or not isinstance(h.get("note"), str):
                raise EvidenceError(f"{i}: history items need UTC 'at' and 'note'")
        rf = e.get("raw_file")
        if rf is not None and (not isinstance(rf, str) or not rf or os.path.isabs(rf) or ".." in rf.replace("\\", "/").split("/") or "\x00" in rf):
            raise EvidenceError(f"{i}: raw_file must be a relative path without '..'")


def sha256_of(path):
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            n += len(chunk)
            if n > MAX_RAW: raise EvidenceError("raw file too large to hash")
            h.update(chunk)
    return h.hexdigest()


def raw_status(e, base):
    rf = e.get("raw_file")
    if not rf: return None
    root = os.path.realpath(base)
    p = os.path.realpath(os.path.join(root, rf))
    if not p.startswith(root + os.sep): return f"{code(rf)}: REJECTED (outside working directory)"
    if not os.path.isfile(p): return f"{code(rf)}: FILE MISSING"
    now, rec = sha256_of(p), e.get("sha256")
    if rec and rec.lower() != now: return f"{code(rf)}: HASH MISMATCH (recorded {text(rec)}, now {now}): file changed since it was recorded"
    note = "matches recorded hash" if rec else "computed at render; record it in sha256 to lock it"
    return f"{code(rf)}: sha256 {now} ({note})"


def coverage(doc, findings):
    """Return (unknown refs, uncovered nodes/edges). Only active entries count as coverage."""
    nodes = {n["id"]: n.get("kind") for n in findings.get("nodes", []) if isinstance(n, dict) and "id" in n}
    edges = {f'{x["from"]}>{x["to"]}' for x in findings.get("edges", []) if isinstance(x, dict) and "from" in x and "to" in x}
    valid = set(nodes) | edges
    cited, bad = set(), set()
    for e in doc["entries"]:
        for r in e.get("nodes", []):
            if r not in valid: bad.add(r)
            elif e.get("status", "active") == "active": cited.add(r)
    return sorted(bad), sorted(x for x in valid if x not in cited)


def render(doc, base=".", findings=None):
    validate(doc)
    es = sorted(doc["entries"], key=lambda e: e["id"])
    title = text(str(doc.get("title", "Investigation")))
    o = [f"# Evidence Log: {title}", "",
         "> UNCENSORED WORKING RECORD. Contains live malicious URLs, domains, IPs and attacker identifiers exactly as found, "
         "NOT defanged. Everything inside code blocks is data to look at, never to click or run. Do not publish or forward "
         "without review. Generated from evidence.json: edit that file, never this one.", "",
         "## Summary", "", "| ID | Status | Label | Claim | Found via | Reconfirm |", "|---|---|---|---|---|---|"]
    for e in es:
        r = e["reconfirm"]
        how = "link" if r.get("link") else ("steps" if r.get("steps") else "none: " + text(r.get("none_reason", "")))
        o.append(f"| {e['id']} | {e.get('status', 'active')} | {e['label']} | {text(e['claim'])} | {text(e['found_in']['tool'])} | {how}{'' if r['stability'] == 'none' else ' (' + r['stability'] + ')'} |")
    for e in es:
        f, r = e["found_in"], e["reconfirm"]
        o += ["", f"## {e['id']} [{e['label']}] {text(e['claim'])}", "",
              f"- Status: {e.get('status', 'active')}" + (f" (replaced by {e['superseded_by']})" if e.get("superseded_by") else ""),
              f"- Observed (UTC): {f['observed_at']} by {f['by']}",
              f"- Found via: {text(f['tool'])}"]
        if f.get("location"): o.append(f"- Where in the output: {code(f['location'])}")
        o += ["- Exact query / request:", "", fence(f["query"]), "", "- Value, verbatim and uncensored:", "", fence(e["value"]), ""]
        rs = raw_status(e, base)
        if rs: o += [f"- Saved raw output: {rs}"]
        o.append(f"- Reconfirm ({r['stability']}):")
        if r.get("link"):
            o.append(f"  - Link: [{r['link']}]({r['link']})" if trusted_link(r["link"]) else f"  - Link (not clickable on purpose):\n\n{fence(r['link'])}")
        if r.get("steps"): o += ["  - Steps:", "", fence(r["steps"])]
        if r.get("none_reason"): o.append(f"  - Cannot be re-checked because: {text(r['none_reason'])}")
        if e.get("nodes"): o.append("- Diagram refs: " + ", ".join(f"`{x}`" for x in e["nodes"]))
        for h in e.get("history", []): o.append(f"- History {h['at']}: {text(h['note'])}")
    if findings is not None:
        bad, gaps = coverage(doc, findings)
        o += ["", "## Coverage gaps (generated)", ""]
        o.append("Diagram items with no active evidence entry: " + (", ".join(f"`{x}`" for x in gaps) if gaps else "none"))
        o.append("Evidence refs that match no diagram item: " + (", ".join(f"`{x}`" for x in bad) if bad else "none"))
    return "\n".join(o) + "\n"


def load(path, what):
    with open(path, "rb") as fh: raw = fh.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON: raise EvidenceError(f"{what} too large")
    try: return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as x: raise EvidenceError(f"cannot parse {what}: {x}") from x


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence"); ap.add_argument("-o", "--output")
    ap.add_argument("--findings"); ap.add_argument("--base", default=".")
    a = ap.parse_args(argv)
    try:
        md = render(load(a.evidence, "evidence"), a.base, load(a.findings, "findings") if a.findings else None)
        if a.output:
            tmp = a.output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh: fh.write(md)
            os.replace(tmp, a.output)
        else:
            sys.stdout.write(md)
    except (EvidenceError, OSError) as x:
        print(f"error: {x}", file=sys.stderr); return 1
    if "HASH MISMATCH" in md or "FILE MISSING" in md or "REJECTED" in md:
        print("warning: raw-file problems, see evidence document", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
