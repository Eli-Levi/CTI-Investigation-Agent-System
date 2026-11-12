#!/usr/bin/env python3
# usage: cert_pivot.py DOMAIN=crtsh.json [DOMAIN=crtsh.json ...]
import json, re, sys
HOST = re.compile(r"^(\*\.)?([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")
DOM = re.compile(r"^[a-z0-9][a-z0-9.-]{2,252}$")
MAX_BYTES, BIG = 5_000_000, 25
class PivotError(ValueError): pass

def load(path):
    with open(path, "rb") as fh: raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise PivotError(f"{path}: too large")
    try: rows = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as x:
        raise PivotError(f"{path}: not valid JSON ({x}); crt.sh may have failed: result is UNKNOWN, not negative") from x
    if not isinstance(rows, list) or not rows:
        raise PivotError(f"{path}: empty result: UNKNOWN, not negative; retry later")
    return rows

def names_of(r):
    raw = str(r.get("name_value", "")).split("\n") + [str(r.get("common_name", ""))]
    return {n.strip().lower() for n in raw if HOST.match(n.strip().lower())}

def pivot(sources):
    certs = {}
    for dom, rows in sources.items():
        for r in rows:
            if not isinstance(r, dict): continue
            ser = re.sub(r"[^0-9a-fA-F]", "", str(r.get("serial_number")))[:64]
            ca = re.sub(r"[^0-9]", "", str(r.get("issuer_ca_id")))[:12]
            c = certs.setdefault((ca, ser), {"names": set(), "targets": set(), "nb": ""})
            c["names"] |= names_of(r); c["targets"].add(dom)
            c["nb"] = max(c["nb"], re.sub(r"[^0-9-]", "", str(r.get("not_before", "")))[:10])
    return certs

def inside(n, dom): return n == dom or n == "*." + dom or n.endswith("." + dom)

def report(sources):
    certs, doms = pivot(sources), list(sources)
    out = ["serial | issued | targets | names | flags | names outside targets"]
    for (ca, ser), c in sorted(certs.items(), key=lambda kv: kv[1]["nb"], reverse=True):
        outside = sorted(n for n in c["names"] if not any(inside(n, d) for d in doms))
        flags = []
        if len(c["targets"]) > 1: flags.append("SHARED-BETWEEN-TARGETS")
        if outside: flags.append("OTHER-NAMES")
        if len(c["names"]) > BIG: flags.append("LARGE-SAN(shared platform/CDN likely: weak)")
        if flags:
            out.append(f"{ser[:16]} | {c['nb']} | {','.join(sorted(c['targets']))} | {len(c['names'])} | {' '.join(flags)} | {', '.join(outside[:15])}")
    if len(out) == 1: out.append("none in the fetched data (this is not proof of absence)")
    return "\n".join(out)

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: cert_pivot.py DOMAIN=crtsh.json ...", file=sys.stderr); return 1
    try:
        src = {}
        for a in argv:
            dom, sep, path = a.partition("=")
            dom = dom.strip().lower()
            if not sep or not DOM.match(dom): raise PivotError(f"bad argument (want DOMAIN=file): {a!r}")
            src[dom] = load(path)
        print(report(src))
    except (PivotError, OSError) as x:
        print(f"error: {x}", file=sys.stderr); return 1
    return 0

if __name__ == "__main__": sys.exit(main())
