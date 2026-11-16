#!/usr/bin/env python3
"""Summarise logs/*.jsonl (written by .claude/hooks/telemetry.py and ctilib.tlog).

usage: python scripts/log_report.py [--since 2026-11-16] [--session ID] [--json]
Sections: token usage by model/source, tool frequency + failure rate + latency + result size,
failures/errors, network destinations (scripts/ -> intel services), guard decisions, subagent runs.
Stdlib only; reads logs only (no case data, no keys).
"""
import argparse, collections, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctilib import LOG_DIR


def load(stream, since, session):
    p = os.path.join(LOG_DIR, stream + ".jsonl")
    out = []
    if os.path.isfile(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if since and r.get("ts", "") < since:
                continue
            if session and r.get("session") not in (None, session):
                continue
            out.append(r)
    return out


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


def table(rows, head):
    if not rows:
        print("  (none)")
        return
    w = [max(len(str(x)) for x in col) for col in zip(head, *rows)]
    for r in [head] + rows:
        print("  " + "  ".join(str(c).ljust(w[i]) if i == 0 else str(c).rjust(w[i]) for i, c in enumerate(r)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since")
    ap.add_argument("--session")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sessions", action="store_true", help="list sessions (id, start, title, cases) and exit")
    a = ap.parse_args()
    if a.sessions or a.session:  # same session index the Grafana API uses (monitoring/log_api.py)
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitoring"))
        import datetime, log_api
        idx = log_api.session_index(LOG_DIR)
        if a.session:  # accept a unique prefix
            hits = [k for k in idx if k.startswith(a.session)]
            if len(hits) != 1:
                sys.exit(f"--session {a.session!r}: {'no match' if not hits else 'ambiguous'}; run --sessions to list ids")
            a.session = hits[0]
        if a.sessions:
            f = lambda ms: datetime.datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M")  # noqa: E731
            rows = [[k, f(e["started"]), f(e["last_seen"]), e["title"] or "(untitled)", ", ".join(sorted(e["cases"])) or "-",
                     e["api_calls"], e["tool_calls"]] for k, e in sorted(idx.items(), key=lambda kv: -kv[1]["started"])]
            table(rows, ["session", "started", "last_seen", "title", "cases", "api_calls", "tool_calls"])
            return
    usage_raw, tools = load("usage", a.since, a.session), load("tools", a.since, a.session)
    net, guard, errs, events = (load(s, a.since, a.session) for s in ("network", "guard", "errors", "events"))

    uniq = {}
    for u in usage_raw:  # dedupe repeated ingestion of the same API call
        k = u.get("msg_id")
        if k not in uniq or u.get("output_tokens", 0) >= uniq[k].get("output_tokens", 0):
            uniq[k] = u
    usage = list(uniq.values())

    print(f"== Token usage ({len(usage)} API calls) ==")
    agg = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
    for u in usage:
        g = agg[(u.get("model") or "?", u.get("src", "?").split(":")[0] + (":" + u["src"].split(":", 1)[1] if ":" in u.get("src", "") and u["src"].split(":", 1)[1].startswith("cti-") else ""))]
        g[0] += 1
        g[1] += u.get("input_tokens", 0)
        g[2] += u.get("output_tokens", 0)
        g[3] += u.get("cache_creation_input_tokens", 0)
        g[4] += u.get("cache_read_input_tokens", 0)
    rows = [[m, s, *v, pct(v[4], v[1] + v[3] + v[4])] for (m, s), v in sorted(agg.items())]
    table(rows, ["model", "source", "calls", "input", "output", "cache_write", "cache_read", "cache_hit"])
    tot = [sum(v[i] for v in agg.values()) for i in range(5)]
    print(f"  TOTAL calls={tot[0]} input={tot[1]} output={tot[2]} cache_write={tot[3]} cache_read={tot[4]}")
    big = sorted(usage, key=lambda u: -(u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0)))[:3]
    for u in big:
        print(f"  largest context: {u.get('input_tokens', 0) + u.get('cache_creation_input_tokens', 0) + u.get('cache_read_input_tokens', 0)} tokens "
              f"({u.get('model')}, {u.get('src')}, {u.get('msg_ts') or u.get('ts')})")

    print(f"\n== Tool usage ({len(tools)} calls) ==")
    by = collections.defaultdict(list)
    for t in tools:
        by[t.get("tool")].append(t)
    rows = []
    for name, ts in sorted(by.items(), key=lambda kv: -len(kv[1])):
        fails = sum(1 for t in ts if not t.get("ok"))
        ms = sorted(t["ms"] for t in ts if isinstance(t.get("ms"), (int, float)))
        sizes = [t["result_chars"] for t in ts if isinstance(t.get("result_chars"), int)]
        rows.append([name, len(ts), fails, pct(fails, len(ts)), f"{ms[len(ms) // 2]}ms" if ms else "-",
                     f"{ms[-1]}ms" if ms else "-", sum(sizes), max(sizes) if sizes else "-"])
    table(rows, ["tool", "calls", "fail", "fail%", "p50", "max", "result_chars", "max_result"])

    scripts = collections.Counter((t["in"].get("script"), " ".join(t["in"].get("args", []))) for t in tools
                                  if t.get("in", {}).get("kind") == "script")
    print("\n== scripts/ invocations (script, leading args) ==")
    table([[s, ar, n] for (s, ar), n in scripts.most_common(15)], ["script", "args", "n"])

    print("\n== Failures / errors ==")
    ec = collections.Counter((e.get("kind"), e.get("tool"), (e.get("text") or "")[:90]) for e in errs)
    table([[k, t, x, n] for (k, t, x), n in ec.most_common(15)], ["kind", "tool", "text", "n"])

    print("\n== Network (scripts/ -> hosts) ==")
    nh = collections.defaultdict(lambda: [0, 0, 0, 0])
    for n in net:
        g = nh[(n.get("service"), n.get("host"))]
        g[0] += 1
        g[1] += 0 if (n.get("status") and n["status"] < 400) else 1
        g[2] += n.get("ms") or 0
        g[3] += n.get("bytes") or 0
    table([[s, h, v[0], v[1], f"{v[2] // v[0]}ms", v[3]] for (s, h), v in sorted(nh.items(), key=lambda kv: -kv[1][0])],
          ["service", "host", "calls", "non2xx/err", "avg", "bytes"])
    codes = collections.Counter(str(n.get("status")) for n in net)
    print("  status codes:", dict(codes))

    print("\n== passive_guard decisions ==")
    gc = collections.Counter((g.get("decision"), g.get("reason", "")[:70]) for g in guard)
    table([[d, r, n] for (d, r), n in gc.most_common(10)], ["decision", "reason", "n"])

    print("\n== Sessions / subagents ==")
    ev = collections.Counter(e.get("event") + (":" + e["agent_type"] if e.get("agent_type") else "") for e in events)
    print(" ", dict(ev))
    if a.json:
        print(json.dumps({"usage_calls": len(usage), "tool_calls": len(tools), "network_calls": len(net)}))


if __name__ == "__main__":
    main()
