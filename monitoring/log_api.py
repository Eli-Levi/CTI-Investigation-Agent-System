#!/usr/bin/env python3
"""Read-only JSON API that serves Claude Code telemetry logs to Grafana (Infinity datasource).

Independent of the CTI investigation code: stdlib only, imports nothing from the project, and only
reads the *.jsonl files in a log directory (default: ../logs, override with --log-dir or LOG_DIR).
Logs are re-read on EVERY request (cached per file by size+mtime, so only changed files are re-parsed):
Grafana refreshing a panel is what "loads" the logs - no separate loader process or database.

  python monitoring/log_api.py [--host 127.0.0.1] [--port 8765] [--log-dir PATH]

Every /api/* endpoint takes ?from=&to= (ISO-8601 or epoch ms; Grafana: ${__from:date:iso}) and returns a
JSON array of flat objects. Time-series endpoints are WIDE (one row per bucket, one column per series,
`time` in epoch ms). Endpoints: health stats tokens tools_ts tool_summary network network_ts errors guard agents
sessions. Optional `session=<id or unique prefix>` narrows any endpoint (except sessions/health) to one session;
network/guard rows carry no session id, so they are narrowed to that session's [first, last activity] time window.
"""
import argparse, collections, datetime, json, os, re, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_DIR = os.environ.get("LOG_DIR") or os.path.join(os.path.dirname(HERE), "logs")
STEPS = [60, 300, 900, 3600, 6 * 3600, 86400]  # bucket sizes (s)
_cache, _lock = {}, threading.Lock()


# ---------------------------------------------------------------- loading
_ctx = threading.local()  # per-request session scope (set by the handler when ?session= is given)
NO_SESSION_FIELD = ("network", "guard")  # scripts/guard never see the session id -> scoped by time window


def load(log_dir, stream):
    """Rows of <log_dir>/<stream>.jsonl, narrowed to the requested session (?session=) if any."""
    rows = _load_raw(log_dir, stream)
    sid = getattr(_ctx, "sid", None)
    if not sid:
        return rows
    if stream in NO_SESSION_FIELD:
        lo, hi = _ctx.win
        return [r for r in rows if r["_t"] is not None and lo <= r["_t"] <= hi]
    return [r for r in rows if r.get("session") == sid]


def _load_raw(log_dir, stream):
    """Parsed rows of <log_dir>/<stream>.jsonl; re-parsed only if the file changed."""
    p = os.path.join(log_dir, stream + ".jsonl")
    try:
        st = os.stat(p)
    except OSError:
        return []
    key = (st.st_size, st.st_mtime_ns)
    with _lock:
        hit = _cache.get(p)
        if hit and hit[0] == key:
            return hit[1]
    rows = []
    with open(p, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                r["_t"] = to_ms(r.get("msg_ts") or r.get("ts"))
                rows.append(r)
    with _lock:
        _cache[p] = (key, rows)
    return rows


def to_ms(v):
    """ISO-8601 string / epoch seconds-or-ms -> epoch ms (None if unparseable)."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) or str(v).replace(".", "", 1).isdigit():
        n = float(v)
        return int(n if n > 1e11 else n * 1000)
    try:
        d = datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def window(q):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    hi = to_ms(q.get("to")) or now
    lo = to_ms(q.get("from")) or hi - 86400_000
    return lo, hi


def inrange(rows, lo, hi):
    return [r for r in rows if r["_t"] is not None and lo <= r["_t"] <= hi]


def step_ms(q, lo, hi):
    if q.get("interval", "").isdigit():
        return max(1, int(q["interval"])) * 1000
    want = (hi - lo) / 1000 / 60  # aim for ~60 buckets
    return next((s for s in STEPS if s >= want), STEPS[-1]) * 1000


def usage_rows(log_dir, lo, hi):
    """usage.jsonl deduped by API message id (the hook may ingest a message more than once)."""
    best = {}
    for u in inrange(load(log_dir, "usage"), lo, hi):
        k = u.get("msg_id") or id(u)
        if k not in best or u.get("output_tokens", 0) >= best[k].get("output_tokens", 0):
            best[k] = u
    return list(best.values())


def source_of(u):
    s = u.get("src", "main")
    if s.startswith("subagent:"):
        return s if s.split(":", 1)[1].startswith("cti-") else "subagent"
    return s


def pivot(triples, step, lo, hi, shape="wide"):
    """[(t_ms, series, value)] -> zero-filled buckets across the window.
    shape=wide: one row per bucket, one column per series.  shape=long: one row per (bucket, series) as
    {time, series, value} - fixed columns, which Grafana/Infinity can type without knowing series names."""
    series = sorted({s for _, s, _ in triples})
    acc = collections.defaultdict(lambda: collections.defaultdict(float))
    for t, s, v in triples:
        acc[t // step * step][s] += v
    if shape == "long":
        return [{"time": b, "series": s, "value": round(acc[b].get(s, 0), 3) if b in acc else 0}
                for b in range(lo // step * step, hi + 1, step) for s in series]
    out = []
    for b in range(lo // step * step, hi + 1, step):
        row = {"time": b}
        for s in series:
            row[s] = round(acc[b].get(s, 0), 3) if b in acc else 0
        out.append(row)
    return out


def pct(a, b):
    return round(100 * a / b, 1) if b else 0


def p50(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else 0


# ---------------------------------------------------------------- endpoints
def ep_health(d, q):
    names = ("usage", "tools", "errors", "network", "guard", "events", "sessions")
    return [{"ok": True, "log_dir": d, **{n: len(load(d, n)) for n in names}}]


def ep_stats(d, q):
    lo, hi = window(q)
    u, t = usage_rows(d, lo, hi), inrange(load(d, "tools"), lo, hi)
    n = inrange(load(d, "network"), lo, hi)
    g = lambda k: sum(x.get(k, 0) or 0 for x in u)  # noqa: E731
    ctx = g("input_tokens") + g("cache_creation_input_tokens") + g("cache_read_input_tokens")
    fails = sum(1 for x in t if not x.get("ok"))
    return [{"api_calls": len(u), "input_tokens": g("input_tokens"), "output_tokens": g("output_tokens"),
             "cache_read_tokens": g("cache_read_input_tokens"), "cache_write_tokens": g("cache_creation_input_tokens"),
             "cache_hit_pct": pct(g("cache_read_input_tokens"), ctx), "tool_calls": len(t), "tool_failures": fails,
             "tool_failure_pct": pct(fails, len(t)), "network_calls": len(n),
             "network_errors": sum(1 for x in n if not x.get("status") or x["status"] >= 400),
             "guard_blocks": len(inrange(load(d, "guard"), lo, hi))}]


METRICS = {"output": ("output_tokens",), "input": ("input_tokens",), "cache_read": ("cache_read_input_tokens",),
           "cache_write": ("cache_creation_input_tokens",),
           "context": ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")}


def ep_tokens(d, q):
    """?metric=output|input|cache_read|cache_write|context &group=model|source"""
    lo, hi = window(q)
    keys = METRICS.get(q.get("metric", "output"), METRICS["output"])
    by_src = q.get("group") == "source"
    tri = [(u["_t"], source_of(u) if by_src else (u.get("model") or "?"), sum(u.get(k, 0) or 0 for k in keys))
           for u in usage_rows(d, lo, hi)]
    return pivot(tri, step_ms(q, lo, hi), lo, hi, q.get("shape", "wide"))


def ep_tools_ts(d, q):
    """?metric=calls|failures|result_chars"""
    lo, hi = window(q)
    m = q.get("metric", "calls")
    tri = []
    for t in inrange(load(d, "tools"), lo, hi):
        if m == "failures" and t.get("ok"):
            continue
        tri.append((t["_t"], t.get("tool") or "?", (t.get("result_chars") or 0) if m == "result_chars" else 1))
    return pivot(tri, step_ms(q, lo, hi), lo, hi, q.get("shape", "wide"))


def ep_tool_summary(d, q):
    lo, hi = window(q)
    by = collections.defaultdict(list)
    for t in inrange(load(d, "tools"), lo, hi):
        by[t.get("tool") or "?"].append(t)
    rows = []
    for name, ts in by.items():
        ms = [t["ms"] for t in ts if isinstance(t.get("ms"), (int, float))]
        sz = [t["result_chars"] for t in ts if isinstance(t.get("result_chars"), int)]
        f = sum(1 for t in ts if not t.get("ok"))
        rows.append({"tool": name, "calls": len(ts), "failures": f, "failure_pct": pct(f, len(ts)),
                     "p50_ms": p50(ms), "max_ms": max(ms, default=0), "result_chars_total": sum(sz),
                     "result_chars_max": max(sz, default=0)})
    return sorted(rows, key=lambda r: -r["calls"])


def ep_network(d, q):
    lo, hi = window(q)
    by = collections.defaultdict(list)
    for n in inrange(load(d, "network"), lo, hi):
        by[(n.get("service"), n.get("host"))].append(n)
    rows = []
    for (s, h), ns in by.items():
        bad = sum(1 for n in ns if not n.get("status") or n["status"] >= 400)
        ms = [n["ms"] for n in ns if isinstance(n.get("ms"), (int, float))]
        rows.append({"service": s, "host": h, "calls": len(ns), "errors": bad, "error_pct": pct(bad, len(ns)),
                     "avg_ms": round(sum(ms) / len(ms)) if ms else 0, "bytes": sum(n.get("bytes") or 0 for n in ns)})
    return sorted(rows, key=lambda r: -r["calls"])


def ep_network_ts(d, q):
    lo, hi = window(q)
    tri = [(n["_t"], n.get("host") or "?", 1) for n in inrange(load(d, "network"), lo, hi)]
    return pivot(tri, step_ms(q, lo, hi), lo, hi, q.get("shape", "wide"))


def ep_errors(d, q):
    lo, hi = window(q)
    rows = sorted(inrange(load(d, "errors"), lo, hi), key=lambda r: -r["_t"])[:200]
    return [{"time": r["_t"], "kind": r.get("kind"), "tool": r.get("tool"), "source": r.get("src"),
             "text": r.get("text")} for r in rows]


def ep_guard(d, q):
    lo, hi = window(q)
    c = collections.Counter((g.get("decision"), g.get("reason")) for g in inrange(load(d, "guard"), lo, hi))
    return [{"decision": k[0], "reason": k[1], "count": n} for k, n in c.most_common()]


def ep_agents(d, q):
    lo, hi = window(q)
    c = collections.Counter((e.get("event"), e.get("agent_type") or "main") for e in inrange(load(d, "events"), lo, hi)
                            if e.get("event") in ("SubagentStart", "SubagentStop", "UserPromptSubmit", "SessionStart"))
    return [{"event": k[0], "agent": k[1], "count": n} for k, n in sorted(c.items())]


CASE_TOKEN = re.compile(r"^[A-Za-z]{2,5}-\d{8}-[\w-]+$")  # legacy rows: case id only appears inside in.args


def session_index(d):
    """session id -> {started,last_seen,title,cases,models,...} built from events/tools/usage/sessions (unscoped)."""
    saved = getattr(_ctx, "sid", None)
    _ctx.sid = None  # the index always covers every session, even while a request is session-scoped
    try:
        s = collections.defaultdict(lambda: {"started": None, "last_seen": None, "cases": set(), "models": set(),
                                             "api_calls": 0, "output_tokens": 0, "tool_calls": 0, "tool_failures": 0,
                                             "title": None, "title_kind": None})

        def touch(r):
            sid, t = r.get("session"), r.get("_t")
            if not sid or t is None:
                return None
            e = s[sid]
            e["started"] = t if e["started"] is None else min(e["started"], t)
            e["last_seen"] = t if e["last_seen"] is None else max(e["last_seen"], t)
            return e

        for r in load(d, "events"):
            touch(r)
        for r in load(d, "tools"):
            e = touch(r)
            if e is None:
                continue
            e["tool_calls"] += 1
            e["tool_failures"] += 0 if r.get("ok") else 1
            i = r.get("in") or {}
            if i.get("case"):
                e["cases"].add(i["case"])
            e["cases"].update(a for a in i.get("args", []) if CASE_TOKEN.match(str(a)))
        seen = set()
        for r in load(d, "usage"):
            k = r.get("msg_id")
            if k in seen:
                continue
            seen.add(k)
            e = touch(r)
            if e is None:
                continue
            e["api_calls"] += 1
            e["output_tokens"] += r.get("output_tokens", 0) or 0
            if r.get("model"):
                e["models"].add(r["model"])
        for r in load(d, "sessions"):  # latest custom title wins over latest auto title
            e = s.get(r.get("session"))
            if e is not None and (r.get("kind") == "custom" or e["title_kind"] != "custom"):
                e["title"], e["title_kind"] = r.get("title"), r.get("kind")
        return s
    finally:
        _ctx.sid = saved


def ep_sessions(d, q):
    lo, hi = window(q)
    rows = []
    for sid, e in session_index(d).items():
        if e["last_seen"] < lo or e["started"] > hi:
            continue
        rows.append({"session": sid, "short": sid[:8], "started": e["started"], "last_seen": e["last_seen"],
                     "duration_min": round((e["last_seen"] - e["started"]) / 60000, 1),
                     "title": e["title"] or "(untitled)", "cases": ", ".join(sorted(e["cases"])) or "-",
                     "models": ", ".join(sorted(e["models"])) or "-", "api_calls": e["api_calls"],
                     "output_tokens": e["output_tokens"], "tool_calls": e["tool_calls"],
                     "tool_failures": e["tool_failures"]})
    return sorted(rows, key=lambda r: -r["started"])


def scope_session(d, prefix):
    """Resolve ?session= (full id or unique prefix) and scope this request to it. Unknown id -> empty results."""
    idx = session_index(d)
    hits = [k for k in idx if k.startswith(prefix)]
    if len(hits) == 1:
        e = idx[hits[0]]
        _ctx.sid, _ctx.win = hits[0], (e["started"], e["last_seen"] + 60_000)
    else:
        _ctx.sid, _ctx.win = "\0no-such-session", (0, -1)


ENDPOINTS = {"health": ep_health, "stats": ep_stats, "tokens": ep_tokens, "tools_ts": ep_tools_ts,
             "tool_summary": ep_tool_summary, "network": ep_network, "network_ts": ep_network_ts,
             "errors": ep_errors, "guard": ep_guard, "agents": ep_agents, "sessions": ep_sessions}


class Handler(BaseHTTPRequestHandler):
    log_dir = DEFAULT_LOG_DIR

    def do_GET(self):
        u = urlsplit(self.path)
        name = u.path.removeprefix("/api/").strip("/") if u.path.startswith("/api/") else None
        fn = ENDPOINTS.get(name)
        if not fn:
            return self.send(404, {"error": "unknown endpoint", "endpoints": sorted(ENDPOINTS)})
        try:
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            _ctx.sid = None
            if q.get("session", "").strip() and name not in ("sessions", "health"):
                scope_session(self.log_dir, q["session"].strip())
            self.send(200, fn(self.log_dir, q))
        except Exception as e:  # never crash the server on a bad query
            self.send(500, {"error": f"{type(e).__name__}: {e}"})
        finally:
            _ctx.sid = None

    def send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    ap.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    a = ap.parse_args()
    Handler.log_dir = a.log_dir
    print(f"log_api: serving {a.log_dir} on http://{a.host}:{a.port}/api/  (read-only)", flush=True)
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
