#!/usr/bin/env python3
"""Telemetry hook: append-only JSONL logs for token usage, tool usage/failures, errors and call frequency.

Registered for SessionStart, UserPromptSubmit, PostToolUse, PostToolUseFailure, SubagentStart,
SubagentStop, Stop, SessionEnd (see .claude/settings.json). It NEVER blocks or alters a tool call:
always exit 0, all errors swallowed. Output goes to logs/ (gitignored; override with CTI_LOG_DIR):

  logs/tools.jsonl    one line per tool call (ok/fail, duration, result size, privacy-safe input summary)
  logs/events.jsonl   session/subagent/prompt lifecycle (prompt TEXT is never stored, only its length)
  logs/sessions.jsonl session id -> title (the title Claude Code already keeps in the transcript; custom > ai)
  logs/usage.jsonl    one line per model API call, parsed from the transcript (tokens, model, tools used)
  logs/errors.jsonl   API errors seen in transcripts
  logs/guard.jsonl    passive_guard decisions (ask/deny) - written by passive_guard.py
  logs/network.jsonl  every outbound HTTP call made by scripts/ (host only, never URL/query/keys) - ctilib.tlog

Privacy: tool inputs are summarised (script name + subcommand, URL host, file area), never logged
verbatim, because commands/URLs carry attacker IOCs and could carry secrets. Error text is truncated
and long token-like strings are masked. Analyse with: python scripts/log_report.py
"""
import datetime, glob, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.environ.get("CTI_LOG_DIR") or os.path.join(ROOT, "logs")
SECRETISH = re.compile(r"[A-Za-z0-9_\-]{32,}")
URL_HOST = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)://([^/\s'\"`<>:?#]+)")
SCRIPT = re.compile(r"(?i)python[3w]?(?:\.exe)?\s+(?:\S*[\\/])?scripts[\\/]([\w.]+)\.py\s*(.*)")


CASE_ID = re.compile(r"\b([A-Za-z]{2,5}-\d{8}-[\w-]+)\b")  # e.g. SMS-20261116-help4kids


def case_of(text):
    m = CASE_ID.search(text or "")
    return m.group(1) if m else None


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def write(stream, rec):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, stream + ".jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": now(), **rec}, ensure_ascii=False) + "\n")


def scrub(s, n=300):
    return SECRETISH.sub("<masked>", str(s))[:n]


def summarize_input(tool, ti):
    """Privacy-safe description of what the call did (+ the case id it touched, if any)."""
    ti = ti if isinstance(ti, dict) else {}
    out = _summarize(tool, ti)
    c = case_of(ti.get("command") or ti.get("file_path") or ti.get("notebook_path") or "")
    if c:
        out["case"] = c
    return out


def _summarize(tool, ti):
    if tool in ("Bash", "PowerShell"):
        cmd = ti.get("command", "")
        m = SCRIPT.search(cmd)
        if m:
            args = [a for a in re.split(r"\s+", m.group(2).strip()) if a and not a.startswith("-")]
            # intel.py CASE SERVICE ACTION ; case.py CASE? subcmd ... -> keep first 3 non-IOC-looking tokens
            keep = [a for a in args[:4] if not URL_HOST.search(a) and not re.search(r"\d+\.\d+\.\d+|[A-Za-z0-9-]+\.[a-z]{2,}", a)]
            return {"kind": "script", "script": m.group(1) + ".py", "args": keep[:3]}
        first = re.split(r"[\s|;&]+", cmd.strip(), maxsplit=1)[0] if cmd.strip() else ""
        return {"kind": "shell", "cmd0": first[:40], "len": len(cmd), "hosts": sorted(set(URL_HOST.findall(cmd)))[:5]}
    if tool == "WebFetch":
        m = URL_HOST.search(ti.get("url", ""))
        return {"host": m.group(1) if m else None}
    if tool == "WebSearch":
        return {"query_len": len(ti.get("query", "")), "mode": ti.get("mode")}
    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = (ti.get("file_path") or ti.get("notebook_path") or "").replace("\\", "/")
        area = "case-data" if "/Investigation Records/" in p else ("scripts" if "/scripts/" in p else
               (".claude" if "/.claude/" in p else "other"))
        return {"area": area, "ext": os.path.splitext(p)[1], "limit": ti.get("limit")}
    if tool in ("Grep", "Glob"):
        return {"pattern_len": len(ti.get("pattern", ""))}
    if tool in ("Agent", "Task"):
        return {"subagent": ti.get("subagent_type"), "desc": scrub(ti.get("description", ""), 80)}
    if tool == "Skill":
        return {"skill": ti.get("skill")}
    return {}


def resp_size(r):
    try:
        return len(r) if isinstance(r, str) else len(json.dumps(r, ensure_ascii=False))
    except Exception:
        return None


def title_of(o):
    """(kind, text) if this transcript line is a session-title record. A user rename (custom) beats the auto title."""
    t = o.get("type")
    if t == "custom-title" and o.get("customTitle"):
        return "custom", scrub(o["customTitle"], 120)
    if t == "ai-title" and o.get("aiTitle"):
        return "ai", scrub(o["aiTitle"], 120)
    return None


def write_title(cur, sid, found):
    """found: {'custom': text?, 'ai': text?} -> sessions.jsonl row if the effective title changed."""
    if not sid or not found:
        return
    kind = "custom" if "custom" in found else "ai"
    key = "title:" + sid
    if cur.get(key) == [kind, found[kind]]:
        return
    cur[key] = [kind, found[kind]]
    write("sessions", {"session": sid, "title": found[kind], "kind": kind})


def backfill_titles(projects_dir=None):
    """One-off: titles for sessions already in events.jsonl, scanned from their full transcripts."""
    sids = set()
    p = os.path.join(LOG_DIR, "events.jsonl")
    if os.path.isfile(p):
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    s = json.loads(line).get("session")
                except ValueError:
                    continue
                if s:
                    sids.add(s)
    base = projects_dir or os.path.join(os.path.expanduser("~"), ".claude", "projects")
    cur_path, n = os.path.join(LOG_DIR, ".cursors.json"), 0
    try:
        with open(cur_path, encoding="utf-8") as fh:
            cur = json.load(fh)
    except Exception:
        cur = {}
    for sid in sorted(sids):
        hits = glob.glob(os.path.join(base, "*", sid + ".jsonl")) + glob.glob(os.path.join(base, sid + ".jsonl"))
        if not hits:
            continue
        found = {}
        with open(hits[0], encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if '-title"' not in line:
                    continue
                try:
                    t = title_of(json.loads(line))
                except ValueError:
                    continue
                if t:
                    found[t[0]] = t[1]
        before = cur.get("title:" + sid)
        write_title(cur, sid, found)
        n += cur.get("title:" + sid) != before
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(cur_path, "w", encoding="utf-8") as fh:
        json.dump(cur, fh)
    print(f"backfill: {len(sids)} sessions seen in events.jsonl, {n} titles written")


def ingest_transcript(path, label):
    """Append new per-API-call usage rows from a transcript JSONL (byte-offset cursor, idempotent enough:
    log_report.py dedupes by message id)."""
    if not path or not os.path.isfile(path):
        return
    cur_path = os.path.join(LOG_DIR, ".cursors.json")
    try:
        cur = json.load(open(cur_path, encoding="utf-8"))
    except Exception:
        cur = {}
    off = cur.get(path, 0)
    size = os.path.getsize(path)
    if size < off:  # file rotated/truncated
        off = 0
    with open(path, "rb") as fh:
        fh.seek(off)
        chunk = fh.read()
    end = chunk.rfind(b"\n")
    if end < 0:
        return
    chunk = chunk[:end + 1]
    best, titles, tsid = {}, {}, None
    for raw in chunk.splitlines():
        try:
            o = json.loads(raw)
        except Exception:
            continue
        t = title_of(o)
        if t:
            titles[t[0]] = t[1]
            tsid = o.get("sessionId") or tsid
            continue
        if o.get("isApiErrorMessage") or o.get("subtype") == "api_error" or o.get("type") == "api_error":
            msg = o.get("message", {})
            txt = msg.get("content") if isinstance(msg, dict) else None
            if isinstance(txt, list):
                txt = " ".join(c.get("text", "") for c in txt if isinstance(c, dict))
            write("errors", {"src": label, "session": o.get("sessionId"), "kind": "api_error",
                             "text": scrub(txt or o.get("error") or o.get("content") or "", 300)})
            continue
        m = o.get("message")
        if o.get("type") != "assistant" or not isinstance(m, dict) or not m.get("usage"):
            continue
        mid = m.get("id") or o.get("uuid")
        u = m["usage"]
        tools = [c.get("name") for c in (m.get("content") or []) if isinstance(c, dict) and c.get("type") == "tool_use"]
        rec = best.setdefault(mid, {"msg_id": mid, "model": m.get("model"), "src": label,
                                    "session": o.get("sessionId"), "sidechain": bool(o.get("isSidechain")),
                                    "stop_reason": None, "tools": [], "msg_ts": o.get("timestamp")})
        for k in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            rec[k] = max(rec.get(k, 0), u.get(k) or 0)
        rec["tools"] += [t for t in tools if t]
        rec["stop_reason"] = m.get("stop_reason") or rec["stop_reason"]
        st = u.get("server_tool_use")
        if isinstance(st, dict):
            rec["server_tools"] = {k: v for k, v in st.items() if v}
    for rec in best.values():
        write("usage", rec)
    if label == "main" and titles:  # session description: title Claude Code already stores; never prompt text
        prev = cur.get("title:" + (tsid or ""), [None, None])
        if "custom" not in titles and prev[0] == "custom":
            titles["custom"] = prev[1]  # keep an earlier user rename over a newer auto title
        write_title(cur, tsid or os.path.basename(path)[:-6], titles)
    cur[path] = off + len(chunk)
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(cur_path, "w", encoding="utf-8") as fh:
        json.dump(cur, fh)


def main():
    try:
        d = json.load(sys.stdin)
    except Exception:
        return
    ev = d.get("hook_event_name", "")
    sid = d.get("session_id")
    base = {"session": sid, "agent": d.get("agent_type") or d.get("agent_id")}
    if ev in ("PostToolUse", "PostToolUseFailure"):
        tool = d.get("tool_name", "")
        rec = {**base, "event": ev, "tool": tool, "ok": ev == "PostToolUse", "ms": d.get("duration_ms"),
               "in": summarize_input(tool, d.get("tool_input")), "result_chars": resp_size(d.get("tool_response"))}
        if ev == "PostToolUseFailure":
            rec["error"] = scrub(d.get("error", ""))
            rec["interrupt"] = bool(d.get("is_interrupt"))
        else:  # some tools report failure inside a successful hook payload
            tr = d.get("tool_response")
            if isinstance(tr, dict) and (tr.get("is_error") or tr.get("success") is False):
                rec["ok"] = False
                rec["error"] = scrub(tr.get("error") or tr.get("stderr") or "")
        write("tools", rec)
        if not rec["ok"]:
            write("errors", {**base, "kind": "tool_failure", "tool": tool, "text": rec.get("error", "")})
    elif ev == "SessionStart":
        write("events", {**base, "event": ev, "source": d.get("source"), "model": d.get("model"),
                         "cwd": d.get("cwd"), "api_host": re.sub(r"^https?://", "", os.environ.get("ANTHROPIC_BASE_URL", "") or
                          "api.anthropic.com (default)").split("/")[0]})
    elif ev == "UserPromptSubmit":
        write("events", {**base, "event": ev, "prompt_chars": len(d.get("prompt", "") or "")})
    elif ev in ("SubagentStart", "SubagentStop"):
        write("events", {**base, "event": ev, "agent_type": d.get("agent_type"), "agent_id": d.get("agent_id")})
        if ev == "SubagentStop":
            ingest_transcript(d.get("agent_transcript_path"), f"subagent:{d.get('agent_type')}")
    elif ev in ("Stop", "SessionEnd"):
        write("events", {**base, "event": ev, "reason": d.get("reason")})
        tp = d.get("transcript_path")
        ingest_transcript(tp, "main")
        if tp and sid:  # subagent transcripts live beside the session transcript
            for sp in glob.glob(os.path.join(os.path.dirname(tp), sid, "subagents", "*.jsonl")):
                ingest_transcript(sp, "subagent:" + os.path.basename(sp)[:-6])


if __name__ == "__main__":
    if "--backfill-titles" in sys.argv:  # manual one-off: python .claude/hooks/telemetry.py --backfill-titles [--projects-dir DIR]
        pd = sys.argv[sys.argv.index("--projects-dir") + 1] if "--projects-dir" in sys.argv else None
        backfill_titles(pd)
        sys.exit(0)
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
