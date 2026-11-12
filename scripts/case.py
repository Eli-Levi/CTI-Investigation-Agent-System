#!/usr/bin/env python3
"""Case lifecycle and investigation state (state.json).

usage:
  case.py init CASE --seed "SMS text / URL" [--max-depth 2] [--max-tasks 10]
  case.py probe CASE                      # which keys/services work -> capabilities.json
  case.py next CASE                       # show pending pivot queue (Q-ids)
  case.py add CASE VALUE [--type T] --depth N --why "reason (cite E-id)"
  case.py skip CASE Q-ID --why "e.g. Cloudflare shared IP, reverse-IP not meaningful"
  case.py task CASE start TASK_ID --agent NAME --targets Q-001,Q-002 [--force]
  case.py task CASE done|fail TASK_ID [--note "..."]
  case.py need CASE --action "..." --why "..." --bring "..." --safety "..."
  case.py resolve CASE N-ID [--note "..."]
  case.py question CASE "open question text"
  case.py phase CASE PHASE [--confirmed]   # REPORT/DONE need --confirmed (user verified the case is complete)
  case.py reopen CASE --why "..."          # resume a closed case; archives old report/diagram to closed/<ts>/
  case.py status CASE                     # compact (~20 line) resume summary
exit: 0 ok, 1 usage/error, 2 budget exhausted / UNKNOWN
"""
import argparse, json, os, sys, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctilib import (CTIError, KEY_ENVS, Lock, get_key, key_source, case_dir, extract, normalize, read_json, utc, write_json)
import ioc_index

PHASES = ["INIT", "NORMALIZE", "PROBE", "DISPATCH", "INGEST", "TRIAGE_PIVOTS", "ENRICH", "VALIDATE", "REPORT", "DONE"]


class State:
    def __init__(self, case):
        self.dir = case_dir(case)
        self.path = os.path.join(self.dir, "state.json")
        self.lock = Lock(os.path.join(self.dir, "state.lock"))

    def __enter__(self):
        self.lock.__enter__()
        self.s = read_json(self.path)
        return self.s

    def __exit__(self, exc_type, *a):
        if exc_type is None:
            self.s["updated"] = utc()
            write_json(self.path, self.s)
        self.lock.__exit__()


def _next_id(items, prefix):
    n = max((int(x["id"].split("-")[1]) for x in items if x.get("id", "").startswith(prefix + "-")), default=0)
    return f"{prefix}-{n + 1:03d}"


def _enqueue(s, value, typ, depth, why):
    value, typ = normalize(value, typ)
    key = f"{typ}:{value}"
    if key in s["seen"]:
        return None, f"already seen ({s['seen'][key]['first']})"
    qid = _next_id(s["queue"] + s["done_queue"], "Q")
    s["seen"][key] = {"first": qid, "at": utc()}
    item = {"id": qid, "value": value, "type": typ, "depth": depth, "why": why, "added": utc()}
    if depth > s["budget"]["max_depth"]:
        item.update(status="over_budget")
        s["done_queue"].append(item)
        s["open_questions"].append(f"{qid} {typ} {value}: not investigated (depth {depth} > max_depth). Reason it surfaced: {why}")
        return item, "over depth budget -> recorded as open question"
    item["status"] = "pending"
    s["queue"].append(item)
    return item, "queued"


def cmd_init(a):
    d = case_dir(a.case, must_exist=False)
    if os.path.exists(os.path.join(d, "state.json")):
        raise CTIError(f"case {a.case} already exists")
    for sub in ("", "raw", "work", os.path.join("work", "ingested")):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    s = {"case": a.case, "created": utc(), "updated": utc(), "phase": "NORMALIZE", "seed": a.seed,
         "budget": {"max_depth": a.max_depth, "max_tasks": a.max_tasks},
         "seen": {}, "queue": [], "done_queue": [], "tasks": {}, "needs_user": [], "open_questions": []}
    found = extract(a.seed)
    for v, t, note in found:
        _enqueue(s, v, t, 0, "seed" + (f" ({note})" if note else ""))
    write_json(os.path.join(d, "state.json"), s)
    write_json(os.path.join(d, "evidence.json"), {"title": a.case, "entries": []})
    write_json(os.path.join(d, "findings.json"), {"nodes": [], "edges": []})
    open(os.path.join(d, "audit.log"), "a", encoding="utf-8").close()
    print(f"case {a.case} created at {d}")
    print(f"seed indicators ({len(found)}):")
    for q in s["queue"]:
        print(f"  {q['id']} {q['type']:6} {q['value']}  [{q['why']}]")
    if not found:
        print("  none extracted: add indicators manually with case.py add")


def _get(url, headers=None, method="GET", timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "cti-investigation", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(200_000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000)
    except Exception as e:  # network blocked, DNS, timeout
        return None, str(e).encode()


def cmd_probe(a):
    d = case_dir(a.case)
    src = {k: key_source(k) for k in KEY_ENVS}
    keys = {k: bool(v) for k, v in src.items()}
    K = lambda n: get_key(n)  # noqa: E731  (values used only in request headers, never printed)
    caps = {"probed_at": utc(), "keys": src, "services": {}}

    def rec(name, code, body, need=None, quota=None):
        if need and not keys[need]:
            st = "no_key"
        elif code is None:
            st = "blocked"
        elif code == 429:
            st = "rate_limited"
        elif code in (401, 403):
            st = "auth_failed"
        elif 200 <= code < 400:
            st = "ok"
        else:
            st = f"http_{code}"
        caps["services"][name] = {"status": st, **({"quota": quota} if quota else {})}

    if keys["URLSCAN_API_KEY"]:
        c, b = _get("https://urlscan.io/user/quotas/", {"API-Key": K("URLSCAN_API_KEY")})
        q = None
        if c == 200:
            try:
                lim = json.loads(b).get("limits", {})
                q = {k: {p: v.get(p, {}).get("remaining") for p in ("minute", "hour", "day") if isinstance(v, dict)}
                     for k, v in lim.items() if isinstance(v, dict)}
            except ValueError:
                pass
        rec("urlscan", c, b, "URLSCAN_API_KEY", q)
    else:
        rec("urlscan", None, b"", "URLSCAN_API_KEY")
    if keys["VT_API_KEY"]:
        c, b = _get("https://www.virustotal.com/api/v3/domains/example.com", {"x-apikey": K("VT_API_KEY")})
        rec("virustotal", c, b, "VT_API_KEY")
    else:
        rec("virustotal", None, b"", "VT_API_KEY")
    if keys["ABUSEIPDB_KEY"]:
        c, b = _get("https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1",
                    {"Key": K("ABUSEIPDB_KEY"), "Accept": "application/json"})
        rec("abuseipdb", c, b, "ABUSEIPDB_KEY")
    else:
        rec("abuseipdb", None, b"", "ABUSEIPDB_KEY")
    for name, url, need in (("crtsh", "https://crt.sh/", None),
                            ("rdap", "https://rdap.org/domain/example.com", None),
                            ("dns_doh", "https://dns.google/resolve?name=example.com&type=A", None),
                            ("wayback", "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1", None),
                            ("wheregoes", "https://wheregoes.com/", None),
                            ("otx", "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general", None)):
        c, b = _get(url)
        rec(name, c, b, need)
    if keys["ABUSECH_KEY"]:
        c, b = _get("https://urlhaus-api.abuse.ch/v1/host/", {"Auth-Key": K("ABUSECH_KEY")}, method="POST")
        rec("urlhaus_threatfox", c, b, "ABUSECH_KEY")
    else:
        rec("urlhaus_threatfox", None, b"", "ABUSECH_KEY")
    write_json(os.path.join(d, "capabilities.json"), caps)
    print("capabilities (key values never shown):")
    for k, v in caps["services"].items():
        print(f"  {k:18} {v['status']}" + (f"  quota={json.dumps(v['quota'])}" if v.get("quota") else ""))
    missing = [k for k, v in keys.items() if not v]
    if missing:
        print("missing keys: " + ", ".join(missing) + " -> related lookups will be UNKNOWN "
              "(user stores them with: python scripts\\keystore.py set NAME, in their own terminal)")
    in_env = [k for k, v in src.items() if v == "env"]
    if in_env:
        print("SECURITY: " + ", ".join(in_env) + " read from environment variables (inherited by every process). "
              "Recommend moving them to the key store and deleting the env vars.")
    if keys["VIEWDNS_KEY"]:
        caps["services"]["viewdns"] = {"status": "key_present (not probed: trial quota is small)"}
        write_json(os.path.join(d, "capabilities.json"), caps)
    with State(a.case) as s:
        if s["phase"] in ("INIT", "NORMALIZE", "PROBE"):
            s["phase"] = "DISPATCH"


def cmd_next(a):
    with State(a.case) as s:
        pend = [q for q in s["queue"] if q["status"] == "pending"]
        used = len(s["tasks"])
        print(f"phase {s['phase']} | tasks used {used}/{s['budget']['max_tasks']} | max_depth {s['budget']['max_depth']}")
        if not pend:
            print("queue empty: no pending pivots")
        for q in pend:
            print(f"  {q['id']} d{q['depth']} {q['type']:6} {q['value']}  [{q['why']}]")


def cmd_add(a):
    with State(a.case) as s:
        item, msg = _enqueue(s, a.value, a.type, a.depth, a.why)
        print(f"{item['id'] + ' ' if item else ''}{a.value}: {msg}")


def cmd_skip(a):
    with State(a.case) as s:
        for q in s["queue"]:
            if q["id"] == a.qid:
                s["queue"].remove(q)
                q.update(status="skipped", skip_reason=a.why, closed=utc())
                s["done_queue"].append(q)
                print(f"{a.qid} skipped: {a.why}")
                return
        raise CTIError(f"{a.qid} not in pending queue")


def cmd_task(a):
    with State(a.case) as s:
        t = s["tasks"].get(a.task_id)
        if a.op == "start":
            if t and t["status"] == "running":
                raise CTIError(f"{a.task_id} already running")
            if not t and len(s["tasks"]) >= s["budget"]["max_tasks"] and not a.force:
                print(f"BUDGET EXHAUSTED ({s['budget']['max_tasks']} tasks). Record remaining queue as open questions, "
                      f"or ask the user and rerun with --force.")
                sys.exit(2)
            targets = [x for x in (a.targets or "").split(",") if x]
            for qid in targets:
                for q in list(s["queue"]):
                    if q["id"] == qid:
                        s["queue"].remove(q)
                        q.update(status="dispatched", task=a.task_id)
                        s["done_queue"].append(q)
            retries = (t["retries"] + 1) if t else 0
            s["tasks"][a.task_id] = {"agent": a.agent, "targets": targets, "status": "running",
                                     "retries": retries, "started": utc(), "notes": (t or {}).get("notes", [])}
            print(f"{a.task_id} started ({a.agent}) targets={targets} retries={retries}"
                  f" -> agent writes Investigation Records/{a.case}/work/{a.task_id}.json")
        else:
            if not t:
                raise CTIError(f"unknown task {a.task_id}")
            t["status"] = "done" if a.op == "done" else ("failed" if t["retries"] >= 1 else "failed_retryable")
            t["ended"] = utc()
            if a.note:
                t["notes"].append(a.note)
            if t["status"] == "failed":
                s["open_questions"].append(f"{a.task_id} ({t['agent']}) failed after retry: {a.note or 'no note'} -> its targets stay UNKNOWN")
            print(f"{a.task_id} -> {t['status']}")


def cmd_need(a):
    with State(a.case) as s:
        nid = _next_id(s["needs_user"], "N")
        s["needs_user"].append({"id": nid, "action": a.action, "why": a.why, "bring": a.bring,
                                "safety": a.safety, "status": "open", "at": utc()})
        print(f"{nid} recorded")


def cmd_resolve(a):
    with State(a.case) as s:
        for n in s["needs_user"]:
            if n["id"] == a.nid:
                n.update(status="resolved", resolved=utc(), note=a.note or "")
                print(f"{a.nid} resolved")
                return
        raise CTIError(f"{a.nid} not found")


def cmd_question(a):
    with State(a.case) as s:
        s["open_questions"].append(a.text)
        print(f"open question #{len(s['open_questions'])} recorded")


def cmd_phase(a):
    if a.phase not in PHASES:
        raise CTIError(f"phase must be one of {PHASES}")
    if a.phase in ("REPORT", "DONE") and not a.confirmed:
        raise CTIError(f"phase {a.phase} (final report + diagram) requires the user's explicit confirmation that the "
                       "investigation is complete; ask the user, then rerun with --confirmed")
    with State(a.case) as s:
        if s["phase"] in ("REPORT", "DONE") and a.phase not in ("REPORT", "DONE"):
            raise CTIError("case is closed; use `case.py reopen CASE --why ...` (archives the old report/diagram first)")
        s["phase"] = a.phase
        if a.confirmed and a.phase == "REPORT":
            s["close_confirmed"] = utc()
        print(f"phase -> {a.phase}")
    if a.phase == "DONE" and a.confirmed:
        ioc_index.refresh(a.case)  # report.md exists by now; fills the case node's report pointer


def cmd_reopen(a):
    """Resume a closed case. The old report/diagram are archived, never silently kept as current."""
    import glob, shutil
    with State(a.case) as s:
        if s["phase"] not in ("REPORT", "DONE"):
            raise CTIError(f"case is not closed (phase {s['phase']}); nothing to reopen")
        d, stamp = case_dir(a.case), utc().replace(":", "").replace("-", "")
        arch = os.path.join(d, "closed", stamp)
        moved = []
        for pat in ("report*.md", "diagram.mmd", "*handoff*.md"):
            for fp in glob.glob(os.path.join(d, pat)):
                os.makedirs(arch, exist_ok=True)
                shutil.move(fp, os.path.join(arch, os.path.basename(fp)))
                moved.append(os.path.basename(fp))
        s.setdefault("reopened", []).append({"at": utc(), "why": a.why, "closed_at": s.get("close_confirmed"),
                                             "archived": moved})
        s.pop("close_confirmed", None)
        s["phase"] = "DISPATCH"
        used, mx = len(s["tasks"]), s["budget"]["max_tasks"]
        print(f"reopened -> DISPATCH; archived {len(moved)} file(s)" + (f" to closed/{stamp}/" if moved else ""))
        if used >= mx:
            print(f"note: task budget exhausted ({used}/{mx}); more work needs the user's OK (`task start --force`)")
        print("when finished, the user must confirm completion again before new report/diagram are generated")
    ioc_index.refresh(a.case)  # clears the case node's report pointer


def cmd_status(a):
    d = case_dir(a.case)
    s = read_json(os.path.join(d, "state.json"))
    ev = read_json(os.path.join(d, "evidence.json"), {"entries": []})
    fi = read_json(os.path.join(d, "findings.json"), {"nodes": [], "edges": []})
    caps = read_json(os.path.join(d, "capabilities.json"), {})
    act = [e for e in ev["entries"] if e.get("status", "active") == "active"]
    by = {l: sum(1 for e in act if e.get("label") == l) for l in ("CONFIRMED", "INFERRED", "UNKNOWN")}
    pend = [q for q in s["queue"] if q["status"] == "pending"]
    tasks = s["tasks"]
    frag = [f for f in os.listdir(os.path.join(d, "work")) if f.endswith(".json")]
    print(f"CASE {s['case']} | phase {s['phase']} | updated {s['updated']}"
          + (f" | reopened {len(s['reopened'])}x" if s.get("reopened") else "")
          + (" | CLOSED (use `case.py reopen` to continue)" if s["phase"] in ("REPORT", "DONE") else ""))
    print(f"evidence: {len(ev['entries'])} entries ({len(act)} active) C={by['CONFIRMED']} I={by['INFERRED']} U={by['UNKNOWN']}"
          f" | diagram {len(fi['nodes'])} nodes {len(fi['edges'])} edges | un-ingested fragments: {len(frag)}")
    if caps:
        bad = [k for k, v in caps.get("services", {}).items() if v["status"] != "ok"]
        print(f"capabilities ({caps.get('probed_at')}): not ok -> {', '.join(bad) or 'none'}")
    else:
        print("capabilities: not probed (run case.py probe)")
    print(f"tasks {len(tasks)}/{s['budget']['max_tasks']}: " + (", ".join(f"{k}={v['status']}" for k, v in tasks.items()) or "none"))
    print(f"pending pivots ({len(pend)}): " + ("; ".join(f"{q['id']} {q['type']} {q['value']}" for q in pend[:8]) or "none")
          + (" ..." if len(pend) > 8 else ""))
    if ev["entries"] and fi["nodes"]:
        try:
            from evidence_doc import coverage
            bad, gaps = coverage(ev, fi)
            print(f"coverage gaps: {', '.join(gaps) or 'none'}" + (f" | bad refs: {', '.join(bad)}" if bad else ""))
        except Exception as x:
            print(f"coverage: could not compute ({x})")
    opn = [n for n in s["needs_user"] if n["status"] == "open"]
    print(f"needs user ({len(opn)}): " + ("; ".join(f"{n['id']} {n['action'][:70]}" for n in opn) or "none"))
    print(f"open questions: {len(s['open_questions'])}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("init"); p.add_argument("case"); p.add_argument("--seed", required=True)
    p.add_argument("--max-depth", type=int, default=2); p.add_argument("--max-tasks", type=int, default=10)
    for name in ("probe", "next", "status"):
        sp.add_parser(name).add_argument("case")
    p = sp.add_parser("add"); p.add_argument("case"); p.add_argument("value"); p.add_argument("--type")
    p.add_argument("--depth", type=int, required=True); p.add_argument("--why", required=True)
    p = sp.add_parser("skip"); p.add_argument("case"); p.add_argument("qid"); p.add_argument("--why", required=True)
    p = sp.add_parser("task"); p.add_argument("case"); p.add_argument("op", choices=["start", "done", "fail"])
    p.add_argument("task_id"); p.add_argument("--agent", default="inline"); p.add_argument("--targets")
    p.add_argument("--note"); p.add_argument("--force", action="store_true")
    p = sp.add_parser("need"); p.add_argument("case")
    for f in ("--action", "--why", "--bring", "--safety"):
        p.add_argument(f, required=True)
    p = sp.add_parser("resolve"); p.add_argument("case"); p.add_argument("nid"); p.add_argument("--note")
    p = sp.add_parser("question"); p.add_argument("case"); p.add_argument("text")
    p = sp.add_parser("phase"); p.add_argument("case"); p.add_argument("phase")
    p.add_argument("--confirmed", action="store_true", help="user explicitly confirmed the investigation is complete (required for REPORT/DONE)")
    p = sp.add_parser("reopen"); p.add_argument("case"); p.add_argument("--why", required=True)
    a = ap.parse_args(argv)
    try:
        globals()["cmd_" + a.cmd](a)
    except CTIError as x:
        print(f"error: {x}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
