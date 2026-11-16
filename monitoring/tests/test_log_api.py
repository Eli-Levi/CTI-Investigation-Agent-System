"""Offline tests for monitoring/log_api.py: python -m unittest discover -s monitoring/tests"""
import json, os, sys, tempfile, threading, unittest, urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import log_api  # noqa: E402

T0 = "2026-11-16T10:00:00+00:00"
T1 = "2026-11-16T10:30:00+00:00"
Q = {"from": "2026-11-16T09:00:00Z", "to": "2026-11-16T11:00:00Z"}


def jl(d, name, rows):
    with open(os.path.join(d, name + ".jsonl"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        jl(cls.d, "usage", [
            {"ts": T0, "msg_id": "a", "model": "m1", "src": "main", "input_tokens": 10, "output_tokens": 1, "cache_read_input_tokens": 90},
            {"ts": T0, "msg_id": "a", "model": "m1", "src": "main", "input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 90},
            {"ts": T1, "msg_id": "b", "model": "m2", "src": "subagent:cti-infra", "input_tokens": 0, "output_tokens": 7}])
        jl(cls.d, "tools", [
            {"ts": T0, "tool": "Read", "ok": True, "ms": 5, "result_chars": 100},
            {"ts": T1, "tool": "Read", "ok": False, "ms": 9, "result_chars": 0},
            {"ts": T1, "tool": "PowerShell", "ok": True, "ms": 50, "result_chars": 7}])
        jl(cls.d, "network", [{"ts": T0, "service": "urlscan", "host": "urlscan.io", "status": 200, "ms": 100, "bytes": 5},
                              {"ts": T1, "service": "urlscan", "host": "urlscan.io", "status": None, "ms": 300}])
        jl(cls.d, "errors", [{"ts": T1, "kind": "tool_failure", "tool": "Read", "text": "boom"}])

    def call(self, ep, **extra):
        return log_api.ENDPOINTS[ep](self.d, {**Q, **extra})

    def test_stats_dedupes_usage_and_counts_failures(self):
        s = self.call("stats")[0]
        self.assertEqual((s["api_calls"], s["output_tokens"], s["tool_calls"], s["tool_failures"]), (2, 12, 3, 1))
        self.assertEqual(s["cache_hit_pct"], 90.0)
        self.assertEqual(s["network_errors"], 1)

    def test_tokens_wide_by_model_and_source(self):
        rows = self.call("tokens", metric="output", group="model")
        self.assertEqual({k for r in rows for k in r} - {"time"}, {"m1", "m2"})
        self.assertEqual(sum(r["m1"] for r in rows), 5)
        by_src = self.call("tokens", metric="output", group="source")
        self.assertIn("subagent:cti-infra", by_src[0])

    def test_long_shape_has_fixed_columns(self):
        rows = self.call("tokens", metric="output", group="model", shape="long")
        self.assertTrue(rows and all(set(r) == {"time", "series", "value"} for r in rows))
        self.assertEqual(sum(r["value"] for r in rows if r["series"] == "m2"), 7)

    def test_sessions_rows_titles_cases(self):
        d = tempfile.mkdtemp()
        jl(d, "events", [{"ts": T0, "session": "aaaa1111-x", "event": "SessionStart"},
                         {"ts": T1, "session": "bbbb2222-y", "event": "SessionStart"}])
        jl(d, "tools", [{"ts": T0, "session": "aaaa1111-x", "tool": "PowerShell", "ok": True,
                         "in": {"kind": "script", "script": "intel.py", "case": "SMS-20261116-help4kids"}},
                        {"ts": T1, "session": "aaaa1111-x", "tool": "PowerShell", "ok": False,  # legacy row: case only in args
                         "in": {"kind": "script", "script": "case.py", "args": ["status", "URL-20261112-marom"]}}])
        jl(d, "usage", [{"ts": T0, "msg_id": "m", "session": "aaaa1111-x", "model": "m1", "output_tokens": 4}])
        jl(d, "sessions", [{"ts": T0, "session": "aaaa1111-x", "title": "auto", "kind": "ai"},
                           {"ts": T0, "session": "aaaa1111-x", "title": "mine", "kind": "custom"},
                           {"ts": T1, "session": "aaaa1111-x", "title": "newer auto", "kind": "ai"}])
        rows = {r["short"]: r for r in log_api.ENDPOINTS["sessions"](d, Q)}
        a = rows["aaaa1111"]
        self.assertEqual((a["title"], a["tool_calls"], a["tool_failures"], a["api_calls"], a["output_tokens"]),
                         ("mine", 2, 1, 1, 4))  # custom title beats a newer auto title
        self.assertEqual(a["cases"], "SMS-20261116-help4kids, URL-20261112-marom")
        self.assertEqual((rows["bbbb2222"]["title"], rows["bbbb2222"]["cases"]), ("(untitled)", "-"))
        self.assertEqual(list(rows)[0], "bbbb2222")  # newest first

    def test_session_scope_filters_rows_and_time_windows_network(self):
        d = tempfile.mkdtemp()
        jl(d, "events", [{"ts": T0, "session": "s1", "event": "SessionStart"},
                         {"ts": "2026-11-16T10:10:00+00:00", "session": "s2", "event": "SessionStart"}])
        jl(d, "tools", [{"ts": T0, "session": "s1", "tool": "Read", "ok": True},
                        {"ts": "2026-11-16T10:12:00+00:00", "session": "s2", "tool": "Read", "ok": True},
                        {"ts": "2026-11-16T10:13:00+00:00", "session": "s2", "tool": "Read", "ok": True}])
        jl(d, "network", [{"ts": T0, "host": "a", "status": 200},                          # inside s1's window
                          {"ts": "2026-11-16T10:12:30+00:00", "host": "b", "status": 200}])  # s2's window only
        h = log_api.Handler
        h.log_dir = d
        srv = ThreadingHTTPServer(("127.0.0.1", 0), h)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def get(ep, sess):
                url = f"http://127.0.0.1:{srv.server_address[1]}/api/{ep}?from={Q['from']}&to={Q['to']}&session={sess}"
                with urllib.request.urlopen(url) as r:
                    return json.load(r)
            self.assertEqual(get("stats", "s2")[0]["tool_calls"], 2)
            self.assertEqual(get("stats", "s1")[0]["tool_calls"], 1)
            self.assertEqual([n["host"] for n in get("network", "s2")], ["b"])
            self.assertEqual(get("stats", "nope")[0]["tool_calls"], 0)
            self.assertEqual(len(get("sessions", "s2")), 2)  # the Sessions table is never narrowed
            self.assertEqual(get("stats", "")[0]["tool_calls"], 3)  # empty variable = everything
        finally:
            srv.shutdown()
            srv.server_close()

    def test_tool_summary_and_failures_series(self):
        r = {x["tool"]: x for x in self.call("tool_summary")}
        self.assertEqual((r["Read"]["calls"], r["Read"]["failures"], r["Read"]["failure_pct"]), (2, 1, 50.0))
        f = self.call("tools_ts", metric="failures")
        self.assertEqual(sum(x.get("Read", 0) for x in f), 1)

    def test_network_errors_and_time_filter(self):
        n = self.call("network")[0]
        self.assertEqual((n["calls"], n["errors"]), (2, 1))
        self.assertEqual(log_api.ENDPOINTS["network"](self.d, {"from": "2020-01-01T00:00:00Z", "to": "2020-01-02T00:00:00Z"}), [])

    def test_missing_logs_dir_is_empty_not_error(self):
        self.assertEqual(log_api.ENDPOINTS["tool_summary"](tempfile.mkdtemp(), Q), [])

    def test_reloads_when_file_changes(self):
        d = tempfile.mkdtemp()
        jl(d, "tools", [{"ts": T0, "tool": "A", "ok": True}])
        self.assertEqual(log_api.ENDPOINTS["stats"](d, Q)[0]["tool_calls"], 1)
        jl(d, "tools", [{"ts": T0, "tool": "A", "ok": True}, {"ts": T1, "tool": "A", "ok": True}])
        self.assertEqual(log_api.ENDPOINTS["stats"](d, Q)[0]["tool_calls"], 2)

    def test_http_roundtrip(self):
        log_api.Handler.log_dir = self.d
        srv = ThreadingHTTPServer(("127.0.0.1", 0), log_api.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/api/stats?from={Q['from']}&to={Q['to']}"
            with urllib.request.urlopen(url) as r:
                self.assertEqual(json.load(r)[0]["tool_calls"], 3)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/etc/passwd")
            self.assertEqual(cm.exception.code, 404)
            cm.exception.close()
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
