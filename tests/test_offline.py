"""Offline tests (no network): python -m unittest discover -s tests -v"""
import io, json, os, shutil, subprocess, sys, tempfile, unittest, contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import ctilib, case, evidence_ingest, evidence_doc, intel, ioc_index  # noqa: E402

HOOK = os.path.join(ROOT, ".claude", "hooks", "passive_guard.py")
CASE = "TEST-offline"


def hook(tool, ti, env=None):
    p = subprocess.run([sys.executable, HOOK], input=json.dumps({"tool_name": tool, "tool_input": ti}),
                       capture_output=True, text=True, env={**os.environ, **(env or {})})
    return json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] if p.stdout.strip() else "pass"


class Hook(unittest.TestCase):
    def test_intel_services_never_blocked(self):
        for u in ("https://urlscan.io/api/v1/scan/", "https://www.virustotal.com/api/v3/urls",
                  "https://wheregoes.com/trace/", "https://crt.sh/?q=x.com"):
            self.assertEqual(hook("WebFetch", {"url": u}), "pass", u)
        self.assertEqual(hook("PowerShell", {"command": 'curl.exe -s -X POST https://urlscan.io/api/v1/scan/ -H "API-Key: $env:URLSCAN_API_KEY"'}), "pass")
        self.assertEqual(hook("Bash", {"command": 'curl -s -H "x-apikey: $VT_API_KEY" https://www.virustotal.com/api/v3/domains/x.com -o vt.json'}), "pass")

    def test_scripts_pass_even_with_attacker_url(self):
        self.assertEqual(hook("PowerShell", {"command": 'python scripts/intel.py C urlscan submit https://pay-il.xyz/login --country il'}), "pass")
        self.assertEqual(hook("PowerShell", {"command": 'python scripts/case.py init C --seed "click https://evil.top/a"'}), "pass")

    def test_direct_contact_asks(self):
        self.assertEqual(hook("WebFetch", {"url": "https://pay-il.xyz/login"}), "ask")
        self.assertEqual(hook("PowerShell", {"command": "Invoke-WebRequest https://pay-il.xyz/"}), "ask")
        self.assertEqual(hook("Bash", {"command": "curl -sI http://evil.top/x"}), "ask")

    def test_key_leaks_denied(self):
        self.assertEqual(hook("PowerShell", {"command": "echo $env:VT_API_KEY"}), "deny")
        self.assertEqual(hook("PowerShell", {"command": "Get-ChildItem env:"}), "deny")
        fake = "k" * 40
        self.assertEqual(hook("Write", {"file_path": "x", "content": f"key={fake}"}, {"VT_API_KEY": fake}), "deny")
        self.assertEqual(hook("Write", {"file_path": "x", "content": "harmless"}, {"VT_API_KEY": fake}), "pass")

    def test_keystore_access_denied_but_scripts_pass(self):
        self.assertEqual(hook("PowerShell", {"command": 'python -c "import keystore; print(keystore.load(\'VT_API_KEY\'))"'}), "deny")
        self.assertEqual(hook("PowerShell", {"command": "Get-Content $env:APPDATA\\cti-investigation\\keys\\VT_API_KEY.bin"}), "deny")
        self.assertEqual(hook("PowerShell", {"command": "python scripts/keystore.py list"}), "pass")
        self.assertEqual(hook("PowerShell", {"command": "python scripts/intel.py C viewdns subdomains x.com"}), "pass")


@unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
class KeyStore(unittest.TestCase):
    def test_dpapi_roundtrip_and_binding(self):
        import keystore
        blob = keystore._dpapi(b"secret-value-123", "VT_API_KEY", protect=True)
        self.assertNotIn(b"secret-value-123", blob)
        self.assertEqual(keystore._dpapi(blob, "VT_API_KEY", protect=False), b"secret-value-123")
        with self.assertRaises(OSError):  # entropy is bound to the key name
            keystore._dpapi(blob, "URLSCAN_API_KEY", protect=False)


class Extract(unittest.TestCase):
    def test_hebrew_sms(self):
        found = ctilib.extract("חבילתך מעוכבת, עדכן פרטים:hxxps://bit[.]ly/3AbCd עכשיו. 054-123-4567")
        vals = {(v, t) for v, t, _ in found}
        self.assertIn(("https://bit.ly/3AbCd", "url"), vals)
        self.assertIn(("bit.ly", "domain"), vals)
        self.assertIn(("0541234567", "phone"), vals)

    def test_hyphen_not_mangled(self):
        self.assertEqual(evidence_doc.show("pay-il.xyz"), "pay-il.xyz")
        self.assertEqual(evidence_doc.show("a‮b"), "a<U+202E>b")


class Pipeline(unittest.TestCase):
    def setUp(self):
        # auto-refresh would otherwise write TEST-offline into the REAL _index: isolate it
        self._idx_orig = (ctilib.INDEX_DIR, ioc_index.INDEX_DIR)
        self.idx_dir = tempfile.mkdtemp()
        ctilib.INDEX_DIR = ioc_index.INDEX_DIR = self.idx_dir
        self.d = os.path.join(ctilib.INVESTIGATIONS, CASE)
        shutil.rmtree(self.d, ignore_errors=True)
        with contextlib.redirect_stdout(io.StringIO()):
            case.main(["init", CASE, "--seed", "Your parcel: https://bit.ly/xyz", "--max-tasks", "2"])

    def tearDown(self):
        ctilib.INDEX_DIR, ioc_index.INDEX_DIR = self._idx_orig
        shutil.rmtree(self.idx_dir, ignore_errors=True)
        shutil.rmtree(self.d, ignore_errors=True)

    def _index(self):
        return ctilib.read_json(os.path.join(self.idx_dir, "ioc-index.json"), {"observations": {}, "nodes": {}})

    def test_ingest_auto_refreshes_index(self):
        self.run_cli(case.main, ["add", CASE, "pay-il.xyz", "--depth", "1", "--why", "lure"])
        self.frag("WEB-001", 1, ["PAY"], [])
        rc, out = self.run_cli(evidence_ingest.main, [CASE])  # no manual `index` call
        self.assertEqual(rc, 0, out)
        o = self._index()["observations"][f"obs:{CASE}|domain:pay-il.xyz"]
        self.assertEqual((o["label"], o["status"]), ("CONFIRMED", "active"))

    def test_refresh_failure_is_nonfatal_and_loud(self):
        self.run_cli(case.main, ["add", CASE, "pay-il.xyz", "--depth", "1", "--why", "lure"])
        self.frag("WEB-001", 1, ["PAY"], [])
        orig = ioc_index.Lock

        def boom(*a, **k):
            raise RuntimeError("lock busy")
        ioc_index.Lock = boom
        try:
            rc, out = self.run_cli(evidence_ingest.main, [CASE])
        finally:
            ioc_index.Lock = orig
        self.assertEqual(rc, 0, out)  # ingest's own exit code is unchanged
        self.assertIn("WARNING: IOC index refresh failed for " + CASE, out)
        self.assertIn("stale", out)
        self.assertEqual(len(ctilib.read_json(os.path.join(self.d, "evidence.json"))["entries"]), 1)

    def test_close_links_report_and_reopen_clears_it(self):
        self.run_cli(case.main, ["phase", CASE, "REPORT", "--confirmed"])
        with open(os.path.join(self.d, "report.md"), "w", encoding="utf-8") as fh:
            fh.write("# r\n")
        self.run_cli(case.main, ["phase", CASE, "DONE", "--confirmed"])
        self.assertEqual(self._index()["nodes"][f"case:{CASE}"]["report"], f"{CASE}/report.md")
        self.run_cli(case.main, ["reopen", CASE, "--why", "lead"])
        self.assertIsNone(self._index()["nodes"][f"case:{CASE}"]["report"])

    def run_cli(self, fn, args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                rc = fn(args)
            except SystemExit as e:
                rc = e.code
        return rc, buf.getvalue()

    def test_report_phase_requires_user_confirmation(self):
        for ph in ("REPORT", "DONE"):
            rc, _ = self.run_cli(case.main, ["phase", CASE, ph])
            self.assertNotEqual(rc, 0)
        self.assertNotEqual(ctilib.read_json(os.path.join(self.d, "state.json"))["phase"], "REPORT")
        rc, _ = self.run_cli(case.main, ["phase", CASE, "REPORT", "--confirmed"])
        self.assertEqual(rc, 0)
        self.assertEqual(ctilib.read_json(os.path.join(self.d, "state.json"))["phase"], "REPORT")

    def test_reopen_closed_case_archives_deliverables(self):
        self.run_cli(case.main, ["phase", CASE, "REPORT", "--confirmed"])
        for f in ("report.md", "report.he.md", "diagram.mmd"):
            open(os.path.join(self.d, f), "w").close()
        rc, _ = self.run_cli(case.main, ["phase", CASE, "DISPATCH"])  # must go through reopen
        self.assertNotEqual(rc, 0)
        rc, _ = self.run_cli(case.main, ["reopen", CASE, "--why", "new lead"])
        self.assertEqual(rc, 0)
        st = ctilib.read_json(os.path.join(self.d, "state.json"))
        self.assertEqual(st["phase"], "DISPATCH")
        self.assertNotIn("close_confirmed", st)
        self.assertEqual(st["reopened"][0]["why"], "new lead")
        for f in ("report.md", "report.he.md", "diagram.mmd"):
            self.assertFalse(os.path.exists(os.path.join(self.d, f)))
        self.assertEqual(len(st["reopened"][0]["archived"]), 3)
        rc, _ = self.run_cli(case.main, ["reopen", CASE, "--why", "x"])  # not closed anymore
        self.assertNotEqual(rc, 0)
        rc, _ = self.run_cli(case.main, ["phase", CASE, "REPORT"])  # gate applies again
        self.assertNotEqual(rc, 0)

    def frag(self, tid, n, nodes, edges, raw=True):
        rawf = f"raw/{tid}.json"
        with open(os.path.join(self.d, rawf), "w") as fh:
            fh.write('{"x":1}')
        entries = [{"id": f"{tid}-{i:02d}", "claim": f"claim {i}", "label": "CONFIRMED", "value": f"https://pay-il.xyz/{tid}-0{i}",
                    "found_in": {"tool": "urlscan.io", "query": "GET https://urlscan.io/api/v1/result/u/", "observed_at": "2026-11-06T10:00:00Z", "by": "claude"},
                    "reconfirm": {"link": "https://urlscan.io/result/u/", "stability": "stable"},
                    "nodes": nodes, **({"raw_file": rawf} if raw else {})} for i in range(1, n + 1)]
        ctilib.write_json(os.path.join(self.d, "work", f"{tid}.json"),
                          {"task_id": tid, "entries": entries, "nodes": [{"id": x, "label": x, "kind": "confirmed"} for x in nodes if ">" not in x], "edges": edges})

    def test_parallel_fragments_no_collisions_and_updates(self):
        self.frag("WEB-001", 2, ["SHORT", "PAY", "SHORT>PAY"], [{"from": "SHORT", "to": "PAY", "technique": "WhereGoes", "confidence": "inferred"}])
        self.frag("INF-001", 2, ["PAY"], [])
        rc, out = self.run_cli(evidence_ingest.main, [CASE])
        self.assertEqual(rc, 0, out)
        ev = ctilib.read_json(os.path.join(self.d, "evidence.json"))
        ids = [e["id"] for e in ev["entries"]]
        self.assertEqual(ids, ["E-001", "E-002", "E-003", "E-004"])
        self.assertTrue(all(len(e["sha256"]) == 64 for e in ev["entries"]))
        self.assertTrue(any(e["value"] == "https://pay-il.xyz/WEB-001-01" for e in ev["entries"]))  # verbatim value never remapped
        self.assertFalse(os.path.exists(os.path.join(self.d, "diagram.mmd")))  # diagram only at confirmed close
        self.assertTrue(os.path.isfile(os.path.join(self.d, "evidence.md")))
        # second round: upgrade edge, supersede E-001 with a new local entry
        self.frag("WEB-002", 1, ["SHORT>PAY"], [{"from": "SHORT", "to": "PAY", "technique": "urlscan", "confidence": "confirmed"}])
        f = ctilib.read_json(os.path.join(self.d, "work", "WEB-002.json"))
        f["nodes"] = []
        f["updates"] = [{"id": "E-001", "status": "superseded", "superseded_by": "WEB-002-01", "note": "newer scan WEB-002-01"}]
        ctilib.write_json(os.path.join(self.d, "work", "WEB-002.json"), f)
        rc, out = self.run_cli(evidence_ingest.main, [CASE])
        self.assertEqual(rc, 0, out)
        ev = ctilib.read_json(os.path.join(self.d, "evidence.json"))
        e1 = ev["entries"][0]
        self.assertEqual(ev["entries"][-1]["value"], "https://pay-il.xyz/WEB-002-01")
        self.assertEqual((e1["status"], e1["superseded_by"]), ("superseded", "E-005"))
        self.assertIn("E-005", e1["history"][-1]["note"])
        fi = ctilib.read_json(os.path.join(self.d, "findings.json"))
        self.assertEqual(fi["edges"][0]["confidence"], "confirmed")
        self.assertEqual(fi["edges"][0]["technique"], "WhereGoes + urlscan")

    def test_bad_fragment_rejected_and_kept(self):
        self.frag("WEB-001", 1, ["PAY"], [])
        f = ctilib.read_json(os.path.join(self.d, "work", "WEB-001.json"))
        f["entries"][0]["sha256"] = "0" * 64
        ctilib.write_json(os.path.join(self.d, "work", "WEB-001.json"), f)
        rc, out = self.run_cli(evidence_ingest.main, [CASE])
        self.assertEqual(rc, 2)
        self.assertIn("HASH MISMATCH", out)
        self.assertTrue(os.path.isfile(os.path.join(self.d, "work", "WEB-001.json")))
        self.assertEqual(ctilib.read_json(os.path.join(self.d, "evidence.json"))["entries"], [])

    def test_queue_budget_and_status(self):
        rc, out = self.run_cli(case.main, ["add", CASE, "BIT.LY", "--depth", "1", "--why", "dup"])
        self.assertIn("already seen", out)
        rc, out = self.run_cli(case.main, ["add", CASE, "far.example", "--depth", "3", "--why", "deep"])
        self.assertIn("over depth budget", out)
        self.run_cli(case.main, ["task", CASE, "start", "WEB-001", "--targets", "Q-001"])
        self.run_cli(case.main, ["task", CASE, "start", "INF-001"])
        rc, out = self.run_cli(case.main, ["task", CASE, "start", "INF-002"])
        self.assertEqual(rc, 2)
        self.assertIn("BUDGET EXHAUSTED", out)
        rc, out = self.run_cli(case.main, ["status", CASE])
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(out.splitlines()), 20)

    def test_intel_unknown_without_key(self):
        orig = intel.get_key
        intel.get_key = lambda n: None
        try:
            rc, out = self.run_cli(intel.main, [CASE, "vt", "domain", "example.com"])
        finally:
            intel.get_key = orig
        self.assertEqual(rc, 2)
        self.assertIn("UNKNOWN: no API key", out)

    def test_query_key_never_recorded_and_raw_redacted(self):
        fake = "SECRETKEY_" + "z" * 30
        orig_get, orig_http = intel.get_key, intel.Ctx.http
        seen = {}
        intel.get_key = lambda n: fake if n == "VIEWDNS_KEY" else None

        def fake_http(self, service, method, url, headers=None, data=None, key_env=None, key_header=None, key_query=None, **k):
            seen["url"] = url + "&apikey=" + intel.get_key(key_env)  # what would really go on the wire
            return 200, json.dumps({"query": {"apikey": fake}, "response": {"domain_count": 1,
                                    "subdomains": [{"name": "a.pay-il.xyz"}]}}).encode(), "application/json"
        intel.Ctx.http = fake_http
        try:
            rc, out = self.run_cli(intel.main, [CASE, "viewdns", "subdomains", "pay-il.xyz"])
        finally:
            intel.get_key, intel.Ctx.http = orig_get, orig_http
        self.assertEqual(rc, 0, out)
        self.assertNotIn(fake, out)
        self.assertIn("<VIEWDNS_KEY from key store>", out)
        self.assertIn("a.pay-il.xyz", out)
        raw = [f for f in os.listdir(os.path.join(self.d, "raw")) if f.startswith("viewdns")][0]
        intel.get_key = lambda n: fake if n == "VIEWDNS_KEY" else None
        try:
            body = open(os.path.join(self.d, "raw", raw), encoding="utf-8").read()
        finally:
            intel.get_key = orig_get
        self.assertNotIn(fake, body)
        self.assertIn("<VIEWDNS_KEY>", body)
        self.assertNotIn(fake, open(os.path.join(self.d, "audit.log"), encoding="utf-8").read())

    def test_urlscan_diff_shows_new_backend(self):
        c = intel.Ctx(CASE)
        old = {"task": {"time": "2026-10-01T00:00"}, "page": {"url": "https://pay-il.xyz/l", "ip": "1.1.1.1"},
               "lists": {"domains": ["pay-il.xyz"], "ips": ["1.1.1.1"], "hashes": ["a" * 64]}, "data": {"requests": []}}
        new = {"task": {"time": "2026-11-06T00:00"}, "page": {"url": "https://pay-il.xyz/l", "ip": "2.2.2.2"},
               "lists": {"domains": ["pay-il.xyz", "abc.supabase.co"], "ips": ["2.2.2.2"], "hashes": ["b" * 64]},
               "data": {"requests": [{"request": {"request": {"url": "https://abc.supabase.co/rest/v1/cards", "method": "POST"}, "type": "Fetch"}}]}}
        c.call = lambda *a, **k: ((old if "11111111" in a[2] else new), {"raw_file": "raw/x.json", "sha256": "0" * 64})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            intel.us_diff(c, "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        out = buf.getvalue()
        self.assertIn("NEW domains: abc.supabase.co", out)
        self.assertIn("NEW backend/XHR/POST: POST https://abc.supabase.co/rest/v1/cards", out)
        self.assertIn("NEW page_ip: 2.2.2.2", out)

    def test_urlscan_result_summary_from_fixture(self):
        c = intel.Ctx(CASE)
        fixture = {"task": {"time": "2026-11-06T10:00:00Z", "visibility": "unlisted", "url": "https://bit.ly/xyz"},
                   "page": {"url": "https://pay-il.xyz/l", "domain": "pay-il.xyz", "ip": "104.21.1.1", "asn": "AS13335", "asnname": "CLOUDFLARENET"},
                   "verdicts": {"overall": {"malicious": True, "score": 100, "brands": ["Israel Post"]}},
                   "data": {"requests": [
                       {"request": {"request": {"url": "https://pay-il.xyz/l", "method": "GET"}, "type": "Document",
                                    "redirectResponse": {"status": 301, "url": "https://bit.ly/xyz"}}},
                       {"request": {"request": {"url": "https://api.telegram.org/bot123/sendMessage", "method": "POST"}, "type": "XHR"}}]},
                   "lists": {"domains": ["pay-il.xyz", "api.telegram.org"], "ips": ["104.21.1.1"], "hashes": ["a" * 64]}}
        c.call = lambda *a, **k: (fixture, {"raw_file": "raw/x.json", "sha256": "0" * 64})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            intel.us_result(c, "12345678-1234-1234-1234-123456789abc")
        out = buf.getvalue()
        self.assertIn("redirect[0] 301 https://bit.ly/xyz -> https://pay-il.xyz/l", out)
        self.assertIn("exfil/backend pattern", out)
        self.assertLessEqual(len(out.splitlines()), 26)


SECRET = "AkiaMixedCase_Token_1234567890abcDEF"
HASH = "a" * 64


def _ent(eid, value, nodes=(), label="CONFIRMED", status="active"):
    return {"id": eid, "claim": f"{label.lower()} {value}", "label": label, "value": value, "status": status,
            "found_in": {"tool": "t", "query": "q", "observed_at": "2026-11-08T10:00:00Z", "by": "claude"},
            "reconfirm": {"link": "x", "stability": "stable"}, "nodes": list(nodes)}


class IocGateway(unittest.TestCase):
    def setUp(self):
        self.vault = tempfile.mkdtemp()
        self._orig = (ctilib.INVESTIGATIONS, ctilib.INDEX_DIR, ioc_index.INVESTIGATIONS, ioc_index.INDEX_DIR)
        idx = os.path.join(self.vault, "_index")
        ctilib.INVESTIGATIONS, ctilib.INDEX_DIR = self.vault, idx
        ioc_index.INVESTIGATIONS, ioc_index.INDEX_DIR = self.vault, idx

    def tearDown(self):
        ctilib.INVESTIGATIONS, ctilib.INDEX_DIR, ioc_index.INVESTIGATIONS, ioc_index.INDEX_DIR = self._orig
        shutil.rmtree(self.vault, ignore_errors=True)

    def mkcase(self, name, seen, entries, phase="VALIDATE", report=False):
        d = os.path.join(self.vault, name)
        os.makedirs(os.path.join(d, "work", "ingested"), exist_ok=True)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        st = {"case": name, "created": "2026-11-08T00:00:00Z", "updated": "2026-11-08T00:00:00Z",
              "phase": phase, "seed": "", "budget": {"max_depth": 2, "max_tasks": 10},
              "seen": {k: {"first": "Q-001", "at": "2026-11-08T00:00:00Z"} for k in seen},
              "queue": [], "done_queue": [], "tasks": {}, "needs_user": [], "open_questions": []}
        if phase in ("REPORT", "DONE"):
            st["close_confirmed"] = "2026-11-08T12:00:00Z"
        ctilib.write_json(os.path.join(d, "state.json"), st)
        ctilib.write_json(os.path.join(d, "evidence.json"), {"title": name, "entries": entries})
        ctilib.write_json(os.path.join(d, "findings.json"), {"nodes": [], "edges": []})
        if report:
            with open(os.path.join(d, "report.md"), "w", encoding="utf-8") as fh:
                fh.write("# report\n")
        return d

    def cli(self, args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ioc_index.main(args)
        return rc, buf.getvalue()

    # the closed prior case, with one of every strong IOC type + a shortener that must NOT be indexed
    def prior(self):
        self.mkcase("PRIOR-closed", ["domain:alpha.example", "ip:5.5.5.5", f"hash:{HASH}",
                                     f"secret:{SECRET}", "domain:bit.ly"],
                    [_ent("E-001", "https://alpha.example/login", ["ALPHA"]),
                     _ent("E-002", "resolves to 5.5.5.5"),
                     _ent("E-003", f"resource sha256 {HASH}"),
                     _ent("E-004", f"attacker api key {SECRET}"),
                     _ent("E-005", "lure via https://bit.ly/x")],
                    phase="REPORT", report=True)
        self.assertEqual(self.cli(["index", "PRIOR-closed"])[0], 0)

    def test_ioc_class(self):
        self.assertEqual(ctilib.ioc_class("domain", "alpha.example"), "strong")
        self.assertEqual(ctilib.ioc_class("ip", "5.5.5.5"), "strong")
        self.assertEqual(ctilib.ioc_class("hash", HASH), "strong")
        self.assertEqual(ctilib.ioc_class("phone", "+972500000000"), "strong")
        self.assertEqual(ctilib.ioc_class("secret", SECRET), "strong")
        self.assertEqual(ctilib.ioc_class("domain", "bit.ly"), "shared")
        self.assertEqual(ctilib.ioc_class("url", "https://x/y"), "exclude")
        self.assertEqual(ctilib.ioc_class("other", "x"), "exclude")

    def test_secret_normalize_preserves_case(self):
        self.assertEqual(ctilib.normalize(f"  {SECRET} ", "secret"), (SECRET, "secret"))
        self.assertNotEqual(ctilib.normalize(SECRET, "secret")[0], SECRET.lower())

    def test_index_vets_and_excludes_shortener(self):
        self.prior()
        idx = ctilib.read_json(os.path.join(self.vault, "_index", "ioc-index.json"))
        self.assertEqual(idx["version"], 2)
        self.assertIn("domain:alpha.example", idx["nodes"])
        self.assertIn(f"secret:{SECRET}", idx["nodes"])
        self.assertNotIn("domain:bit.ly", idx["nodes"])  # shorteners never enter the graph
        self.assertNotIn("obs:PRIOR-closed|domain:bit.ly", idx["observations"])
        reg = idx["nodes"]["case:PRIOR-closed"]
        self.assertEqual(reg["report"], "PRIOR-closed/report.md")  # closed + report.md present
        self.assertTrue(reg["source"])
        o = idx["observations"]["obs:PRIOR-closed|domain:alpha.example"]
        self.assertEqual((o["label"], o["status"], list(o["evidence"])), ("CONFIRMED", "active", ["E-001"]))
        self.assertEqual((o["case"], o["finding"]), ("case:PRIOR-closed", "domain:alpha.example"))

    def test_match_two_strong_surfaces_with_report(self):
        self.prior()
        self.mkcase("NEW-a", ["domain:alpha.example", "ip:5.5.5.5", "domain:bit.ly"], [])
        rc, out = self.cli(["match", "NEW-a"])
        self.assertEqual(rc, 0)
        self.assertIn("PRIOR-closed", out)
        self.assertIn("linked candidate", out)
        self.assertIn("alpha[.]example", out)  # defanged in output
        self.assertIn("PRIOR-closed/report.md", out)  # Tier 1 points at the report

    def test_match_single_hash_or_secret_surfaces(self):
        self.prior()
        self.mkcase("NEW-h", [f"hash:{HASH}"], [])
        self.mkcase("NEW-s", [f"secret:{SECRET}"], [])
        self.assertIn("linked candidate", self.cli(["match", "NEW-h"])[1])  # weight 2 alone
        self.assertIn("linked candidate", self.cli(["match", "NEW-s"])[1])

    def test_match_shortener_only_does_not_link(self):
        self.prior()
        self.mkcase("NEW-short", ["domain:bit.ly"], [])
        self.assertIn("no strong cross-case overlap", self.cli(["match", "NEW-short"])[1])

    def test_match_open_candidate_has_null_report_and_fallback(self):
        self.mkcase("OPEN-prior", ["domain:omega.example", "ip:9.9.9.9"],
                    [_ent("E-001", "https://omega.example/l"), _ent("E-002", "at 9.9.9.9")],
                    phase="VALIDATE")  # open: no report
        self.cli(["index", "OPEN-prior"])
        self.mkcase("NEW-o", ["domain:omega.example", "ip:9.9.9.9"], [])
        rc, out = self.cli(["match", "NEW-o"])
        self.assertIn("OPEN-prior", out)
        self.assertIn('"report": null', out)   # machine line reports no Tier 1
        self.assertIn("pending", out)          # fallback to card + status

    def test_card_is_thin_connector_and_masks_secret(self):
        self.prior()
        rc, out = self.cli(["card", "PRIOR-closed", "--alias", "CASA MAYA"])
        self.assertEqual(rc, 0)
        card = open(os.path.join(self.vault, "_index", "cards", "PRIOR-closed.md"), encoding="utf-8").read()
        self.assertIn("[[alpha[.]example]]", card)      # wikilinked anchor for the graph
        self.assertIn("E-001", card)
        self.assertIn("CASA MAYA", card)                # alias bound to folder id
        self.assertIn("report.md", card)                # links to source of truth
        self.assertIn("[[secret-", card)                # secret shown by fingerprint, not value
        self.assertNotIn(SECRET, card)                  # full attacker key never written to the card
        self.assertIn(SECRET, open(os.path.join(self.vault, "_index", "ioc-index.json"),
                                    encoding="utf-8").read())  # verbatim only in the index

    def test_lookup_and_shortener_absent(self):
        self.prior()
        out = self.cli(["lookup", "domain", "alpha.example"])[1]
        self.assertIn("1 observation", out)
        self.assertIn("CONFIRMED active E-001", out)
        self.assertIn("not in index", self.cli(["lookup", "domain", "bit.ly"])[1])

    def test_index_folder_reserved_and_match_is_read_only(self):
        with self.assertRaises(ctilib.CTIError):
            ctilib.case_dir("_index")  # '_' prefix is not a valid case id
        self.prior()
        self.mkcase("NEW-ro", ["domain:alpha.example", "ip:5.5.5.5"], [])
        before = open(os.path.join(self.vault, "NEW-ro", "state.json"), encoding="utf-8").read()
        idx_before = open(os.path.join(self.vault, "_index", "ioc-index.json"), encoding="utf-8").read()
        self.cli(["match", "NEW-ro"])
        self.assertEqual(open(os.path.join(self.vault, "NEW-ro", "state.json"), encoding="utf-8").read(), before)
        self.assertEqual(open(os.path.join(self.vault, "_index", "ioc-index.json"), encoding="utf-8").read(), idx_before)

    def idx(self):
        return ctilib.read_json(os.path.join(self.vault, "_index", "ioc-index.json"))

    def test_inferred_only_is_context_not_candidate(self):
        self.mkcase("INF", ["domain:inf.example", "ip:7.7.7.7"],
                    [_ent("E-001", "inf.example", label="INFERRED"), _ent("E-002", "at 7.7.7.7", label="INFERRED")])
        self.cli(["index", "INF"])
        self.mkcase("NEW-i", ["domain:inf.example", "ip:7.7.7.7"], [])
        out = self.cli(["match", "NEW-i"])[1]
        self.assertIn("no strong cross-case overlap", out)
        self.assertNotIn("linked candidate", out)
        self.assertIn("context: 2 INFERRED overlap(s) with INF (not scored)", out)

    def test_retracted_citer_is_tombstoned_not_scored(self):
        self.mkcase("TOMB", ["domain:gone.example", "ip:8.8.4.4"],
                    [_ent("E-001", "gone.example", status="retracted"), _ent("E-002", "at 8.8.4.4", status="retracted")])
        self.cli(["index", "TOMB"])
        o = self.idx()["observations"]["obs:TOMB|domain:gone.example"]
        self.assertEqual((o["label"], o["status"]), ("CONFIRMED", "retracted"))
        self.mkcase("NEW-t", ["domain:gone.example", "ip:8.8.4.4"], [])
        out = self.cli(["match", "NEW-t"])[1]
        self.assertNotIn("linked candidate", out)
        self.assertIn("2 retracted", out)

    def test_derivation_precedence_keeps_evidence_map(self):
        self.mkcase("PREC", ["domain:mix.example"],
                    [_ent("E-001", "mix.example", status="retracted"),
                     _ent("E-002", "mix.example", label="INFERRED")])
        self.cli(["index", "PREC"])
        o = self.idx()["observations"]["obs:PREC|domain:mix.example"]
        self.assertEqual((o["label"], o["status"]), ("INFERRED", "active"))
        self.assertEqual(o["evidence"]["E-001"], {"label": "CONFIRMED", "status": "retracted"})
        self.assertEqual(o["evidence"]["E-002"], {"label": "INFERRED", "status": "active"})

    def test_boundary_matching(self):
        c = ioc_index._cited
        self.assertFalse(c("domain", "a0r.me", {"value": "https://xa0r.me/x"}))
        self.assertTrue(c("domain", "a0r.me", {"value": "https://a0r.me/x"}))
        self.assertTrue(c("domain", "a0r.me", {"claim": "host a0r.me."}))
        self.assertFalse(c("ip", "5.5.5.5", {"value": "15.5.5.55"}))
        self.assertTrue(c("ip", "5.5.5.5", {"value": "resolves to 5.5.5.5."}))
        self.assertFalse(c("domain", "shemesh.me", {"value": "https://ran.shemesh.me/"}))
        self.assertTrue(c("domain", "shemesh.me", {"value": "hxxps://shemesh[.]me/"}))

    def _chain(self):
        hb, hc = "b" * 64, "c" * 64
        self.mkcase("N", ["domain:nb.example", "ip:1.1.1.1"], [])
        self.mkcase("B", ["domain:nb.example", "ip:1.1.1.1", f"hash:{hb}"],
                    [_ent("E-001", "nb.example"), _ent("E-002", "at 1.1.1.1"), _ent("E-003", f"sha256 {hb}")])
        self.mkcase("C", [f"hash:{hb}", f"hash:{hc}"], [_ent("E-001", f"sha256 {hb}"), _ent("E-002", f"sha256 {hc}")],
                    phase="REPORT", report=True)
        self.mkcase("D", [f"hash:{hc}"], [_ent("E-001", f"sha256 {hc}")], phase="REPORT", report=True)
        for c in "BCD":
            self.cli(["index", c])

    def test_indirect_one_hop_only_and_not_loaded(self):
        self._chain()
        out = self.cli(["match", "N"])[1]
        self.assertIn("B also links to C", out)
        self.assertIn("indirect, not loaded", out)
        self.assertNotIn("C/report.md", out)  # no Tier 1 path for an indirect case
        self.assertNotIn(" to D", out)        # never recurses past one hop
        self.assertNotIn("linked candidate case(s)", out.replace("1 linked candidate case(s)", ""))

    def test_verify_detects_manual_edit_and_match_warns(self):
        self.prior()
        self.assertEqual(self.cli(["verify"])[0], 0)
        ep = os.path.join(self.vault, "PRIOR-closed", "evidence.json")
        ev = ctilib.read_json(ep)
        ev["entries"].append(_ent("E-099", "alpha.example"))
        ctilib.write_json(ep, ev)
        rc, out = self.cli(["verify"])
        self.assertEqual(rc, 2)
        self.assertIn("stale: PRIOR-closed", out)
        self.mkcase("NEW-v", ["domain:alpha.example"], [])
        self.assertIn("index stale for: PRIOR-closed", self.cli(["match", "NEW-v"])[1])
        self.cli(["index", "PRIOR-closed"])
        self.assertNotIn("stale:", self.cli(["verify"])[1])
        self.assertNotIn("index stale", self.cli(["match", "NEW-v"])[1])  # the queried case itself is never flagged
        self.cli(["index", "NEW-v"])
        self.assertEqual(self.cli(["verify"])[0], 0)

    def test_v1_index_migrates_keeping_alias(self):
        self.prior()
        ctilib.write_json(os.path.join(self.vault, "_index", "ioc-index.json"),
                          {"version": 1, "updated": "x", "iocs": {"domain:alpha.example": {"cases": {}}},
                           "cases": {"PRIOR-closed": {"aliases": ["CASA MAYA"], "verdict": "CONFIRMED",
                                                      "cluster": "k", "report": None}}})
        idx = ioc_index.load_index()
        self.assertEqual(idx["version"], 2)
        self.assertEqual(idx["nodes"]["case:PRIOR-closed"]["aliases"], ["CASA MAYA"])
        self.assertEqual(idx["observations"], {})
        self.cli(["reindex-all", "--include-open"])
        self.assertEqual(self.idx()["nodes"]["case:PRIOR-closed"]["aliases"], ["CASA MAYA"])
        self.assertIn("obs:PRIOR-closed|domain:alpha.example", self.idx()["observations"])

    def test_card_context_has_no_wikilinks(self):
        self.mkcase("CTX", ["domain:conf.example", "domain:inf.example", "domain:gone.example"],
                    [_ent("E-001", "conf.example"), _ent("E-002", "inf.example", label="INFERRED"),
                     _ent("E-003", "gone.example", status="retracted")])
        self.cli(["card", "CTX"])
        card = open(os.path.join(self.vault, "_index", "cards", "CTX.md"), encoding="utf-8").read()
        anchors, _, context = card.partition("## Context (not scored)")
        self.assertIn("[[conf[.]example]]", anchors)
        self.assertIn("inf[.]example", context)
        self.assertIn("gone[.]example", context)
        self.assertIn("retracted (E-003)", context)
        self.assertNotIn("[[inf", card)
        self.assertNotIn("[[gone", card)


if __name__ == "__main__":
    unittest.main()
