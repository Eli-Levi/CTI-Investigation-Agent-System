#!/usr/bin/env python3
"""PreToolUse hook: keep the investigator's own machine from contacting attacker hosts directly.

- Intel services (urlscan, VirusTotal, WhereGoes, crt.sh, RDAP, ...) are ALWAYS allowed, including
  submissions where the service fetches the attacker URL from its own infrastructure.
- WebFetch / curl / Invoke-WebRequest / browser-open to any other host -> "ask" (user decides).
- Commands that would print an API key, or file writes containing a key's value -> "deny".
- scripts/*.py calls pass through (intel.py only talks to intel services).
No output + exit 0 = normal permission flow.
"""
import json, os, re, sys

ALLOW = ("urlscan.io", "virustotal.com", "wheregoes.com", "crt.sh", "sslmate.com", "certspotter.com", "rdap.org",
         "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net", "iana.org", "icann.org", "abuseipdb.com",
         "abuse.ch", "alienvault.com", "archive.org", "dns.google", "cloudflare-dns.com", "shodan.io", "censys.io",
         "censys.com", "bgpview.io", "ipinfo.io", "hackertarget.com", "viewdns.info", "dnslytics.com", "phishtank.org",
         "openphish.com", "securitytrails.com", "dnsdumpster.com", "commoncrawl.org", "safebrowsing.googleapis.com",
         "transparencyreport.google.com", "gchq.github.io",
         # docs / tooling (not attacker infra)
         "docs.claude.com", "code.claude.com", "anthropic.com", "python.org", "github.com", "githubusercontent.com",
         "mermaid.live", "mermaid.js.org", "attack.mitre.org")
KEY_ENVS = ("VT_API_KEY", "URLSCAN_API_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "ABUSECH_KEY", "VIEWDNS_KEY")
NET_TOOL = re.compile(r"(?i)(?<![\w-])(curl(\.exe)?|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer|"
                      r"nc|ncat|telnet|httpie|aria2c|urllib|requests\.get|requests\.post|httpx|Start-Process|start|explorer(\.exe)?|msedge|chrome|firefox)(?![\w-])")
URL = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)://([^/\s'\"`<>:?#]+)")
PRINT_KEY = re.compile(r"(?i)(echo|Write-Host|Write-Output|printenv|print\s*\(|Set-Content|Add-Content|Out-File|\btee\b|clip)"
                       r"[^|;&\n]*(\$env:|\$\{?|os\.environ[^\n]*)(" + "|".join(KEY_ENVS) + r")")
DUMP_ENV = re.compile(r"(?i)^\s*(printenv|env|set|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:|ls\s+env:)\s*$")


def allowed(host):
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in ALLOW)


def out(decision, reason):
    try:  # telemetry: record the decision (reason only; never the command) - best effort
        import datetime
        d = os.environ.get("CTI_LOG_DIR") or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "guard.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
                                 "decision": decision, "reason": re.sub(r"[A-Za-z0-9_\-]{32,}", "<masked>", reason)[:200]}) + "\n")
    except Exception:
        pass
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    sys.exit(0)


KEYSTORE_ACCESS = re.compile(r"(?i)import\s+keystore|from\s+keystore|keystore\.load|get_key\s*\(|CryptUnprotectData|"
                             r"ProtectedData|Unprotect|cti-investigation[\\/]+keys")


def key_values():
    vals = [os.environ.get(k) for k in KEY_ENVS]
    try:  # also guard against leaking key-store values
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts"))
        import keystore
        vals += [keystore.load(n) for n in keystore.NAMES]
    except Exception:
        pass
    return [v for v in vals if v and len(v) >= 16]


def check(tool, ti):
    if tool == "WebFetch":
        host = (URL.search(ti.get("url", "")) or [None, ""])[1]
        if host and not allowed(host):
            out("ask", f"Direct fetch of {host} from YOUR IP. If this may be attacker infrastructure, use urlscan "
                       f"(intel.py urlscan search/submit) or WhereGoes instead. Approve only if {host} is benign.")
        return
    if tool in ("Bash", "PowerShell"):
        cmd = ti.get("command", "")
        if PRINT_KEY.search(cmd) or DUMP_ENV.search(cmd):
            out("deny", "This command would print or write an API key. Keys stay in the key store; scripts read them.")
        if KEYSTORE_ACCESS.search(cmd):
            out("deny", "Direct key-store access is reserved for scripts/intel.py and case.py; keys are never handled in commands.")
        for v in key_values():
            if v in cmd:
                out("deny", "Command contains a literal API key value. Use the env var instead.")
        # our own scripts are the sanctioned path to intel services
        stripped = re.sub(r"(?i)python[3w]?(\.exe)?\s+\S*scripts[\\/][\w.]+\.py[^|;&\n]*", " ", cmd)
        if NET_TOOL.search(stripped):
            bad = sorted({h for h in URL.findall(stripped) if not allowed(h)})
            if bad:
                out("ask", f"Command would contact {', '.join(bad)} directly from YOUR IP (possible attacker infra). "
                           f"Prefer intel.py (urlscan/WhereGoes/VT do the fetching). Approve only if benign.")
        return
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        blob = json.dumps(ti)
        if tool == "Write" and KEYSTORE_ACCESS.search(blob) and not re.search(r"(?i)scripts[\\/]+(keystore|ctilib|intel|case)\.py$|passive_guard\.py$", ti.get("file_path", "")):
            out("ask", "This file would access the API key store. Only the project scripts should do that.")
        for v in key_values():
            if v in blob:
                out("deny", "File content contains an API key value. Never write secrets to files.")


def main():
    try:
        data = json.load(sys.stdin)
    except Exception as x:  # fail closed: with "onFailure": "block" the tool call is stopped
        print(f"passive_guard: unreadable hook input ({x})", file=sys.stderr)
        return 2
    check(data.get("tool_name", ""), data.get("tool_input") or {})
    return 0


if __name__ == "__main__":
    sys.exit(main())
