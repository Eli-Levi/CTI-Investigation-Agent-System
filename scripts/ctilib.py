"""Shared helpers for the CTI investigation scripts (stdlib only)."""
import datetime, hashlib, json, os, re, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Cases live in the Obsidian vault folder (one subfolder per case). Override with CTI_CASES_DIR.
INVESTIGATIONS = os.environ.get("CTI_CASES_DIR") or os.path.join(ROOT, "Investigation Records")
# Reserved vault-level folder for the cross-case IOC gateway (see scripts/ioc_index.py). Its '_'
# prefix is not a valid CASE_RE id, so case_dir() can never resolve a case here.
INDEX_DIR = os.path.join(INVESTIGATIONS, "_index")
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# API keys: DPAPI key store first (scripts/keystore.py), env var as fallback. Values are never printed.
KEY_ENVS = ("VT_API_KEY", "URLSCAN_API_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "ABUSECH_KEY", "VIEWDNS_KEY")


def get_key(name):
    try:
        import keystore
        v = keystore.load(name)
        if v:
            return v
    except (OSError, ValueError, ImportError):
        pass
    return os.environ.get(name) or None


def key_source(name):
    try:
        import keystore
        if keystore.has(name):
            return "keystore"
    except (OSError, ValueError, ImportError):
        pass
    return "env" if os.environ.get(name) else None

SHORTENERS = {"bit.ly", "tinyurl.com", "did.li", "cutt.ly", "rb.gy", "t.ly", "is.gd", "ow.ly", "s.id",
              "shorturl.at", "tiny.cc", "rebrand.ly", "short.io", "t.co", "goo.su", "clck.ru", "v.gd",
              "bl.ink", "lnkd.in", "qrco.de", "tinyurl.is", "u.to", "shorturl.asia", "surl.li", "y2u.be"}


class CTIError(Exception):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


LOG_DIR = os.environ.get("CTI_LOG_DIR") or os.path.join(ROOT, "logs")


def tlog(stream, **fields):
    """Best-effort telemetry: append one JSON line to logs/<stream>.jsonl. Never raises, never logs
    URLs/queries/keys/bodies (callers pass host + metadata only). The logs dir is gitignored."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"), **fields}
        with open(os.path.join(LOG_DIR, stream + ".jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def case_dir(case, must_exist=True):
    if not CASE_RE.match(case or ""):
        raise CTIError(f"bad case id {case!r} (letters, digits, _ . - only)")
    p = os.path.join(INVESTIGATIONS, case)
    if must_exist and not os.path.isfile(os.path.join(p, "state.json")):
        raise CTIError(f"case {case} not found; run: python scripts/case.py init {case} --seed \"...\"")
    return p


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


class Lock:
    """Cross-process lock via an exclusive lock file (stale after 120 s)."""

    def __init__(self, path, timeout=60):
        self.path, self.timeout = path, timeout

    def __enter__(self):
        end = time.time() + self.timeout
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > 120:
                        os.remove(self.path)
                        continue
                except OSError:
                    pass
                if time.time() > end:
                    raise CTIError(f"could not acquire lock {self.path}")
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            os.remove(self.path)
        except OSError:
            pass


# ---------- indicator extraction / normalisation ----------
HEB = "֐-׿"
URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s<>\"'" + HEB + r"]+", re.I)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![A-Za-z0-9-])", re.I)
IP_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\- ]{7,15}\d)(?!\d)")
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
FILE_EXT = {"php", "html", "htm", "js", "css", "png", "jpg", "jpeg", "gif", "svg", "json", "txt", "apk", "exe", "zip", "pdf"}


def undefang(t):
    t = re.sub(r"hxxp", "http", t, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"), ("[://]", "://")):
        t = t.replace(a, b)
    return t


def host_of(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#:@]+@)?([^/?#:]+)", url, re.I)
    return m.group(2).lower().rstrip(".") if m else None


def classify(value):
    v = value.strip()
    if re.match(r"^https?://", v, re.I):
        return "url"
    if IP_RE.fullmatch(v):
        return "ip"
    if SHA256_RE.fullmatch(v) or re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}", v, re.I):
        return "hash"
    if DOMAIN_RE.fullmatch(v):
        return "domain"
    if PHONE_RE.fullmatch(v):
        return "phone"
    return "other"


def normalize(value, typ=None):
    raw = value.strip()
    typ = typ or classify(undefang(raw))
    if typ == "secret":
        # Attacker-owned key/token/unique identifier: case-sensitive, never undefanged or lowercased.
        return raw, typ
    v = undefang(raw)
    if typ == "url":
        v = v.rstrip(".,;:!?)]}'\"")
        scheme, rest = v.split("://", 1)
        netloc, sep, path = rest.partition("/")
        v = f"{scheme.lower()}://{netloc.lower()}{sep}{path}"
    elif typ == "domain":
        v = v.lower().rstrip(".")
    elif typ == "hash":
        v = v.lower()
    elif typ == "phone":
        v = re.sub(r"[\s-]", "", v)
    return v, typ


# IOC classes for the cross-case index (scripts/ioc_index.py). 'strong' indicators are indexed and
# scored; 'shared' (shortener hosts, future CDN/shared-host set) are leads too weak to link cases;
# 'exclude' is never indexed (url/other carry per-victim tokens; the host/domain is captured instead).
def ioc_class(typ, value):
    if typ in ("url", "other"):
        return "exclude"
    if typ == "domain" and value.lower() in SHORTENERS:
        return "shared"
    if typ in ("domain", "ip", "hash", "phone", "secret"):
        return "strong"
    return "exclude"


def extract(text):
    """Return list of (value, type, note) found in free text (SMS/email, Hebrew-safe)."""
    t = undefang(text)
    out, seen = [], set()

    def add(v, typ, note=""):
        v, typ = normalize(v, typ)
        if (typ, v) not in seen:
            seen.add((typ, v))
            out.append((v, typ, note))

    for u in URL_RE.findall(t):
        u = u.rstrip(".,;:!?)]}'\"")
        h = host_of(u)
        add(u, "url", "shortener" if h in SHORTENERS else "")
        if h and not IP_RE.fullmatch(h):
            add(h, "domain", "shortener" if h in SHORTENERS else "host of seed URL")
        elif h:
            add(h, "ip", "host of seed URL")
    stripped = URL_RE.sub(" ", t)
    for d in DOMAIN_RE.findall(stripped):
        if d.rsplit(".", 1)[-1].lower() in FILE_EXT:
            continue
        add(d, "domain", "shortener" if d.lower() in SHORTENERS else "bare domain in text")
    for ip in IP_RE.findall(stripped):
        add(ip, "ip")
    for h in SHA256_RE.findall(stripped):
        add(h, "hash")
    no_ips = IP_RE.sub(" ", stripped)
    for p in PHONE_RE.findall(no_ips):
        if len(re.sub(r"\D", "", p)) >= 9:
            add(p, "phone", "sender/callback number in artifact (attacker-side, not victim)")
    return out
