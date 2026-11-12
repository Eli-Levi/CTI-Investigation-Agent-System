#!/usr/bin/env python3
"""Encrypted API-key store (Windows DPAPI, per-user). Keys never live in env vars, files in the project,
chat, or command lines.

Run these YOURSELF in a normal PowerShell window (not through Claude); input is hidden:
  python scripts\\keystore.py set URLSCAN_API_KEY
  python scripts\\keystore.py list            # names + whether stored (never values)
  python scripts\\keystore.py delete URLSCAN_API_KEY

Storage: %APPDATA%\\cti-investigation\\keys\\<NAME>.bin, encrypted with DPAPI (CryptProtectData) bound to
your Windows account + a per-name entropy. Only the scripts decrypt, in-process, at request time.
Limit (be honest): any program running as your Windows user can call DPAPI too. This keeps keys out of
the environment, child processes, logs, transcripts and git; it is not a boundary against code you run.
"""
import ctypes, getpass, os, sys

NAMES = ("VT_API_KEY", "URLSCAN_API_KEY", "ABUSEIPDB_KEY", "ABUSECH_KEY", "OTX_KEY", "VIEWDNS_KEY")
DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "cti-investigation", "keys")
_FLAGS = 0x1  # CRYPTPROTECT_UI_FORBIDDEN


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(b):
    buf = ctypes.create_string_buffer(b, len(b))
    return _Blob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _dpapi(data, name, protect):
    if os.name != "nt":
        raise OSError("DPAPI key store is Windows-only; use environment variables on other systems")
    inp, _k1 = _blob(data)
    ent, _k2 = _blob(("cti-investigation:" + name).encode())
    out = _Blob()
    c = ctypes.windll.crypt32
    ok = (c.CryptProtectData(ctypes.byref(inp), "cti-investigation", ctypes.byref(ent), None, None, _FLAGS, ctypes.byref(out))
          if protect else
          c.CryptUnprotectData(ctypes.byref(inp), None, ctypes.byref(ent), None, None, _FLAGS, ctypes.byref(out)))
    if not ok:
        raise OSError(f"DPAPI {'encrypt' if protect else 'decrypt'} failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def _path(name):
    if name not in NAMES:
        raise ValueError(f"unknown key name {name}; expected one of {', '.join(NAMES)}")
    return os.path.join(DIR, name + ".bin")


def has(name):
    return os.path.isfile(_path(name))


def load(name):
    """Return the decrypted key or None. For use by scripts only; never print the result."""
    p = _path(name)
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as fh:
        return _dpapi(fh.read(), name, protect=False).decode()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("set", "list", "delete"):
        print(__doc__); return 1
    if argv[0] == "list":
        for n in NAMES:
            env = " (also set as env var: remove it)" if os.environ.get(n) else ""
            print(f"  {n:16} {'stored' if has(n) else '-'}{env}")
        return 0
    if len(argv) != 2:
        print("usage: keystore.py set|delete NAME"); return 1
    name = argv[1]
    if argv[0] == "delete":
        try:
            os.remove(_path(name)); print(f"{name} deleted")
        except FileNotFoundError:
            print(f"{name} not stored")
        return 0
    if not sys.stdin.isatty():
        print("refusing: run this in your own interactive terminal so the key is typed hidden, not piped"); return 1
    val = getpass.getpass(f"{name} (input hidden): ").strip()
    if len(val) < 8:
        print("empty/too short, nothing stored"); return 1
    os.makedirs(DIR, exist_ok=True)
    tmp = _path(name) + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(_dpapi(val.encode(), name, protect=True))
    os.replace(tmp, _path(name))
    assert load(name) == val
    print(f"{name} stored encrypted at {_path(name)} (value not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
