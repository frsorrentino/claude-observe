#!/usr/bin/env python3
"""Verifica del servizio anonimo (server/report.php) contro un GitHub finto. Serve php (curl, openssl, mbstring) e il
comando openssl; nessuna rete.

SV1  GET: 200 con i plugin e il link alla nota privacy; PUT → 405
SV2  una bozza observe valida → 201 con l'URL della issue; la issue sul repo dell'allowlist con le etichette
     from-observe e anonymous e la riga «Sent anonymously»; il JWT dell'App firmato RS256 (verificato con openssl);
     il token d'installazione limitato a quel solo repo
SV3  stesso titolo di una issue anonima aperta → commento su quella, nessuna issue nuova
SV4  security → segnalazione privata di vulnerabilita', mai una issue; severity high passa
SV5  rifiuti 400 senza chiamare GitHub: plugin fuori allowlist, campo in piu', tipi sbagliati, titolo non di una bozza
     (o di un altro plugin), corpo non di una bozza, riga che non e' una voce; 413 oltre 64 KB; 415 senza JSON
SV6  seconda rete: percorso della home, e-mail, token GitHub, chiave privata → 422, niente pubblicato
SV7  limite per IP (5 l'ora): la sesta → 429; nel file di stato nessun IP in chiaro, solo HMAC con chiave del giorno
SV8  limite globale del giorno; `php report.php purge` cancella i file dei giorni prima (chiave compresa)
SV9  GitHub che rifiuta → 502, niente pubblicato; nel log degli errori lo stato, mai il testo
SV10 nessun contenuto resta: dopo tutti i casi, il testo delle bozze non e' in nessun file di stato ne' nel log
SV11 segreti o stato sotto la document root, o leggibili da altri → 503, niente pubblicato
SV12 server/check-live.sh contro un servizio acceso: tutto ok
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import base64
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"\n     {str(detail)[:600]}"))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


TMP = Path(tempfile.mkdtemp(prefix="observe-server-"))
PRIV = TMP / "private"
STATE = PRIV / "state"
STATE.mkdir(parents=True)
os.chmod(PRIV, 0o700)
os.chmod(STATE, 0o700)
KEY, PUB = PRIV / "app.pem", PRIV / "app.pub"
subprocess.run(["openssl", "genrsa", "-out", str(KEY), "2048"], check=True, capture_output=True)
subprocess.run(["openssl", "rsa", "-in", str(KEY), "-pubout", "-out", str(PUB)], check=True, capture_output=True)
os.chmod(KEY, 0o600)
DOCROOT = TMP / "public_html"
(DOCROOT / "api/observe").mkdir(parents=True)
shutil.copy(ROOT / "server/report.php", DOCROOT / "api/observe/report.php")
ERRLOG = TMP / "php_errors.log"

# ------------------------------------------------------------------------------------------------ GitHub finto
GH = {"calls": [], "issues": {}, "reports": [], "fail": None, "jwt_ok": []}


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(tok):
    h, p, s = tok.split(".")
    (TMP / "sig").write_bytes(b64d(s))
    (TMP / "msg").write_bytes(f"{h}.{p}".encode())
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(PUB), "-signature", str(TMP / "sig"), str(TMP / "msg")],
                       capture_output=True, text=True)
    claims = json.loads(b64d(p))
    return r.returncode == 0 and json.loads(b64d(h))["alg"] == "RS256" and claims["iss"] == "4242" \
        and claims["exp"] - claims["iat"] <= 600


class GitHub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, data):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def handle_any(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"null") if n else None
        auth = self.headers.get("Authorization") or ""
        path = self.path
        GH["calls"].append((method, path, auth, body))
        if GH["fail"] and GH["fail"] in path:
            return self.reply(500, {"message": "boom"})
        parts = path.split("?")[0].strip("/").split("/")
        if method == "GET" and parts[0] == "repos" and parts[-1] == "installation":
            GH["jwt_ok"].append(auth.startswith("Bearer ") and verify_jwt(auth[7:]))
            return self.reply(200, {"id": 77})
        if method == "POST" and path == "/app/installations/77/access_tokens":
            GH["jwt_ok"].append(auth.startswith("Bearer ") and verify_jwt(auth[7:]))
            return self.reply(201, {"token": "ghs_test", "repositories": body.get("repositories")})
        if not auth == "token ghs_test":
            return self.reply(401, {"message": "bad token"})
        repo = "/".join(parts[1:3])
        if method == "GET" and parts[3:] == ["issues"]:
            return self.reply(200, [i for i in GH["issues"].get(repo, []) if i["state"] == "open"])
        if method == "POST" and parts[3:] == ["issues"]:
            lst = GH["issues"].setdefault(repo, [])
            i = {"number": len(lst) + 1, "title": body["title"], "body": body["body"], "labels": body.get("labels"),
                 "state": "open", "comments": [], "html_url": f"https://github.com/{repo}/issues/{len(lst) + 1}"}
            lst.append(i)
            return self.reply(201, i)
        if method == "POST" and parts[3] == "issues" and parts[5:] == ["comments"]:
            i = GH["issues"][repo][int(parts[4]) - 1]
            i["comments"].append(body["body"])
            return self.reply(201, {"html_url": f"{i['html_url']}#issuecomment-{len(i['comments'])}"})
        if method == "POST" and parts[3:] == ["security-advisories", "reports"]:
            GH["reports"].append((repo, body))
            return self.reply(201, {"html_url": f"https://github.com/{repo}/security/advisories/GHSA-test-{len(GH['reports'])}"})
        return self.reply(404, {"message": "not found"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


GHPORT = free_port()
ghs = ThreadingHTTPServer(("127.0.0.1", GHPORT), GitHub)
threading.Thread(target=ghs.serve_forever, daemon=True).start()

CONF = PRIV / "config.php"


def write_conf(**over):
    c = {"app_id": "4242", "private_key": str(KEY), "state_dir": str(STATE), "github_api": f"http://127.0.0.1:{GHPORT}",
         "per_ip_hour": 5, "per_ip_day": 10, "global_day": 50}
    c.update(over)
    CONF.write_text("<?php\nreturn " + "[" + ", ".join(f"{json.dumps(k)} => {json.dumps(v)}" for k, v in c.items()) + "];\n")


write_conf()
PORT = free_port()
php = subprocess.Popen(["php", "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0", "-d", "log_errors=1", "-d", f"error_log={ERRLOG}", "-S", f"127.0.0.1:{PORT}", "-t", str(DOCROOT)],
                       env={**os.environ, "OBSERVE_CONFIG": str(CONF)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
URL = f"http://127.0.0.1:{PORT}/api/observe/report.php"
for _ in range(50):
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.1)


def call(data=None, method=None, ctype="application/json", raw=None):
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(URL, data=body, method=method or ("POST" if body is not None else "GET"),
                                 headers={"Content-Type": ctype} if body is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def reset_rate():
    for f in STATE.glob("rate-*"):
        f.unlink()


MARK = "zq-marker-7731"


def draft(plugin="chrome-bridge", security=False, title=None, rows=None, severity=None, version="1.24.0"):
    head = ("Private security report prepared on 2026-09-27 by claude-observe (https://github.com/frsorrentino/claude-observe), "
            "for the maintainers only — never a public issue. Parameter values are never stored.") if security else \
        ("Collected on 2026-09-27 by claude-observe (https://github.com/frsorrentino/claude-observe): errors recorded by a "
         "hook and notes added by hand; parameter values are never stored.")
    rows = rows or [f"- `mcp__chrome-bridge__navigate` — timeout {MARK} (×3, 09-26–09-27; chrome-bridge 1.24.0, Linux)",
                    "  - note: happens on ~/<dir>/<file>.html"]
    t = title or (f"[{plugin}] security observation(s): 1" if security else
                  f"[{plugin}] field observations: 1 error(s), most frequent `mcp__chrome-bridge__navigate`")
    return {"plugin": plugin, "version": version, "security": security, "severity": severity, "title": t,
            "body": "\n".join([head, "", *rows])}


# SV1
s1, j1 = call()
s1b, _ = call(method="PUT", raw=b"{}")
check("SV1 GET → 200 with the plugins of the allowlist and the privacy link; PUT → 405",
      s1 == 200 and "chrome-bridge" in j1["plugins"] and "pixelfarm" not in j1["plugins"] and j1["privacy"].endswith("PRIVACY.md")
      and s1b == 405, (s1, j1, s1b))

# SV2
GH["calls"].clear()
s2, j2 = call(draft())
iss = GH["issues"].get("frsorrentino/chrome-bridge", [{}])[0]
tokreq = [c for c in GH["calls"] if c[1].endswith("/access_tokens")]
check("SV2 a valid observe draft → 201 with the issue URL; issue on the allowlisted repo with labels from-observe, anonymous and the «Sent anonymously» line",
      s2 == 201 and j2["url"] == "https://github.com/frsorrentino/chrome-bridge/issues/1" and iss.get("labels") == ["from-observe", "anonymous"]
      and MARK in iss.get("body", "") and "Sent anonymously through the claude-observe service" in iss["body"]
      and "chrome-bridge 1.24.0" in iss["body"], (s2, j2, iss))
check("SV2 the App JWT is RS256-signed with the private key (verified with openssl), iss = app id, at most 10 minutes",
      GH["jwt_ok"] and all(GH["jwt_ok"]), GH["jwt_ok"])
check("SV2 the installation token is limited to the destination repository only",
      tokreq and tokreq[0][3] == {"repositories": ["chrome-bridge"]}, tokreq)

# SV3
s3, j3 = call(draft())
lst = GH["issues"]["frsorrentino/chrome-bridge"]
check("SV3 same title as an open anonymous issue → a comment on it, no new issue",
      s3 == 201 and len(lst) == 1 and len(lst[0]["comments"]) == 1 and "#issuecomment-1" in j3["url"]
      and lst[0]["comments"][0].startswith("**[chrome-bridge] field observations"), (s3, j3, lst))

# SV4
reset_rate()
n_issues = sum(len(v) for v in GH["issues"].values())
s4, j4 = call(draft("fable-director", security=True, severity="high"))
check("SV4 security → a private vulnerability report (severity high passed), never an issue",
      s4 == 201 and "/security/advisories/GHSA-test-1" in j4["url"] and GH["reports"][-1][0] == "frsorrentino/fable-director"
      and GH["reports"][-1][1].get("severity") == "high" and MARK in GH["reports"][-1][1]["description"]
      and sum(len(v) for v in GH["issues"].values()) == n_issues, (s4, j4, GH["reports"]))

# SV5
reset_rate()
GH["calls"].clear()
bad = {
    "plugin outside the allowlist": {**draft(), "plugin": "pixelfarm"},
    "one field more": {**draft(), "user": "x"},
    "one field less": {k: v for k, v in draft().items() if k != "version"},
    "security not a bool": {**draft(), "security": "no"},
    "severity not high": {**draft(), "severity": "low"},
    "version with spaces": {**draft(), "version": "1 2"},
    "title of another plugin": {**draft(), "title": "[claude-master] field observations: 1 error(s)"},
    "free title": {**draft(), "title": "Hello"},
    "security flag with a public title": {**draft(), "security": True},
    "body not a draft": {**draft(), "body": "hello\n\n- x"},
    "a line that is not a row": {**draft(rows=["- `x` — y", "Visit http://spam"])},
}
res5 = {}
for k, v in bad.items():
    reset_rate()   # every POST counts for the per-IP limit
    res5[k] = call(v)[0]
reset_rate()
res5["not a JSON object"] = call(raw=b"[1,2]")[0]
res5["not JSON"] = call(raw=b"hello")[0]
reset_rate()
s5a = call(draft(rows=["- " + "x" * 1999] * 40))[0]
s5b = call(raw=json.dumps(draft()).encode(), ctype="text/plain")[0]
check("SV5 refused with 400 and no GitHub call: plugin outside the allowlist, a field more or less, wrong types, a title not of a draft (or of another plugin), a body not of a draft, a line not a row",
      all(v == 400 for v in res5.values()) and not GH["calls"], (res5, GH["calls"][:2]))
check("SV5 over 64 KB → 413; not application/json → 415", s5a == 413 and s5b == 415, (s5a, s5b))

# SV6
reset_rate()
GH["calls"].clear()
leaks = {"home": "- `x` — cannot open /home/mario/notes.txt", "windows home": "- `x` — C:\\Users\\Mario\\x",
         "mac home": "- `x` — /Users/anna/y", "email": "- `x` — mail to anna.rossi@example.org failed",
         "github token": "- `x` — ghp_" + "a" * 36, "private key": "- `x` — -----BEGIN RSA PRIVATE KEY-----"}
res6 = {}
for k, row in leaks.items():
    reset_rate()
    st, js = call(draft(rows=[row]))
    res6[k] = (st, js.get("error", ""))
calls6 = list(GH["calls"])
reset_rate()
ok6 = call(draft(rows=["- `x` — failed on ~/<dir>/<file>.txt and C:\\Users\\Public\\x and /home/<USER>/y"]))[0]
check("SV6 second net: a home path (Linux, Windows, macOS), an e-mail, a GitHub token, a private key → 422 «nothing was published», no GitHub call",
      all(v[0] == 422 and "nothing was published" in v[1] for v in res6.values()) and not calls6, res6)
check("SV6 the anonymized forms (~/<dir>, <USER>, C:\\Users\\Public) pass", ok6 == 201, ok6)

# SV7
reset_rate()
codes = [call(draft(rows=[f"- `x` — err {i}"]))[0] for i in range(6)]
rate_files = list(STATE.glob("rate-*.json"))
st7 = json.loads(rate_files[0].read_text()) if rate_files else {}
check("SV7 per-IP limit 5 an hour: the sixth → 429", codes[:5] == [201] * 5 and codes[5] == 429, codes)
check("SV7 the state file has no IP in clear: only HMACs (64 hex) with a 64-hex key of the day; the file is 0600",
      rate_files and "127.0.0.1" not in rate_files[0].read_text() and len(st7["key"]) == 64
      and all(len(k) == 64 for k in st7["ips"]) and (rate_files[0].stat().st_mode & 0o077) == 0, st7)

# SV8
reset_rate()
write_conf(global_day=2)
codes8 = [call(draft(rows=[f"- `x` — g {i}"]))[0] for i in range(3)]
write_conf()
old = STATE / "rate-20200101.json"
old.write_text('{"key": "k", "ips": {}}')
p8 = subprocess.run(["php", str(ROOT / "server/report.php"), "purge"], env={**os.environ, "OBSERVE_CONFIG": str(CONF)},
                    capture_output=True, text=True)
check("SV8 global daily limit: beyond it → 429", codes8 == [201, 201, 429], codes8)
check("SV8 `php report.php purge` deletes the files of the days before (key included), keeps today's",
      p8.returncode == 0 and not old.exists() and list(STATE.glob("rate-*.json")), (p8.returncode, p8.stderr))

# SV9
reset_rate()
GH["fail"] = "/issues"
n9 = sum(len(v) for v in GH["issues"].values())
s9, j9 = call(draft(rows=[f"- `x` — {MARK} fail"]))
GH["fail"] = None
log = ERRLOG.read_text() if ERRLOG.exists() else ""
check("SV9 GitHub refusing → 502 «nothing was published»; the error log has the status, never the text",
      s9 == 502 and "nothing was published" in j9["error"] and sum(len(v) for v in GH["issues"].values()) == n9
      and "GitHub answered 500" in log and MARK not in log, (s9, j9, log[-300:]))

# SV10
blob = "".join(p.read_text(errors="replace") for p in STATE.iterdir() if p.is_file()) + log
check("SV10 no content is kept: the drafts' text is in no state file nor in the log", MARK not in blob and "navigate" not in blob,
      [p.name for p in STATE.iterdir()])

# SV11
reset_rate()
GH["calls"].clear()
inside = DOCROOT / "state"
inside.mkdir(mode=0o700)
write_conf(state_dir=str(inside))
s11a = call(draft(rows=["- `x` — a"]))[0]
write_conf()
os.chmod(KEY, 0o644)
s11b = call(draft(rows=["- `x` — b"]))[0]
os.chmod(KEY, 0o600)
os.chmod(STATE, 0o755)
s11c = call(draft(rows=["- `x` — c"]))[0]
os.chmod(STATE, 0o700)
check("SV11 state folder under the document root, key readable by others, state folder open to others → 503, no GitHub call",
      (s11a, s11b, s11c) == (503, 503, 503) and not GH["calls"], (s11a, s11b, s11c))

# SV12
reset_rate()
cl = subprocess.run(["bash", str(ROOT / "server/check-live.sh"), URL], capture_output=True, text=True, timeout=120)
check("SV12 server/check-live.sh against a running service: GET 200, non-draft POST 400, secret and state paths 403/404 → all ok",
      cl.returncode == 0 and "all ok" in cl.stdout and cl.stdout.count("ok   ") == 11, cl.stdout + cl.stderr)

php.terminate()
ghs.shutdown()
shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} ok")
sys.exit(1 if FAIL else 0)
