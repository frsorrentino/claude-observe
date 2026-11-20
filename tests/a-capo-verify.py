#!/usr/bin/env python3
"""Un errore su piu' righe non rompe la bozza (20/11/2026, claude-observe-righe-a-capo-20-11; approvato dal maintainer alle 08:19).

Caso vero: la bozza 74959145fb di chrome-bridge (16 osservazioni) e' stata rifiutata dal servizio anonimo con HTTP 400 «the
body is not the one of a claude-observe draft». Il messaggio CSP di mcp__chrome-bridge__execute_js contiene un a capo, e la
riga « (page CSP blocks dynamic code …» non comincia con «- » ne' con «  - note: », come vuole server/report.php. Ogni
testo che esce nella bozza sta ora su una riga: gli a capo diventano spazi (anche il link «dal mio GitHub» resta una
lista pulita).

AC1 il messaggio CSP vero, registrato dall'hook: nella bozza e' una riga sola, con tutto il testo, e il corpo passa la
    regola del servizio (righe «- » o «  - note|workaround: », intestazione, riga vuota)
AC2 una nota (add --on) e un aggiramento su piu' righe: anche loro una riga ciascuno
AC3 il file locale tiene il messaggio com'era (con l'a capo): cambia solo la bozza che esce
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

REPO = Path(__file__).resolve().parent.parent
OBS = REPO / "observe.py"
FAILS, OKS = [], 0


def check(name, ok, detail=""):
    global OKS
    if ok:
        OKS += 1
        print(f"  OK  {name}")
    else:
        FAILS.append(name)
        print(f"  FAIL {name} — {str(detail)[:1500]}")


tmp = Path(tempfile.mkdtemp(prefix="claude-observe-acapo-"))
home = tmp / "home"
for d in (".claude", "ws/clienti/acme-shop"):
    (home / d).mkdir(parents=True, exist_ok=True)
state = tmp / "state"
box = state / "claude-observe"
cfg = tmp / "config.json"
cfg.write_text(json.dumps({"tools": {}, "endpoint": ""}))   # mai il servizio vero
CB = tmp / "chrome-bridge.json"
CB.write_text(json.dumps({"name": "chrome-bridge", "repo": "frsorrentino/chrome-bridge", "security": "advisory", "match": {"mcp": ["mcp__chrome-bridge__"]}}))


def env():
    e = {"PATH": os.environ["PATH"], "HOME": str(home), "LANG": "it_IT.UTF-8", "XDG_STATE_HOME": str(state), "CLAUDE_OBSERVE_CONFIG": str(cfg),
         "CLAUDE_OBSERVE_TOOL": str(CB), "CLAUDE_CONFIG_DIR": str(home / ".claude")}
    e.update({k: os.environ[k] for k in ("SYSTEMROOT", "USERPROFILE") if k in os.environ})
    return e


def obs(*args, stdin=None):
    return subprocess.run([sys.executable, str(OBS), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env(),
                          input=stdin, cwd=str(home), timeout=60)


# il messaggio vero di execute_js (bozza 74959145fb), col suo a capo
CSP = ("Evaluating a string as JavaScript violates the following Content Security Policy directive because 'unsafe-eval' is not an allowed "
       "source of script: script-src github.githubassets.com '<SECRET>='\".\n (page CSP blocks dynamic code — strip it with network_rules "
       "modify_header on \"content-security-policy\")")
p = {"hook_event_name": "PostToolUseFailure", "session_id": "S-1", "cwd": str(home / "ws" / "clienti" / "acme-shop"), "tool_name": "mcp__chrome-bridge__execute_js",
     "tool_input": {"code": "eval('1')"}, "tool_use_id": "t1", "error": CSP, "is_interrupt": False, "duration_ms": 12}
h = obs("hook", stdin=json.dumps(p, ensure_ascii=False))
rec = [json.loads(l) for l in (box / "chrome-bridge.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()] if (box / "chrome-bridge.jsonl").exists() else []
rid = rec[0]["id"] if rec else None
a = obs("add", "--on", str(rid), "--workaround", "togliere la CSP\ncon network_rules", "la pagina ha una CSP\nche blocca eval") if rid else None
d = obs("send", "chrome-bridge")
out = d.stdout
body = out.split("\n\n", 2)[-1] if "\n\n" in out else out


def server_ok(text):
    """La regola di server/report.php:240-249 sul corpo: intestazione, riga vuota, poi solo righe della lista."""
    m = re.search(r"(Collected on \d{4}-\d{2}-\d{2} by claude-observe .*?)(?:\n\n(?:Mostra|Show|OPZIONI|OPTIONS)|\Z)", text, re.S)
    if not m:
        return False, "no body"
    lines = m.group(1).rstrip("\n").split("\n")
    if len(lines) < 3 or lines[1] != "":
        return False, lines[:3]
    bad = [l for l in lines[2:] if not re.match(r"^(- |  - (note|workaround): )", l)]
    return not bad, bad


ok_srv, why = server_ok(out)
one = [l for l in out.splitlines() if "unsafe-eval" in l]
check("AC1 the real CSP message from the hook: one line in the draft, with all its text, and the body passes the service's rule",
      h.returncode == 0 and len(one) == 1 and "page CSP blocks dynamic code" in one[0] and ok_srv, f"{why} | {one}")
check("AC2 a note (add --on) and a workaround on several lines: one line each",
      a is not None and a.returncode == 0 and any(l.startswith("  - note: la pagina ha una CSP che blocca eval") for l in out.splitlines())
      and any(l.startswith("  - workaround: togliere la CSP con network_rules") for l in out.splitlines()), out[-800:] + (a.stderr if a else ""))
local = (box / "chrome-bridge.jsonl").read_text(encoding="utf-8") if (box / "chrome-bridge.jsonl").exists() else ""
check("AC3 the local file keeps the message as it was (with its newline): only the draft that goes out changes", "\\n (page CSP" in local, local[:400])

print(f"\n{OKS}/{OKS + len(FAILS)} OK" + (f", FAIL: {', '.join(FAILS)}" if FAILS else ""))
sys.exit(1 if FAILS else 0)
