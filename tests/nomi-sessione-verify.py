#!/usr/bin/env python3
"""I nomi di progetto e di sessione non escono nel rapporto (26/11/2026, claude-observe-nomi-sessione-26-11).

Caso vero: la #4 di supervisor, mandata da un collega con claude-observe, portava tre domini di clienti presi dai nomi
delle sessioni (testo pubblico gia' ripulito). normalize generalizza solo i testi fra «»: il nome scritto nudo
(«pix-acme.it not closed: …») usciva intero. Ora, oltre a generalizzare, il nome del progetto di ogni record (la cartella
di lavoro, o per i componenti del plugin il nome della sessione, anche HOST:nome) e della cartella da cui si manda
diventano <session>, anche dentro un nome di sessione che li contiene.

NS1 un errore registrato da un componente (record_external, project = la sessione «pix-acme.it») con il nome nudo nel testo
    e nella chiamata: nella bozza c'e' <session>, mai acme.it ne' pix-acme.it
NS2 un errore dell'hook dalla cartella clienti/shop-rossi.com e una nota a mano con «host:shop-rossi.com»: <session>
NS3 restano le parole del plugin e quelle corte (supervisor, app, web), e un nome che solo somiglia (acme.items) non cambia
NS4 il file locale tiene il testo com'era: cambia solo la bozza che esce
"""
import json
import os
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


tmp = Path(tempfile.mkdtemp(prefix="claude-observe-nomi-"))
home = tmp / "home"
for d in (".claude", "ws/clienti/shop-rossi.com"):
    (home / d).mkdir(parents=True, exist_ok=True)
state = tmp / "state"
box = state / "claude-observe"
cfg = tmp / "config.json"
cfg.write_text(json.dumps({"tools": {}, "endpoint": ""}))   # mai il servizio vero
SV = tmp / "supervisor.json"
SV.write_text(json.dumps({"name": "supervisor", "repo": "frsorrentino/supervisor", "security": "advisory", "match": {"bash": ["supervisor"]}}))


def env():
    e = {"PATH": os.environ["PATH"], "HOME": str(home), "LANG": "en_US.UTF-8", "XDG_STATE_HOME": str(state), "CLAUDE_OBSERVE_CONFIG": str(cfg),
         "CLAUDE_OBSERVE_TOOL": str(SV), "CLAUDE_CONFIG_DIR": str(home / ".claude"), "PYTHONPATH": str(REPO)}
    e.update({k: os.environ[k] for k in ("SYSTEMROOT", "USERPROFILE") if k in os.environ})
    return e


def obs(*args, stdin=None, cwd=None):
    return subprocess.run([sys.executable, str(OBS), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env(),
                          input=stdin, cwd=str(cwd or home), timeout=60)


# NS1: un componente del plugin (come il relay di supervisor) registra con project = la sessione
code = ("import observe as o; o.record_external('relay', 'relay close pix-acme.it', "
        "'pix-acme.it not closed: acme.it has typed text; the app shows web and app as usual; acme.items stays', 'pix-acme.it')")
r1 = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env(), cwd=str(home), timeout=60)
# NS2: l'hook da una cartella di cliente, e una nota a mano con host:nome
work = home / "ws" / "clienti" / "shop-rossi.com"
p = {"hook_event_name": "PostToolUseFailure", "session_id": "S-1", "cwd": str(work), "tool_name": "Bash",
     "tool_input": {"command": "supervisor close shop-rossi.com"}, "tool_use_id": "t1",
     "error": "Exit code 1\nsession shop-rossi.com is attached elsewhere", "is_interrupt": False, "duration_ms": 12}
h = obs("hook", stdin=json.dumps(p, ensure_ascii=False))
n = obs("add", "supervisor", "close from the phone", "win:shop-rossi.com stays open after close", cwd=work)
d = obs("send", "supervisor")
out = d.stdout
local = (box / "supervisor.jsonl").read_text(encoding="utf-8") if (box / "supervisor.jsonl").exists() else ""

lines = [ln for ln in out.splitlines() if ln.startswith("- ") or ln.startswith("  - ")]
check("NS1 a component's error (project = the session pix-acme.it), the bare name in text and call: <session> in the draft, never acme.it",
      r1.returncode == 0 and "<session> not closed: <session> has typed text" in out and "acme.it " not in out and "pix-acme" not in out,
      f"{r1.stderr[-300:]} | {out[-1500:]}")
check("NS2 the hook from clienti/shop-rossi.com and a note with win:shop-rossi.com: <session>, never the client's name",
      h.returncode == 0 and n.returncode == 0 and "shop-rossi" not in out and out.count("<session>") >= 3, f"{n.stderr[-300:]} | {out[-1500:]}")
check("NS3 the plugin's words and short ones stay (supervisor, web, app), a name that only looks alike (acme.items) is unchanged",
      "web and app as usual" in out and "acme.items stays" in out and "supervisor" in out, out[-1200:])
check("NS4 the local file keeps the text as it was: only the outgoing draft changes", "pix-acme.it not closed" in local and "shop-rossi.com" in local, local[:400])

print(f"\n{OKS}/{OKS + len(FAILS)} OK" + (f", FAIL: {', '.join(FAILS)}" if FAILS else ""))
sys.exit(1 if FAILS else 0)
