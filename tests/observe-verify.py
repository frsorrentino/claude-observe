#!/usr/bin/env python3
"""Verifica di claude-observe (observe.py, sync.py, check.sh). Solo libreria standard, nessuna rete.

I payload hanno la forma letta dal vivo il 23/09/2026 (Claude Code 2.1.280): PostToolUseFailure con `error`
(«No tab with id: 1.», «Exit code 2\\n…»), `is_interrupt`, `mcp_server`.

OB1  errore MCP del plugin → un record hook-mcp con la forma dei parametri, mai i valori
OB2  lo stesso errore con id diversi → un record, count 2 (deduplica per errore normalizzato)
OB3  Bash del plugin con uscita 2 → record hook-bash con il comando redatto
OB4  codici documentati come innocui (benign_exits) → nessun record
OB5  il comando del plugin non e' l'ultimo della riga → record «uncertain», fuori dall'avviso
OB6  comandi e tool di altri, successi e interruzioni → nessun record; ogni copia solo il proprio plugin
OB7  segreti: password, token, email, query degli URL e home non arrivano mai nel file
OB8  altro account (cartella di config): letto anonimizzato; intero con --raw o dallo stesso account
OB9  add a mano, --on per arricchire, mark, export
OB10 rotazione: tetto di record e giorni
OB11 session-start nella cartella che mantiene il plugin (maintainer_dir o remote git): nuove e ricorrenti, una volta
OB12 invio: UNA issue per plugin; bozza senza invio; --send con l'hash giusto → gh issue create; hash diverso → rifiuto;
     issue uguale gia' aperta → commento; senza gh → link precompilato entro il limite; mai riproposte
OB13 un plugin nuovo entra con il solo tool.json
OB14 sync.py: copia, SOURCE, hook con matcher stretto, idempotente, rispetta gli altri hook; check.sh: ok e rifiuto
OB15 record_external: un componente fuori dagli hook (relay, server MCP)
OB16 proposta a session-start in una sessione qualsiasi (non quella che mantiene): una volta, oltre la soglia
OB17 contesto: versione del plugin, di Claude Code e del modello, sistema, NOMI degli ultimi tool
OB18 errore noto che torna: additionalContext con l'aggiramento; niente se non c'e'; niente dall'altro account
OB19 «gia' risolto in X»: --fixed-in o `known` in tool.json con versione installata piu' vecchia → aggiornare; mai in issue
OB20 formato: record v1; un file con record di formato piu' nuovo non viene riscritto
OB21 un plugin di sole skill: bozza «N note(s)», senza «error(s)» ne' testi di claude-master; proposta senza «hook»;
     sync.py non lascia PostToolUseFailure vuoto
OB22 lock a cartella (FORMAT.md): 12 hook in parallelo → 12 conteggi; un lock abbandonato da piu' di 10 s si toglie
OB23 convivenza con le copie gia' distribuite (solo flock su <dir>/.lock): la copia nuova aspetta il loro flock
OB24 benign_exits per script senza sottocomandi («external-exec.py»: [2]) e per script con sottocomando
OB25 sync.py rifiuta una fonte con observe.py non committato; check.sh confronta con la fonte committata
OB26 lock occupato oltre l'attesa: la voce va in <plugin>.pending.jsonl e il prossimo scrittore la incorpora; niente si perde
"""
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

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


tmp = Path(tempfile.mkdtemp(prefix="claude-observe-"))
home = tmp / "home"
for d in (".claude", ".claude-pixel", "ws/chrome-bridge", "ws/clienti/acme-shop", "bin"):
    (home / d).mkdir(parents=True, exist_ok=True)
state = tmp / "state"
box = state / "claude-observe"
cfg = tmp / "config.json"
BASE = {"tools": {"chrome-bridge": {"maintainer_dir": str(home / "ws" / "chrome-bridge")}}}
cfg.write_text(json.dumps(BASE))
TOOLS = tmp / "tools"
TOOLS.mkdir()
CB = TOOLS / "chrome-bridge.json"
CM = TOOLS / "claude-master.json"
CB.write_text(json.dumps({"name": "chrome-bridge", "repo": "frsorrentino/chrome-bridge", "match": {"mcp": ["mcp__chrome-bridge__"]}}))
CM.write_text(json.dumps({"name": "claude-master", "repo": "frsorrentino/claude-master", "command": "claude-master observe",
                          "match": {"bash": [r"(^|\s|/)claude-master(\s|$)", r"/scripts/cm-[\w-]+\.(sh|py)\b"]},
                          "benign_exits": {"restart arm": [4], "model": [2, 3], "close": [3, 4]}}))
PERSONAL = {"CLAUDE_CONFIG_DIR": str(home / ".claude")}
PIXEL = {"CLAUDE_CONFIG_DIR": str(home / ".claude-pixel")}


def env(extra=None, tool=CB):
    e = {"PATH": f"{home / 'bin'}:{os.environ['PATH']}", "HOME": str(home), "LANG": "it_IT.UTF-8", "XDG_STATE_HOME": str(state),
         "CLAUDE_OBSERVE_CONFIG": str(cfg), "CLAUDE_OBSERVE_TOOL": str(tool)}
    e.update(extra or PERSONAL)
    return e


def obs(*args, extra=None, stdin=None, cwd=None, tool=CB):
    return subprocess.run([sys.executable, str(OBS), *args], capture_output=True, text=True, env=env(extra, tool), input=stdin,
                          cwd=cwd or str(home), timeout=60)


def tool_for(name):
    return CM if name == "Bash" else CB


def fail(tool_name, tool_input, error, cwd=None, extra=None, tool=None, **kw):
    p = {"hook_event_name": "PostToolUseFailure", "session_id": "S-1", "cwd": str(cwd or home / "ws" / "clienti" / "acme-shop"),
         "tool_name": tool_name, "tool_input": tool_input, "tool_use_id": "t1", "error": error, "is_interrupt": False,
         "duration_ms": 12, **kw}
    return obs("hook", stdin=json.dumps(p), extra=extra, tool=tool or tool_for(tool_name))


def recs(tool):
    try:
        return [json.loads(l) for l in (box / f"{tool}.jsonl").read_text().splitlines() if l.strip()]
    except OSError:
        return []


def raw_box():
    return "\n".join(p.read_text() for p in box.glob("*.jsonl")) if box.exists() else ""


def clean_source(name):
    """Una copia della fonte in un repo git suo, committata: sync.py rifiuta una fonte con modifiche non committate."""
    d = tmp / name
    shutil.copytree(REPO, d, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    subprocess.run(["git", "-C", str(d), "add", "."], check=True)
    subprocess.run(["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"], check=True)
    return d


def start(cwd, tool=CB):
    return obs("session-start", stdin=json.dumps({"session_id": "S-3", "cwd": str(cwd), "source": "startup"}), tool=tool).stdout.strip()


# OB1-OB2
fail("mcp__chrome-bridge__navigate", {"tab_id": 1, "url": "https://acme-shop.example/checkout?token=zzz"}, "No tab with id: 1.",
     mcp_server={"name": "chrome-bridge", "source": "user"})
r = recs("chrome-bridge")
check("OB1 MCP error → one hook-mcp record, call and error, input as shape only",
      len(r) == 1 and r[0]["source"] == "hook-mcp" and r[0]["call"] == "mcp__chrome-bridge__navigate" and r[0]["error"] == "No tab with id: 1."
      and r[0]["examples"][0]["input_shape"] == {"tab_id": "number", "url": len("https://acme-shop.example/checkout?token=zzz")}
      and "acme-shop.example" not in json.dumps(r[0]["examples"]), json.dumps(r)[:600])
fail("mcp__chrome-bridge__navigate", {"tab_id": 77, "url": "about:blank"}, "No tab with id: 77.")
r = recs("chrome-bridge")
check("OB2 the same error with another id → the same record, count 2, two examples", len(r) == 1 and r[0]["count"] == 2 and len(r[0]["examples"]) == 2, json.dumps(r)[:600])

# OB3-OB6
fail("Bash", {"command": "claude-master comando-inesistente", "description": "x"},
     "Exit code 2\nclaude-master: sottocomando sconosciuto «comando-inesistente»\nuso: …")
r = recs("claude-master")
check("OB3 Bash command of the plugin with exit 2 → hook-bash record, redacted call, first line of the output",
      len(r) == 1 and r[0]["source"] == "hook-bash" and r[0]["call"] == "claude-master comando-inesistente"
      and r[0]["error"].startswith("Exit code 2: claude-master: sottocomando sconosciuto"), json.dumps(r)[:600])
fail("Bash", {"command": "claude-master restart arm --switch-account"}, "Exit code 4\nrifiutato")
fail("Bash", {"command": "cd ~/x && claude-master close alfa"}, "Exit code 3\nnon esiste")
check("OB4 documented benign exits (restart arm 4, close 3) → no record", len(recs("claude-master")) == 1, json.dumps(recs("claude-master"))[:600])
fail("Bash", {"command": "claude-master sessions --json | grep -q beta"}, "Exit code 1")
unc = [x for x in recs("claude-master") if x.get("attribution") == "uncertain"]
check("OB5 the plugin's command not last in the line → an «uncertain» record", len(unc) == 1, json.dumps(recs("claude-master"))[:800])
n_before = len(recs("claude-master")) + len(recs("chrome-bridge"))
fail("Bash", {"command": "false"}, "Exit code 1")
fail("Bash", {"command": "npm test"}, "Exit code 1\nfailing")
fail("mcp__other__thing", {}, "boom")
fail("mcp__chrome-bridge__click", {"selector": "#a"}, "Interrupted", is_interrupt=True)
fail("mcp__chrome-bridge__click", {"selector": "#a"}, "boom", tool=CM)     # la copia di claude-master non vede chrome-bridge
fail("Bash", {"command": "claude-master x"}, "Exit code 1", tool=CB)       # e quella di chrome-bridge non vede i comandi
obs("hook", stdin=json.dumps({"hook_event_name": "PostToolUse", "tool_name": "mcp__chrome-bridge__click", "tool_input": {}, "error": "x"}))
check("OB6 others' commands and tools, successes, interruptions, the other plugin's calls → no record",
      len(recs("claude-master")) + len(recs("chrome-bridge")) == n_before and not (box / "other.jsonl").exists(), raw_box()[-400:])

# OB7
fail("mcp__chrome-bridge__fill_form", {"fields": {"password": "hunter2-secret"}, "submit_selector": "#go"},
     'mismatch: value_after "hunter2-secret" for mario.rossi@acme-shop.example at https://acme-shop.example/login?sid=abc123')
FAKE_KEY = "sk" + "_live_" + "ABCDEF1234567890abcdef99"   # composta a runtime: una chiave finta intera fa scattare i controlli dei segreti
fail("Bash", {"command": f"claude-master talk master 'password=hunter2-secret token {FAKE_KEY}'"},
     f"Exit code 1\nerrore: token {FAKE_KEY} non valido per " + str(home) + "/ws/clienti/acme-shop")
b = raw_box()
check("OB7 no password, token, email, URL query or home path in the files",
      not any(s in b for s in ("hunter2", FAKE_KEY[:12], "mario.rossi", "sid=abc123", str(home))) and "claude-master talk <ARG> <ARG>" in b, b[-900:])

# OB8
fail("mcp__chrome-bridge__screenshot", {"presets": ["mobile"]}, "Command screenshot timed out after 10000ms (tab 483581071)", extra=PIXEL)
rid_pix = next(x["id"] for x in recs("chrome-bridge") if x.get("account") == ".claude-pixel")
v = json.loads(obs("show", rid_pix).stdout)
v_raw = json.loads(obs("show", rid_pix, "--raw").stdout)
lst = obs("list", "chrome-bridge").stdout
check("OB8 a record of the other account is read anonymized: project hidden, normalized error, no examples",
      v.get("anonymized") is True and v["project"].startswith("[PROGETTO_") and "acme-shop" not in json.dumps(v)
      and "examples" not in v and "<N>" in v["error"] and "483581071" not in lst, json.dumps(v))
check("OB8 --raw shows it whole; the same account sees it whole without --raw",
      v_raw.get("project") == "acme-shop" and json.loads(obs("show", rid_pix, extra=PIXEL).stdout).get("project") == "acme-shop", json.dumps(v_raw)[:300])

# OB9
r = obs("add", "chrome-bridge", "find_text non trova le etichette divise in piu' nodi", "--class", "D", "--workaround", "execute_js sui li")
man = next((x for x in recs("chrome-bridge") if x["source"] == "manual"), {})
obs("add", "--on", rid_pix, "--workaround", "portare la finestra davanti", "--class", "L", extra=PIXEL)
pix = next(x for x in recs("chrome-bridge") if x["id"] == rid_pix)
obs("mark", man.get("id", "?"), "done")
exp = obs("export", "chrome-bridge").stdout
check("OB9 add (manual record with class and workaround), --on enriches a hook record, mark done, export as a table",
      r.returncode == 0 and man.get("class") == "D" and pix.get("workaround") == "portare la finestra davanti" and pix.get("class") == "L"
      and next(x for x in recs("chrome-bridge") if x["id"] == man["id"])["status"] == "done"
      and exp.startswith("| id |") and "execute_js sui li" in exp and "483581071" not in exp, exp[:700])
check("OB9 list hides done records unless --all", man["id"] not in obs("list").stdout and man["id"] in obs("list", "--all").stdout, "")

# OB10
cfg.write_text(json.dumps({**BASE, "max_records": 3}))
for i in range(5):
    fail("mcp__chrome-bridge__query_dom", {"selector": "x"}, f"errore diverso numero-{'abcde'[i]}")
    time.sleep(0.05)
n = len(recs("chrome-bridge"))
cfg.write_text(json.dumps(BASE))
old = recs("claude-master")
old[0]["last_seen"] = int(time.time()) - 100 * 86400
(box / "claude-master.jsonl").write_text("".join(json.dumps(x) + "\n" for x in old))
fail("Bash", {"command": "claude-master nuovo-errore"}, "Exit code 1\nx")
check("OB10 rotation: at most max_records per plugin, records older than max_days dropped",
      n == 3 and old[0]["id"] not in {x["id"] for x in recs("claude-master")}, f"{n} {[x['id'] for x in recs('claude-master')]}")

# OB11 (senza proposte: quelle le prova OB16)
cfg.write_text(json.dumps({**BASE, "propose": False}))
for f in box.glob(".seen-*"):
    f.unlink()
a = start(home / "ws" / "chrome-bridge")
b2 = start(home / "ws" / "chrome-bridge")
fail("mcp__chrome-bridge__query_dom", {"selector": "y"}, "errore diverso numero-e")   # un errore gia' visto che torna
c = start(home / "ws" / "chrome-bridge" / "server")
gitdir = home / "ws" / "cm-clone"
gitdir.mkdir()
subprocess.run(["git", "init", "-q", str(gitdir)], check=True)
subprocess.run(["git", "-C", str(gitdir), "remote", "add", "origin", "git@github.com:frsorrentino/claude-master.git"], check=True)
g = start(gitdir, tool=CM)
check("OB11 session-start in the maintainer's folder: new and recurring counted once, then silent until something changes",
      "OSSERVAZIONI chrome-bridge:" in a and "nuove" in a and b2 == "" and "1 ricorrenti" in c, f"{a!r} | {b2!r} | {c!r}")
check("OB11 the maintainer found from the git remote, without maintainer_dir; uncertain records not counted; nothing elsewhere",
      "OSSERVAZIONI claude-master: 2 nuove" in g and "claude-master observe list claude-master" in g
      and start(home / "ws" / "clienti" / "acme-shop") == "" and start(gitdir, tool=CB) == "", g)
cfg.write_text(json.dumps(BASE))

# OB12
gh_log = tmp / "gh.log"
GH = home / "bin" / "gh"


def fake_gh(auth=True, existing=None):
    GH.write_text(f"""#!/usr/bin/env bash
case "$1 $2" in
  "auth status") exit {0 if auth else 1} ;;
  "issue list") echo '{json.dumps([existing] if existing else [])}' ;;
  "issue create") echo "CREATE $@" >> {gh_log}; cat >> {gh_log}; echo https://github.com/frsorrentino/chrome-bridge/issues/99 ;;
  "issue comment") echo "COMMENT $@" >> {gh_log}; cat >> {gh_log}; echo https://github.com/frsorrentino/chrome-bridge/issues/7#c1 ;;
esac
""")
    GH.chmod(0o755)


def sent_hash(out):
    return out.strip().split()[-1]


def reset_status():
    rs = recs("chrome-bridge")
    for x in rs:
        if x.get("status") == "reported":
            x["status"] = "new"
    (box / "chrome-bridge.jsonl").write_text("".join(json.dumps(x) + "\n" for x in rs))


fail("mcp__chrome-bridge__screenshot", {"presets": ["mobile"]}, "Command screenshot timed out after 10000ms (tab 483581071)", extra=PIXEL)
fake_gh()
n_pending = len([x for x in recs("chrome-bridge") if x.get("status") not in ("done", "reported")])
d = obs("report", "chrome-bridge")
check("OB12 report: ONE draft with every unsent observation of the plugin, the send command with its hash; nothing sent",
      d.returncode == 0 and "BOZZA" in d.stdout and f"{n_pending} osservazioni in una issue" in d.stdout
      and d.stdout.count("\n- `mcp__chrome-bridge__") == n_pending and "screenshot" in d.stdout and "--send" in d.stdout
      and not gh_log.exists(), d.stdout + d.stderr)
bad = obs("report", "chrome-bridge", "--send", "0000000000")
check("OB12 --send with another hash → refused, nothing sent", bad.returncode == 3 and not gh_log.exists(), bad.stderr)
ok = obs("report", "chrome-bridge", "--send", sent_hash(d.stdout))
check("OB12 --send with the hash of the draft shown → one gh issue create on the plugin's repo, all those records reported",
      ok.returncode == 0 and gh_log.read_text().count("CREATE") == 1 and "-R frsorrentino/chrome-bridge" in gh_log.read_text()
      and all(x["status"] in ("reported", "done") for x in recs("chrome-bridge")), ok.stdout + ok.stderr)
check("OB12 what was sent is not offered again", "nessuna osservazione da inviare" in obs("report", "chrome-bridge").stdout, "")
check("OB12 the other account's observation went out anonymized", "acme-shop" not in gh_log.read_text() and "483581071" not in gh_log.read_text(),
      gh_log.read_text()[-600:])
reset_status()
fake_gh(existing={"number": 7, "title": "[chrome-bridge] No tab with id", "url": "https://github.com/frsorrentino/chrome-bridge/issues/7"})
d = obs("report", "chrome-bridge")
ok = obs("report", "chrome-bridge", "--send", sent_hash(d.stdout))
check("OB12 an open issue on the same error → the draft says so and sending adds a COMMENT to #7, no new issue",
      "#7" in d.stdout and ok.returncode == 0 and "COMMENT issue comment 7" in gh_log.read_text() and gh_log.read_text().count("CREATE") == 1,
      d.stdout[:400] + ok.stdout + ok.stderr)
reset_status()
fake_gh(auth=False)
for i in range(40):
    fail("mcp__chrome-bridge__extract", {"selector": "t"}, f"variante-{chr(97 + i % 26)}{chr(97 + i // 26)} errore lungo {'è' * 250}")
d = obs("report", "chrome-bridge")
ok = obs("report", "chrome-bridge", "--send", sent_hash(d.stdout))
url = ok.stdout.strip().split()[-1]
check("OB12 without gh (missing or not logged in) → a prefilled github.com/…/issues/new link within the URL limit, truncated with a note",
      "gh non c'è" in d.stdout and url.startswith("https://github.com/frsorrentino/chrome-bridge/issues/new?title=") and len(url) <= 7500
      and "truncated" in urllib.parse.unquote_plus(url) and gh_log.read_text().count("CREATE") == 1, f"len={len(url)} {ok.stdout[:200]}")
check("OB12 after the link, those observations are not offered again either", "nessuna osservazione da inviare" in obs("report", "chrome-bridge").stdout, "")

# OB13
MT = TOOLS / "mytool.json"
MT.write_text(json.dumps({"name": "mytool", "repo": "me/mytool", "match": {"mcp": ["mcp__mytool__"], "bash": [r"(^|/)mytool(\s|$)"]}}))
fail("mcp__mytool__run", {"x": 1}, "kaputt", tool=MT)
fail("Bash", {"command": "mytool build"}, "Exit code 3\nmissing", tool=MT)
check("OB13 a new plugin from its tool.json only: its MCP and CLI errors are recorded", len(recs("mytool")) == 2, json.dumps(recs("mytool"))[:400])

# OB14
SRC1 = clean_source("src1")
plug = tmp / "plugin"
(plug / "observe").mkdir(parents=True)
(plug / "hooks").mkdir()
(plug / "observe" / "tool.json").write_text(CB.read_text())
(plug / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo mine"}]}]}}))
s1 = subprocess.run([sys.executable, str(SRC1 / "sync.py"), str(plug)], capture_output=True, text=True)
s2 = subprocess.run([sys.executable, str(SRC1 / "sync.py"), str(plug)], capture_output=True, text=True)
hk = json.loads((plug / "hooks" / "hooks.json").read_text())["hooks"]
src_meta = json.loads((plug / "observe" / "SOURCE").read_text())
check("OB14 sync: copy and SOURCE; PostToolUseFailure with the plugin's matcher; SessionStart; idempotent; other hooks kept",
      s1.returncode == 0 and s2.returncode == 0 and (plug / "observe" / "observe.py").read_bytes() == (SRC1 / "observe.py").read_bytes()
      and len(hk["PostToolUseFailure"]) == 1 and hk["PostToolUseFailure"][0]["matcher"].startswith("mcp__chrome")
      and len(hk["SessionStart"]) == 2 and hk["SessionStart"][0]["hooks"][0]["command"] == "echo mine"
      and "observe.py\" session-start" in hk["SessionStart"][1]["hooks"][0]["command"] and "observe.py" in src_meta["sha256"],
      s1.stdout + s1.stderr + json.dumps(hk))
c1 = subprocess.run(["bash", str(SRC1 / "check.sh"), str(plug)], capture_output=True, text=True)
with open(plug / "observe" / "observe.py", "a") as f:
    f.write("# toccato a mano\n")
c2 = subprocess.run(["bash", str(SRC1 / "check.sh"), str(plug)], capture_output=True, text=True)
check("OB14 check.sh: ok on a synced copy; FAIL with the remedy when the copy differs from the source",
      c1.returncode == 0 and "ok" in c1.stdout and c2.returncode == 1 and "diverso dalla fonte" in c2.stderr and "sync.py" in c2.stderr, c1.stdout + c1.stderr + c2.stderr)

# OB15
code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('o',sys.argv[1]);m=importlib.util.module_from_spec(s);"
        "s.loader.exec_module(m);m.record_external('relay','relay answer','sessione occupata','atlas-shop')")
subprocess.run([sys.executable, "-c", code, str(OBS)], env=env(tool=CM), check=True, timeout=30)
check("OB15 record_external: a component outside the hooks writes in the plugin's file with its own source",
      any(x["source"] == "relay" and x["call"] == "relay answer" for x in recs("claude-master")), json.dumps(recs("claude-master"))[-400:])
check("OB15 files are private (0600) in a private folder (0700)",
      oct(box.stat().st_mode & 0o777) == "0o700" and all(oct(p.stat().st_mode & 0o777) == "0o600" for p in box.glob("*.jsonl")), "")

# OB16
cfg.write_text(json.dumps({**BASE, "propose_after": 2}))
for i in range(3):
    fail("Bash", {"command": "claude-master sessions --json"}, f"Exit code 1\nerrore {'abc'[i]}")
for f in box.glob(".proposed-*"):
    f.unlink()
p1 = start(home / "ws" / "clienti" / "acme-shop", tool=CM)
p2 = start(home / "ws" / "clienti" / "acme-shop", tool=CM)
pm = start(gitdir, tool=CM)
check("OB16 any session: enough unsent observations → one line asking Claude to offer sending, once",
      "OSSERVAZIONI DA INVIARE claude-master:" in p1 and "claude-master observe report claude-master" in p1 and p2 == "", f"{p1!r} | {p2!r}")
check("OB16 never offered in the session that maintains the plugin", "DA INVIARE" not in pm, pm)
cfg.write_text(json.dumps({**BASE, "propose": False}))
for f in box.glob(".proposed-*"):
    f.unlink()
check("OB16 propose false → no offer", "DA INVIARE" not in start(home / "ws" / "clienti" / "acme-shop", tool=CM), "")
cfg.write_text(json.dumps(BASE))

# OB16b (25/09): la proposta parte anche con poche osservazioni quando la piu' vecchia aspetta da propose_after_days,
# o subito con una classe D; due osservazioni di ieri: nessuna proposta
CMJ = box / "claude-master.jsonl"


def seed(*recs_):
    for f in box.glob(".proposed-*"):
        f.unlink()
    now = time.time()
    rows = []
    for i, (age_days, cls) in enumerate(recs_):
        t = now - age_days * 86400
        rows.append({"v": 1, "id": f"claude-master-{i:08d}", "tool": "claude-master", "source": "hook-bash", "kind": "error",
                     "call": f"claude-master cmd{i}", "error": f"errore {i}", "key": f"k{i}", "count": 1, "first_seen": t, "last_seen": t,
                     "examples": [], "workaround": None, "class": cls, "status": "new"})
    CMJ.write_text("".join(json.dumps(r) + "\n" for r in rows))


offer = lambda: "DA INVIARE claude-master" in start(home / "ws" / "clienti" / "acme-shop", tool=CM)  # noqa: E731
cfg.write_text(json.dumps(BASE))
seed((1, None), (1, None))
check("OB16b two observations from yesterday, below propose_after and younger than propose_after_days → no offer", not offer(), CMJ.read_text()[-200:])
seed((4, None), (1, None))
check("OB16b two observations, the oldest 4 days old (≥ propose_after_days 3) → offer", offer(), "")
seed((0, "D"))
check("OB16b one observation of class D (a defect marked by hand), from today → offer at once", offer(), "")
seed((0, None), (0, None), (0, None))
check("OB16b three observations from today (≥ propose_after) → offer", offer(), "")
cfg.write_text(json.dumps({**BASE, "propose_after_days": 0}))
seed((10, None))
check("OB16b propose_after_days 0 → age never counts: one 10-day-old observation, no offer", not offer(), "")
cfg.write_text(json.dumps({**BASE, "propose_after_days": 1}))
seed((2, None))
p_a = offer(); p_b = offer()
check("OB16b propose_after_days 1: a 2-day-old observation → offer, and not again within propose_every_days", p_a and not p_b, f"{p_a} {p_b}")
cfg.write_text(json.dumps(BASE))
CMJ.unlink()

# OB17-OB19
(home / ".claude" / "plugins").mkdir(parents=True, exist_ok=True)
(home / ".claude" / "plugins" / "installed_plugins.json").write_text(json.dumps({"plugins": {"chrome-bridge@local": [{"version": "1.18.0"}]}}))
tp = tmp / "t.jsonl"
turn = lambda names: json.dumps({"type": "assistant", "message": {"model": "claude-opus-5-5", "content": [  # noqa: E731
    {"type": "tool_use", "name": n, "input": {"url": "https://acme-shop.example/segreto"}} for n in names]}}, separators=(",", ":"))
tp.write_text("\n".join(["{}", turn(["mcp__chrome-bridge__navigate"]), turn(["mcp__chrome-bridge__get_interactives", "Bash"]),
                         turn(["mcp__chrome-bridge__type_text"])]) + "\n")
CC = {"CLAUDE_CODE_EXECPATH": "/x/versions/2.1.280"}


def hook_out(error, tool_name="mcp__chrome-bridge__type_text", extra=None):
    p = {"hook_event_name": "PostToolUseFailure", "session_id": "S-9", "cwd": str(home / "ws" / "clienti" / "acme-shop"),
         "transcript_path": str(tp), "tool_name": tool_name, "tool_input": {"selector": "#q", "text": "hunter2"},
         "error": error, "is_interrupt": False}
    return obs("hook", stdin=json.dumps(p), extra={**(extra or PERSONAL), **CC}).stdout.strip()


first = hook_out("mismatch: value_after empty for type_text")
r17 = next(x for x in recs("chrome-bridge") if x["call"] == "mcp__chrome-bridge__type_text")
c17 = r17.get("context") or {}
check("OB17 context: plugin version, Claude Code, model, OS, names of the last tools before the error",
      c17.get("tool_version") == "1.18.0" and c17.get("claude_code") == "2.1.280" and c17.get("model") == "claude-opus-5-5"
      and c17.get("os", "").startswith(platform.system())
      and c17.get("recent_tools") == ["mcp__chrome-bridge__navigate", "mcp__chrome-bridge__get_interactives", "Bash"], json.dumps(c17))
check("OB17 never the parameters of those tools", "acme-shop.example/segreto" not in raw_box(), "")
check("OB18 a first-seen error without a workaround → no additionalContext", first == "", first)
obs("add", "--on", r17["id"], "--workaround", "usare type_text mode:keys dopo un click sul campo")
again = hook_out("mismatch: value_after empty for type_text")
ctx = json.loads(again)["hookSpecificOutput"] if again else {}
check("OB18 the same error again → additionalContext with the recorded workaround and the plugin version",
      ctx.get("hookEventName") == "PostToolUseFailure" and "usare type_text mode:keys" in ctx.get("additionalContext", "")
      and "1.18.0" in ctx.get("additionalContext", ""), again)
other = hook_out("mismatch: value_after empty for type_text", extra=PIXEL)
check("OB18 a workaround written by the other account is not handed over", "usare type_text" not in other, other)
m = obs("mark", r17["id"], "--fixed-in", "1.19.0")
fixed = hook_out("mismatch: value_after empty for type_text")
check("OB19 --fixed-in 1.19.0 with 1.18.0 installed → the hint says to update instead of reporting",
      m.returncode == 0 and "1.19.0" in fixed and "aggiornare" in fixed and next(x for x in recs("chrome-bridge") if x["id"] == r17["id"])["fixed_in"] == "1.19.0", fixed)
check("OB19 a record fixed in a later version is not offered as an issue", r17["id"] not in obs("report", "chrome-bridge").stdout, "")
cb_known = json.loads(CB.read_text())
cb_known["known"] = [{"call": "mcp__chrome-bridge__screenshot", "error": "image readback failed", "fixed_in": "1.20.0", "workaround": "finestra davanti"}]
CB.write_text(json.dumps(cb_known))
k1 = hook_out("Failed to capture tab: image readback failed", tool_name="mcp__chrome-bridge__screenshot")
check("OB19 a `known` entry of tool.json (shipped with the plugin) works on a first-seen error too", "1.20.0" in k1, k1)

# OB20
check("OB20 new records carry the format version v1", all(x.get("v") == 1 for x in recs("mytool")), json.dumps(recs("mytool"))[:300])
fut = recs("mytool")
fut.append({"v": 2, "id": "mytool-future", "tool": "mytool", "status": "new", "last_seen": time.time(), "count": 1})
(box / "mytool.jsonl").write_text("".join(json.dumps(x) + "\n" for x in fut))
before = (box / "mytool.jsonl").read_text()
fail("mcp__mytool__run", {"x": 1}, "kaputt di nuovo", tool=MT)
check("OB20 a file holding records of a newer format is not rewritten by an older copy", (box / "mytool.jsonl").read_text() == before, "")

# OB21
SK = TOOLS / "skills-only.json"
SK.write_text(json.dumps({"name": "skills-only", "repo": "me/skills-only", "match": {}}))
for what in ("la skill deploy porta fuori strada", "la skill release salta un passo", "la skill ads cita un campo vecchio"):
    obs("add", "skills-only", what, tool=SK)
d21 = obs("report", "skills-only", tool=SK).stdout
cfg.write_text(json.dumps({**BASE, "propose_after": 2}))
for f in box.glob(".proposed-*"):
    f.unlink()
p21 = start(home / "ws" / "clienti" / "acme-shop", tool=SK)
cfg.write_text(json.dumps(BASE))
plug2 = tmp / "plugin2"
(plug2 / "observe").mkdir(parents=True)
(plug2 / "observe" / "tool.json").write_text(SK.read_text())
subprocess.run([sys.executable, str(SRC1 / "sync.py"), str(plug2)], capture_output=True, text=True, check=True)
hk2 = json.loads((plug2 / "hooks" / "hooks.json").read_text())["hooks"]
check("OB21 skills-only plugin: the draft counts note(s), no error(s), no claude-master wording; the offer does not say «hook»",
      "3 note(s)" in d21 and "error(s)" not in d21 and "claude-master" not in d21 and "claude-observe" in d21
      and "DA INVIARE skills-only" in p21 and "registrati da un hook su" not in p21, d21[:500] + p21)
check("OB21 sync.py on a plugin without match: SessionStart only, no empty PostToolUseFailure", list(hk2) == ["SessionStart"], json.dumps(hk2))

# OB22 (via il record di formato futuro di OB20, che blocca la riscrittura del file)
(box / "mytool.jsonl").write_text("".join(json.dumps(x) + "\n" for x in recs("mytool") if x.get("v") == 1))
procs = [subprocess.Popen([sys.executable, str(OBS), "hook"], stdin=subprocess.PIPE, env=env(tool=MT), text=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(12)]
for pr in procs:
    pr.communicate(json.dumps({"hook_event_name": "PostToolUseFailure", "session_id": "S", "cwd": str(home), "tool_name": "mcp__mytool__par",
                               "tool_input": {}, "error": "in parallelo", "is_interrupt": False}))
par = [x for x in recs("mytool") if x.get("call") == "mcp__mytool__par"]
# un file di formato futuro blocca la riscrittura (OB20): lo si toglie per questa prova
check("OB22 12 hooks at the same time → one record with count 12 (the directory lock serializes them)",
      len(par) == 1 and par[0]["count"] == 12, json.dumps(par)[:300])
lk = box / "skills-only.jsonl.lock"
lk.mkdir()
os.utime(lk, (time.time() - 60, time.time() - 60))
obs("add", "skills-only", "dopo un lock abbandonato", tool=SK)
check("OB22 a lock left by a dead process (older than 10 s) is removed and the write goes through",
      not lk.exists() and any("dopo un lock abbandonato" in (x.get("call") or "") for x in recs("skills-only")), json.dumps(recs("skills-only"))[-300:])
lk.mkdir()
t0 = time.time()
busy = obs("add", "skills-only", "con il lock tenuto da un altro", tool=SK)
check("OB22 a live lock: the writer waits at most ~3 s, the file is untouched",
      time.time() - t0 < 8 and not any("tenuto da un altro" in (x.get("call") or "") for x in recs("skills-only")), f"{time.time() - t0:.1f}s {busy.returncode}")
lk.rmdir()
# OB26
check("OB26 …and the record is not lost: it waits in skills-only.pending.jsonl",
      "tenuto da un altro" in (box / "skills-only.pending.jsonl").read_text() if (box / "skills-only.pending.jsonl").exists() else False, "")
obs("add", "skills-only", "la scrittura dopo", tool=SK)
check("OB26 the next writer with the lock takes the pending entry in and empties the pending file",
      any("tenuto da un altro" in (x.get("call") or "") for x in recs("skills-only")) and not (box / "skills-only.pending.jsonl").exists()
      and not list(box.glob("*.taking")), json.dumps(recs("skills-only"))[-400:])

# OB23
holder = subprocess.Popen([sys.executable, "-c", "import fcntl,sys,time;f=open(sys.argv[1],'w');fcntl.flock(f,fcntl.LOCK_EX);"
                           "print('held',flush=True);time.sleep(1.5)", str(box / ".lock")], stdout=subprocess.PIPE, text=True)
holder.stdout.readline()
t0 = time.time()
obs("add", "skills-only", "scritta mentre una copia vecchia tiene flock", tool=SK)
waited = time.time() - t0
holder.wait()
check("OB23 an old copy holding only flock on <dir>/.lock: the new copy waits for it, then writes",
      waited >= 1.0 and any("copia vecchia" in (x.get("call") or "") for x in recs("skills-only")), f"{waited:.2f}s")

# OB24
FD = TOOLS / "fd.json"
FD.write_text(json.dumps({"name": "fd", "repo": "me/fd", "match": {"bash": [r"\b(external-exec|fd-telemetry)\.py\b"]},
                          "benign_exits": {"external-exec.py": [2], "fd-telemetry.py budget-open": [3]}}))
fail("Bash", {"command": "python3 ~/p/scripts/external-exec.py --task x"}, "Exit code 2\nNEEDS_CONTEXT", tool=FD)
fail("Bash", {"command": "python3 ~/p/scripts/fd-telemetry.py budget-open --x 1"}, "Exit code 3\ngate", tool=FD)
n24 = len(recs("fd"))
fail("Bash", {"command": "python3 ~/p/scripts/external-exec.py --task x"}, "Exit code 1\nboom", tool=FD)
fail("Bash", {"command": "python3 ~/p/scripts/fd-telemetry.py report"}, "Exit code 3\nerr", tool=FD)
check("OB24 benign_exits by script name (no subcommand) and by script + subcommand; other codes and subcommands still recorded",
      n24 == 0 and len(recs("fd")) == 2, json.dumps(recs("fd"))[:500])

# OB25 (su una copia della fonte, in un repo git suo)
src2 = clean_source("src2")
plug3 = tmp / "plugin3"
(plug3 / "observe").mkdir(parents=True)
(plug3 / "observe" / "tool.json").write_text(CB.read_text())
ok25 = subprocess.run([sys.executable, str(src2 / "sync.py"), str(plug3)], capture_output=True, text=True)
with open(src2 / "observe.py", "a") as f:
    f.write("# modifica in corso\n")
dirty25 = subprocess.run([sys.executable, str(src2 / "sync.py"), str(plug3)], capture_output=True, text=True)
chk25 = subprocess.run(["bash", str(src2 / "check.sh"), str(plug3)], capture_output=True, text=True)
check("OB25 sync.py refuses a source with uncommitted observe.py; check.sh compares with the committed source, not the working tree",
      ok25.returncode == 0 and dirty25.returncode == 1 and "non committate" in dirty25.stderr and chk25.returncode == 0,
      ok25.stderr + dirty25.stderr + chk25.stdout + chk25.stderr)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{OKS}/{OKS + len(FAILS)} OK" + (", FAIL: " + ", ".join(FAILS) if FAILS else ""))
sys.exit(1 if FAILS else 0)
