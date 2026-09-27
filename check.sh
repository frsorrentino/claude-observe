#!/usr/bin/env bash
# check.sh <plugin-root> — per il release.sh di un plugin: la copia di observe coincide con la fonte?
# Fallisce (1) se observe/observe.py o observe/py.sh sono stati toccati a mano o sono rimasti indietro rispetto alla
# fonte, se manca tool.json o se hooks.json non chiama la copia attraverso il lanciatore py.sh.
# Rimedio: python3 <claude-observe>/sync.py <plugin-root>.
set -euo pipefail
ROOT="${1:?uso: check.sh <plugin-root>}"
SRC="$(cd "$(dirname "$0")" && pwd)"
fail() { echo "FAIL claude-observe: $*" >&2; echo "  rimedio: python3 $SRC/sync.py $ROOT" >&2; exit 1; }
[ -f "$ROOT/observe/tool.json" ] || fail "manca $ROOT/observe/tool.json"
# la fonte committata, non il working tree: una modifica in corso nella fonte non deve far passare ne' fallire un plugin
for f in observe.py py.sh; do
  [ -f "$ROOT/observe/$f" ] || fail "manca $ROOT/observe/$f"
  if git -C "$SRC" rev-parse -q --verify HEAD >/dev/null 2>&1; then
    w=$(git -C "$SRC" show "HEAD:$f" | sha256sum | cut -d' ' -f1)
  else
    w=$(sha256sum "$SRC/$f" | cut -d' ' -f1)
  fi
  h=$(sha256sum "$ROOT/observe/$f" | cut -d' ' -f1)
  [ "$w" = "$h" ] || fail "$f diverso dalla fonte (copia ${h:0:12}, fonte ${w:0:12})"
  if [ "$f" = observe.py ]; then want=$w; fi
done
# gli hook passano dal lanciatore: `python3` nudo su Windows e' l'alias dello Store e non registra nulla (27/09)
if grep -q 'python3 \\"${CLAUDE_PLUGIN_ROOT}/observe/observe.py' "$ROOT/hooks/hooks.json" 2>/dev/null; then
  fail "hooks.json chiama observe.py con python3 nudo, non con observe/py.sh"
fi
grep -q '/observe/py.sh\\" \\"${CLAUDE_PLUGIN_ROOT}/observe/observe.py\\" session-start' "$ROOT/hooks/hooks.json" 2>/dev/null || fail "hooks.json non chiama observe.py session-start attraverso observe/py.sh"
grep -q '/observe/observe.py\\" stop' "$ROOT/hooks/hooks.json" 2>/dev/null || fail "hooks.json non chiama observe.py stop (la riga a schermo)"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ROOT/observe/tool.json" || fail "tool.json non valido"
echo "claude-observe ok: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$ROOT/observe/tool.json") = fonte ${want:0:12}"
