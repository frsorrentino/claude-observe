#!/usr/bin/env bash
# check.sh <plugin-root> — per il release.sh di un plugin: la copia di observe coincide con la fonte?
# Fallisce (1) se observe/observe.py e' stato toccato a mano o e' rimasto indietro rispetto alla fonte, se manca
# tool.json o se hooks.json non chiama la copia. Rimedio: python3 <claude-observe>/sync.py <plugin-root>.
set -euo pipefail
ROOT="${1:?uso: check.sh <plugin-root>}"
SRC="$(cd "$(dirname "$0")" && pwd)"
fail() { echo "FAIL claude-observe: $*" >&2; echo "  rimedio: python3 $SRC/sync.py $ROOT" >&2; exit 1; }
[ -f "$ROOT/observe/tool.json" ] || fail "manca $ROOT/observe/tool.json"
[ -f "$ROOT/observe/observe.py" ] || fail "manca $ROOT/observe/observe.py"
# la fonte committata, non il working tree: una modifica in corso nella fonte non deve far passare ne' fallire un plugin
if git -C "$SRC" rev-parse -q --verify HEAD >/dev/null 2>&1; then
  want=$(git -C "$SRC" show HEAD:observe.py | sha256sum | cut -d' ' -f1)
else
  want=$(sha256sum "$SRC/observe.py" | cut -d' ' -f1)
fi
have=$(sha256sum "$ROOT/observe/observe.py" | cut -d' ' -f1)
[ "$want" = "$have" ] || fail "observe.py diverso dalla fonte (copia ${have:0:12}, fonte ${want:0:12})"
grep -q '/observe/observe.py\\" session-start' "$ROOT/hooks/hooks.json" 2>/dev/null || fail "hooks.json non chiama observe.py session-start"
grep -q '/observe/observe.py\\" stop' "$ROOT/hooks/hooks.json" 2>/dev/null || fail "hooks.json non chiama observe.py stop (la riga a schermo)"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ROOT/observe/tool.json" || fail "tool.json non valido"
echo "claude-observe ok: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$ROOT/observe/tool.json") = fonte ${want:0:12}"
