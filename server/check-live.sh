#!/usr/bin/env bash
# check-live.sh [URL] — checks the live anonymous service from outside, over HTTPS (server/README.md, step 7).
# The endpoint answers; a request that is not a draft is refused (400) and nothing is published; the paths where a
# secret or the state would sit by mistake are not served (403/404: on SiteGround Nginx serves static files without
# Apache, so an .htaccess does not protect them). Costs one POST of the per-IP limit. Exit 1 at the first failure.
set -uo pipefail
URL="${1:-https://www.francescosorrentino.com/api/observe/report.php}"
SITE="$(printf '%s' "$URL" | sed -E 's#^(https?://[^/]+).*#\1#')"
DIR="$(dirname "$URL")"
fails=0
ok() { echo "ok   $*"; }
ko() { echo "FAIL $*"; fails=$((fails + 1)); }

out=$(curl -sS -m 20 -w '\n%{http_code}' "$URL" 2>&1); rc=$?
code=${out##*$'\n'}; body=${out%$'\n'*}
if [ $rc -ne 0 ]; then ko "GET $URL: curl exit $rc (TLS or network: $body)"
elif [ "$code" = 200 ] && printf '%s' "$body" | grep -q '"claude-observe anonymous reports"'; then ok "GET → 200, the service answers"
else ko "GET → $code: $body"; fi

out=$(curl -sS -m 20 -w '\n%{http_code}' -H 'Content-Type: application/json' -d '{"plugin":"check-live"}' "$URL" 2>&1)
code=${out##*$'\n'}
[ "$code" = 400 ] && ok "POST of a non-draft → 400, nothing published" || ko "POST of a non-draft → $code: ${out%$'\n'*}"

day=$(date -u +%Y%m%d)
for p in "$DIR/config.php" "$DIR/app.pem" "$DIR/state/" "$DIR/.lock" "$DIR/rate-$day.json" "$DIR/state/rate-$day.json" \
         "$SITE/private/observe/config.php" "$SITE/private/observe/app.pem" "$SITE/private/observe/state/rate-$day.json"; do
  code=$(curl -sL -o /dev/null -m 20 -w '%{http_code}' "$p")   # -L: the site's own redirects (trailing slash, .php) must still end in 403/404
  case "$code" in 403|404) ok "$p → $code" ;; *) ko "$p → $code (must be 403 or 404)" ;; esac
done
[ $fails -eq 0 ] && echo "check-live: all ok" || echo "check-live: $fails failure(s)"
[ $fails -eq 0 ]
