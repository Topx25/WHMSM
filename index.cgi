#!/usr/bin/env bash
# Safety Monitor Pro (smpro) — CGI entry wrapper.
# Read-only. Isolated from the existing safety_monitor plugin.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"

PHP_BIN="/usr/local/cpanel/3rdparty/bin/php"
[[ -x "$PHP_BIN" ]] || PHP_BIN="$(command -v php 2>/dev/null || true)"

# Detect cPanel session prefix (/cpsessXXXX) so in-page links stay authenticated.
detect_cpsess_prefix() {
  local v
  for v in "${REQUEST_URI:-}" "${SCRIPT_NAME:-}" "${REDIRECT_URL:-}" "${ORIG_SCRIPT_NAME:-}"; do
    case "$v" in
      /cpsess[0-9]*/*) printf '%s\n' "$v" | sed -E 's#^(/cpsess[0-9]+).*#\1#'; return 0;;
    esac
  done
  printf ''
}
CP_PREFIX="$(detect_cpsess_prefix)"
# Hard whitelist: must be exactly /cpsess<digits> or empty. Anything else is dropped so it can never carry a
# sed metacharacter into the link-rewrite step below.
[[ "$CP_PREFIX" =~ ^/cpsess[0-9]+$ ]] || CP_PREFIX=""
export SM_CPANEL_PREFIX="$CP_PREFIX"

if [[ -z "$PHP_BIN" || ! -x "$PHP_BIN" ]]; then
  printf 'Content-Type: text/html; charset=utf-8\r\n\r\n'
  echo "<h1>Safety Monitor Pro</h1><p>PHP binary not found.</p>"
  exit 0
fi

cd "$DIR" || exit 0

# Run PHP, capture body.
# memory_limit: cPanel's php.ini caps the CLI at 128M. A log page that reads a 200k-line window needs ~300MB and died
# silently at that cap (blank page, nothing logged — measured 2026-09-07). 768M is a ceiling, not an allocation.
# memory_limit: cPanel's php.ini caps the CLI at 128M. A log page that reads a 200k-line window needs ~300MB and died
# silently at that cap (blank page, nothing logged — measured 2026-09-07). 768M is a ceiling, not an allocation.
BODY="$(REQUEST_METHOD="${REQUEST_METHOD:-GET}" \
  SCRIPT_FILENAME="$DIR/index.php" \
  "$PHP_BIN" -d display_errors=0 -d memory_limit=768M -d serialize_precision=-1 -d precision=14 "$DIR/index.php" 2>/dev/null)"

# JSON API requests: serve raw JSON, no link rewriting.
case "&${QUERY_STRING:-}&" in
  *"&format=json&"*)
    printf 'Content-Type: application/json; charset=utf-8\r\n'
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '%s' "$BODY"
    exit 0
    ;;
  *"&format=csv&"*)
    printf 'Content-Type: text/csv; charset=utf-8\r\n'
    printf 'Content-Disposition: attachment; filename="smpro-export.csv"\r\n'
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '%s' "$BODY"
    exit 0
    ;;
  *"&format=html&"*)
    # Self-contained HTML report — download as a file, no link rewriting.
    printf 'Content-Type: text/html; charset=utf-8\r\n'
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf 'X-Frame-Options: SAMEORIGIN\r\n'
    printf 'Referrer-Policy: no-referrer\r\n'
    printf 'Content-Disposition: attachment; filename="smpro-report.html"\r\n'
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '%s' "$BODY"
    exit 0
    ;;
  *"&format=pdf&"*)
    # Print-friendly HTML opened inline; the page auto-triggers the print dialog
    # so the operator can "Save as PDF". No link rewriting.
    printf 'Content-Type: text/html; charset=utf-8\r\n'
    printf "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'; form-action 'self'\r\n"
    printf 'X-Frame-Options: SAMEORIGIN\r\n'
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf 'Referrer-Policy: no-referrer\r\n'
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '%s' "$BODY"
    exit 0
    ;;
  *"&format=ioc&"*)
    # Indicators of Compromise — plain-text list, download as a file.
    printf 'Content-Type: text/plain; charset=utf-8\r\n'
    printf 'Content-Disposition: attachment; filename="smpro-iocs.txt"\r\n'
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '%s' "$BODY"
    exit 0
    ;;
esac

# Emit CGI header + body, rewriting absolute /cgi/ links with the cpsess prefix.
# no-store so the browser never serves a stale plugin page after an update.
printf 'Content-Type: text/html; charset=utf-8\r\n'
printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n'
printf 'Pragma: no-cache\r\n'
# Defense-in-depth for the root WHM DOM (PHP runs as CLI SAPI so header() is a no-op — headers MUST be emitted
# here). Inline script/style are pervasive + server-emitted, so 'unsafe-inline' is required; the CSP still kills
# external script/img/connect/object exfil vectors and constrains any injected markup. Same-origin framing (WHM
# chrome) stays allowed.
printf "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'; form-action 'self'\r\n"
printf 'X-Frame-Options: SAMEORIGIN\r\n'
printf 'X-Content-Type-Options: nosniff\r\n'
printf 'Referrer-Policy: no-referrer\r\n\r\n'
if [[ -n "$CP_PREFIX" ]]; then
  printf '%s' "$BODY" | sed -E \
    -e "s#(href|src|action)=([\"'])/cgi/#\1=\2${CP_PREFIX}/cgi/#g"
else
  printf '%s' "$BODY"
fi
exit 0
