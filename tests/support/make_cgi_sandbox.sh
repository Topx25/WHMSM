#!/bin/sh
# make_cgi_sandbox.sh — build a SANDBOXED, side-effect-neutralized copy of the plugin so the live CGI
# render smoke can spawn the real front controller (index.php) without touching production state.
#
#   $1 = enforce mode: "off" (default) -> license gate disabled, every page renders;
#                      "on"            -> license gate ACTIVE (no valid license) to test the B2 recovery path.
#
# Containment: data dirs (SMPRO_VARLIB/VARLOG) are redirected to the sandbox; the top-level cron-install
# and hub-tick calls in index.php are neutralized (they write the REAL /etc/cron.d); terms are pre-accepted
# so module pages render. Prints the sandbox dir on the LAST stdout line.
SRC="$(cd "$(dirname "$0")/../.." && pwd)"           # plugin source root
MODE="${1:-off}"
SB="$(mktemp -d "${TMPDIR:-/tmp}/smpro_cgi.XXXXXX")"
mkdir -p "$SB/plugin" "$SB/varlib/cache" "$SB/varlib/locks" "$SB/varlib/license" "$SB/varlog" "$SB/crond"

rsync -a "$SRC/includes" "$SRC/modules" "$SRC/bin" "$SRC/index.php" "$SB/plugin/" 2>/dev/null
[ -d "$SRC/lang" ] && rsync -a "$SRC/lang" "$SB/plugin/" 2>/dev/null

# redirect the data dirs to the sandbox (defines.php hardcodes /var/lib|log/smpro)
sed -i "s#/var/lib/smpro#$SB/varlib#g; s#/var/log/smpro#$SB/varlog#g" "$SB/plugin/includes/defines.php"

# redirect EVERY /etc/cron.d write to the sandbox — modules call cron-install during page render, so
# neutralizing index.php's top-level calls alone is not enough; this catches all of them at the path.
find "$SB/plugin" -name '*.php' -exec sed -i "s#/etc/cron\.d#$SB/crond#g" {} +
# also neutralize the hub member-tick (a relay poll, not a cron write) at index.php call sites
sed -i "s/smpro_hub_member_tick()/null/g" "$SB/plugin/index.php"

# license enforcement: off -> force-disable; on -> leave default (true) so the gate engages.
# Pre-define the constant right after SMPRO_BOOT (a stable single-line anchor) so the signed-dev-token block
# below is a no-op (constant already defined) and license.php's default never sets it true. Robust to the
# dev-block being multi-line (the old single-line sed left a dangling brace and broke the sandbox).
if [ "$MODE" = "off" ]; then
  sed -i "s#^define('SMPRO_BOOT', 1);#define('SMPRO_BOOT', 1);\ndefine('SMPRO_LIC_ENFORCE', false);#" "$SB/plugin/index.php"
fi

# pre-accept the Terms gate (version must match smpro_legal_version() or the gate shows Terms first)
LV="$(grep -oE "return '[0-9]{4}-[0-9]{2}-[0-9]{2}'" "$SB/plugin/includes/legal.php" | head -1 | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}")"
[ -n "$LV" ] && printf '{"version":"%s","ts":1,"actor":"root","ip":"127.0.0.1"}' "$LV" > "$SB/varlib/legal_accepted.json"

echo "$SB"
