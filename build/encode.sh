#!/usr/bin/env bash
#
# encode.sh - produce an ENCODED, tamper-resistant build of Safety Monitor Pro.
#
# Why: the plugin's source runs as root on the customer's server, so root can
# otherwise just edit out the licence gate (set SMPRO_LIC_ENFORCE=false or stub
# smpro_lic_is_valid()). Bytecode-encoding the PHP removes the plaintext source,
# so the gate can no longer be edited. The whole plugin is encoded (not just the
# gate) so an attacker has no readable file from which to rebuild an un-gated
# loader. The bash wrapper (index.cgi) and static assets are copied as-is.
#
# Target runtime: cPanel PHP 8.4 (verified: ionCube Loader AND SourceGuardian
# are both already active in /usr/local/cpanel/3rdparty/bin/php on the server,
# so NO loader needs to be installed - encoded files just run).
#
# Usage:
#   ./build/encode.sh [SRC_DIR] [OUT_DIR]
#     SRC_DIR  plaintext plugin root      (default: parent of this script)
#     OUT_DIR  encoded output directory   (default: <SRC>-encoded)
#
# Requires ONE of (run on a Linux build host - encoders are Linux/commercial):
#   - ionCube Encoder 14+      (binary: ioncube_encoder8.4 / ioncube_encoder)
#       https://www.ioncube.com/sa_encoder.php   (needs PHP 8.4 target support)
#   - SourceGuardian 13+       (binary: sourceguardian / sg_encode)
#       https://www.sourceguardian.com/
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$(cd "$HERE/.." && pwd)}"
SRC="${SRC%/}"
OUT="${2:-${SRC}-encoded}"
TARGET="8.4"

[ -f "$SRC/index.php" ] || { echo "ERROR: $SRC does not look like the plugin root (no index.php)"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
echo "Source : $SRC"
echo "Output : $OUT"
echo "Target : PHP $TARGET"
echo

# ---- pick an encoder -------------------------------------------------------
IONCUBE=""; SGUARD=""
for b in ioncube_encoder8.4 ioncube_encoder84 ioncube_encoder; do command -v "$b" >/dev/null 2>&1 && { IONCUBE="$b"; break; }; done
for b in sourceguardian sg_encode sgcli;          do command -v "$b" >/dev/null 2>&1 && { SGUARD="$b"; break; }; done

if [ -n "$IONCUBE" ]; then
  echo ">> Using ionCube encoder: $IONCUBE"
  # --copy '*'      : copy files that aren't encoded (index.cgi, assets, .md ...)
  # --ignore        : never ship VCS / build / local state
  # --obfuscate all : rename internal symbols + strip structure
  # --binary        : binary-format output (smaller, harder to inspect)
  # --no-doc-comments: drop docblocks
  "$IONCUBE" \
    --into "$OUT" \
    --copy '*' \
    --ignore '.git' --ignore 'build' --ignore '*.log' --ignore '*-encoded' \
    --php-target-version "$TARGET" \
    --obfuscate all \
    --no-doc-comments \
    --binary \
    "$SRC"

elif [ -n "$SGUARD" ]; then
  echo ">> Using SourceGuardian encoder: $SGUARD"
  # SourceGuardian: recurse, target 8.4, mirror tree into OUT, keep non-php files
  "$SGUARD" \
    --php "$TARGET" \
    -r \
    -o "$OUT" \
    --keepfile '*' \
    --exclude '.git' --exclude 'build' --exclude '*-encoded' \
    "$SRC"

else
  cat >&2 <<MSG
ERROR: no encoder found on this host.

Install ONE of these on a Linux build machine, then re-run:
  * ionCube Encoder 14+  (must list PHP 8.4 as a supported target)
        https://www.ioncube.com/sa_encoder.php
  * SourceGuardian 13+
        https://www.sourceguardian.com/

The TARGET SERVER already has both loaders active in cPanel PHP 8.4 — you only
need the ENCODER here on the build host. Run this script wherever the encoder is.
MSG
  exit 2
fi

# ---- sanity: the gate files must have come out encoded ----------------------
echo
echo "Verifying gate files are encoded (no plaintext PHP left):"
fail=0
for f in index.php includes/license.php includes/menu.php includes/layout.php; do
  if [ ! -f "$OUT/$f" ]; then echo "  MISSING: $f"; fail=1; continue; fi
  if grep -qsm1 'SMPRO_LIC_ENFORCE\|smpro_lic_is_valid' "$OUT/$f"; then
    echo "  !! STILL PLAINTEXT: $f"; fail=1
  else
    echo "  ok (encoded): $f"
  fi
done
[ "$fail" = 0 ] && echo && echo "DONE. Encoded build at: $OUT" || { echo; echo "ENCODING INCOMPLETE — see above."; exit 3; }
