#!/usr/bin/env bash
#
# sign-release.sh - OFFLINE signing of a Safety Monitor Pro release tarball.
#
# Point 3 of the security hardening: the plugin verifies an RSA-SHA256 signature over the EXACT
# tarball bytes against a public key embedded in includes/update.php (SMPRO_UPD_PUBKEY) before it
# applies any update. The matching PRIVATE key lives ONLY on this build machine (never on the
# license server), so even a fully compromised license server cannot forge a malicious update.
#
# This script produces "<tarball>.sig" = base64( openssl dgst -sha256 -sign <private key> ).
# Upload BOTH the tarball and the .sig to the license server's releases dir
# (/opt/vendor-license-server/releases/), e.g.:
#     smpro-latest.tar.gz
#     smpro-latest.tar.gz.sig      <-- update_ext.php / download_ext.php serve this as X-Smpro-Sig
#
# Usage:
#   ./build/sign-release.sh <tarball> [private_key] [public_key]
#     tarball       path to the release .tar.gz to sign
#     private_key   default: ~/smpro_keys/smpro_update_private.pem   (KEEP OFFLINE)
#     public_key    default: ~/smpro_keys/smpro_update_public.pem    (for the self-verify step)
#
set -euo pipefail

TGZ="${1:?usage: sign-release.sh <tarball> [private_key] [public_key]}"
PRIV="${2:-$HOME/smpro_keys/smpro_update_private.pem}"
PUB="${3:-$HOME/smpro_keys/smpro_update_public.pem}"
SIG="${TGZ}.sig"

[ -f "$TGZ" ]  || { echo "ERROR: tarball not found: $TGZ"; exit 1; }
[ -f "$PRIV" ] || { echo "ERROR: private key not found: $PRIV (must be the OFFLINE build-host key)"; exit 1; }

echo "Signing : $TGZ"
echo "Key     : $PRIV (offline)"

# raw RSA-SHA256 signature -> base64 (single line, no wrapping) so it travels cleanly in an HTTP header
openssl dgst -sha256 -sign "$PRIV" -out "${SIG}.raw" "$TGZ"
base64 -w0 "${SIG}.raw" > "$SIG"
rm -f "${SIG}.raw"
echo "Wrote   : $SIG ($(wc -c < "$SIG") base64 bytes)"

# ---- self-verify against the public key (the SAME bytes embedded in update.php) ----
if [ -f "$PUB" ]; then
  # decode to a real (seekable) file - openssl -signature cannot read a non-seekable pipe/stdin
  VTMP="$(mktemp)"; base64 -d "$SIG" > "$VTMP"
  if openssl dgst -sha256 -verify "$PUB" -signature "$VTMP" "$TGZ" >/dev/null 2>&1; then
    echo "Verify  : OK (signature matches public key — the plugin will accept this release)"
    rm -f "$VTMP"
  else
    rm -f "$VTMP"
    echo "Verify  : FAILED — the .sig does NOT match the public key. Do NOT publish."; exit 2
  fi
else
  echo "Verify  : skipped (public key not found at $PUB)"
fi

echo
echo "DONE. Upload BOTH next to each other in the license server's releases dir:"
echo "   $TGZ"
echo "   $SIG   (served as the X-Smpro-Sig header)"
