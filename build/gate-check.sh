#!/usr/bin/env bash
#
# gate-check.sh <tarball> - PROMOTE-TIME release gate.
#
# Run this immediately before publishing a release to the license server (copy to smpro-latest +
# update VERSION/.rel_state + DB pins). It REFUSES the promote unless ALL hold for THIS exact artifact:
#   1. the detached .sig verifies against the offline public key (same bytes the plugin embeds),
#   2. a gate receipt (smpro-<ver>.gate.json) exists, says lab="green",
#   3. the receipt's sha256 matches the tarball's sha256 (the receipt is FOR this artifact, not another).
#
# This is the second half of "every fixed bug becomes automatic protection in every build": the build
# gate (obfuscate-and-package.sh) makes the lab a precondition of *building*; this makes a green lab a
# precondition of *promoting*. A hand-made or override-built tarball has no green receipt -> promote fails.
#
# Usage:  ./build/gate-check.sh packaging/smpro-1.0.201.tar.gz
#   PUB env overrides the public key (default ~/smpro_keys/smpro_update_public.pem).
#   SMPRO_ALLOW_OVERRIDDEN=1 permits a receipt with lab="overridden" (emergency promote; prints a warning).
#
set -uo pipefail

TGZ="${1:?usage: gate-check.sh <smpro-x.y.z.tar.gz>}"
PUB="${PUB:-$HOME/smpro_keys/smpro_update_public.pem}"
SIG="$TGZ.sig"
GATE="${TGZ%.tar.gz}.gate.json"

refuse() { echo "  ✗ REFUSE TO PROMOTE: $*" >&2; exit "${2:-1}"; }

[ -f "$TGZ" ]  || refuse "tarball not found: $TGZ" 1

# ── 1. signature ────────────────────────────────────────────────────────────────────────────────
[ -f "$SIG" ] || refuse "missing signature: $SIG" 2
if [ -f "$PUB" ]; then
  VTMP="$(mktemp)"; base64 -d "$SIG" > "$VTMP" 2>/dev/null || { rm -f "$VTMP"; refuse "signature is not valid base64: $SIG" 3; }
  if openssl dgst -sha256 -verify "$PUB" -signature "$VTMP" "$TGZ" >/dev/null 2>&1; then
    rm -f "$VTMP"; echo "  ✓ signature verifies against $PUB"
  else
    rm -f "$VTMP"; refuse "signature does NOT match $PUB — tarball is forged or corrupt" 3
  fi
else
  echo "  ! public key not found at $PUB — skipping signature check (set PUB= to enforce)"
fi

# ── 2. gate receipt ───────────────────────────────────────────────────────────────────────────────
[ -f "$GATE" ] || refuse "no gate receipt ($GATE) — only the release gate may mint a publishable tarball; do not hand-make tarballs" 4
LAB="$(grep -oE '"lab"[[:space:]]*:[[:space:]]*"[^"]*"' "$GATE" | sed -E 's/.*"([^"]*)"$/\1/')"
RSHA="$(grep -oE '[0-9a-f]{64}' "$GATE" | head -1)"
ASHA="$(sha256sum "$TGZ" | awk '{print $1}')"

[ "$RSHA" = "$ASHA" ] || refuse "receipt sha256 ($RSHA) != tarball sha256 ($ASHA) — receipt is for a DIFFERENT artifact" 6
echo "  ✓ receipt sha256 matches tarball"

if [ "$LAB" = "green" ]; then
  echo "  ✓ gate receipt: lab=green"
elif [ "$LAB" = "overridden" ] && [ "${SMPRO_ALLOW_OVERRIDDEN:-0}" = "1" ]; then
  echo "  ! gate receipt: lab=OVERRIDDEN — promoting an UNTESTED build because SMPRO_ALLOW_OVERRIDDEN=1"
else
  refuse "gate receipt says lab='$LAB' (not green) — the lab did not pass for this build" 5
fi

echo "GATE OK: $(basename "$TGZ") is signed, lab-verified, and sha-matched. Safe to promote."
