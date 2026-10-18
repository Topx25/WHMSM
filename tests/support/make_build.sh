#!/bin/sh
# make_build.sh — (re)generate tests/.build: a harness copy of the plugin source where the two
# PINNED RSA public keys are made re-definable, so a crypto test can inject a TEST public key
# (matching a TEST private key it signs fixtures with) BEFORE requiring the include. The real
# source's `define('SMPRO_LIC_PUBKEY',...)` has no guard, so without this a test could not
# substitute a test key. Nothing else is altered, so behavior under test is the real code.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/tests/.build"
rm -rf "$BUILD"
mkdir -p "$BUILD"
for d in includes modules bin lang; do [ -d "$ROOT/$d" ] && cp -a "$ROOT/$d" "$BUILD/"; done
[ -f "$ROOT/index.php" ]      && cp -a "$ROOT/index.php" "$BUILD/"
[ -f "$ROOT/integrity.json" ] && cp -a "$ROOT/integrity.json" "$BUILD/"

# make the pinned pubkey defines re-definable (test injects a TEST key before require)
[ -f "$BUILD/includes/license.php" ] && sed -i "s/^define('SMPRO_LIC_PUBKEY',/if(!defined('SMPRO_LIC_PUBKEY'))define('SMPRO_LIC_PUBKEY',/" "$BUILD/includes/license.php"
[ -f "$BUILD/includes/update.php" ]  && sed -i "s/^define('SMPRO_UPD_PUBKEY',/if(!defined('SMPRO_UPD_PUBKEY'))define('SMPRO_UPD_PUBKEY',/"  "$BUILD/includes/update.php"

# Neutralize side-effecting SEAM callees so a test's stubfns provides the real NAME. We RENAME the
# real definition to a dead name (a function DECLARATION can't be an unbraced `if` body, so the
# if(!function_exists) trick is only valid for the define() calls above). Internal callers still use
# the original name -> they hit the stub. Any test requiring .build/includes/helpers.php MUST call
# smpro_test_install_stubs() first (it defines ALL of these). Only seams that tests stub are listed
# (NOT smpro_lic_server_ip/fingerprint — the license crypto test needs those REAL).
SEAMS="smpro_ip_intel smpro_ip_is_datacenter smpro_server_ips smpro_is_server_ip"
for fn in $SEAMS; do
  for f in "$BUILD"/includes/*.php; do
    [ -f "$f" ] && sed -i "s/^function $fn(/function _smpro_disabled_$fn(/" "$f"
  done
done

echo ".build ready: $BUILD"
