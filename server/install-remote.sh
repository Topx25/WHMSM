#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro — license-gated remote installer.
#
# The plugin is NEVER downloadable without a valid license that is ACTIVE and
# bound to THIS server's IP + hostname + hardware fingerprint. This bootstrapper
# proves the server's identity to the license server (plugins.iptvpro.org), which
# only then streams the plugin tarball and runs its installer.
#
# Usage (any ONE of):
#   curl -fsSL https://plugins.iptvpro.org/install.sh | bash -s -- <LICENSE_KEY>
#   SMPRO_LICENSE_KEY=XXXX-XXXX bash install.sh
#   bash install.sh <LICENSE_KEY>
###############################################################################
set -uo pipefail

API="https://dl.iptvpro.org/api/download"   # direct download host (bypasses Cloudflare bot challenge)
# The license server sits behind Cloudflare, whose managed bot-challenge 403s plain
# curl/library agents. Send the same browser UA the plugin uses (legitimate client id).
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SafetyMonitorPro/installer"

red(){ printf '\033[1;31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
cya(){ printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die(){ red "  ✗ $*" >&2; exit 1; }

# --- requirements ----------------------------------------------------------
[ "$(id -u)" = "0" ]    || die "Run as root:  sudo bash install.sh <LICENSE_KEY>"
[ -d /usr/local/cpanel ] || die "cPanel/WHM not found at /usr/local/cpanel — this is a WHM plugin."
command -v curl >/dev/null 2>&1 || die "curl is required (install it: 'dnf install curl' / 'apt install curl')."

PHP=/usr/local/cpanel/3rdparty/bin/php
[ -x "$PHP" ] || PHP="$(command -v php 2>/dev/null || true)"
[ -x "$PHP" ] || die "PHP not found."

# --- license key -----------------------------------------------------------
LICENSE_KEY="${1:-${SMPRO_LICENSE_KEY:-}}"
if [ -z "$LICENSE_KEY" ] && [ -t 0 ]; then
  read -rp "Enter your Safety Monitor Pro license key: " LICENSE_KEY
fi
[ -n "$LICENSE_KEY" ] || die "No license key. Usage: bash install.sh <LICENSE_KEY>"

# --- server identity (computed EXACTLY like the plugin so the binding matches) ---
FP="$("$PHP" -r '$m="";foreach(["/etc/machine-id","/var/lib/dbus/machine-id"] as $f){if(is_readable($f)){$m=trim(file_get_contents($f));if($m!=="")break;}}if($m==="")$m=trim((string)shell_exec("hostid 2>/dev/null")).php_uname("n");echo hash("sha256",$m."|".php_uname("n")."|smprov1");')"   # fixed salt (matches SMPRO_LIC_FP_SALT) — slug-independent
HOST_N="$("$PHP" -r 'echo php_uname("n");')"
SERVER_IP="$(cat /var/cpanel/mainip 2>/dev/null || true)"
[ -n "$SERVER_IP" ] || SERVER_IP="$(cat /var/cpanel/mainserverip 2>/dev/null || true)"
[ -n "$SERVER_IP" ] || SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$FP" ]        || die "Could not compute the server fingerprint."
[ -n "$SERVER_IP" ] || die "Could not determine the server IP."

cya "Verifying license for ${HOST_N} (${SERVER_IP}) …"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
TARBALL="$TMP/smpro.tar.gz"; HDRS="$TMP/headers.txt"

BODY="$("$PHP" -r 'echo json_encode(["license_key"=>$argv[1],"server_ip"=>$argv[2],"hostname"=>$argv[3],"fingerprint"=>$argv[4],"plugin_version"=>"installer"]);' "$LICENSE_KEY" "$SERVER_IP" "$HOST_N" "$FP")"

HTTP="$(curl -sS --max-time 180 -o "$TARBALL" -D "$HDRS" -w '%{http_code}' \
        -A "$UA" -H 'Content-Type: application/json' -H 'Accept: application/json' \
        -X POST --data "$BODY" "$API" 2>"$TMP/curl.err" || true)"

# A rejected license comes back as JSON (ok:false). A valid one streams a gzip tarball.
CT="$(grep -i '^content-type:' "$HDRS" 2>/dev/null | tail -1)"
if echo "$CT" | grep -qi 'application/json' || { [ -s "$TARBALL" ] && head -c1 "$TARBALL" | grep -q '{'; }; then
  MSG="$("$PHP" -r '$j=json_decode(@file_get_contents($argv[1]),true);if(!is_array($j)){echo "";exit;}echo ($j["message"]??"License check failed").(isset($j["status"])?" [".$j["status"]."]":"");' "$TARBALL" 2>/dev/null)"
  die "License rejected: ${MSG:-unknown error (HTTP $HTTP)}"
fi
[ "$HTTP" = "200" ] || die "Download failed (HTTP ${HTTP}). $(cat "$TMP/curl.err" 2>/dev/null)"
[ -s "$TARBALL" ]   || die "Empty download."
gzip -t "$TARBALL" 2>/dev/null || die "Downloaded file is not a valid archive."

# integrity: verify the SHA-256 the server advertised (defends against a corrupted/truncated transfer)
WANT_SHA="$(grep -i '^x-smpro-sha256:' "$HDRS" 2>/dev/null | tail -1 | tr -d '\r' | awk '{print $2}')"
if [ -n "$WANT_SHA" ] && command -v sha256sum >/dev/null 2>&1; then
  GOT_SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
  [ "$WANT_SHA" = "$GOT_SHA" ] || die "Integrity check FAILED (sha256 mismatch) — download corrupted, please retry."
fi

VER="$(grep -i '^x-smpro-version:' "$HDRS" 2>/dev/null | tail -1 | tr -d '\r' | awk '{print $2}')"
grn "  ✓ License valid — downloaded $(du -h "$TARBALL" | cut -f1)${VER:+ (v$VER)}"

cya "Installing …"
mkdir -p "$TMP/x"
tar -xzf "$TARBALL" -C "$TMP/x" || die "Could not extract the package."
ROOT="$(find "$TMP/x" -maxdepth 2 -name install.sh -printf '%h\n' 2>/dev/null | head -1)"
[ -n "$ROOT" ] || die "install.sh not found inside the package."
bash "$ROOT/install.sh"

# pre-activate: seed the verified license key so the plugin is licensed WITHOUT manual entry.
# The plugin validates it against the license server on first open and stores the signed state.
LIC_DIR="/var/lib/smpro/license"
if mkdir -p "$LIC_DIR" 2>/dev/null; then
  printf '{"key":"%s"}\n' "$LICENSE_KEY" > "$LIC_DIR/state.json" && chmod 0600 "$LIC_DIR/state.json" 2>/dev/null \
    && grn "  ✓ License activated automatically (key seeded — no manual entry needed)."
fi

grn "Done. Open WHM › Plugins › Safety Monitor Pro."
