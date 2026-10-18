#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro — WHM re-registration
#
# Run automatically after every deploy (dev or production update) to ensure
# the WHM menu entry and security whitelist are always in sync with the files.
#
# Idempotent: safe to call multiple times.
# Survives cPanel upcp: writes /var/cpanel/apps/ AND calls rebuild_whm_chrome.
#
# Usage:
#   bash /path/to/cgi/addons/smpro/bin/register.sh
#   bash /path/to/cgi/addons/smprov1/bin/register.sh   (dev/test build)
###############################################################################
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
ADDON_NAME="$(basename "$PLUGIN_DIR")"   # "smpro" on production, "smprov1" on test

ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*" >&2; }

# Display name: read from the plugin or fall back to a sensible default
DISPLAY_NAME="Safety Monitor Pro"
[ "$ADDON_NAME" = "smprov1" ] && DISPLAY_NAME="Safety Monitor Pro DEV"

# --- 1. Write appconfig file in the correct WHM format (name=, NOT appname=) --
# Both register_appconfig and /var/cpanel/apps/ expect the SAME format.
APPCONFIG="${PLUGIN_DIR}/${ADDON_NAME}.appconfig"
cat > "$APPCONFIG" << EOF
name=${ADDON_NAME}
service=whostmgr
user=root
acls=all
displayname=${DISPLAY_NAME}
url=/cgi/addons/${ADDON_NAME}/index.cgi
entryurl=addons/${ADDON_NAME}/index.cgi
target=_self
searchtext=safety monitor pro security forensics login account audit spam phishing php harden notifications hardware disk imunify firewall backup
EOF

# --- 2. Register with AppConfig (security whitelist) -------------------------
REG="/usr/local/cpanel/bin/register_appconfig"
if [ -x "$REG" ]; then
  if "$REG" "$APPCONFIG" >/dev/null 2>&1; then
    ok "AppConfig registered: ${ADDON_NAME}"
  else
    warn "register_appconfig returned non-zero — may already be registered (harmless)"
  fi
else
  warn "register_appconfig not found"
fi

# --- 3. Always write /var/cpanel/apps/ in the correct WHM tile format ---------
# register_appconfig sometimes writes its own version; we overwrite to ensure
# the correct format (with name=, not appname=) is what WHM reads.
APPS_DIR="/var/cpanel/apps"
if [ -d "$APPS_DIR" ]; then
  cp -f "$APPCONFIG" "${APPS_DIR}/${ADDON_NAME}.conf"
  chmod 0600 "${APPS_DIR}/${ADDON_NAME}.conf"
  ok "WHM tile written: ${APPS_DIR}/${ADDON_NAME}.conf"
else
  warn "/var/cpanel/apps not found — is this a cPanel server?"
fi

# --- 4. Rebuild WHM navigation (NON-disruptive: no service restart) -----------
if [ -x /usr/local/cpanel/scripts/rebuild_whm_chrome ]; then
  /usr/local/cpanel/scripts/rebuild_whm_chrome >/dev/null 2>&1 \
    && ok "WHM navigation rebuilt — link visible immediately (no re-login needed)" \
    || warn "rebuild_whm_chrome failed (non-fatal — re-login to WHM will show the link)"
fi

# --- 5. Sync appconfig apps list ---------------------------------------------
if [ -x /usr/local/cpanel/bin/update_appconfig_apps ]; then
  /usr/local/cpanel/bin/update_appconfig_apps >/dev/null 2>&1 || true
fi

ok "Done — ${DISPLAY_NAME} is registered in WHM › Plugins"
