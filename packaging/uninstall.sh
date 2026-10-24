#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro (smpro) - uninstaller
# Removes the plugin + WHM registration. Keeps data (/var/lib/smpro) unless
# you pass --purge. Never touches customer accounts or the legacy safety_monitor.
#
# Usage:   sudo bash uninstall.sh            # remove plugin, keep data
#          sudo bash uninstall.sh --purge    # also remove data, logs, crons
###############################################################################
set -euo pipefail

PLUGIN="smpro"
DEST="/usr/local/cpanel/whostmgr/docroot/cgi/addons/${PLUGIN}"
DATA="/var/lib/${PLUGIN}"
LOGDIR="/var/log/${PLUGIN}"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "Run as root."; exit 1; }

say "Unregistering from WHM"
[ -x /usr/local/cpanel/bin/unregister_appconfig ] && /usr/local/cpanel/bin/unregister_appconfig "$PLUGIN" 2>/dev/null && ok "Unregistered" || true

say "Removing plugin files"
rm -rf "$DEST" && ok "Removed ${DEST}"

# crons this plugin may have installed (hub / update / login-guard / notify / tgbot / cooler / ...)
rm -f /etc/cron.d/${PLUGIN}-* 2>/dev/null && ok "Removed crons" || true

if [ "$PURGE" = "1" ]; then
  say "Purging data + logs"
  rm -rf "$DATA" "$LOGDIR" && ok "Removed ${DATA} and ${LOGDIR}"
  echo "    (Detection backups under /home/backup/detections were KEPT for safety.)"
else
  echo "    Data kept at ${DATA} (re-run with --purge to remove)."
fi
ok "Uninstall complete."
