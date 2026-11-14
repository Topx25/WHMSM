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

# what would stay enforcing with nothing left to manage it comes down first, while the plugin's code is still here
PHPBIN=/usr/local/cpanel/3rdparty/bin/php; [ -x "$PHPBIN" ] || PHPBIN="$(command -v php || true)"
if [ -n "$PHPBIN" ] && [ -f "$DEST/bin/teardown.php" ]; then
  say "Taking down the country wall and this product's firewall hooks"
  "$PHPBIN" "$DEST/bin/teardown.php" 2>/dev/null | sed 's/^/    /' || echo "    (could not run - check the firewall for rules tagged smpro before a restart)"
fi

say "Unregistering from WHM"
[ -x /usr/local/cpanel/bin/unregister_appconfig ] && /usr/local/cpanel/bin/unregister_appconfig "$PLUGIN" 2>/dev/null && ok "Unregistered" || true

say "Removing plugin files"
rm -rf "$DEST" && ok "Removed ${DEST}"

# crons this plugin may have installed (hub / update / login-guard / notify / tgbot / cooler / ...)
rm -f /etc/cron.d/${PLUGIN}-* 2>/dev/null && ok "Removed crons" || true

if [ "$PURGE" = "1" ]; then
  say "Purging data + logs"
  # what cannot be recreated is moved aside first: the only copies of quarantined customer files, the backups
  # taken before a fix, and the book that says how to undo an emergency clean-up
  KEEP="/var/lib/${PLUGIN}-keep"; STAMP="$(date +%Y%m%d_%H%M%S)"
  for item in quarantine backups detections emergency.json learn php_harden; do
    if [ -e "$DATA/$item" ]; then mkdir -p "$KEEP" && chmod 700 "$KEEP" && mv "$DATA/$item" "$KEEP/${item}.${STAMP}" 2>/dev/null && echo "    kept: $KEEP/${item}.${STAMP}"; fi
  done
  rm -rf "$DATA" "$LOGDIR" && ok "Removed ${DATA} and ${LOGDIR}"
  echo "    (Detection backups under /home/backup/detections were KEPT for safety.)"
else
  echo "    Data kept at ${DATA} (re-run with --purge to remove)."
fi
ok "Uninstall complete."
