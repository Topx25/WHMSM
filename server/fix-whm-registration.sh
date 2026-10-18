#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro — fix WHM registration on ALL servers
#
# Self-contained: does NOT require register.sh to exist on the server.
# Finds every active smpro* installation (skips .bak dirs), re-registers,
# and rebuilds the WHM nav.
#
# Usage:
#   bash fix-whm-registration.sh           (fix all: test + dc2)
#   bash fix-whm-registration.sh test      (test server only)
#   bash fix-whm-registration.sh dc2       (dc2 only)
###############################################################################

# Inline fix — runs entirely on the remote server, no register.sh needed
read -r -d '' FIX << 'REMOTE'
ADDONS=/usr/local/cpanel/whostmgr/docroot/cgi/addons
APPS=/var/cpanel/apps
APPCONFIG_BIN=/usr/local/cpanel/bin/register_appconfig
NAV_REBUILD=/usr/local/cpanel/scripts/rebuild_whm_chrome

ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }

fixed=0
for d in "$ADDONS"/smpro*/; do
  name="$(basename "$d")"
  # skip backup dirs and dirs without plugin files
  [[ "$name" =~ \.bak ]] && continue
  [[ ! -f "$d/index.php" ]]  && continue

  # determine display name
  dn="Safety Monitor Pro"
  [[ "$name" == *"v1"* ]] && dn="Safety Monitor Pro DEV"

  # write /var/cpanel/apps/ conf (WHM tile + appconfig format = same)
  cat > "$APPS/$name.conf" << EOF
name=$name
service=whostmgr
user=root
acls=any
displayname=$dn
url=/cgi/addons/$name/index.cgi
entryurl=addons/$name/index.cgi
target=_self
searchtext=safety monitor pro security forensics login account audit spam phishing php harden notifications hardware disk imunify firewall backup
EOF
  chmod 0600 "$APPS/$name.conf"

  # register with AppConfig whitelist
  if [ -x "$APPCONFIG_BIN" ]; then
    "$APPCONFIG_BIN" "$APPS/$name.conf" >/dev/null 2>&1 || true
  fi

  # also update bin/register.sh if the bin/ dir exists (keeps it in sync)
  if [ -d "${d}bin" ]; then
    cp -f "$APPS/$name.conf" "${d}bin/.last_reg_conf" 2>/dev/null || true
  fi

  ok "Registered: $name → /cgi/addons/$name/index.cgi ($dn)"
  (( fixed++ )) || true
done

[ "$fixed" -eq 0 ] && warn "No active smpro* installations found in $ADDONS"

# rebuild WHM nav once after all registrations
[ -x "$NAV_REBUILD" ] && "$NAV_REBUILD" >/dev/null 2>&1 \
  && ok "WHM navigation rebuilt — visible immediately (no re-login needed)" \
  || warn "rebuild_whm_chrome not found (re-login to WHM to see the links)"

[ -x /usr/local/cpanel/bin/update_appconfig_apps ] \
  && /usr/local/cpanel/bin/update_appconfig_apps >/dev/null 2>&1 || true
REMOTE

run_on() {
  local label="$1"; shift
  echo
  printf '\033[1;36m%s\033[0m\n' "══════════════════════════════════════════════"
  printf '\033[1;36m  %s\033[0m\n' "$label"
  printf '\033[1;36m%s\033[0m\n' "══════════════════════════════════════════════"
  ssh "$@" bash <<< "$FIX"
}

TARGET="${1:-all}"

[[ "$TARGET" == "all" || "$TARGET" == "test" ]] && \
  run_on "Test server  (167.233.29.168)" \
    -i ~/.ssh/cpanel_audit_178_63_134_16 root@167.233.29.168

[[ "$TARGET" == "all" || "$TARGET" == "dc2" ]] && \
  run_on "dc2  (dc2.efadh.com:2245)" \
    -i ~/.ssh/smprov1_key -p 2245 root@dc2.efadh.com

echo
echo "Done."
