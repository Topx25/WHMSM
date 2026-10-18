#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro — unified deploy pipeline
#
# Flow: local build → test server (verify) → dc2 production
#
# Usage:
#   bash deploy.sh test          # deploy raw build to test server
#   bash deploy.sh dc2           # deploy obfuscated build to dc2
#   bash deploy.sh all           # test first, then dc2 (with confirmation)
###############################################################################
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$SCRIPT_DIR")"

# ── server config ─────────────────────────────────────────────────────────────
TEST_HOST="167.233.29.168"
TEST_KEY="$HOME/.ssh/cpanel_audit_178_63_134_16"
TEST_PORT="22"
TEST_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/addons/smprov1"

DC2_HOST="dc2.efadh.com"
DC2_KEY="$HOME/.ssh/smprov1_key"
DC2_PORT="2245"
DC2_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro"
# ──────────────────────────────────────────────────────────────────────────────

grn() { printf '\033[1;32m  ✓  %s\033[0m\n' "$*"; }
red() { printf '\033[1;31m  ✗  %s\033[0m\n' "$*" >&2; }
cya() { printf '\033[1;36m═══  %s\033[0m\n' "$*"; }
ask() { read -rp "$(printf '\033[1;33m  ?  %s [y/N]: \033[0m' "$1")" r; [[ "$r" =~ ^[Yy]$ ]]; }

deploy_to() {
  local label="$1" key="$2" port="$3" host="$4" dest="$5" raw="$6"
  cya "Deploying → $label  ($host)"

  local ssh_opts=(-i "$key" -p "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=10)

  # verify connectivity
  ssh "${ssh_opts[@]}" "root@$host" "echo ok" >/dev/null 2>&1 \
    || { red "Cannot connect to $host:$port"; return 1; }

  # push files
  cd "$BUILD_DIR"
  if [ "$raw" = "1" ]; then
    # raw (non-obfuscated) build → test server
    tar czf - index.cgi index.php includes modules lang assets bin \
      | ssh "${ssh_opts[@]}" "root@$host" "tar xzf - -C $dest"
  else
    # obfuscated build → production
    OBF_DIR="$BUILD_DIR/_obf"
    if [ ! -d "$OBF_DIR" ]; then
      red "Obfuscated build not found at $_obf — run build/obfuscate-and-package.sh first"
      return 1
    fi
    tar czf - -C "$OBF_DIR" . \
      | ssh "${ssh_opts[@]}" "root@$host" "tar xzf - -C $dest"
  fi
  grn "Files transferred"

  # re-register WHM (self-contained, no dependency on register.sh)
  ssh "${ssh_opts[@]}" "root@$host" bash << REMOTE
name="\$(basename $dest)"
dn="Safety Monitor Pro"
[[ "\$name" == *v1* ]] && dn="Safety Monitor Pro DEV"
cat > /var/cpanel/apps/\$name.conf << EOF
name=\$name
service=whostmgr
user=root
acls=any
displayname=\$dn
url=/cgi/addons/\$name/index.cgi
entryurl=addons/\$name/index.cgi
target=_self
searchtext=safety monitor pro security forensics login account audit spam phishing php harden notifications hardware disk imunify firewall backup
EOF
chmod 0600 /var/cpanel/apps/\$name.conf
REG=/usr/local/cpanel/bin/register_appconfig
[ -x "\$REG" ] && "\$REG" /var/cpanel/apps/\$name.conf >/dev/null 2>&1
[ -x /usr/local/cpanel/scripts/rebuild_whm_chrome ] && /usr/local/cpanel/scripts/rebuild_whm_chrome >/dev/null 2>&1
echo "WHM registered: \$name"
REMOTE
  grn "WHM registration refreshed"

  # verify: check version on server matches local
  local local_ver
  local_ver=$(grep "SMPRO_VERSION" "$BUILD_DIR/includes/defines.php" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
  local remote_ver
  remote_ver=$(ssh "${ssh_opts[@]}" "root@$host" \
    "grep -oE '[0-9]+\.[0-9]+\.[0-9]+' $dest/includes/defines.php 2>/dev/null | head -1" 2>/dev/null || true)
  if [ "$local_ver" = "$remote_ver" ]; then
    grn "Version verified: v$remote_ver on $host"
  else
    red "Version mismatch — local=$local_ver remote=$remote_ver"
  fi

  echo
}

TARGET="${1:-test}"

case "$TARGET" in
  test)
    deploy_to "Test server" "$TEST_KEY" "$TEST_PORT" "$TEST_HOST" "$TEST_DIR" "1"
    ;;
  dc2)
    cya "Deploying to PRODUCTION (dc2)"
    echo "  This will update the LIVE plugin on dc2.efadh.com."
    ask "Are you sure?" || { echo "  Cancelled."; exit 0; }
    deploy_to "dc2 PRODUCTION" "$DC2_KEY" "$DC2_PORT" "$DC2_HOST" "$DC2_DIR" "0"
    ;;
  all)
    deploy_to "Test server" "$TEST_KEY" "$TEST_PORT" "$TEST_HOST" "$TEST_DIR" "1"
    echo
    cya "Test deploy complete. Push to production?"
    ask "Deploy to dc2 now?" && \
      deploy_to "dc2 PRODUCTION" "$DC2_KEY" "$DC2_PORT" "$DC2_HOST" "$DC2_DIR" "0" \
      || echo "  Skipped dc2. Run 'bash deploy.sh dc2' when ready."
    ;;
  *)
    echo "Usage: $0 [test|dc2|all]"
    exit 1
    ;;
esac

echo; grn "Done."
