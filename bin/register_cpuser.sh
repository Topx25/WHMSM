#!/usr/bin/env bash
###############################################################################
# Site Protection — install/refresh the ACCOUNT-SIDE plugin (what the customer
# opens inside cPanel).
#
# Called automatically from bin/register.sh, which runs after every deploy and
# self-update. There is deliberately no manual install step: a licensee updates
# the WHM plugin and the page appears in their customers' cPanel, the same way
# the WHM entry re-asserts itself.
#
# It goes through cPanel's OWN installer (scripts/install_plugin) rather than
# writing theme files and a dynamicui conf directly. Writing them directly does
# make the icon appear, which is exactly what makes it a trap: it skips feature
# registration, so the host gets no entry in Feature Manager and cannot turn the
# section off for a package. A protection page that cannot be withheld from a
# package is not something a host can sell around. install_plugin also survives
# cPanel's own theme housekeeping, which a hand-written conf does not.
#
# Idempotent: re-installing overwrites, so running it twice changes nothing, and
# running it after an upcp that dropped theme files puts them back.
###############################################################################
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="${PLUGIN_DIR}/cpuser"

ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*" >&2; }

# Identity comes from the plugin's own constants — read by asking PHP, not by
# reading the file as text.
#
# This used to sed the define() out of includes/defines.php, which worked on the
# source and failed on every real installation: the shipped file is obfuscated,
# so the value is stored as escaped hex inside double quotes and the pattern
# matched nothing. The script then refused to install and said the constant was
# "not found", which points at the wrong thing entirely — the constant is there,
# it just is not spelled the way a text search expects. PHP has no such problem:
# it executes the obfuscated file and hands back the value.
PHP_BIN=""
for C in /usr/local/cpanel/3rdparty/bin/php $(ls -1 /opt/cpanel/ea-php*/root/usr/bin/php 2>/dev/null | sort -r) php; do
  if command -v "$C" >/dev/null 2>&1 || [ -x "$C" ]; then PHP_BIN="$C"; break; fi
done
if [ -z "$PHP_BIN" ]; then
  warn "no PHP interpreter found, so the plugin's own name could not be read — account-side plugin NOT installed."
  exit 1
fi

read_define() {
  "$PHP_BIN" -r "define('SMPRO_BOOT',1); require '${PLUGIN_DIR}/includes/defines.php'; echo defined('$1') ? constant('$1') : '';" 2>/dev/null
}
SLUG="$(read_define SMPRO_CPS_SLUG)"
NAME="$(read_define SMPRO_CPS_NAME)"
GROUP="$(read_define SMPRO_CPS_GROUP)"

[ -n "$SLUG" ] || { warn "SMPRO_CPS_SLUG came back empty from ${PLUGIN_DIR}/includes/defines.php — account-side plugin NOT installed."; exit 1; }
[ -n "$NAME" ]  || NAME="Site Protection"
[ -n "$GROUP" ] || GROUP="security"

# cPanel's group vocabulary for a plugin is a fixed short list (mail|logs|files|
# domains|db|sec|software|pref|advanced). "security" is the modern theme's
# section name and is NOT accepted here, so it is translated rather than passed
# through to be silently dropped into the wrong section.
# group_id is the theme's own section id (the same values cPanel's own entries
# use: files, databases, domains, email, metrics, security, software, advanced,
# preferences). An unknown id does not error — the entry lands in a section the
# customer is not looking in, which is worse, so it is checked here.
case "$GROUP" in
  files|databases|domains|email|metrics|security|software|advanced|preferences) : ;;
  sec) GROUP="security" ;;
  *) warn "group '${GROUP}' is not a cPanel section id — using 'security'"; GROUP="security" ;;
esac

[ -d "$SRC_DIR" ] || { warn "${SRC_DIR} is missing — account-side plugin NOT installed."; exit 1; }
[ -f "${SRC_DIR}/index.live.php" ] || { warn "cpuser/index.live.php missing — NOT installed."; exit 1; }
[ -f "${SRC_DIR}/stack.php" ] || { warn "cpuser/stack.php missing (generated at build time) — NOT installed."; exit 1; }

# --- OFF until the host asks for it -----------------------------------------
# This is the one part of the product that puts something in front of somebody
# else's customers. Appearing in every account's cPanel because the server took
# a routine update is not a decision an update should make on a host's behalf —
# they may not sell this, may not want to answer questions about it, or may want
# to introduce it themselves. So the update always brings the files and never
# switches them on: enabling it is one click in WHM, and after that everything
# here happens automatically on every update, with no per-server install step.
ENABLE_FLAG="/var/lib/smpro/cpuser_enabled"
if [ ! -f "$ENABLE_FLAG" ]; then
  # Switched off. If it was on before, take it back out rather than leaving a
  # page in customers' cPanel that the host believes they turned off.
  SLUG_OFF="$SLUG"
  for THEME_DIR in /usr/local/cpanel/base/frontend/*; do
    [ -d "${THEME_DIR}/${SLUG_OFF}" ] || [ -f "${THEME_DIR}/dynamicui/dynamicui_${SLUG_OFF}.conf" ] || continue
    rm -rf "${THEME_DIR}/${SLUG_OFF}" "${THEME_DIR}/dynamicui/dynamicui_${SLUG_OFF}.conf" 2>/dev/null
    ok "removed from theme $(basename "$THEME_DIR") — it is switched off for this server"
  done
  printf '  · %s
' "account-side plugin is off on this server — enable it in WHM › Plugin Control"
  exit 0
fi

# --- retire the standalone Safety Lock, if this server carries one -----------
# Some servers already run a separate Safety Lock plugin under 3rdparty/. This
# replaces it: same name, same place in cPanel, so a customer who used the old
# one finds it where they left it. Leaving both installed is the one outcome to
# avoid — two tools setting and clearing the SAME immutable bits, each reporting
# the other's work as tampering, and a customer unlocking in one while the other
# locks again.
#
# It is somebody's installed software, so it is archived before it is removed and
# the archive path is printed. Nothing it did to the customer's FILES is undone:
# files it locked stay locked, and this plugin manages them from here.
LEGACY_DIR="/usr/local/cpanel/base/3rdparty/safetylock"
if [ -d "$LEGACY_DIR" ] && [ ! -L "$LEGACY_DIR" ]; then
  BK="/var/lib/smpro/backups"
  mkdir -p "$BK"
  STAMP="$(date +%Y%m%d_%H%M%S)"
  ARCH="${BK}/legacy_safetylock_${STAMP}.tar.gz"
  if tar czf "$ARCH" -C /usr/local/cpanel/base/3rdparty safetylock 2>/dev/null && [ -s "$ARCH" ]; then
    rm -rf "$LEGACY_DIR"
    if [ -d "$LEGACY_DIR" ]; then
      warn "the previous Safety Lock could not be removed from ${LEGACY_DIR} — BOTH are now installed, which will make them fight over the same file locks. Remove it by hand."
    else
      ok "previous Safety Lock removed (archived to ${ARCH})"
    fi
    # Its cPanel entries, wherever they were registered.
    for THEME_DIR in /usr/local/cpanel/base/frontend/*; do
      for C in "${THEME_DIR}/dynamicui/dynamicui_safetylock.conf"; do
        [ -f "$C" ] || continue
        grep -q '3rdparty/safetylock' "$C" 2>/dev/null && rm -f "$C" && ok "removed its old cPanel entry in $(basename "$THEME_DIR")"
      done
    done
  else
    # No archive, no deletion. Removing software with no way back is not something
    # to do quietly because a tar happened to fail.
    rm -f "$ARCH" 2>/dev/null
    warn "could not archive the previous Safety Lock, so it was LEFT IN PLACE. Both may now appear in cPanel."
  fi
fi

INSTALLER="/usr/local/cpanel/scripts/install_plugin"
[ -x "$INSTALLER" ] || { warn "$INSTALLER not found — is this a cPanel server? Account-side plugin NOT installed."; exit 1; }

# --- build the archive cPanel expects: <slug>/ + <slug>.cpanelplugin ---------
WORK="$(mktemp -d /tmp/sp_plugin.XXXXXX)" || { warn "could not create a temporary directory"; exit 1; }
trap 'rm -rf "$WORK"' EXIT

mkdir -p "${WORK}/${SLUG}"
# The icon is not PHP. Copying only *.php left the cPanel entry with no icon at all - the build takes care
# to ship the svg precisely because obfuscation never sees a non-PHP file, and then this step dropped it.
cp -f "${SRC_DIR}"/*.php "${WORK}/${SLUG}/" || { warn "could not stage the plugin files"; exit 1; }
cp -f "${SRC_DIR}"/*.svg "${WORK}/${SLUG}/" 2>/dev/null || true
cp -f "${SRC_DIR}/${SLUG}.svg" "${WORK}/" 2>/dev/null || { warn "the icon ${SLUG}.svg is missing — cPanel refuses an entry without one."; exit 1; }
chmod 0644 "${WORK}/${SLUG}"/*.php "${WORK}/${SLUG}.svg"

# cPanel's installer reads install.json. The legacy .cpanelplugin format still
# has a sample file shipped beside it, which is a trap: install_plugin refuses an
# archive without install.json, and it announces that through a buffered print
# followed by POSIX::_exit — which never flushes. So the archive comes back as a
# bare "exit 1" with no message at all, and the natural conclusion is that the
# files are wrong rather than the manifest is missing.
#
# "icon" is REQUIRED and cPanel says so only in its own error_log, never on the
# terminal — the command just exits 1 in silence. A link entry accepts SVG or PNG.
#
# "featuremanager": true is the line that gives the host a per-package switch.
cat > "${WORK}/install.json" << EOF
[
  {
    "id": "${SLUG}",
    "name": "${NAME}",
    "icon": "${SLUG}.svg",
    "group_id": "${GROUP}",
    "order": "1",
    "type": "link",
    "featuremanager": true,
    "uri": "${SLUG}/index.live.php",
    "target": "_self"
  }
]
EOF

ARCHIVE="${WORK}/${SLUG}.tar.gz"
tar czf "$ARCHIVE" -C "$WORK" "${SLUG}" install.json "${SLUG}.svg" || { warn "could not build the plugin archive"; exit 1; }

# --- install into every theme on the server ---------------------------------
# A server can carry more than one theme, and a customer on the theme we skipped
# would simply never see the page.
# Two halves, and both are needed. install_plugin registers the ENTRY — the icon,
# the section, and the Feature Manager switch — but it does NOT carry the plugin's
# own code anywhere: a plugin is expected to place its files itself and point the
# manifest at them. Run only the installer and the icon appears while the page
# behind it 404s, which is the worst of the two failures because it looks installed.
INSTALLED=0
for THEME_DIR in /usr/local/cpanel/base/frontend/*; do
  [ -d "$THEME_DIR" ] || continue
  THEME="$(basename "$THEME_DIR")"

  DEST="${THEME_DIR}/${SLUG}"
  if ! mkdir -p "$DEST" || ! cp -f "${SRC_DIR}"/*.php "$DEST"/ 2>/dev/null; then
    warn "theme ${THEME}: could not place the page files — skipping"
    continue
  fi
  cp -f "${SRC_DIR}"/*.svg "$DEST"/ 2>/dev/null || true
  chmod 0644 "$DEST"/*.php 2>/dev/null
  chmod 0644 "$DEST"/*.svg 2>/dev/null

  if OUT="$("$INSTALLER" "$ARCHIVE" --theme "$THEME" 2>&1)"; then
    INSTALLED=$((INSTALLED+1))
    ok "installed into theme ${THEME}"
  else
    warn "theme ${THEME}: registration failed${OUT:+: $OUT} (see /usr/local/cpanel/logs/error_log)"
  fi
done

if [ "$INSTALLED" -eq 0 ]; then
  warn "${NAME} installed into NO theme — customers will not see it."
  exit 1
fi

# The feature defaults to enabled for existing packages only if cPanel is told to
# do so; without this an installed plugin can stay invisible to every account.
if [ -x /usr/local/cpanel/bin/ensure_autoenabled_features ]; then
  /usr/local/cpanel/bin/ensure_autoenabled_features >/dev/null 2>&1 || true
fi
if [ -x /usr/local/cpanel/bin/refresh_plugin_cache ]; then
  /usr/local/cpanel/bin/refresh_plugin_cache >/dev/null 2>&1 || true
fi

# --- prove it, rather than trusting the installer's exit code ----------------
# Check the two halves separately, because "the page is there" and "the customer
# can reach it" fail independently and each alone is useless.
VERIFIED=0; PAGE_ONLY=0; ENTRY_ONLY=0
for THEME_DIR in /usr/local/cpanel/base/frontend/*; do
  [ -d "$THEME_DIR" ] || continue
  HAS_PAGE=0; HAS_ENTRY=0
  [ -f "${THEME_DIR}/${SLUG}/index.live.php" ] && [ -f "${THEME_DIR}/${SLUG}/stack.php" ] && HAS_PAGE=1
  [ -f "${THEME_DIR}/dynamicui/dynamicui_${SLUG}.conf" ] && HAS_ENTRY=1
  if [ "$HAS_PAGE" = 1 ] && [ "$HAS_ENTRY" = 1 ]; then VERIFIED=$((VERIFIED+1))
  elif [ "$HAS_PAGE" = 1 ]; then PAGE_ONLY=$((PAGE_ONLY+1))
  elif [ "$HAS_ENTRY" = 1 ]; then ENTRY_ONLY=$((ENTRY_ONLY+1))
  fi
done
[ "$PAGE_ONLY"  -gt 0 ] && warn "${PAGE_ONLY} theme(s) have the page but no cPanel entry — nobody can reach it there."
[ "$ENTRY_ONLY" -gt 0 ] && warn "${ENTRY_ONLY} theme(s) show the icon but the page is missing — it would open to an error."
if [ "$VERIFIED" -eq 0 ]; then
  warn "nothing verified on disk afterwards — treat ${NAME} as NOT installed."
  exit 1
fi

ok "${NAME} is in cPanel for ${VERIFIED} theme(s), section '${GROUP}', switchable per package in Feature Manager"
