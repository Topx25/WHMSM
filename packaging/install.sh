#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro (smpro) — adaptive production installer
#
# Works on ANY cPanel & WHM server regardless of the underlying distro
# (AlmaLinux / CentOS / CloudLinux / Rocky / RHEL / Ubuntu — cPanel supports
# Ubuntu too). cPanel is detected by the presence of /usr/local/cpanel, NOT by
# the OS name. Missing optional components (Imunify360, CSF, Exim, JetBackup,
# chattr, curl, whois) do NOT stop the install — they are reported as warnings
# and surfaced in the plugin header so you can enable them later if you want.
#
# Usage:   sudo bash install.sh
###############################################################################
set -uo pipefail   # not -e: we want to collect warnings, not abort on optional steps

PLUGIN="smpro"
ADDONS="/usr/local/cpanel/whostmgr/docroot/cgi/addons"
DEST="${ADDONS}/${PLUGIN}"
DATA="/var/lib/${PLUGIN}"
LOGDIR="/var/log/${PLUGIN}"
BACKUP_DET="/home/backup/detections"
SRC="$(cd "$(dirname "$0")" && pwd)"
WARN_LIST=()

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m%s\n' "$*"; WARN_LIST+=("$*"); }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. minimal hard requirements -----------------------------------------
[ "$(id -u)" = "0" ] || die "Run as root:  sudo bash install.sh"
[ -d "${SRC}/${PLUGIN}" ] || die "Plugin payload '${SRC}/${PLUGIN}' missing — extract the full tarball first."

if [ -r /etc/os-release ]; then . /etc/os-release; say "Host OS: ${PRETTY_NAME:-unknown}"; fi

# --- 2. cPanel detection (by path, not OS name) ----------------------------
if [ -d /usr/local/cpanel ]; then
  HAS_CPANEL=1; ok "cPanel & WHM detected ($( [ -r /usr/local/cpanel/version ] && cat /usr/local/cpanel/version || echo 'version?' ))"
else
  HAS_CPANEL=0
  warn "cPanel/WHM not found at /usr/local/cpanel. This is a WHM plugin; account-level features will be disabled and shown as warnings. Core files will still be installed."
fi

# --- 3. PHP binary (warn, don't abort) -------------------------------------
PHP="/usr/local/cpanel/3rdparty/bin/php"
[ -x "$PHP" ] || PHP="$(command -v php 2>/dev/null || true)"
if [ -n "$PHP" ] && [ -x "$PHP" ]; then
  ok "PHP: $PHP ($("$PHP" -r 'echo PHP_VERSION;' 2>/dev/null || echo '?'))"
else
  PHP=""
  warn "PHP CLI not found. Install it (e.g. 'apt install php-cli php-curl' or 'dnf install php-cli php-curl') — the plugin needs PHP to run."
fi

# --- 4. install plugin files (always) --------------------------------------
say "Installing plugin to ${DEST}"
mkdir -p "$DEST" || die "Cannot create ${DEST} (is this a cPanel server?)."
# Edition guard: never overlay a WHM-only package on a cPanel-user-edition (Safety Lock) install — it would remove
# the helpers the account-side root worker needs while leaving its cron and the customers' page in place.
if [ -f "${DEST}/includes/spqueue.php" ] && [ ! -f "${SRC}/${PLUGIN}/includes/spqueue.php" ] && [ "${SMPRO_FORCE_EDITION:-}" != "1" ]; then
  die "This server runs the cPanel-user edition of SM Pro (Safety Lock). This package is the WHM-only build; installing it would break the account-side worker. Use the cPanel-user release, or set SMPRO_FORCE_EDITION=1 if you really mean to replace it."
fi
cp -a "${SRC}/${PLUGIN}/." "${DEST}/"
chown -R root:root "$DEST" 2>/dev/null || true
find "$DEST" -type d -exec chmod 0755 {} \; 2>/dev/null || true
find "$DEST" -type f -name '*.php' -exec chmod 0644 {} \; 2>/dev/null || true
chmod 0755 "${DEST}/index.cgi" 2>/dev/null || true
[ -d "${DEST}/bin" ] && find "${DEST}/bin" -name '*.php' -exec chmod 0755 {} \; 2>/dev/null || true
ok "Files installed"

# --- 5. data / log / backup dirs (root-only, isolated) ---------------------
say "Creating data directories"
mkdir -p "$DATA"/{cache,reports,notifications,php_harden,ai} "$LOGDIR" 2>/dev/null || true
chmod 0700 "$DATA" "$LOGDIR" "$DATA/notifications" "$DATA/php_harden" "$DATA/ai" 2>/dev/null || true
chown -R root:root "$DATA" "$LOGDIR" 2>/dev/null || true
mkdir -p "$BACKUP_DET" 2>/dev/null && chmod 0700 "$BACKUP_DET" 2>/dev/null || warn "Could not pre-create ${BACKUP_DET} (created on first use)."
ok "Data dirs ready under ${DATA}"

# --- 6. SELinux context (only where SELinux exists) ------------------------
have restorecon && { restorecon -R "$DEST" 2>/dev/null && ok "SELinux context restored"; } || true

# --- 7. register in WHM + rebuild the menu (only if cPanel present) ---------
# Delegated to bin/register.sh (idempotent, also called after every update).
# We still handle the icon PNG here since it lives outside the plugin dir.
if [ "$HAS_CPANEL" = "1" ]; then
  say "Registering with WHM AppConfig"
  # copy the plugin icon into its own asset folder so WHM can serve it
  ICODIR=/usr/local/cpanel/whostmgr/docroot/smproassets
  [ -f "${SRC}/${PLUGIN}.png" ] && mkdir -p "$ICODIR" 2>/dev/null \
    && cp -f "${SRC}/${PLUGIN}.png" "$ICODIR/${PLUGIN}.png" 2>/dev/null \
    && chmod 0644 "$ICODIR/${PLUGIN}.png" 2>/dev/null || true
  # run the shared registration script (creates conf + registers + rebuilds nav)
  if [ -x "${DEST}/bin/register.sh" ]; then
    bash "${DEST}/bin/register.sh" || warn "register.sh returned non-zero (non-fatal)"
  else
    warn "bin/register.sh not found in ${DEST} — WHM registration skipped"
  fi
fi

# --- 7a. retire the legacy predecessor plugin (safety_monitor / safety_monitor_pro) -----
# Older dev builds registered under these names + lived at /cgi/safety_monitor. They show as a
# duplicate "Safety Monitor Pro" in WHM › Plugins. Unregister them and archive their files so the
# ONLY menu entry is this (smpro) plugin. Backed up first; never touches unrelated products.
if [ "$HAS_CPANEL" = "1" ]; then
  LEGACY_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/safety_monitor"
  LEGACY_BK="${DATA}/backups/legacy_$(date +%Y%m%d_%H%M%S)"
  for app in safety_monitor safety_monitor_pro; do
    if [ -f "/var/cpanel/apps/${app}.conf" ]; then
      mkdir -p "$LEGACY_BK"; cp -a "/var/cpanel/apps/${app}.conf" "$LEGACY_BK/" 2>/dev/null || true
      [ -x /usr/local/cpanel/bin/unregister_appconfig ] && /usr/local/cpanel/bin/unregister_appconfig "$app" >/dev/null 2>&1 \
        && ok "Retired legacy menu entry: ${app}" || warn "Could not unregister legacy ${app} (remove /var/cpanel/apps/${app}.conf manually)."
    fi
  done
  if [ -d "$LEGACY_DIR" ]; then
    mkdir -p "$LEGACY_BK"
    tar -czf "$LEGACY_BK/safety_monitor_files.tar.gz" -C "$(dirname "$LEGACY_DIR")" "$(basename "$LEGACY_DIR")" 2>/dev/null \
      && rm -rf "$LEGACY_DIR" && ok "Archived + removed legacy files ($LEGACY_BK)" || warn "Legacy files at $LEGACY_DIR could not be removed."
  fi
fi

# --- 7b. best-effort install of lm-sensors (powers the header TEMP gauge) ----
# Non-blocking: if the OS package manager is available we try once; failures are
# just a warning. (Bare-metal servers expose CPU/board temps; most VMs do not.)
if ! have sensors; then
  say "Installing lm-sensors (header temperature)"
  if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y lm-sensors >/dev/null 2>&1
  elif have dnf;     then dnf install -y lm_sensors >/dev/null 2>&1
  elif have yum;     then yum install -y lm_sensors >/dev/null 2>&1
  elif have zypper;  then zypper -n install lm_sensors >/dev/null 2>&1
  fi
  have sensors && ok "lm-sensors installed" || warn "lm-sensors could not be installed — header TEMP shows '—' (normal on VMs with no thermal sensor)."
fi

# --- 7c. best-effort install of cpulimit (Cooler mode / Auto-Load-Guard CPU cap) ----
# Without cpulimit the guard can only lower priority (renice/ionice) — which does NOT reduce the
# load average. With it, a runaway process is throttled to a hard CPU % (held under the cap), so
# the load actually comes down. cpulimit lives in EPEL on RHEL-family. Non-blocking best-effort.
if ! have cpulimit; then
  say "Installing cpulimit (Cooler mode / Load Guard CPU cap)"
  if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y cpulimit >/dev/null 2>&1
  elif have dnf;     then dnf install -y epel-release >/dev/null 2>&1; dnf install -y cpulimit >/dev/null 2>&1
  elif have yum;     then yum install -y epel-release >/dev/null 2>&1; yum install -y cpulimit >/dev/null 2>&1
  elif have zypper;  then zypper -n install cpulimit >/dev/null 2>&1
  fi
  if ! have cpulimit && [ -f "$DEST/bin/cpulimit-bundle/cpulimit" ]; then
    say "Installing bundled cpulimit (no repo needed)"
    cp -f "$DEST/bin/cpulimit-bundle/cpulimit" /usr/local/bin/cpulimit 2>/dev/null && chmod 0755 /usr/local/bin/cpulimit 2>/dev/null
  fi
  { have cpulimit || [ -x /usr/local/bin/cpulimit ]; } && ok "cpulimit installed" || warn "cpulimit not installed — Cooler/Load Guard uses the built-in throttle instead (the CPU cap still works)."
fi

# --- 7d. best-effort install of small helper tools (never blocking) ----------
# whois (IP intelligence), curl (AI/Telegram/WhatsApp), e2fsprogs→chattr (PHP-Harden file locking).
for pair in "whois:whois:whois" "curl:curl:curl" "chattr:e2fsprogs:e2fsprogs"; do
  bin="${pair%%:*}"; deb="$(printf '%s' "$pair" | cut -d: -f2)"; rpm="$(printf '%s' "$pair" | cut -d: -f3)"
  have "$bin" && continue
  say "Installing ${bin}"
  if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb" >/dev/null 2>&1
  elif have dnf;     then dnf install -y "$rpm" >/dev/null 2>&1
  elif have yum;     then yum install -y "$rpm" >/dev/null 2>&1
  elif have zypper;  then zypper -n install "$rpm" >/dev/null 2>&1
  fi
  have "$bin" && ok "${bin} installed" || true
done

# --- 8. detect OPTIONAL components → warnings (never blocking) --------------
say "Checking optional components"
chk() { if have "$1" || [ -x "/usr/sbin/$1" ] || [ -x "/usr/local/cpanel/3rdparty/bin/$1" ]; then ok "$2: present"; else warn "$2 not installed — $3"; fi; }
chk sensors          "lm-sensors"   "header CPU/board TEMP shows '—' (install lm-sensors; VMs may have no sensor)."
chk cpulimit         "cpulimit"     "Cooler mode/Load Guard CPU cap disabled — cooling only lowers priority, not load (install cpulimit; in EPEL on RHEL-family)."
chk imunify360-agent "Imunify360"  "malware/forensics features disabled (install Imunify360 or ImunifyAV)."
chk csf              "CSF firewall" "IP block/allow disabled (install ConfigServer CSF)."
chk exim             "Exim"         "spam/queue features limited (install/enable Exim)."
chk jetbackup5api    "JetBackup 5"  "backup monitor disabled (install JetBackup 5)."
chk chattr           "chattr/lsattr" "PHP-Harden file locking disabled (install e2fsprogs)."
chk curl             "curl"         "AI/Telegram/Pushbullet/WhatsApp disabled (install curl)."
chk whois            "whois"        "IP intelligence limited (install whois)."

# --- 9. smoke test ---------------------------------------------------------
[ -n "$PHP" ] && { "$PHP" -l "${DEST}/index.php" >/dev/null 2>&1 && ok "index.php syntax OK" || warn "index.php failed lint — check PHP version."; }

# --- 10. summary -----------------------------------------------------------
echo
ok "Safety Monitor Pro installed."
if [ "$HAS_CPANEL" = "1" ]; then
  echo "    WHM:  Home › Plugins › Safety Monitor Pro"
  echo "    URL:  https://<server-hostname>:2087/cgi/addons/${PLUGIN}/index.cgi"
else
  echo "    cPanel not detected — install on a cPanel/WHM server to use the web UI."
fi
if [ "${#WARN_LIST[@]}" -gt 0 ]; then
  echo
  printf '\033[1;33m  %s warning(s):\033[0m\n' "${#WARN_LIST[@]}"
  for w in "${WARN_LIST[@]}"; do echo "    - $w"; done
  echo
  echo "    These are non-fatal. The plugin runs; the features above stay disabled"
  echo "    until you install their component — and are also shown in the plugin header."
fi
exit 0
