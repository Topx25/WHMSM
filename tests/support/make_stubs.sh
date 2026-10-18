#!/bin/sh
# make_stubs.sh — (re)generate the recording stub binaries that shadow real, dangerous
# commands on PATH while tests run. bootstrap.php prepends this dir to PATH in each child
# test process, so any exec() the code-under-test attempts hits a shim, never the real tool.
# Each shim records its argv to $SMPRO_TEST_REC/<name>.calls so tests can assert call-shape
# (or assert a recorder stayed EMPTY = "the blocker was never called").
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/stub_path"
mkdir -p "$DIR"

# 1) recording no-op shims: record argv, succeed, take NO real action.
for b in csf systemctl service kill pkill renice ionice cpulimit nohup setsid chattr lsattr \
         sshd apachectl httpd mysql mysqldump whmapi1 uapi exim sendmail jetbackup5api \
         imunify360-agent dnf yum apt-get restartsrv rm unregister_appconfig register_appconfig; do
  cat > "$DIR/$b" <<EOF
#!/bin/sh
REC="\${SMPRO_TEST_REC:-/tmp/smpro_rec}"; mkdir -p "\$REC" 2>/dev/null || true
printf '%s\n' "\$*" >> "\$REC/$b.calls"
exit 0
EOF
  chmod +x "$DIR/$b"
done

# 2) curl shim: record argv; if SMPRO_FIX_CURL points at a fixture, deliver it to the -o target
#    (download path) or stdout. Exit code overridable via SMPRO_FIX_CURL_RC. Zero network.
cat > "$DIR/curl" <<'EOF'
#!/bin/sh
REC="${SMPRO_TEST_REC:-/tmp/smpro_rec}"; mkdir -p "$REC" 2>/dev/null || true
printf '%s\n' "$*" >> "$REC/curl.calls"
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
if [ -n "$SMPRO_FIX_CURL" ] && [ -f "$SMPRO_FIX_CURL" ]; then
  if [ -n "$out" ]; then cp "$SMPRO_FIX_CURL" "$out"; else cat "$SMPRO_FIX_CURL"; fi
fi
exit "${SMPRO_FIX_CURL_RC:-0}"
EOF
chmod +x "$DIR/curl"

# 3) read-only data commands: record argv, emit a fixture chosen by env (else empty). Deterministic.
for pair in "tail:SMPRO_FIX_TAIL" "ss:SMPRO_FIX_SS" "ps:SMPRO_FIX_PS" "df:SMPRO_FIX_DF" \
            "vnstat:SMPRO_FIX_VNSTAT" "whois:SMPRO_FIX_WHOIS" "host:SMPRO_FIX_HOST" \
            "mmdblookup:SMPRO_FIX_MMDBLOOKUP"; do
  bin="${pair%%:*}"; var="${pair##*:}"
  cat > "$DIR/$bin" <<EOF
#!/bin/sh
REC="\${SMPRO_TEST_REC:-/tmp/smpro_rec}"; mkdir -p "\$REC" 2>/dev/null || true
printf '%s\n' "\$*" >> "\$REC/$bin.calls"
eval f="\\\$$var"
[ -n "\$f" ] && [ -f "\$f" ] && cat "\$f"
exit 0
EOF
  chmod +x "$DIR/$bin"
done

echo "stub_path ready: $DIR"
ls "$DIR" | tr '\n' ' '; echo
