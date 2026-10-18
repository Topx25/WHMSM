#!/bin/bash
# hg-harden.sh - repeatable cPanel/CloudLinux/AlmaLinux server hardening.
#   hg-harden.sh audit            show what would change (no writes)
#   hg-harden.sh apply            apply every safe step; originals kept under /root/hg-harden/<stamp>/ with rollback.sh
#   HG_ROOT_KEYONLY=1 ... apply   also make root SSH key-only (only when every root login uses a key)
# Every step checks the current state first, discovers paths on its own, and is skipped when it does not apply.
set -u
MODE=${1:-audit}; ST=$(date +%Y%m%d-%H%M%S); B=/root/hg-harden/$ST; RB=$B/rollback.sh
[ "$MODE" = apply ] && { mkdir -p $B; chmod 700 /root/hg-harden $B; printf '#!/bin/bash\n# undo hg-harden %s\n' $ST > $RB; chmod 700 $RB; }
say() { printf '%-10s %s\n' "$1" "$2"; }
keep() { [ "$MODE" = apply ] || return 0; [ -e "$1" ] && { mkdir -p "$B$(dirname "$1")"; cp -a "$1" "$B$1"; echo "cp -a '$B$1' '$1'" >> $RB; } || echo "rm -f '$1'" >> $RB; }

# 1) SSH daemon: a drop-in read before the others (sshd keeps the first value it sees)
if command -v sshd >/dev/null; then
  F=/etc/ssh/sshd_config.d/00-hg-harden.conf
  W="MaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\nClientAliveInterval 300\nClientAliveCountMax 2\nPermitEmptyPasswords no\nMaxStartups 10:30:60\n"
  [ "${HG_ROOT_KEYONLY:-0}" = 1 ] && W="${W}PermitRootLogin prohibit-password\n"
  if grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config && [ "$(cat $F 2>/dev/null)" != "$(printf "$W")" ]; then
    say ssh "set: $(printf "$W" | tr '\n' ';')"
    if [ "$MODE" = apply ]; then keep $F; printf "$W" > $F; chmod 600 $F
      if sshd -t; then systemctl reload sshd; echo "systemctl reload sshd" >> $RB; else say ssh "INVALID - reverted"; rm -f $F; fi; fi
  else say ssh "ok"; fi
fi

# 2) kernel network and info-leak settings
F=/etc/sysctl.d/90-hg-harden.conf
SC="net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 net.ipv6.conf.all.accept_redirects=0 net.ipv4.conf.all.log_martians=1 net.ipv4.tcp_syncookies=1 kernel.dmesg_restrict=1 kernel.kptr_restrict=2 kernel.yama.ptrace_scope=1 fs.protected_fifos=2 fs.protected_regular=2 fs.suid_dumpable=0"
D=""; for kv in $SC; do k=${kv%%=*}; v=${kv#*=}; c=$(sysctl -n $k 2>/dev/null) || continue; [ "$c" != "$v" ] && D="$D $kv"; done
if [ -n "$D" ]; then say sysctl "set:$D"
  if [ "$MODE" = apply ]; then keep $F; for kv in $SC; do sysctl -n ${kv%%=*} >/dev/null 2>&1 && echo "$kv"; done > $F
    for kv in $D; do echo "sysctl -qw ${kv%%=*}=$(sysctl -n ${kv%%=*})" >> $RB; done; sysctl -q -p $F; fi
else say sysctl ok; fi

# 3) /dev/shm without exec (where malware keeps loaders between clean-ups)
if ! findmnt -no OPTIONS /dev/shm | grep -q noexec; then say shm "remount /dev/shm noexec,nosuid,nodev"
  if [ "$MODE" = apply ]; then keep /etc/fstab; mount -o remount,noexec,nosuid,nodev /dev/shm
    grep -qE '^\S+\s+/dev/shm\s' /etc/fstab && sed -i -E 's#^(\S+\s+/dev/shm\s+\S+\s+)\S+#\1defaults,noexec,nosuid,nodev#' /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    echo "mount -o remount,exec /dev/shm" >> $RB; fi
else say shm ok; fi

# 4) PHP: never include code from a URL (every installed ea-php / alt-php ini)
for p in /opt/cpanel/ea-php*/root/etc/php.ini /opt/alt/php*/etc/php.ini; do [ -f "$p" ] || continue
  if grep -qiE '^\s*allow_url_include\s*=\s*(on|1)' "$p"; then say php "allow_url_include Off in $p"
    [ "$MODE" = apply ] && { keep "$p"; sed -i -E 's/^\s*allow_url_include\s*=.*/allow_url_include = Off/I' "$p"; }; fi
done

# 5) CSF/LFD: distributed-attack and script detection, ipset for big deny lists, SSH connection caps
if [ -f /etc/csf/csf.conf ]; then
  set_csf() { local k=$1 v=$2 c; c=$(grep -E "^$k\s*=" /etc/csf/csf.conf | head -1 | cut -d'"' -f2)
    [ "$c" = "$v" ] && return 1; say csf "$k: '$c' -> '$v'"; [ "$MODE" = apply ] && sed -i -E "s|^($k\s*=\s*)\".*\"|\1\"$v\"|" /etc/csf/csf.conf; return 0; }
  CH=0; keep /etc/csf/csf.conf
  set_csf LF_DISTATTACK 1 && CH=1; set_csf LF_SCRIPT_ALERT 1 && CH=1; set_csf RESTRICT_SYSLOG 3 && CH=1
  set_csf CONNLIMIT "22;10" && CH=1; set_csf PORTFLOOD "22;tcp;20;60" && CH=1
  command -v ipset >/dev/null && { set_csf LF_IPSET 1 && CH=1; }
  [ "$MODE" = apply ] && [ $CH = 1 ] && { csf -r >/dev/null 2>&1 && systemctl restart lfd; echo "csf -r >/dev/null; systemctl restart lfd" >> $RB; }
  [ $CH = 0 ] && say csf ok
fi

# 6) cPanel tweaks: cap outgoing mail per domain
if [ -f /var/cpanel/cpanel.config ] && command -v whmapi1 >/dev/null; then
  tw() { local k=$1 v=$2 c; c=$(grep -E "^$k=" /var/cpanel/cpanel.config | cut -d= -f2); [ "$c" = "$v" ] && return
    say tweak "$k: '$c' -> '$v'"; [ "$MODE" = apply ] && { whmapi1 set_tweaksetting key=$k value=$v >/dev/null; echo "whmapi1 set_tweaksetting key=$k value='$c' >/dev/null" >> $RB; }; }
  tw maxemailsperhour 500; tw emailsperdaynotify 1000   # never bind sessions to the IP: a front proxy flips it and logs everyone out
fi

# 7) frozen mail (bounces that will never go): saved, then removed
if command -v exiqgrep >/dev/null; then N=$(exiqgrep -z -i 2>/dev/null | wc -l)
  if [ "$N" -gt 0 ]; then say mailq "$N frozen message(s) saved then removed"
    if [ "$MODE" = apply ]; then SP=$(exim -bP spool_directory 2>/dev/null | awk '{print $3}'); L=$B/frozen.list; exiqgrep -z -i > $L
      ( cd $SP/input && sed 's/$/-*/' $L | xargs -I{} sh -c 'ls {} 2>/dev/null' | tar czf $B/frozen-mail.tgz -T - 2>/dev/null )
      xargs -a $L exim -Mrm >/dev/null 2>&1; fi
  else say mailq ok; fi
fi

# 8) security updates, kernel left to live patching / a planned reboot
if command -v dnf >/dev/null; then N=$(dnf -q updateinfo list --security 2>/dev/null | grep -v kernel | wc -l)
  if [ "$N" -gt 0 ]; then say updates "$N security update(s), kernel excluded"
    [ "$MODE" = apply ] && { rpm -qa | sort > $B/rpm-before.txt; dnf -y -q update --security --exclude='kernel*' > $B/dnf.log 2>&1; say updates "dnf exit $? (log $B/dnf.log)"; }
  else say updates ok; fi
fi

# 9) Imunify360: daily malware scan, FTP brute-force protection, kernel exploit detection
if command -v imunify360-agent >/dev/null; then
  CUR=$(imunify360-agent config show --json 2>/dev/null)
  WANT=$(echo "$CUR" | python3 -c '
import json,sys
c=json.load(sys.stdin)["items"]; w={}
def need(sec,k,v):
    if sec in c and k in c[sec] and c[sec][k]!=v: w.setdefault(sec,{})[k]=v
need("MALWARE_SCAN_SCHEDULE","interval","day"); need("PAM","ftp_protection",True); need("KERNELCARE","edf",True)
need("PROACTIVE_DEFENCE","php_immunity",True); need("MALWARE_DATABASE_SCAN","enable",True); need("MOD_SEC","cms_account_compromise_prevention",True)
print(json.dumps(w) if w else "")' 2>/dev/null)
  if [ -n "$WANT" ]; then say imunify "set: $WANT"
    if [ "$MODE" = apply ]; then
      UNDO=$(echo "$CUR" | python3 -c 'import json,sys; c=json.load(sys.stdin)["items"]; w=json.loads(sys.argv[1]); print(json.dumps({s:{k:c[s][k] for k in v} for s,v in w.items()}))' "$WANT")
      imunify360-agent config update "$WANT" >/dev/null && echo "imunify360-agent config update '$UNDO' >/dev/null" >> $RB; fi
  else say imunify ok; fi
fi

[ "$MODE" = apply ] && say done "originals and rollback: $B (bash $RB)"
