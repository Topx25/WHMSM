#!/usr/bin/env bash
###############################################################################
# Safety Monitor Pro — seed fake test data on test server
#
# Creates simulation accounts, domains, emails, databases, and FTP users
# so every plugin feature can be tested with realistic data.
# All data is clearly fake (sim-* prefix, .dev/.test TLDs).
#
# Usage:
#   bash seed-test-data.sh          (create all test data)
#   bash seed-test-data.sh clean    (remove all sim-* accounts)
###############################################################################
set -uo pipefail

TEST_HOST="167.233.29.168"
TEST_KEY="$HOME/.ssh/cpanel_audit_178_63_134_16"

ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
cya()  { printf '\033[1;36m─── %s ───\033[0m\n' "$*"; }
ssh_r() { ssh -i "$TEST_KEY" -p 22 root@"$TEST_HOST" "$@" 2>/dev/null; }

###############################################################################
# Fake accounts catalogue
# Format: "cpuser|domain|email|password"
###############################################################################
declare -A ACCOUNTS=(
  [simhost1]="simhost1|simhost1.dev|admin@simhost1.dev|T3st!Pass#01"
  [simstore]="simstore|simstore.shop|shop@simstore.shop|T3st!Pass#02"
  [simmail]="simmail|simmail.net|postmaster@simmail.net|T3st!Pass#03"
  [simblog]="simblog|simblog.xyz|blog@simblog.xyz|T3st!Pass#04"
  [simcorp]="simcorp|simcorp.ltd|info@simcorp.ltd|T3st!Pass#05"
)

# Extra email accounts per domain (user:pass)
declare -A EXTRA_EMAILS=(
  [simhost1.dev]="support:Sup!2024 noreply:Nr!2024"
  [simstore.shop]="orders:Ord!2024 returns:Ret!2024"
  [simmail.net]="abuse:Abu!2024 helpdesk:Help!2024"
)

# MySQL databases per cpuser
declare -A DATABASES=(
  [simhost1]="simhost1_wp simhost1_app"
  [simstore]="simstore_shop simstore_logs"
  [simblog]="simblog_blog"
)

###############################################################################
create_accounts() {
  cya "Creating cPanel accounts"
  for cpuser in "${!ACCOUNTS[@]}"; do
    IFS='|' read -r user domain email pass <<< "${ACCOUNTS[$cpuser]}"
    echo -n "  $user ($domain) ... "
    result=$(ssh_r "whmapi1 createacct username=$user domain=$domain password='$pass' contactemail=$email" \
      | grep -E 'result:|reason:' | head -2)
    if echo "$result" | grep -q 'result: 1'; then
      echo "created"; ok "$user created"
    else
      reason=$(echo "$result" | grep 'reason:' | cut -d: -f2-)
      echo "skipped:$reason"
    fi
  done
}

create_emails() {
  cya "Creating extra email accounts"
  # domain→cpuser map (derived from ACCOUNTS catalogue)
  declare -A DOMAIN_USER
  for cpuser in "${!ACCOUNTS[@]}"; do
    IFS='|' read -r user domain email pass <<< "${ACCOUNTS[$cpuser]}"
    DOMAIN_USER[$domain]="$user"
  done
  for domain in "${!EXTRA_EMAILS[@]}"; do
    cpuser="${DOMAIN_USER[$domain]:-}"
    [ -z "$cpuser" ] && { warn "domain $domain not in catalogue, skipping"; continue; }
    for pair in ${EXTRA_EMAILS[$domain]}; do
      euser="${pair%%:*}"; epass="${pair##*:}"
      ssh_r "uapi --user=$cpuser Email add_pop email=${euser}@${domain} password='${epass}' quota=250 >/dev/null 2>&1" && \
        ok "$euser@$domain" || warn "could not create $euser@$domain"
    done
  done
}

create_databases() {
  cya "Creating MySQL databases"
  for cpuser in "${!DATABASES[@]}"; do
    for dbname in ${DATABASES[$cpuser]}; do
      # cPanel prefixes db name with username_
      ssh_r "uapi --user=$cpuser Mysql create_database name=${dbname} >/dev/null 2>&1 && \
             uapi --user=$cpuser Mysql create_user name=${dbname}_usr password=Db!Fake2024 >/dev/null 2>&1 && \
             uapi --user=$cpuser Mysql set_privileges_on_database database=${dbname} databaseuser=${dbname}_usr privileges=ALL >/dev/null 2>&1" && \
        ok "$cpuser: database $dbname" || warn "could not create db $dbname for $cpuser"
    done
  done
}

create_ftp() {
  cya "Creating FTP users (for login monitor simulation)"
  for cpuser in "${!ACCOUNTS[@]}"; do
    IFS='|' read -r user domain email pass <<< "${ACCOUNTS[$cpuser]}"
    ssh_r "uapi --user=$user Ftp add_ftp user=ftpuser homedir=/public_html password=Ftp!2024 quota=500 >/dev/null 2>&1" && \
      ok "ftpuser@$domain" || warn "could not create FTP for $user"
  done
}

inject_fake_logs() {
  cya "Injecting fake ModSecurity events (Intrusion Monitor test data)"
  ssh_r 'cat >> /var/log/modsec_audit.log << '"'"'EOF'"'"'
--ABC001--A--
[18/Jun/2026:12:01:00 +0000] 192.168.1.100 55000 203.0.113.5 80
--ABC001--B--
POST /wp-login.php HTTP/1.1
Host: simhost1.dev
User-Agent: sqlmap/1.7
--ABC001--F--
HTTP/1.1 403 Forbidden
--ABC001--H--
Message: Access denied with code 403. Pattern match "union.*select" at ARGS.
Severity: CRITICAL
--ABC001--Z--

--ABC002--A--
[18/Jun/2026:12:02:30 +0000] 203.0.113.77 44000 203.0.113.5 80
--ABC002--B--
GET /?id=1'"'"' OR 1=1-- HTTP/1.1
Host: simstore.shop
--ABC002--H--
Message: SQL Injection detected at QUERY_STRING.
Severity: HIGH
--ABC002--Z--

--ABC003--A--
[18/Jun/2026:12:05:00 +0000] 198.51.100.9 61234 203.0.113.5 80
--ABC003--B--
GET /wp-content/plugins/../../../../etc/passwd HTTP/1.1
Host: simblog.xyz
--ABC003--H--
Message: Path traversal attempt.
Severity: CRITICAL
--ABC003--Z--
EOF
echo "modsec entries injected"'
}

inject_fake_logins() {
  cya "Injecting fake login events (Login Monitor test data)"
  ssh_r 'for i in $(seq 1 5); do
    echo "$(date -d "-$((i*3)) minutes" +"%b %d %H:%M:%S") $(hostname) sshd[$$]: Failed password for root from 198.51.100.$((i+10)) port 4$((i*1000+4200)) ssh2"
    echo "$(date -d "-$((i*3+1)) minutes" +"%b %d %H:%M:%S") $(hostname) sshd[$$]: Failed password for simhost1 from 203.0.113.$((i+50)) port 5$((i*1000+3300)) ssh2"
  done >> /var/log/secure
  # also fake some cPanel login failures
  CPLOG=/usr/local/cpanel/logs/access_log
  [ -f "$CPLOG" ] && echo "203.0.113.99 - - [18/Jun/2026:12:10:00 +0000] \"POST /login/ HTTP/1.1\" 401 -" >> "$CPLOG" || true
  echo "login events injected"'
}

###############################################################################
clean_all() {
  cya "Removing all sim-* test accounts"
  for cpuser in "${!ACCOUNTS[@]}"; do
    IFS='|' read -r user domain email pass <<< "${ACCOUNTS[$cpuser]}"
    echo -n "  removing $user ... "
    ssh_r "whmapi1 removeacct user=$user keepdns=0 2>/dev/null | grep -E 'result:|reason:'" && echo "done"
  done
}

###############################################################################
TARGET="${1:-create}"

case "$TARGET" in
  clean)
    clean_all
    ;;
  *)
    echo
    cya "Seeding test data on $TEST_HOST"
    echo
    create_accounts
    echo
    create_emails
    echo
    create_databases
    echo
    create_ftp
    echo
    inject_fake_logs
    echo
    inject_fake_logins
    echo
    cya "Summary of fake accounts created"
    printf '  %-12s  %-22s  %-28s\n' "cpuser" "domain" "email"
    printf '  %-12s  %-22s  %-28s\n' "──────" "──────" "─────"
    for cpuser in "${!ACCOUNTS[@]}"; do
      IFS='|' read -r user domain email pass <<< "${ACCOUNTS[$cpuser]}"
      printf '  %-12s  %-22s  %-28s\n' "$user" "$domain" "$email"
    done
    echo
    ok "Test data ready — open Safety Monitor Pro DEV and verify each section"
    ;;
esac
