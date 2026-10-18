<?php
require __DIR__ . '/../support/bootstrap.php';

/*
 * t15_cooler_profiles.php — pure matcher + builtin-definition tests.
 *
 * Targets (all pure: args in, value out — no shell/network/CSF/server-IO):
 *   includes/cooler.php   : smpro_cool_is_critical, smpro_cool_is_site_engine, smpro_cool_is_protected
 *   includes/profiles.php : smpro_prof_keys_intrusion, smpro_prof_keys_notify_thr, smpro_prof_builtin
 *
 * Expected values are derived by reading the source directly (see comments).
 */

require SMPRO_BASE . '/includes/cooler.php';
require SMPRO_BASE . '/includes/profiles.php';

/* =====================================================================
 * smpro_cool_is_critical($comm, $pid=0)
 *   - pid 1 or 2  -> true (regardless of comm)
 *   - empty comm  -> false
 *   - exact membership in smpro_cool_critical_exact() (case-insensitive)
 *   - prefix match in smpro_cool_critical_prefix() (strpos === 0, lowercased)
 * ===================================================================== */

// pid<=2 critical branch (security-relevant: kernel/init processes)
ok(smpro_cool_is_critical('', 1), 'is_critical: pid 1 critical even with empty comm');
ok(smpro_cool_is_critical('anything', 1), 'is_critical: pid 1 critical regardless of comm');
ok(smpro_cool_is_critical('phpunit', 2), 'is_critical: pid 2 critical');
nok(smpro_cool_is_critical('phpunit', 3), 'is_critical: pid 3 not auto-critical');
nok(smpro_cool_is_critical('phpunit', 0), 'is_critical: pid 0 (default) not auto-critical');

// empty comm with non-special pid -> false
nok(smpro_cool_is_critical('', 0), 'is_critical: empty comm + pid 0 -> false');
nok(smpro_cool_is_critical('   ', 0), 'is_critical: whitespace-only comm -> false');

// exact-set members (web/db/mail/dns/ftp/ssh/firewall/cpanel)
ok(smpro_cool_is_critical('httpd'), 'is_critical: httpd (web)');
ok(smpro_cool_is_critical('mysqld'), 'is_critical: mysqld (db)');
ok(smpro_cool_is_critical('php-fpm'), 'is_critical: php-fpm (master serves all pools)');
ok(smpro_cool_is_critical('sshd'), 'is_critical: sshd');
ok(smpro_cool_is_critical('exim'), 'is_critical: exim (mail)');
ok(smpro_cool_is_critical('lfd'), 'is_critical: lfd (firewall)');
ok(smpro_cool_is_critical('cpsrvd'), 'is_critical: cpsrvd (cpanel)');
ok(smpro_cool_is_critical('named'), 'is_critical: named (dns)');

// case-insensitive matching (security: attacker proc named HTTPD must still be protected)
ok(smpro_cool_is_critical('HTTPD'), 'is_critical: HTTPD upper-case matches (case-insensitive)');
ok(smpro_cool_is_critical('MySQLd'), 'is_critical: MySQLd mixed-case matches');
ok(smpro_cool_is_critical('  httpd  '), 'is_critical: httpd with surrounding whitespace trimmed');

// prefix-set members: smpro_cool_critical_prefix() =
//   ['systemd-','php-fpm','imunify','cpanel','cphulk','mysql','maria','named','exim','clamd','dovecot']
ok(smpro_cool_is_critical('systemd-journald'), 'is_critical: systemd- prefix');
ok(smpro_cool_is_critical('mysqld_safe'), 'is_critical: mysql prefix (mysqld_safe)');
ok(smpro_cool_is_critical('mariadbd'), 'is_critical: maria prefix');
ok(smpro_cool_is_critical('imunify360-agent'), 'is_critical: imunify prefix');
ok(smpro_cool_is_critical('dovecot-auth'), 'is_critical: dovecot prefix');
ok(smpro_cool_is_critical('php-fpm82'), 'is_critical: php-fpm prefix variant');

// non-critical unrelated processes
nok(smpro_cool_is_critical('phpunit'), 'is_critical: phpunit (unrelated) -> false');
nok(smpro_cool_is_critical('node'), 'is_critical: node -> false');
nok(smpro_cool_is_critical('python3'), 'is_critical: python3 -> false');
nok(smpro_cool_is_critical('backup.sh'), 'is_critical: backup.sh -> false');
nok(smpro_cool_is_critical('php'), 'is_critical: bare php -> false (site engine, not critical)');

/* =====================================================================
 * smpro_cool_is_site_engine($comm)
 *   matches: php-cgi, lsphp, suphp, cgiwrap  (=== OR strpos===0 prefix),
 *   plus exact 'php'. case-insensitive (lowercased+trimmed).
 * ===================================================================== */

ok(smpro_cool_is_site_engine('php-cgi'), 'site_engine: php-cgi');
ok(smpro_cool_is_site_engine('lsphp'), 'site_engine: lsphp');
ok(smpro_cool_is_site_engine('suphp'), 'site_engine: suphp');
ok(smpro_cool_is_site_engine('cgiwrap'), 'site_engine: cgiwrap');
ok(smpro_cool_is_site_engine('php'), 'site_engine: bare php (exact)');

// prefix variants (lsphp7.4, php-cgi82)
ok(smpro_cool_is_site_engine('lsphp7.4'), 'site_engine: lsphp7.4 (prefix)');
ok(smpro_cool_is_site_engine('php-cgi82'), 'site_engine: php-cgi82 (prefix)');

// case-insensitive + trim
ok(smpro_cool_is_site_engine('LSPHP'), 'site_engine: LSPHP (case-insensitive)');
ok(smpro_cool_is_site_engine('  php  '), 'site_engine: bare php trimmed');

// not site engines
nok(smpro_cool_is_site_engine('phpunit'), 'site_engine: phpunit -> false (no php-/php exact)');
nok(smpro_cool_is_site_engine('httpd'), 'site_engine: httpd -> false');
nok(smpro_cool_is_site_engine(''), 'site_engine: empty -> false');
nok(smpro_cool_is_site_engine('myphp'), 'site_engine: myphp -> false (not a prefix)');

/* =====================================================================
 * smpro_cool_is_protected($comm, $pid=0)
 *   == smpro_cool_is_critical (alias). Per source it is the CRITICAL set only,
 *   NOT the site-engine set (an admin may manually cool a site engine).
 * ===================================================================== */

ok(smpro_cool_is_protected('httpd'), 'is_protected: httpd (critical) -> true');
ok(smpro_cool_is_protected('', 1), 'is_protected: pid 1 -> true');
ok(smpro_cool_is_protected('mysqld'), 'is_protected: mysqld -> true');
nok(smpro_cool_is_protected('phpunit'), 'is_protected: phpunit -> false');
// site engines are NOT protected (only critical infra is) — matches is_critical exactly
nok(smpro_cool_is_protected('lsphp'), 'is_protected: lsphp site-engine -> false (not in critical set)');
is_eq(
    smpro_cool_is_protected('httpd', 0),
    smpro_cool_is_critical('httpd', 0),
    'is_protected is identical to is_critical for httpd'
);
is_eq(
    smpro_cool_is_protected('phpunit', 1),
    smpro_cool_is_critical('phpunit', 1),
    'is_protected is identical to is_critical for (phpunit,pid1)'
);

/* =====================================================================
 * smpro_prof_keys_intrusion()  — EXACT ordered list from source.
 * ===================================================================== */
$intrKeys = smpro_prof_keys_intrusion();
is_eq($intrKeys, [
    'alert_window_min','thr_domain_attacks','thr_ip_domains','auto_block','auto_block_dryrun','ai_block',
    'use_csf','use_cloudflare','emergency','emergency_dryrun','emergency_harden','emergency_clean',
], 'prof_keys_intrusion: exact ordered key set');
is_eq(count($intrKeys), 12, 'prof_keys_intrusion: 12 keys');

/* =====================================================================
 * smpro_prof_keys_notify_thr() — EXACT ordered list from source.
 * ===================================================================== */
$thrKeys = smpro_prof_keys_notify_thr();
is_eq($thrKeys, [
    'disk_pct','load','failed_logins','spam_events','db_injections','remind_hours',
], 'prof_keys_notify_thr: exact ordered key set');
is_eq(count($thrKeys), 6, 'prof_keys_notify_thr: 6 keys');

/* =====================================================================
 * smpro_prof_builtin() — exact builtin definitions (medium + maximum).
 * ===================================================================== */
$b = smpro_prof_builtin();

is_eq(array_keys($b), ['medium','maximum'], 'prof_builtin: exactly medium + maximum');

// --- medium ---
$m = $b['medium'];
is_eq($m['label'], 'Medium protection', 'medium: label');
ok(isset($m['intrusion']) && isset($m['notify_thr']), 'medium: has intrusion + notify_thr');
// intrusion keys present must match the controlled key set exactly (ordered)
is_eq(array_keys($m['intrusion']), smpro_prof_keys_intrusion(), 'medium: intrusion keys match key set');
is_eq(array_keys($m['notify_thr']), smpro_prof_keys_notify_thr(), 'medium: notify_thr keys match key set');
// exact intrusion values (security-relevant: dry-run on, enforcement off)
is_eq($m['intrusion']['alert_window_min'], 15, 'medium: alert_window_min=15');
is_eq($m['intrusion']['thr_domain_attacks'], 150, 'medium: thr_domain_attacks=150');
is_eq($m['intrusion']['thr_ip_domains'], 12, 'medium: thr_ip_domains=12');
is_eq($m['intrusion']['auto_block'], true, 'medium: auto_block=true');
is_eq($m['intrusion']['auto_block_dryrun'], true, 'medium: auto_block_dryrun=true (SAFE default)');
is_eq($m['intrusion']['ai_block'], false, 'medium: ai_block=false');
is_eq($m['intrusion']['use_csf'], true, 'medium: use_csf=true');
is_eq($m['intrusion']['use_cloudflare'], true, 'medium: use_cloudflare=true');
is_eq($m['intrusion']['emergency'], false, 'medium: emergency=false (auto-response OFF)');
is_eq($m['intrusion']['emergency_dryrun'], true, 'medium: emergency_dryrun=true');
is_eq($m['intrusion']['emergency_harden'], true, 'medium: emergency_harden=true');
is_eq($m['intrusion']['emergency_clean'], true, 'medium: emergency_clean=true');
// exact notify thresholds
is_eq($m['notify_thr']['disk_pct'], 90, 'medium: disk_pct=90');
is_eq($m['notify_thr']['load'], 20, 'medium: load=20');
is_eq($m['notify_thr']['failed_logins'], 60, 'medium: failed_logins=60');
is_eq($m['notify_thr']['spam_events'], 300, 'medium: spam_events=300');
is_eq($m['notify_thr']['db_injections'], 1, 'medium: db_injections=1');
is_eq($m['notify_thr']['remind_hours'], 12, 'medium: remind_hours=12');

// --- maximum ---
$mx = $b['maximum'];
is_eq($mx['label'], 'Maximum protection', 'maximum: label');
is_eq(array_keys($mx['intrusion']), smpro_prof_keys_intrusion(), 'maximum: intrusion keys match key set');
is_eq(array_keys($mx['notify_thr']), smpro_prof_keys_notify_thr(), 'maximum: notify_thr keys match key set');
// exact intrusion values (security-relevant: enforcement ON, AI on, emergency ON)
is_eq($mx['intrusion']['alert_window_min'], 10, 'maximum: alert_window_min=10');
is_eq($mx['intrusion']['thr_domain_attacks'], 80, 'maximum: thr_domain_attacks=80');
is_eq($mx['intrusion']['thr_ip_domains'], 8, 'maximum: thr_ip_domains=8');
is_eq($mx['intrusion']['auto_block'], true, 'maximum: auto_block=true');
is_eq($mx['intrusion']['auto_block_dryrun'], false, 'maximum: auto_block_dryrun=false (ENFORCED)');
is_eq($mx['intrusion']['ai_block'], true, 'maximum: ai_block=true');
is_eq($mx['intrusion']['use_csf'], true, 'maximum: use_csf=true');
is_eq($mx['intrusion']['use_cloudflare'], true, 'maximum: use_cloudflare=true');
is_eq($mx['intrusion']['emergency'], true, 'maximum: emergency=true (auto-response ON)');
is_eq($mx['intrusion']['emergency_dryrun'], false, 'maximum: emergency_dryrun=false');
is_eq($mx['intrusion']['emergency_harden'], true, 'maximum: emergency_harden=true');
is_eq($mx['intrusion']['emergency_clean'], true, 'maximum: emergency_clean=true');
// exact notify thresholds (more sensitive than medium)
is_eq($mx['notify_thr']['disk_pct'], 85, 'maximum: disk_pct=85');
is_eq($mx['notify_thr']['load'], 15, 'maximum: load=15');
is_eq($mx['notify_thr']['failed_logins'], 40, 'maximum: failed_logins=40');
is_eq($mx['notify_thr']['spam_events'], 200, 'maximum: spam_events=200');
is_eq($mx['notify_thr']['db_injections'], 1, 'maximum: db_injections=1');
is_eq($mx['notify_thr']['remind_hours'], 6, 'maximum: remind_hours=6');

// type strictness: booleans are real bools, ints are real ints (=== guards this)
ok($m['intrusion']['auto_block_dryrun'] === true, 'medium: dryrun is bool true (not 1)');
ok($mx['intrusion']['auto_block_dryrun'] === false, 'maximum: dryrun is bool false (not 0)');
isnt_eq($m['intrusion']['alert_window_min'], '15', 'medium: alert_window_min is int 15 not "15"');
