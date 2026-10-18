<?php
require __DIR__ . '/../support/bootstrap.php';

/*
 * t18_modules_tuning_harden.php — pure-function tests for the Tune-up engine
 * (includes/tuning.php) and the PHP-Harden / Security-Health modules.
 *
 * All expected values are derived by READING the source directly:
 *   includes/tuning.php        : smpro_tun_score (U89), smpro_tun_apply_map (U90)
 *   includes/phstack.php        : smpro_ph_detect (U91)
 *   modules/php-harden.php      : smpro_ph_allowed_exts +
 *                                 smpro_ph_htaccess_marker + smpro_ph_inside +
 *                                 smpro_ph_valid_user (U92)
 *   modules/security-health.php : smpro_sh_fixspec + smpro_sh_mk (U93)
 *
 * includes/tuning.php loads standalone (SMPRO_BOOT guard). The two modules run a
 * router at include time, so we extract ONLY their functions via plugin_funcs.
 */

require SMPRO_BASE . '/includes/tuning.php';
require __DIR__ . '/../support/plugin_funcs.php';
// Stack detection moved out of the module into includes/phstack.php when the account-side plugin needed the same
// answer; smpro_ph_detect and its helpers live there now, so U91 loads it from its new home.
// And the ROOT-only half — chattr, lsattr, web roots — moved to includes/phlock.php, because cron needs it
// and a page module cannot be required from cron: it runs its router at include time.
smpro_plugin_funcs('includes/phlock.php');
smpro_plugin_funcs('includes/phstack.php');
smpro_plugin_funcs('modules/php-harden.php');
smpro_plugin_funcs('modules/security-health.php');

/* =====================================================================
 * U90 — smpro_tun_apply_map(): the exact apply registry.
 *   Read directly from includes/tuning.php lines 259-284.
 * ===================================================================== */
$map = smpro_tun_apply_map();
ok(is_array($map), 'apply_map: returns an array');

// security/perf-relevant exact registry entries (strict deep compare)
is_eq($map['php_opcache'], ['php_ini', 'opcache.enable', '1'], 'apply_map: php_opcache -> php_ini opcache.enable 1');
is_eq($map['php_expose'], ['php_ini', 'expose_php', 'Off'], 'apply_map: php_expose -> php_ini expose_php Off');
is_eq($map['csf_testing'], ['csf', 'TESTING', '0'], 'apply_map: csf_testing -> csf TESTING 0');
is_eq($map['csf_synflood'], ['csf', 'SYNFLOOD', '1'], 'apply_map: csf_synflood -> csf SYNFLOOD 1');
is_eq($map['csf_ct'], ['csf', 'CT_LIMIT', '300'], 'apply_map: csf_ct -> csf CT_LIMIT 300');
is_eq($map['ssh_root'], ['sshd', 'PermitRootLogin', 'prohibit-password'], 'apply_map: ssh_root -> sshd PermitRootLogin prohibit-password');
is_eq($map['ssh_passauth'], ['sshd', 'PasswordAuthentication', 'no'], 'apply_map: ssh_passauth -> sshd PasswordAuthentication no');
is_eq($map['ssh_port'], ['sshd', 'Port', '2222'], 'apply_map: ssh_port -> sshd Port 2222');
is_eq($map['ssh_x11'], ['sshd', 'X11Forwarding', 'no'], 'apply_map: ssh_x11 -> sshd X11Forwarding no');
is_eq($map['mysql_bufferpool'], ['mycnf', 'innodb_buffer_pool_size'], 'apply_map: mysql_bufferpool -> mycnf innodb_buffer_pool_size');
is_eq($map['mysql_skipdns'], ['mycnf_flag', 'skip-name-resolve'], 'apply_map: mysql_skipdns -> mycnf_flag skip-name-resolve');
is_eq($map['mysql_slowlog'], ['mycnf', 'slow_query_log', '1', 'long_query_time', '2'], 'apply_map: mysql_slowlog -> 5-elem mycnf spec');
is_eq($map['mysql_localinfile'], ['mycnf', 'local-infile', '0'], 'apply_map: mysql_localinfile -> mycnf local-infile 0');
is_eq($map['apache_tokens'], ['apache_inc', 'ServerTokens Prod'], 'apply_map: apache_tokens -> apache_inc ServerTokens Prod');
is_eq($map['apache_sig'], ['apache_inc', 'ServerSignature Off'], 'apply_map: apache_sig -> apache_inc ServerSignature Off');
is_eq($map['apache_keepalive'], ['apache_inc', "KeepAlive On\nKeepAliveTimeout 5"], 'apply_map: apache_keepalive multiline');
// advisory-now-real single-element appliers
is_eq($map['csf_alert'], ['csf_alert'], 'apply_map: csf_alert single-elem');
is_eq($map['imunify_pad'], ['imunify_pd'], 'apply_map: imunify_pad -> imunify_pd');
is_eq($map['http_h2_apache'], ['apache_h2'], 'apply_map: http_h2_apache -> apache_h2');

/* =====================================================================
 * U89 — smpro_tun_score(array $recs).
 *   $w = high=>10, medium=>6, low=>3 ; unknown sev penalty = 4 (counts as low).
 *   score = max(0, 100 - sum(penalties)); grade: >=85 A, >=70 B, >=50 C, else D.
 *   Counters: high/medium incremented only on exact 'high'/'medium', else low++.
 * ===================================================================== */

// empty -> 100 / A
$s = smpro_tun_score([]);
is_eq($s['score'], 100, 'score: empty recs -> 100');
is_eq($s['grade'], 'A', 'score: empty recs -> grade A');
is_eq($s['high'], 0, 'score: empty -> high 0');
is_eq($s['medium'], 0, 'score: empty -> medium 0');
is_eq($s['low'], 0, 'score: empty -> low 0');
is_eq($s['open'], 0, 'score: empty -> open 0');
is_eq($s['w'], ['high' => 10, 'medium' => 6, 'low' => 3], 'score: weight table echoed back');

// many-high -> 0 / D : 10 highs => pen 100 => score 0
$tenHigh = array_fill(0, 10, ['sev' => 'high']);
$s = smpro_tun_score($tenHigh);
is_eq($s['score'], 0, 'score: 10 highs -> 0 (floored)');
is_eq($s['grade'], 'D', 'score: 10 highs -> grade D');
is_eq($s['high'], 10, 'score: 10 highs -> high counter 10');
is_eq($s['open'], 10, 'score: 10 highs -> open 10');

// 15 highs => pen 150 but score floored at 0 (max(0,...))
$s = smpro_tun_score(array_fill(0, 15, ['sev' => 'high']));
is_eq($s['score'], 0, 'score: 15 highs still floored at 0 (never negative)');

// A/B boundary: pen 15 -> score 85 -> A (5 lows * 3)
$s = smpro_tun_score(array_fill(0, 5, ['sev' => 'low']));
is_eq($s['score'], 85, 'score: 5 lows -> 85');
is_eq($s['grade'], 'A', 'score: 85 is grade A (boundary >=85)');
is_eq($s['low'], 5, 'score: 5 lows -> low counter 5');

// pen 16 -> score 84 -> B (just below A boundary): 1 high(10) + 1 medium(6)
$s = smpro_tun_score([['sev' => 'high'], ['sev' => 'medium']]);
is_eq($s['score'], 84, 'score: high+medium -> 84');
is_eq($s['grade'], 'B', 'score: 84 is grade B (just below 85)');
is_eq($s['high'], 1, 'score: high+medium -> high 1');
is_eq($s['medium'], 1, 'score: high+medium -> medium 1');

// B/C boundary: pen 30 -> score 70 -> B (3 highs)
$s = smpro_tun_score(array_fill(0, 3, ['sev' => 'high']));
is_eq($s['score'], 70, 'score: 3 highs -> 70');
is_eq($s['grade'], 'B', 'score: 70 is grade B (boundary >=70)');

// pen 31 -> score 69 -> C : 3 highs + 1 low(3) = 33 -> 67 C ; use 5 medium + 1 low = 33 -> 67
$s = smpro_tun_score([['sev' => 'high'], ['sev' => 'high'], ['sev' => 'high'], ['sev' => 'medium']]);
// 10+10+10+6 = 36 -> score 64 -> C
is_eq($s['score'], 64, 'score: 3 high + 1 medium -> 64');
is_eq($s['grade'], 'C', 'score: 64 is grade C');

// C/D boundary: pen 50 -> score 50 -> C (5 highs)
$s = smpro_tun_score(array_fill(0, 5, ['sev' => 'high']));
is_eq($s['score'], 50, 'score: 5 highs -> 50');
is_eq($s['grade'], 'C', 'score: 50 is grade C (boundary >=50)');

// pen 51 -> score 49 -> D : 5 highs + 1 low(3) = 53 -> 47 D
$s = smpro_tun_score(array_merge(array_fill(0, 5, ['sev' => 'high']), [['sev' => 'low']]));
is_eq($s['score'], 47, 'score: 5 high + 1 low -> 47');
is_eq($s['grade'], 'D', 'score: 47 is grade D (below 50)');

// missing 'sev' key -> defaults to 'low' (penalty 3, counted as low). Guard: no undefined-index warning.
$s = smpro_tun_score([[], [], []]);
is_eq($s['score'], 91, 'score: 3 recs without sev key -> 3x low penalty -> 91');
is_eq($s['low'], 3, 'score: missing sev counted as low');
is_eq($s['high'], 0, 'score: missing sev not counted as high');

// unknown sev string -> penalty 4 (the ?? 4 branch), counted in the else (low) bucket
$s = smpro_tun_score([['sev' => 'bogus']]);
is_eq($s['score'], 96, 'score: unknown sev string -> penalty 4 -> 96');
is_eq($s['low'], 1, 'score: unknown sev counted as low (else branch)');
is_eq($s['high'], 0, 'score: unknown sev not high');
is_eq($s['medium'], 0, 'score: unknown sev not medium');

/* =====================================================================
 * U92 — smpro_ph_allowed_exts(array $exts).
 *   allowlist = php,phtml,phar,php[0-9],shtml,html,htm,js,mjs,cgi,pl,py
 *   lowercases+trims; keeps only allowlisted; unique; empty -> default 4.
 * ===================================================================== */
is_eq(smpro_ph_allowed_exts([]), ['php', 'phtml', 'phar', 'php[0-9]'], 'allowed_exts: empty -> default 4');
is_eq(smpro_ph_allowed_exts(['exe', 'sh', 'jpg']), ['php', 'phtml', 'phar', 'php[0-9]'],
    'allowed_exts: all-disallowed -> default 4 (no exe/sh leak)');
is_eq(smpro_ph_allowed_exts(['PHP', '  Phtml  ']), ['php', 'phtml'], 'allowed_exts: case/space normalised');
is_eq(smpro_ph_allowed_exts(['php', 'php', 'js']), ['php', 'js'], 'allowed_exts: de-duplicated');
is_eq(smpro_ph_allowed_exts(['php[0-9]', 'shtml', 'evil']), ['php[0-9]', 'shtml'], 'allowed_exts: drops non-allowlisted token');

/* smpro_ph_htaccess_marker(array $exts): builds a <FilesMatch> deny block.
 * Brackets in php[0-9] are escaped to \[ \] inside the regex. */
$mk = smpro_ph_htaccess_marker([]);
has($mk, 'SMPRO_PH_DENY_EXEC_START', 'htaccess_marker: has START sentinel');
has($mk, 'SMPRO_PH_DENY_EXEC_END', 'htaccess_marker: has END sentinel');
has($mk, 'Require all denied', 'htaccess_marker: emits deny directive');
has($mk, '\.(php|phtml|phar|php\[0-9\])$', 'htaccess_marker: default ext pattern (brackets escaped to \\[0-9\\])');
like($mk, '/<FilesMatch "\\\\\.\(php\|phtml/', 'htaccess_marker: FilesMatch wraps the alternation');
$mk2 = smpro_ph_htaccess_marker(['php', 'js']);
has($mk2, '\.(php|js)$', 'htaccess_marker: custom exts reflected in pattern');

/* =====================================================================
 * U92 — smpro_ph_inside($u, $path): realpath-based containment guard.
 *   Returns false unless realpath($path) is /home/$u or under it.
 *   Non-existent paths -> realpath()===false -> false (the security guarantee).
 * ===================================================================== */
// traversal escape: the path does not exist -> realpath false -> false
nok(smpro_ph_inside('u', '/home/u/../../etc'), 'inside: traversal /home/u/../../etc -> false');
nok(smpro_ph_inside('u', '/etc/passwd'), 'inside: /etc/passwd outside home -> false');
nok(smpro_ph_inside('nobodyuser', '/nonexistent/path/here'), 'inside: non-existent path -> false');
nok(smpro_ph_inside('u', ''), 'inside: empty path -> false');

/* smpro_ph_valid_user($u): regex + /var/cpanel/users + /home dir.
 * Bad chars / empty short-circuit to false regardless of filesystem. */
nok(smpro_ph_valid_user(''), 'valid_user: empty -> false');
nok(smpro_ph_valid_user('../etc'), 'valid_user: path-traversal name -> false');
nok(smpro_ph_valid_user('a b'), 'valid_user: space in name -> false');
nok(smpro_ph_valid_user('user;rm'), 'valid_user: shell metachar -> false');
nok(smpro_ph_valid_user(str_repeat('a', 65)), 'valid_user: 65 chars exceeds {1,64} -> false');
// regex-valid name still false on this box (no /var/cpanel/users entry) — deterministic false
nok(smpro_ph_valid_user('validname'), 'valid_user: regex-ok name still false (no cpanel user file present)');

/* =====================================================================
 * U91 — smpro_ph_detect($root): filesystem stack detection.
 *   We build tiny fake web roots under the sandbox (SMPRO_VARLIB) and assert
 *   the detected key/confidence. Reading the sandbox FS is allowed.
 * ===================================================================== */
$base = SMPRO_VARLIB . '/phdetect';
@mkdir($base, 0777, true);
$mkdirp = function ($p) { @mkdir($p, 0777, true); };
$touch = function ($p, $c = "<?php\n") { @mkdir(dirname($p), 0777, true); @file_put_contents($p, $c); };

// WordPress: wp-config.php + wp-content/ + wp-admin/ -> 3 evidence -> high
$wp = $base . '/wp';
$touch($wp . '/wp-config.php');
$mkdirp($wp . '/wp-content');
$mkdirp($wp . '/wp-admin');
$d = smpro_ph_detect($wp);
is_eq($d['key'], 'wordpress', 'detect: wp tree -> wordpress');
is_eq($d['confidence'], 'high', 'detect: wp 3-evidence -> high confidence');
has(implode(',', $d['evidence']), 'wp-config.php', 'detect: wp evidence lists wp-config.php');

// WordPress weak: only wp-content/ (1 evidence) -> medium
$wp2 = $base . '/wp2';
$mkdirp($wp2 . '/wp-content');
$d = smpro_ph_detect($wp2);
is_eq($d['key'], 'wordpress', 'detect: lone wp-content -> wordpress');
is_eq($d['confidence'], 'medium', 'detect: 1-evidence wp -> medium confidence');

// Laravel: artisan present -> high
$lar = $base . '/lar';
$touch($lar . '/artisan');
$touch($lar . '/composer.json', '{}');
$mkdirp($lar . '/app');
$mkdirp($lar . '/bootstrap');
$d = smpro_ph_detect($lar);
is_eq($d['key'], 'laravel', 'detect: artisan -> laravel');
is_eq($d['confidence'], 'high', 'detect: artisan -> high confidence');

// Laravel without artisan: composer.json + app/ -> medium
$lar2 = $base . '/lar2';
$touch($lar2 . '/composer.json', '{}');
$mkdirp($lar2 . '/app');
$d = smpro_ph_detect($lar2);
is_eq($d['key'], 'laravel', 'detect: composer+app (no artisan) -> laravel');
is_eq($d['confidence'], 'medium', 'detect: no-artisan laravel -> medium');

// Generic PHP: index.php present, < 10 php files in root -> generic / medium
$gen = $base . '/gen';
$touch($gen . '/index.php');
$touch($gen . '/a.php');
$touch($gen . '/b.php');
$d = smpro_ph_detect($gen);
is_eq($d['key'], 'generic', 'detect: index.php + few php -> generic');
is_eq($d['confidence'], 'medium', 'detect: generic with <10 php -> medium');

// Static / unknown: no markers, no index.php, <3 php files -> static / low
$st = $base . '/st';
$mkdirp($st);
$touch($st . '/readme.txt', 'hi');
$d = smpro_ph_detect($st);
is_eq($d['key'], 'static', 'detect: bare dir -> static');
is_eq($d['confidence'], 'low', 'detect: static -> low confidence');
has(implode(',', $d['evidence']), 'No strong framework markers', 'detect: static evidence text');

/* =====================================================================
 * U93 — smpro_sh_fixspec() + smpro_sh_mk(...).
 *   fixspec: a static registry of SSH/MySQL hardening specs.
 *   sh_mk: a plain associative-array builder.
 * ===================================================================== */
$fx = smpro_sh_fixspec();
ok(is_array($fx), 'fixspec: returns array');
is_eq($fx['ssh_rootlogin']['type'], 'sshd', 'fixspec: ssh_rootlogin type sshd');
is_eq($fx['ssh_rootlogin']['key'], 'PermitRootLogin', 'fixspec: ssh_rootlogin key');
is_eq($fx['ssh_rootlogin']['val'], 'prohibit-password', 'fixspec: ssh_rootlogin val');
is_eq($fx['ssh_passauth']['val'], 'no', 'fixspec: ssh_passauth val no');
is_eq($fx['ssh_passauth']['danger'], true, 'fixspec: ssh_passauth flagged danger (lockout risk)');
is_eq($fx['ssh_emptypw']['key'], 'PermitEmptyPasswords', 'fixspec: ssh_emptypw key');
is_eq($fx['ssh_maxauth']['val'], '3', 'fixspec: ssh_maxauth val 3');
is_eq($fx['mysql_bind']['type'], 'mycnf', 'fixspec: mysql_bind type mycnf');
is_eq($fx['mysql_bind']['val'], '127.0.0.1', 'fixspec: mysql_bind binds loopback');
is_eq($fx['mysql_bind']['danger'], true, 'fixspec: mysql_bind danger (restart)');
is_eq($fx['mysql_localinfile']['val'], '0', 'fixspec: mysql_localinfile val 0');
is_eq($fx['mysql_securefile']['val'], '/var/lib/mysql-files', 'fixspec: mysql_securefile path');
// non-danger entries should NOT carry a danger key
ok(!isset($fx['ssh_rootlogin']['danger']), 'fixspec: ssh_rootlogin not flagged danger');
ok(!isset($fx['ssh_maxauth']['danger']), 'fixspec: ssh_maxauth not flagged danger');

// sh_mk builds the canonical row shape (title,status,finding,risk,rec + optional evidence/fix/manual)
$row = smpro_sh_mk('T', 'ok', 'F', 'R', 'REC');
is_eq($row, [
    'title' => 'T', 'status' => 'ok', 'finding' => 'F', 'risk' => 'R', 'rec' => 'REC',
    'evidence' => '', 'fix' => '', 'manual' => '',
], 'sh_mk: defaults for evidence/fix/manual are empty strings');
$row2 = smpro_sh_mk('T2', 'critical', 'F2', 'R2', 'REC2', 'EV', 'FX', 'MAN');
is_eq($row2['status'], 'critical', 'sh_mk: status passed through');
is_eq($row2['evidence'], 'EV', 'sh_mk: evidence passed through');
is_eq($row2['fix'], 'FX', 'sh_mk: fix passed through');
is_eq($row2['manual'], 'MAN', 'sh_mk: manual passed through');

/* ---------------------------------------------------------------------
 * Intentionally NOT asserted (need shells / server IO / stubs — Phase 3):
 *   smpro_tun_scan / smpro_tun_detect / smpro_tun_apply / smpro_tun_ai_optimize
 *   smpro_ph_apply / smpro_ph_apply_htaccess (chattr/exec + chown)
 *   smpro_sh_all / smpro_sh_apply_sshd / smpro_sh_apply_mycnf (sshd -t / restart)
 * ------------------------------------------------------------------- */
tap_skip('smpro_tun_apply — needs stub (Phase 3)', 'shells out to appliers (csf/sshd/apachectl/mysql), backs up + restarts services');
tap_skip('smpro_sh_all — needs stub (Phase 3)', 'probes live ports/processes/configs via ss/pgrep/shell_exec');
tap_skip('smpro_ph_apply_htaccess — needs stub (Phase 3)', 'runs chattr/chown and writes into a real account web root');
