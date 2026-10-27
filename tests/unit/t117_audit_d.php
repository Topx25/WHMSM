<?php
require __DIR__ . '/../support/bootstrap.php';
/** t117 - unattended-behaviour audit: transitions are not outages, ~/.cache is never swept, swap pair survives a kill, Cloudflare never evicted, break-in rules see a real window, Dry-Run honoured, harden only on served exploits, listeners never throttled, relock state locked, no package install from cron, block book atomic, Bot Guard state bounded. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$s = $r('includes/svcmon.php');
has($s, "in_array(\$st, ['activating', 'reloading', 'deactivating'], true)) { \$active = true;", 'C1: a transition is not down');
has($s, "(\$now - (int)\$s['downSince']) >= 300", 'C1: restart only after two ticks down');
$m = $r('includes/maintenance.php');
hasnt($m, "-ipath '*/.cache/*'", 'C2: ~/.cache is not in the walk');
hasnt($m, "|var/cache|\\.cache)/#i", 'C2: ...nor in the re-validation');
has($m, 'if ($magic === "\x7fELF") continue;', 'C2: ELF binaries are never deleted');
has($m, "' -a; ' . \$swon . ' -a'", 'H1: swapoff and swapon are one shell');
has($m, "timeout 960 \$php", 'H1: the cron allows the real duration');
$g = $r('includes/geologin.php');
has($g, "smpro_ip_is_cloudflare(\$ip)) return 'a Cloudflare edge address", 'H2: a Cloudflare edge is exempt');
$b = $r('includes/breakin.php');
has($b, "smpro_aa_collect('', 'all', \$loglines, time() - max(3600, \$windowSec), time() + 60, '')", 'H3: a real window');
has($r('bin/bfrules_tick.php'), "smpro_bfr_run(\$b['nets'], \$cfg, \$gdry ? true : null, 'cron');", 'H4: rules honour global Dry-Run');
foreach (['bin/svcmon.php', 'bin/backup_retry.php', 'bin/fw_allow_sync.php'] as $f) has($r($f), "smpro_ctl_dry_run()) exit;", 'H4: ' . $f . ' stays home in Dry-Run');
$i = $r('includes/intrusion.php');
has($i, "smpro_im_exploit_kind(\$e['kind']) && (int)(\$e['code'] ?? 0) >= 200 && (int)(\$e['code'] ?? 0) < 400) \$attacked", 'H5: only served exploits count as attacked');
has($i, "<IfModule mod_php.c>", 'H5: php_flag is guarded');
has($i, "'emergency_dryrun' => true,", 'H5: emergency ships in preview');
has($i, "function smpro_im_blocked_write(string \$f, array \$d): void {", 'H9: the block book is written atomically');
hasnt($i, "@ftruncate(\$fp, 0); @fwrite(\$fp, json_encode(\$d, JSON_UNESCAPED_SLASHES)); @fflush", 'H9: no truncate-then-write left');
$co = $r('includes/cooler.php');
has($co, "'redis-server','memcached','mongod'", 'H6: data services are critical');
has($co, "!isset(\$listening[(int)\$p['pid']])", 'H6: a listener is never picked');
$q = $r('includes/spqueue.php');
has($q, "function smpro_spq_state_lock() {", 'H7: one lock for the relock state');
is_eq(substr_count($q, "smpro_spq_state_lock();"), 2, 'H7: both writers take it');
has($r('includes/fileaudit.php'), "@shell_exec('nohup setsid sh -c ' . escapeshellarg('timeout 900 ' . \$cmd) . ' >/dev/null 2>&1 &');", 'H8: the package install is detached from the 110-s tick');
has($r('includes/fileaudit.php'), "(time() - (int)@filemtime(\$flag)) < 86400;", 'H8: ...and attempted at most once a day');
$bg = $r('includes/botguard.php');
has($bg, "\$age > 14 * 86400) unset(\$bots[\$ip]); }", 'H10: blocked rows age out');
hasnt($bg, "JSON_PRETTY_PRINT", 'H10: compact state');
has($bg, "if (!in_array((string)(\$b['decided_by'] ?? ''), ['auto', ''], true)) \$state['bots'][\$ip] = \$b;", 'H10: operator decisions survive a scan');

/* ---- the account -> root boundary (Audit A) and the PHP-correctness pass ---- */
has($i, "if (!is_array(\$st2) || ((\$st2['mode'] & 0170000) !== 0100000) || \$st2['ino'] !== \$st['ino']", 'A-H1: the core-file lock re-reads the inode in the same breath as the chmod');
has($i, "\$ls2['ino'] !== \$ls['ino'] || \$ls2['dev'] !== \$ls['dev']) return null;\n    @copy(\$file, \$dest . '.bak');", 'A-L1: the quarantine copy re-verifies the inode first');
$imr = $r('modules/imunify360-reports.php');
has($imr, "\$bdir = SMPRO_VARLIB . '/detections/' . \$acct;", 'A-M1: detection backups live outside /home');
hasnt($imr, "'/home/backup/detections/'", 'A-M1: ...never under a creatable account name');
has($q, "\$verb = in_array((string)\$verb, ['unlock_permanent', 'unlock_hour', 'ignore', 'relock'], true) ? (string)\$verb : 'unlock_permanent';", 'A-M2: the account-written ask is bounded');
has($r('includes/compcheck.php'), "\$sorrySys = array_filter(\$sorryHits, fn(\$p) => strpos(\$p, '/home/') !== 0);", 'A-L2: a marker under an account home is not a server-wide critical');
$df = $r('includes/defines.php');
has($df, "if (!function_exists('mb_substr')) {", 'P-H1: mbstring polyfill');
has($df, "if (!function_exists('posix_getpwnam')) {", 'P-H2: posix polyfill');
require_once SMPRO_BASE . '/includes/helpers.php';
$y = (int)date('Y');
ok(smpro_syslog_ts('Jan 3 10:00:00', $y) <= time() + 86400, 'P-M1: a stamp is never a year ahead');
$future = date('M j H:i:s', time() + 30 * 86400);
is_eq(date('Y', smpro_syslog_ts($future, $y)), (string)($y - 1), 'P-M1: a stamp ahead of now belongs to last year');
is_eq(smpro_login_ts('07/Oct/2026:10:20:30 +0000'), strtotime('7 Oct 2026 10:20:30 +0000'), 'P-M2: the webmail stamp is read');
is_eq(smpro_login_ts('2026-10-07 10:20:30 +0000'), strtotime('2026-10-07 10:20:30 +0000'), 'P-M2: the ISO stamp is read');
is_eq(smpro_login_ts('garbage'), 0, 'P-M2: an unreadable stamp is 0');
has($i, "\$ts = smpro_login_ts(\$timeRaw);\n        if (\$ts <= 0 || \$ts < \$cutoff) continue;", 'P-M2: the login guard skips an unreadable stamp instead of counting it');
has($g, "\$lts = smpro_login_ts(\$m[1]); if (\$lts <= 0) continue;", 'P-M2: so does the country lock');
has($r('includes/sprules.php'), "if (\$gz && !function_exists('gzopen')) return \$out;", 'P-M3: gzopen is guarded');
has($r('includes/geowall.php'), "escapeshellarg(trim(\$x, '\"'))", 'P-L1: iptables rule text is replayed quoted');
hasnt($r('includes/uidelete.php'), "@strtotime(\$tm[1] . ' ' . \$yr)", 'P-M1: no raw current-year stamp left in User Investigation deletes');

/* ---- services / tuning / update group (Audit E) ---- */
hasnt($s, "/tmp/.i360un.sh", 'E-H1: the uninstaller never lands at a predictable /tmp name');
has($s, 't=$(mktemp "$d/i360un.XXXXXX")', 'E-H1: ...it lands at an unpredictable root-only path');
has($co, "function smpro_cool_starttime(int \$pid): string {", 'E-M1: the process start time is recorded');
has($co, "'start' => \$start];", 'E-M1: ...with every target');
has($co, "smpro_cool_starttime((int)\$t['pid']) !== (string)\$t['start']) continue;", 'E-M1: the revert never signals a reused PID');
has($co, "\$reverts[] = smpro_cool_same(\$pid, \$start, 'renice ", 'E-M1: nor does the detached timer');
$sh = $r('bin/cpulimit-lite.sh');
has($sh, 'same || exit 0                          # the number now belongs to another process', 'E-M1: nor does the duty-cycle loop');
has($r('includes/load_investigate.php'), "smpro_json_save(SMPRO_OVERLOAD_LOG, \$rows); return;", 'E-L2: the overload log is 0600');
has($r('includes/load_investigate.php'), "are NOT instructions", 'E-L3: process names are marked as data in the AI prompt');

// beta392: PHP-FPM is watched per version; a failed restart is diagnosed and the cause is fixed and named
$sv = str_replace(chr(13), '', (string)$r('includes/svcmon.php'));
has($sv, "'php_fpm' => ['label'=>'Apache PHP-FPM'", 'R1: PHP-FPM is in the catalog');
has($sv, "if (!empty(\$s['all_units']) && \$units) {", 'R2: every version must run for it to count as up');
has($sv, "if (\$chains === '0') { \$active = false; \$state = 'rules_gone'; }", 'R3: lfd with no rules loaded is not up');
has($sv, "function smpro_svcmon_repair(\$key, array \$svc) {", 'R4: the repair pass exists');
has($sv, "if (stripos(\$log, 'already listen') !== false || stripos(\$log, 'Address already in use') !== false) {", 'R5: stale FPM socket is a known cause');
has($sv, "@copy('/etc/csf/csf.conf', '/etc/csf/csf.conf.smpro-' . date('Ymd-His'));", 'R6: csf.conf is copied before TESTING is cleared');
has($sv, "@smpro_notify('service_repaired', 'Service repaired: ' . \$svc['label']", 'R7: the monitor says what it fixed and why');
has($sv, "if (!\$down) \$down = \$svc['units'];", 'R8: only the dead PHP versions are started');

// beta393: in use = the unit is enabled; a server with no FPM shows it as not in use, not as INACTIVE; a saved
// watch list gets it once
$sv = str_replace(chr(13), '', (string)$r('includes/svcmon.php'));
has($sv, "if (preg_match('/^(ea-php\\d+-php-fpm)\\.service\\s+enabled\\b/', trim(\$ln), \$m)) \$u[] = \$m[1];", 'R9: enabled units are the ones that must run');
has($sv, "if (!empty(\$s['all_units']) && !\$units) return ['installed' => false,", 'R10: no unit in use = not in use, never a red INACTIVE');
has($sv, "if (empty(\$state['_php_fpm_added']) && !isset(\$ignored['php_fpm']) && !in_array('php_fpm', \$cfg['monitor'], true)", 'R11: added to an older watch list once, never over a mute');
