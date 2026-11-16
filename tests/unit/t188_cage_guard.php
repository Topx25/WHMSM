<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t188 - found on a real server after a scheduled reboot: a large home partition was read-only for the boot-time
 * quota check, the account-isolation layer started inside that window, and every account on that partition
 * answered 500 for eleven hours with nothing said. Plus: a phishing scan that could never find anything.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

ok(function_exists('smpro_cage_guard') && function_exists('smpro_cage_broken') && function_exists('smpro_cage_bin'), 'G0: the cage guard exists');
if (smpro_cage_bin('cagefsctl') === '') {
    is_eq(smpro_cage_guard(), ['ran' => false], 'G1: on a server without the isolation layer the guard does nothing');
    is_eq(smpro_cage_broken('someacct'), '', 'G2: ...and no account is reported broken');
} else {
    $g = smpro_cage_guard(false);
    ok(!empty($g['ran']), 'G1: on a server with the isolation layer the guard runs (report only here)');
    is_eq(smpro_cage_broken('bad name;'), '', 'G2: a name that is not an account name is never passed to a shell');
}
$hp = $src('includes/helpers.php');
has($hp, "if (count(\$probe[\$m[1]] ?? []) < 2) \$probe[\$m[1]][] = \$u;", 'G3: accounts of EVERY home root are tried, not of /home alone');
has($hp, "if (\$repair && time() - (int)(\$st['fixed_at'] ?? 0) >= 3600) {", 'G4: the rebuild runs at most once an hour');
has($hp, "'Account isolation is broken - the repair did NOT work'", 'G5: a repair that did not work is said as such');
has($hp, "(stripos(\$msg, 'cagefs jail') !== false || stripos(\$msg, 'Read-only file system') !== false)", 'G6: only the failure of the cage itself counts');
has($src('includes/svcmon.php'), "smpro_cage_guard(!empty(\$cfg['autorestart']));", 'G7: the Service Monitor runs the guard, repairing only when automatic repair is on');

$sb = $src('includes/sdbulk.php');
has($sb, "\$kind = 'cage_broken'; \$text = 'The account cannot enter its isolation cage, so all its sites fail.';", 'D1: Site Doctor names a broken cage as the cause');
has($sb, "if (\$action === 'cage_remount') {", 'D2: and can rebuild it for the account');
has($sb, "function smpro_sdb_mass_alert(): array {", 'D3: many sites failing together is one event');
has($sb, "if (\$prev < 0 || count(\$bad) < 5 || count(\$bad) < \$prev + 5) return", 'D4: told when 5 or more sites started failing since the last scan');
$i = strpos($sb, "smpro_sdb_mass_alert();"); ok($i !== false, 'D5: the check runs after a scan');

$ps = $src('includes/phishscan.php');
ok(strpos($ps, "-not -path '*/vendor/*'") === false, 'P1: find words are no longer handed to grep');
has($ps, "--exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=wp-includes --exclude-dir=wp-admin", 'P2: folders are left out the way grep understands');
has($ps, "this is NOT a clean result.", 'P3: a scan that could not run is not shown as clean');
if (stripos(PHP_OS, 'WIN') !== 0 && is_executable('/bin/bash')) {
    if (!defined('SMPRO_SCAN_NICE')) define('SMPRO_SCAN_NICE', 10);
    require_once SMPRO_BASE . '/includes/phishscan.php';
    $d = sys_get_temp_dir() . '/smpro_t188_' . getmypid(); @mkdir($d . '/vendor', 0700, true);
    file_put_contents($d . '/login.html', '<form action=x><input name=password> verify your account paypal');
    file_put_contents($d . '/vendor/lib.html', '<form action=x><input name=password> verify your account paypal');
    file_put_contents($d . '/plain.html', '<p>hello</p>');
    // the suite puts stand-in tools first on the search path; this one check needs the real grep, on a folder of its own
    $oldPath = (string)getenv('PATH'); putenv('PATH=/usr/bin:/bin:/usr/sbin:/sbin');
    $r = smpro_ps_scan($d);
    is_eq($r['err'], '', 'P4: the scan runs');
    is_eq(array_map(fn($x) => basename($x['file']), $r['rows']), ['login.html'], 'P5: it finds the planted page and leaves vendor out');
    $r2 = smpro_ps_scan($d . '/nothing-here-' . getmypid());
    ok($r2['err'] !== '' || $r2['rows'] === [], 'P6: a path that does not exist is not a list of findings');
    putenv('PATH=' . $oldPath);
    @unlink($d . '/login.html'); @unlink($d . '/vendor/lib.html'); @unlink($d . '/plain.html'); @rmdir($d . '/vendor'); @rmdir($d);
} else {
    tap_skip('P4-P6: a real scan', 'needs bash and grep on Linux');
}

$re = '/^[ \t]*(?:Deny\s+from\s+all|Require\s+all\s+denied)[ \t]*\r?$/mi';
ok((bool)preg_match($re, "Require all denied\n"), 'Q1: a real deny line is accepted');
ok((bool)preg_match($re, "<IfModule x>\n  Deny from all\r\n</IfModule>\n"), 'Q2: ...indented, with a carriage return too');
ok(!preg_match($re, "# Require all denied\n"), 'Q3: a commented one is not');
ok(!preg_match($re, "Require all denied env=whatever\n"), 'Q4: nor one with a condition after it');
has($src('modules/forensics-audit.php'), "if (\$scope === 'glob') {", 'W1: an allow-list pattern is checked');
has($src('modules/forensics-audit.php'), "a pattern must start with the home of the chosen account", 'W2: it is bound to one account and must name something');
