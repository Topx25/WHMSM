<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t166 - acting inside an account's folder AS the account (smpro_acct_*). A folder the account owns can change
 * between a check and the action; root following a link there writes, reads or hands over a system file. The
 * helpers drop to the account for the action itself. Run for real where that is possible (root on Linux with an
 * unprivileged user); elsewhere only the refusals that need no second user are checked.
 */
is_eq(smpro_acct_cmd('root', 'true'), '', 'A1: never as root');
is_eq(smpro_acct_cmd('no such;user', 'true'), '', 'A2: a name that is not an account name is refused');
is_eq(smpro_acct_cmd('smpro-no-such-user-xyz', 'true'), '', 'A3: an account that does not exist is refused');
is_eq(smpro_acct_put('root', '/tmp/x', 'y'), false, 'A4: a write as root is refused');
is_eq(smpro_acct_get('root', '/etc/hostname'), null, 'A5: a read as root is refused');

$real = DIRECTORY_SEPARATOR === '/' && function_exists('posix_geteuid') && posix_geteuid() === 0 && is_array(@posix_getpwnam('nobody'))
     && (is_executable('/usr/sbin/runuser') || is_executable('/sbin/runuser') || is_executable('/usr/bin/runuser'));
if (!$real) {
    tap_skip('B: real run as an unprivileged user', 'needs root on Linux with runuser and the user nobody');
} else {
    $pw = posix_getpwnam('nobody');
    $d = sys_get_temp_dir() . '/smpro-acct-' . bin2hex(random_bytes(5)); mkdir($d, 0755); chown($d, $pw['uid']); chgrp($d, $pw['gid']);
    $victim = sys_get_temp_dir() . '/smpro-acct-victim-' . bin2hex(random_bytes(5)); file_put_contents($victim, "root-only\n"); chmod($victim, 0600);
    $f = $d . '/robots.txt';
    ok(smpro_acct_put('nobody', $f, "User-agent: *\n", 0644), 'B1: a file is written as the account');
    $st = stat($f);
    ok($st && $st['uid'] === $pw['uid'] && ($st['mode'] & 0777) === 0644, 'B2: it belongs to the account, with the mode asked for');
    is_eq(smpro_acct_get('nobody', $f), "User-agent: *\n", 'B3: and is read back as the account');
    chmod($f, 0600);
    ok(smpro_acct_put('nobody', $f, "v2\n") && (stat($f)['mode'] & 0777) === 0600, 'B4: a rewrite keeps the mode the file had');
    ok(!glob($d . '/*smpro-tmp*'), 'B5: no temporary file is left behind');
    // the attack: names the writer uses are links to a file only root may touch
    symlink($victim, $d . '/robots.txt.smpro-orig');
    is_eq(smpro_acct_get('nobody', $d . '/robots.txt.smpro-orig'), null, 'B6: a link is never read');
    ok(!smpro_acct_put('nobody', $d . '/robots.txt.smpro-orig', "evil\n", 0644), 'B7: a link is never written through');
    ok(!smpro_acct_copy('nobody', $f, $d . '/robots.txt.smpro-orig'), 'B8: ...nor copied onto');
    is_eq(file_get_contents($victim), "root-only\n", 'B9: the file behind the link is untouched');
    is_eq(fileowner($victim), 0, 'B10: and still owned by root');
    is_eq(smpro_acct_get('nobody', $victim), null, 'B11: a file the account may not read is not read for it');
    ok(!smpro_acct_put('nobody', dirname($victim) . '/smpro-acct-out-' . bin2hex(random_bytes(4)) . '/x', 'y'), 'B12: nothing is written where the account has no folder');
    file_put_contents($d . '/big', str_repeat('a', 5000)); chown($d . '/big', $pw['uid']);
    is_eq(smpro_acct_get('nobody', $d . '/big', 1000), null, 'B13: a file over the size limit is refused, not cut short');
    ok(smpro_acct_copy('nobody', $f, $d . '/copy') && file_get_contents($d . '/copy') === "v2\n", 'B14: a plain copy works');
    ok(smpro_acct_rm('nobody', $d . '/copy') && !file_exists($d . '/copy'), 'B15: and a plain removal');
    $r = smpro_acct_sh('nobody', 'id -u');
    is_eq(trim($r['out']), (string)$pw['uid'], 'B16: the script really runs as the account');
    @unlink($d . '/robots.txt.smpro-orig'); @unlink($d . '/big'); @unlink($f); @rmdir($d); @unlink($victim);
}
$cr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/investigate.php'));
ok(strpos($cr, '@file_put_contents($abs, $min)') === false && strpos($cr, '@copy($bak, $abs)') === false, 'C1: the asset optimizer no longer writes or restores as root');
$db = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/database-cleanup.php'));
ok(strpos($db, "gzip -c > ' . escapeshellarg(\$path)") === false && strpos($db, 'exec cat > "$2"') !== false, 'C2: the database dump into the home is created by the account');
$wc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/wpcron_fix.php'));
ok(strpos($wc, 'file_put_contents($file') === false, 'C3: wp-config.php is not written by root');
$lic = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/license.php'));
ok(strpos($lic, "ini_get('auto_prepend_file')") !== false && strpos($lic, "ini_get('auto_prepend_file')") < strpos($lic, "define('SMPRO_LIC_ENFORCE', true)"), 'C4: a licence gate value planted through auto_prepend_file stops the plugin');
$sw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sitewatch.php'));
ok(strpos($sw, 'smpro_fw_block_ip($arg') === false, 'C5: Site Watch blocks only through the guarded block function');
ok(strpos((string)file_get_contents(SMPRO_BASE . '/bin/sitewatch.php'), "'intrusion', 'fwallow', 'geowall'") !== false, 'C6: the Site Watch worker loads the block guards');
$sd = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/swdeep.php'));
ok(preg_match('/^Location:[ \t]*(\S+)/mi', "HTTP/1.1 301\r\nLocation: \r\nContent-Type: text/html\r\n") === 0, 'C7: an empty Location header is not filled from the next header');
ok(strpos($sd, "=== 0 || (int)(\$g['code'] ?? 0) === 0) return ['ok' => false") !== false, 'C8: one unanswered home-page request is "could not compare"');
