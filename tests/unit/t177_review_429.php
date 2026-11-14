<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/migrate_da_home.php';
/**
 * t177 - round 429: the request surface of the pages. A backup handed over by a customer is untrusted: links in it
 * must not make root write or read outside the staging tree. A password is never a command argument. "Delivered"
 * means a send that worked.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- links in the way of a destination ---------- */
$base = sys_get_temp_dir() . '/smpro_t177_' . getmypid();
$home = $base . '/homedir'; $out = $base . '/outside';
@mkdir($home, 0700, true); @mkdir($out, 0700, true);
$canLink = @symlink($out, $home . '/public_html');
if ($canLink) {
    is_eq(smpro_mig_da_clear_links($home, $home . '/public_html'), 1, 'K1: a link standing where the site belongs is removed');
    ok(!is_link($home . '/public_html') && is_dir($out), 'K2: ...the link only, never what it pointed at');
    @symlink($out, $home . '/other.test');
    is_eq(smpro_mig_da_clear_links($home, $home . '/other.test/public_html'), 1, 'K3: a link in the middle of the path is removed too');
    @mkdir($home . '/mail', 0700, true); @symlink($out, $home . '/mail/a.test');
    is_eq(smpro_mig_da_clear_links($home, $home . '/mail/a.test/box'), 1, 'K4: and one under mail/');
    @mkdir($home . '/plain/sub', 0700, true);
    is_eq(smpro_mig_da_clear_links($home, $home . '/plain/sub'), 0, 'K5: real folders are left alone');
    is_eq(smpro_mig_da_clear_links($home, $out . '/x'), 0, 'K6: a path outside the staged home is not walked');
} else {
    tap_skip('K1-K6: links in the way of a destination', 'this system cannot create links');
}
@rmdir($home . '/plain/sub'); @rmdir($home . '/plain'); @unlink($home . '/mail/a.test'); @rmdir($home . '/mail'); @unlink($home . '/other.test'); @unlink($home . '/public_html'); @rmdir($home); @rmdir($out); @rmdir($base);

$mh = $src('includes/migrate_da_home.php');
$i = strpos($mh, "smpro_mig_da_clear_links(\$home, \$dst)"); $j = strpos($mh, "if (@rename(\$sub, \$dst)) { \$moved++; continue; }");
ok($i !== false && $j !== false && $i < $j, 'K7: the way is cleared before site content is moved in');
$i2 = strrpos($mh, "smpro_mig_da_clear_links(\$home, \$dst)"); $j2 = strpos($mh, "if (@rename(\$src, \$dst)) { \$boxes++; continue; }");
ok($i2 !== false && $j2 !== false && $i2 > $i && $i2 < $j2, 'K8: ...and before a mailbox is');
has($src('includes/migrate_da.php'), "' -mindepth 1 ! -type f ! -type d -delete'", 'K9: the settings tree keeps plain files and folders only');

/* ---------- a password is not a command argument ---------- */
$mg = $src('includes/migrate.php');
has($mg, "\$cmd = 'whmapi1 --input=json ' . escapeshellarg(\$fn) . ' --output=json < ' . escapeshellarg(\$tmp);", 'W1: the API call takes its arguments on standard input');
ok(strpos($mg, "escapeshellarg(\$k . '=' . \$v)") === false, 'W2: and no longer as command arguments');
has($mg, "@unlink(\$tmp);", 'W3: the request file is removed after the call');
has($mg, "\$old = umask(0077);", 'W4: and is never readable by anyone else while it exists');

/* ---------- notifications ---------- */
$nt = $src('includes/notify.php');
has($nt, "\$went = []; foreach (\$results as \$ch => \$rr) if (!empty(\$rr['ok'])) \$went[] = \$ch;", 'N1: only a send that worked counts as delivered');
has($nt, "smpro_ntf_undelivered_note(\$type, \$subject, \$went);", 'N2: and that is what clears the red bar');
is_eq(substr_count($nt, 'JSON_INVALID_UTF8_SUBSTITUTE') >= 3, true, 'N3: one bad byte in a name does not lose the alert or its log row');
ok(json_encode(['text' => "bad \xff name"], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) !== false, 'N4: (the flag does what it is there for)');

/* ---------- the rest ---------- */
has($src('modules/ai_providers_engine.php'), "\$host = trim((string)\$p['host'], '[]');", 'A1: an IPv6 literal provider address is checked');
has($src('modules/top-processes.php'), "if (!\$isAcct) foreach (\$crit as \$c)", 'P1: a process of a hosting account cannot name itself critical');
has($src('modules/whatsapp.php'), "elseif (!empty(\$waMoved) && !empty(\$w['api_key'])) \$w['api_key'] = '';", 'G1: a saved gateway key does not follow a new address');
has($src('modules/notifications.php'), "elseif (!empty(\$waMoved) && !empty(\$cfg['whatsapp']['api_key'])) \$cfg['whatsapp']['api_key'] = '';", 'G2: ...from either page');
