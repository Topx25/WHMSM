<?php
/**
 * dc2_unstick.php — ONE-TIME manual self-update for a server stuck on an OLD build (e.g. 1.0.123)
 * whose built-in self-update silently no-ops (reports ok but never swaps files).
 *
 * It reuses the stuck plugin's OWN license identity to download the latest SIGNED package from the
 * license server, verifies SHA-256 + the RSA signature against the pinned public key embedded below,
 * backs up the current install, then overlays the new files correctly. After this runs once, the
 * server is on the current build whose self-update works normally.
 *
 * RUN ON THE TARGET SERVER (as root):
 *   SM_HOME=/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro \
 *     /usr/local/cpanel/3rdparty/bin/php /root/dc2_unstick.php
 *
 * Safe: signature-verified (a tampered/unsigned package is refused), backup-first, reversible.
 */
define('SMPRO_BOOT', 1);
error_reporting(E_ALL); ini_set('display_errors', '1');

$home = getenv('SM_HOME') ?: '/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro';
foreach (['defines','env','helpers','secret','license'] as $f) {
    $inc = "$home/includes/$f.php";
    if (!is_file($inc)) { fwrite(STDERR, "missing $inc\n"); exit(2); }
    require_once $inc;
}

$PUBKEY = "-----BEGIN PUBLIC KEY-----\n"
. "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA2OKZTIB4S7cqRnoTj0q0\n"
. "rPGhqSOKT0lDggnza7QYhP0qFe1lH7s3j16varPsiFjBSBY9brHG5GGoS90PnwHx\n"
. "YzNfOXZEIw3UCClaq6roveRN8w9du5egyb1ElXkpV2OXj42WKdMZ8tdA8hm/Q7jY\n"
. "GmmS6+VObnLHrMJyfb03Hxn0G4ximuO77vmttKAkayIbc44e4rLgv3RRAfXNgBSr\n"
. "XnFstDDrr7WbuSdscOnixKyK7DFezt5VL4atnxfj1RlDxgszpPyDC0+Z/Zb5iwr2\n"
. "h5c3EWMAKejoYI30RtACMtJbSWAGBAQEgh55ZJb/DbysFlXPZlm3l0WUw3cccjc8\n"
. "coHVj1G2csGsrURvRGUi4a3p6KsplGyfqDEZaF061LU1C9zS/+oxC5PhDseOs64G\n"
. "SiCA+iSJKm9mwTIQvnxHOcgShwGUF07DsL2a1xsGdaHlWd1GBAOtnqMXwsYC5ChF\n"
. "IO1aoVYQjV9psv6/7kHz/ZcAHvWQU/lolYWcMsEyQHmTAgMBAAE=\n"
. "-----END PUBLIC KEY-----\n";

function die_err($m){ echo "FAILED: $m\n"; exit(1); }

$base = realpath(SMPRO_BASE) ?: SMPRO_BASE;
$from = defined('SMPRO_VERSION') ? SMPRO_VERSION : '?';
echo "Install : $base\n";
echo "Current : $from\n";
echo "License : " . substr((string)smpro_lic_key(), 0, 18) . "…\n";
if (trim((string)smpro_lic_key()) === '') die_err('no license key on this server');

$work = SMPRO_VARLIB . '/unstick'; @shell_exec('rm -rf ' . escapeshellarg($work)); @mkdir($work, 0700, true);
$tgz = "$work/pkg.tgz"; $hdr = "$work/h.txt";

// 1) download the latest signed package using THIS server's license identity
$payload = smpro_lic_payload(smpro_lic_key());
$body = json_encode($payload, JSON_UNESCAPED_SLASHES);
$ua = function_exists('smpro_lic_ua') ? smpro_lic_ua() : 'SafetyMonitorPro-unstick';
$cmd = 'curl -sS -m 180 -o ' . escapeshellarg($tgz) . ' -D ' . escapeshellarg($hdr)
     . ' -w ' . escapeshellarg('%{http_code}') . ' -A ' . escapeshellarg($ua)
     . ' -H ' . escapeshellarg('Content-Type: application/json')
     . ' -X POST --data ' . escapeshellarg($body) . ' ' . escapeshellarg(SMPRO_LIC_BASE . '/api/update') . ' 2>/dev/null';
$code = trim((string)@shell_exec($cmd));
if ($code !== '200') {
    $m = "download HTTP $code";
    if (is_file($tgz)) { $j = json_decode((string)@file_get_contents($tgz), true); if (is_array($j) && isset($j['message'])) $m = $j['message']; }
    die_err($m);
}

// 2) read integrity headers
$want = ''; $ver = ''; $sigB64 = '';
foreach ((is_file($hdr) ? (array)file($hdr) : []) as $l) {
    if (stripos($l, 'x-smpro-sha256:') === 0)  $want   = strtolower(trim(substr($l, 15)));
    if (stripos($l, 'x-smpro-version:') === 0) $ver    = trim(substr($l, 16));
    if (stripos($l, 'x-smpro-sig:') === 0)     $sigB64 = trim(substr($l, 12));
}
echo "Offered : " . ($ver ?: '?') . "\n";
if (!is_file($tgz) || filesize($tgz) < 1000) die_err('empty/short download');
if ($want !== '' && hash_file('sha256', $tgz) !== $want) die_err('SHA-256 mismatch');

// 3) verify RSA signature against the pinned public key (refuse tampered/unsigned)
$sig = $sigB64 !== '' ? base64_decode($sigB64, true) : false;
$pk  = @openssl_pkey_get_public($PUBKEY);
if ($sig === false || !$pk || @openssl_verify((string)@file_get_contents($tgz), $sig, $pk, OPENSSL_ALGO_SHA256) !== 1)
    die_err('signature invalid — refusing to apply');
echo "Verified: signature OK\n";

// 4) extract + locate the smpro/ payload
$ex = "$work/new"; @mkdir($ex, 0700, true);
@shell_exec('tar -xzf ' . escapeshellarg($tgz) . ' -C ' . escapeshellarg($ex) . ' 2>/dev/null');
$pdir = '';
foreach (glob($ex . '/*/' . SMPRO_SLUG, GLOB_ONLYDIR) ?: [] as $p) { if (is_file($p . '/index.cgi') && is_dir($p . '/includes')) { $pdir = $p; break; } }
if ($pdir === '') foreach (glob($ex . '/*', GLOB_ONLYDIR) ?: [] as $p) { if (is_file($p . '/index.cgi') && is_dir($p . '/includes')) { $pdir = $p; break; } }
if ($pdir === '') die_err('payload not found in package');

// 5) backup then overlay
$bk = SMPRO_VARLIB . '/backups/unstick_' . date('Ymd_His'); @mkdir($bk, 0700, true);
@shell_exec('cp -a ' . escapeshellarg($base) . '/. ' . escapeshellarg($bk) . '/ 2>/dev/null');
@shell_exec('cp -a ' . escapeshellarg($pdir) . '/. ' . escapeshellarg($base) . '/ 2>/dev/null');
@shell_exec('chown -R root:root ' . escapeshellarg($base) . ' 2>/dev/null');
@shell_exec('find ' . escapeshellarg($base) . ' -type d -exec chmod 0755 {} \; 2>/dev/null');
@shell_exec('find ' . escapeshellarg($base) . ' -type f -name "*.php" -exec chmod 0644 {} \; 2>/dev/null');
@shell_exec('chmod 0755 ' . escapeshellarg($base . '/index.cgi') . ' 2>/dev/null');

// 6) confirm
$newdef = @file_get_contents($base . '/includes/defines.php');
$applied = (strpos((string)$newdef, $ver) !== false) || is_file($base . '/includes/hub.php');
@shell_exec('rm -rf ' . escapeshellarg($work));
echo "Backup  : $bk\n";
echo ($applied ? "SUCCESS : updated $from -> $ver\n" : "WARNING : files copied but version not confirmed — check manually\n");
echo "Next    : open the plugin's Updates page; future updates now apply automatically.\n";
