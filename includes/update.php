<?php
/**
 * update.php — in-plugin self-update against the license server.
 *   smpro_upd_check()  — ask /api/version for the latest build (vs SMPRO_VERSION).
 *   smpro_upd_apply()  — pull /api/update (license + fingerprint gated), verify SHA, swap files,
 *                        re-register AppConfig. Runs as root (WHM CGI), so it can rewrite its own dir.
 *   smpro_upd_auto()   — called from the notify cron; auto-applies when enabled + a newer build exists.
 * Reuses license.php: smpro_lic_api(), smpro_lic_payload(), smpro_lic_key(), smpro_lic_ua(), SMPRO_LIC_BASE.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_UPD_DIR',  SMPRO_VARLIB . '/updates');
define('SMPRO_UPD_CFG',  SMPRO_VARLIB . '/update.json');
define('SMPRO_UPD_LOCK', SMPRO_UPD_DIR . '/.lock');

// Pinned RSA public key for RELEASE SIGNING. Release tarballs are signed at publish time with the
// matching PRIVATE key, which is kept OFFLINE (build machine only — never on the license server). The
// plugin verifies the signature over the exact tarball bytes before applying any update, so even a fully
// compromised license server cannot push a malicious update (it has no private key to forge a signature).
define('SMPRO_UPD_PUBKEY',
    "-----BEGIN PUBLIC KEY-----\n"
  . "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA2OKZTIB4S7cqRnoTj0q0\n"
  . "rPGhqSOKT0lDggnza7QYhP0qFe1lH7s3j16varPsiFjBSBY9brHG5GGoS90PnwHx\n"
  . "YzNfOXZEIw3UCClaq6roveRN8w9du5egyb1ElXkpV2OXj42WKdMZ8tdA8hm/Q7jY\n"
  . "GmmS6+VObnLHrMJyfb03Hxn0G4ximuO77vmttKAkayIbc44e4rLgv3RRAfXNgBSr\n"
  . "XnFstDDrr7WbuSdscOnixKyK7DFezt5VL4atnxfj1RlDxgszpPyDC0+Z/Zb5iwr2\n"
  . "h5c3EWMAKejoYI30RtACMtJbSWAGBAQEgh55ZJb/DbysFlXPZlm3l0WUw3cccjc8\n"
  . "coHVj1G2csGsrURvRGUi4a3p6KsplGyfqDEZaF061LU1C9zS/+oxC5PhDseOs64G\n"
  . "SiCA+iSJKm9mwTIQvnxHOcgShwGUF07DsL2a1xsGdaHlWd1GBAOtnqMXwsYC5ChF\n"
  . "IO1aoVYQjV9psv6/7kHz/ZcAHvWQU/lolYWcMsEyQHmTAgMBAAE=\n"
  . "-----END PUBLIC KEY-----\n");

/* ---------------- config (auto-update toggle + status) ---------------- */
function smpro_upd_cfg() {
    $d = is_file(SMPRO_UPD_CFG) ? json_decode((string)@file_get_contents(SMPRO_UPD_CFG), true) : null;
    if (!is_array($d)) $d = [];
    return $d + ['auto' => false, 'last_check' => 0, 'last_apply' => 0, 'last_result' => '', 'latest' => '', 'channel' => 'stable'];
}
function smpro_upd_cfg_save($c) {
    @is_dir(dirname(SMPRO_UPD_CFG)) || @mkdir(dirname(SMPRO_UPD_CFG), 0700, true);
    $t = SMPRO_UPD_CFG . '.tmp';
    @file_put_contents($t, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod($t, 0600); @rename($t, SMPRO_UPD_CFG);
}

/* ---------------- check ---------------- */
function smpro_upd_check() {
    $cur = defined('SMPRO_VERSION') ? SMPRO_VERSION : '0';
    $chpayload = smpro_lic_payload(smpro_lic_key());
    if ((smpro_upd_cfg()['channel'] ?? 'stable') === 'beta') $chpayload['channel'] = 'beta';   // opt-in beta channel
    [$code, $j] = smpro_lic_api('/api/version', $chpayload, 15);
    if ($code === 200 && is_array($j) && !empty($j['ok'])) {
        $latest = (string)($j['version'] ?? '');
        $available = $latest !== '' && version_compare($latest, $cur, '>');
        $result = $available ? ('Update available: ' . $latest) : 'Up to date';
        $c = smpro_upd_cfg(); $c['last_check'] = time(); $c['latest'] = $latest; $c['last_result'] = $result; smpro_upd_cfg_save($c);
        return [
            'ok'        => true,
            'current'   => $cur,
            'latest'    => $latest,
            'available' => $available,
            'result'    => $result,
            'sha256'    => (string)($j['sha256'] ?? ''),
            'size'      => (int)($j['size'] ?? 0),
            'notes'     => (string)($j['notes'] ?? ''),
            'pushed_version' => (string)($j['pushed_version'] ?? ''),   // a build the operator pushed to THIS server
            'pushed_id'      => (int)($j['pushed_id'] ?? 0),
            'commands'       => is_array($j['commands'] ?? null) ? $j['commands'] : [],
        ];
    }
    $err = is_array($j) && isset($j['message']) ? (string)$j['message'] : ('Could not reach update server (HTTP ' . (int)$code . ')');
    $c = smpro_upd_cfg(); $c['last_check'] = time(); $c['last_result'] = 'Check failed'; smpro_upd_cfg_save($c);
    return ['ok' => false, 'current' => $cur, 'available' => false, 'result' => 'Check failed', 'message' => $err];
}

/* ---------------- apply ----------------
 * $version : '' = latest, or a specific build the operator pushed to this server.
 * $force   : true = bypass the downgrade guard (an explicit operator push, still signature-verified). */
function smpro_upd_apply($version = '', $force = false) {
    @is_dir(SMPRO_UPD_DIR) || @mkdir(SMPRO_UPD_DIR, 0700, true);
    // single-flight lock — atomic, so a cron poll + a manual UI click can't both extract over each other
    // (the old is_file()+mtime check was TOCTOU-racy → two parallel tar extractions = corrupt install).
    $lockFp = @fopen(SMPRO_UPD_LOCK, 'c');
    if (!$lockFp || !@flock($lockFp, LOCK_EX | LOCK_NB)) { if ($lockFp) fclose($lockFp); return ['ok' => false, 'message' => 'An update is already running.']; }
    @chmod(SMPRO_UPD_LOCK, 0600);

    // NOTE: do NOT @unlink() the lock file here. Unlinking a file another caller may already hold open (or is
    // about to fopen) is the classic flock race — A unlinks inode I1 while B still holds I1 and C fopen('c')s a
    // fresh inode I2 at the same path, so B and C each hold a lock on a DIFFERENT inode and both extract over the
    // live dir at once. Leaving the 0600 lock file in place (persistent) makes fopen('c')+flock single-flight sound.
    $cleanup = function () use ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); };

    $tgz = SMPRO_UPD_DIR . '/pkg.tgz'; $hdr = SMPRO_UPD_DIR . '/h.txt';
    @unlink($tgz); @unlink($hdr);
    $payload = smpro_lic_payload(smpro_lic_key());
    if ((smpro_upd_cfg()['channel'] ?? 'stable') === 'beta') $payload['channel'] = 'beta';   // opt-in beta channel
    $version = preg_replace('/[^0-9.]/', '', (string)$version);
    if ($version !== '') $payload['version'] = $version;     // ask /api/update for this SPECIFIC build
    // body carries the license key — write it to a 0600 temp file (--data-binary @file) so it never reaches argv
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $bodyFile = @tempnam(@sys_get_temp_dir() ?: '/tmp', 'smpu');
    if ($bodyFile === false) $bodyFile = SMPRO_UPD_DIR . '/.req.' . getmypid();
    @file_put_contents($bodyFile, $body); @chmod($bodyFile, 0600);
    $cmd  = 'curl -sS -m 180 -o ' . escapeshellarg($tgz) . ' -D ' . escapeshellarg($hdr)
          . ' -w ' . escapeshellarg('%{http_code}') . ' -A ' . escapeshellarg(smpro_lic_ua())
          . ' -H ' . escapeshellarg('Content-Type: application/json')
          . ' -X POST --data-binary ' . escapeshellarg('@' . $bodyFile) . ' ' . escapeshellarg(SMPRO_LIC_BASE . '/api/update') . ' 2>/dev/null';
    $code = trim((string)@shell_exec($cmd));
    @unlink($bodyFile);

    if ($code !== '200') {
        $msg = 'Update download failed (HTTP ' . $code . ')';
        if (is_file($tgz)) { $j = json_decode((string)@file_get_contents($tgz), true); if (is_array($j) && isset($j['message'])) $msg = (string)$j['message']; }
        $cleanup(); return ['ok' => false, 'message' => $msg];
    }
    // integrity
    $hdrs = is_file($hdr) ? (array)file($hdr) : [];
    $want = ''; $ver = ''; $sigB64 = '';
    foreach ($hdrs as $l) {
        if (stripos($l, 'x-smpro-sha256:') === 0)  $want   = strtolower(trim(substr($l, 15)));
        if (stripos($l, 'x-smpro-version:') === 0) $ver    = trim(substr($l, 16));
        if (stripos($l, 'x-smpro-sig:') === 0)     $sigB64 = trim(substr($l, 12));
    }
    if (!is_file($tgz) || filesize($tgz) < 1000) { $cleanup(); return ['ok' => false, 'message' => 'Empty/short download.']; }
    if ($want !== '' && hash_file('sha256', $tgz) !== $want) { $cleanup(); return ['ok' => false, 'message' => 'Integrity check failed (SHA mismatch).']; }
    // AUTHENTICITY: verify the RSA signature over the exact tarball bytes against the pinned OFFLINE-signing
    // public key. SHA alone is not enough (a compromised server can recompute it); the signature cannot be
    // forged without the offline private key — this is what blocks a malicious push from a hacked server.
    $sig = $sigB64 !== '' ? base64_decode($sigB64, true) : false;
    $pk  = function_exists('openssl_pkey_get_public') ? @openssl_pkey_get_public(SMPRO_UPD_PUBKEY) : false;
    if ($sig === false || !$pk || @openssl_verify((string)@file_get_contents($tgz), $sig, $pk, OPENSSL_ALGO_SHA256) !== 1) {
        $cleanup(); return ['ok' => false, 'message' => 'Update signature invalid — refusing to apply (the package is unsigned or tampered).'];
    }
    // DOWNGRADE GUARD: never apply an OLDER build automatically (defeats a rollback-to-known-vulnerable
    // signed package). Bypassed only on an explicit operator push ($force) — still signature-verified.
    if (!$force && $ver !== '' && defined('SMPRO_VERSION') && version_compare($ver, SMPRO_VERSION, '<')) {
        $cleanup(); return ['ok' => false, 'message' => 'Refusing to downgrade to ' . $ver . ' (current ' . SMPRO_VERSION . ').'];
    }
    if (trim((string)@shell_exec('gzip -t ' . escapeshellarg($tgz) . ' 2>&1 && echo OK')) !== 'OK' && !smpro_upd_is_gzip($tgz)) { $cleanup(); return ['ok' => false, 'message' => 'Downloaded file is not a valid archive.']; }

    // extract + locate the smpro/ payload (smpro-X.Y.Z/smpro/index.cgi)
    $ex = SMPRO_UPD_DIR . '/new'; smpro_upd_rrmdir($ex); @mkdir($ex, 0700, true);
    @shell_exec('tar -xzf ' . escapeshellarg($tgz) . ' -C ' . escapeshellarg($ex) . ' 2>/dev/null');
    $payload = '';
    foreach (glob($ex . '/*/' . SMPRO_SLUG, GLOB_ONLYDIR) ?: [] as $p) { if (is_file($p . '/index.cgi') && is_dir($p . '/includes')) { $payload = $p; break; } }
    if ($payload === '') { foreach (glob($ex . '/*', GLOB_ONLYDIR) ?: [] as $p) { if (is_file($p . '/index.cgi') && is_dir($p . '/includes')) { $payload = $p; break; } } }
    if ($payload === '') { smpro_upd_rrmdir($ex); @unlink($tgz); $cleanup(); return ['ok' => false, 'message' => 'Plugin payload not found in package.']; }

    // AUTHENTICATED downgrade guard: the X-Smpro-Version header used above is NOT signed and can be spoofed by
    // a hostile/compromised update server. The version recorded inside integrity.json lives INSIDE the tarball
    // whose bytes we just RSA-verified, so it is bound to the offline signature and cannot be forged. Re-check
    // the downgrade guard against THIS authenticated version — this is what actually blocks a signed-rollback.
    $authVer = '';
    $ij = @json_decode((string)@file_get_contents($payload . '/integrity.json'), true);
    if (is_array($ij) && isset($ij['version'])) $authVer = preg_replace('/[^0-9A-Za-z.-]/', '', (string)$ij['version']);   // keep -betaN suffix (version_compare handles it); strips only unsafe chars
    if (!$force && $authVer !== '' && defined('SMPRO_VERSION') && version_compare($authVer, SMPRO_VERSION, '<')) {
        smpro_upd_rrmdir($ex); @unlink($tgz); @unlink($hdr); $cleanup();
        return ['ok' => false, 'message' => 'Refusing to downgrade to ' . $authVer . ' (current ' . SMPRO_VERSION . ').'];
    }
    if ($authVer === '') {   // every package built since the manifest gate carries one; a signed package without it is an old build being replayed
        smpro_upd_rrmdir($ex); @unlink($tgz); @unlink($hdr); $cleanup();
        return ['ok' => false, 'message' => 'Package carries no signed version manifest — refusing to install it.'];
    }
    $ver = $authVer;   // log/record the authenticated version, not the unsigned header

    $dest = realpath(SMPRO_BASE); if (!$dest || !is_dir($dest)) { $cleanup(); return ['ok' => false, 'message' => 'Install dir not found.']; }
    $from = defined('SMPRO_VERSION') ? SMPRO_VERSION : '?';

    // EDITION GUARD. The cPanel-user edition (Safety Lock) is a superset: its includes/ carries spqueue.php and the
    // file-lock helpers its root worker needs. Overlaying a WHM-only build on top of it keeps the worker's cron and
    // the customers' page but removes the helpers, so every Protect request queues forever while the page says
    // "protected" — that is exactly what happened on 2026-09-06 when the two products shared one update channel.
    // A payload that lacks the edition's marker must never be applied over an install that has it.
    if (is_file($dest . '/includes/spqueue.php') && !is_file($payload . '/includes/spqueue.php')) {
        smpro_upd_rrmdir($ex); @unlink($tgz); @unlink($hdr); $cleanup();
        if (function_exists('smpro_audit')) @smpro_audit('update_refused_edition', ['from' => $from, 'to' => $ver, 'why' => 'WHM-only payload over the cPanel-user edition']);
        if (function_exists('smpro_notify')) @smpro_notify('update_available', 'Update ' . $ver . ' refused: wrong edition', "This server runs the cPanel-user edition of SM Pro (Safety Lock). The update offered (" . $ver . ") is the WHM-only build and would remove the account-side worker's helpers, so it was NOT applied.\nThe licence must be served the cPanel-user release channel. Nothing was changed.", ['severity' => 'high'], true);
        return ['ok' => false, 'message' => 'Refused: ' . $ver . ' is the WHM-only build, but this install is the cPanel-user edition (Safety Lock). Applying it would break the account-side worker. Nothing was changed.'];
    }

    // backup the current install (restorable) — inside the plugin's own data dir, not /root
    $bk = SMPRO_VARLIB . '/backups/selfupdate_' . date('Ymd_His');
    @mkdir($bk, 0700, true);
    @shell_exec('cp -a ' . escapeshellarg($dest) . '/. ' . escapeshellarg($bk) . '/ 2>/dev/null');
    $pruned = smpro_upd_prune_backups();   // the copy above is the newest, so it is always among the kept ones

    // apply: overlay the new payload over the live dir (php/cgi/assets updated; data dirs are OUTSIDE web root)
    @shell_exec('cp -a ' . escapeshellarg($payload) . '/. ' . escapeshellarg($dest) . '/ 2>/dev/null');
    @shell_exec('chown -R root:root ' . escapeshellarg($dest) . ' 2>/dev/null');
    @shell_exec('find ' . escapeshellarg($dest) . ' -type d -exec chmod 0755 {} \; 2>/dev/null');
    @shell_exec('find ' . escapeshellarg($dest) . ' -type f -name "*.php" -exec chmod 0644 {} \; 2>/dev/null');
    @shell_exec('chmod 0755 ' . escapeshellarg($dest . '/index.cgi') . ' 2>/dev/null');
    @shell_exec('find ' . escapeshellarg($dest . '/bin') . ' -name "*.php" -exec chmod 0755 {} \; 2>/dev/null');

    // SMOKE TEST + ROLLBACK: every shipped PHP file must parse under the CLI the crons use. A package that does not
    // (a half-copied file, a disk that filled mid-copy) is put back to the backup taken above, and the failure is
    // reported instead of a white WHM page and a dead worker fleet.
    $phpBin = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $bad = trim((string)@shell_exec('cd ' . escapeshellarg($dest) . ' && find . -name "*.php" -o -name "*.cgi" | head -n 600 | while read -r f; do ' . escapeshellarg($phpBin) . ' -l "$f" >/dev/null 2>&1 || echo "$f"; done 2>/dev/null | head -n 5'));
    if ($bad !== '') {
        @shell_exec('cp -a ' . escapeshellarg($bk) . '/. ' . escapeshellarg($dest) . '/ 2>/dev/null');
        smpro_upd_rrmdir($ex); @unlink($tgz); @unlink($hdr); $cleanup();
        if (function_exists('smpro_audit')) @smpro_audit('update_rolled_back', ['from' => $from, 'to' => $ver, 'bad' => $bad]);
        if (function_exists('smpro_notify')) @smpro_notify('update_available', 'Update ' . $ver . ' rolled back', 'The new build did not pass the parse check (' . str_replace("\n", ', ', $bad) . "). The previous version was restored from its backup and is running.", ['severity' => 'high']);
        return ['ok' => false, 'message' => 'Update ' . $ver . ' failed the parse check and was rolled back to ' . $from . ' (' . str_replace("\n", ', ', $bad) . ').'];
    }
    // files the new build no longer ships are removed (code under the install dir only; data lives outside it), so a
    // function moved between includes can never be declared twice
    if (is_array($ij) && is_array($ij['files'] ?? null)) {
        $keep = array_flip(array_keys($ij['files'])); $gone = 0;
        $itr = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dest, FilesystemIterator::SKIP_DOTS));
        foreach ($itr as $fi) {
            $rel = ltrim(str_replace('\\', '/', substr($fi->getPathname(), strlen($dest))), '/');
            if (!preg_match('#\.(php|cgi|js|css)$#', $rel) || isset($keep[$rel]) || strpos($rel, 'includes/spqueue') === 0) continue;   // the cPanel-user edition's extras stay
            if (@unlink($fi->getPathname())) $gone++;
        }
        if ($gone && function_exists('smpro_audit')) @smpro_audit('update_pruned', ['removed' => $gone]);
    }
    // re-register AppConfig (in case the conf/url changed) — harmless if unchanged
    smpro_upd_register();

    smpro_upd_rrmdir($ex); @unlink($tgz); @unlink($hdr); $cleanup();

    $c = smpro_upd_cfg(); $c['last_apply'] = time(); $c['last_result'] = 'updated to ' . ($ver ?: 'latest'); smpro_upd_cfg_save($c);
    if (function_exists('smpro_audit')) smpro_audit('self_update', ['from' => $from, 'to' => $ver, 'backup' => $bk, 'pruned_backups' => $pruned]);
    return ['ok' => true, 'from' => $from, 'to' => $ver ?: 'latest', 'backup' => $bk];
}

/** SELF-HEAL the WHM menu entry: if the AppConfig registration is missing (a cPanel upcp/rebuild can wipe
 *  /var/cpanel/apps), re-register so the plugin link reappears WITHOUT needing an update or manual action.
 *  Throttled hourly; runs from the cron workers (independent of the WHM link, so it heals even when the link is
 *  gone). Prefers bin/register.sh (writes /var/cpanel/apps + rebuilds WHM chrome); falls back to smpro_upd_register. */
/**
 * Retire the cron entries of this product's PREDECESSOR ("Safety Monitor" / the first Safety Lock) when they are
 * still installed beside SM Pro. Those workers lock files and write .htaccess guards every minute from their own
 * state and know nothing of SM Pro's ignore list or its unlocks, so an account the operator force-unprotected here
 * was re-locked by them a minute later. The files are MOVED to /root/smpro-legacy-crons (never deleted), the move
 * is audited, and the Notifications channel is told once. Idempotent; hourly-throttled by the caller.
 */
function smpro_upd_retire_legacy_crons(): array {
    $legacy = ['safetylock_relock', 'safety_monitor_php_harden_relock', 'safety_monitor_php_harden_public_sync'];
    $moved = []; $dest = '/root/smpro-legacy-crons';
    foreach ($legacy as $name) {
        $f = '/etc/cron.d/' . $name;
        if (!@is_file($f) || @is_link($f)) continue;
        @is_dir($dest) || @mkdir($dest, 0700, true);
        if (@rename($f, $dest . '/' . $name . '.' . date('Ymd_His'))) $moved[] = $name;
    }
    if ($moved) {
        if (function_exists('smpro_audit')) smpro_audit('legacy_cron_retired', ['crons' => $moved, 'moved_to' => $dest]);
        if (function_exists('smpro_notify')) @smpro_notify('plugin_mode_change', 'Predecessor plugin crons retired',
            "These cron entries of the old Safety Monitor / Safety Lock were still running every minute beside SM Pro and re-locked accounts that SM Pro had unprotected (they do not know SM Pro's ignore list):\n  - " . implode("\n  - ", $moved) .
            "\n\nThey were moved to $dest (not deleted). File protection is handled by SM Pro's PHP Harden and Safety Lock only from now on.", ['severity' => 'medium']);
    }
    return $moved;
}
function smpro_upd_ensure_registered() {
    if (!is_dir('/var/cpanel')) return;                                   // cPanel boxes only
    $stamp = SMPRO_VARLIB . '/.regchk';
    if (is_file($stamp) && (time() - (int)@filemtime($stamp)) < 3600) return;
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true); @touch($stamp);
    $slug = basename(realpath(SMPRO_BASE) ?: (string)SMPRO_BASE);          // actual addon dir: smpro (prod) / smprov1 (test)
    $conf = '/var/cpanel/apps/' . $slug . '.conf';
    // HEAL when the conf is MISSING *or* INCOMPLETE: a conf written by an older self-update path lacked entryurl=,
    // which registers the app but produces NO clickable WHM menu link. Treat "no entryurl" as needs-reregister so a
    // box that updated through that path (e.g. via the license channel) gets its link back automatically.
    $ok = is_file($conf) && stripos((string)@file_get_contents($conf), 'entryurl') !== false;
    if ($ok) return;                                                      // complete menu entry present → nothing to do
    $rs = SMPRO_BASE . '/bin/register.sh';
    if (is_file($rs)) @shell_exec('bash ' . escapeshellarg($rs) . ' >/dev/null 2>&1');
    else smpro_upd_register();
    if (function_exists('smpro_audit')) smpro_audit('appconfig_reregister', ['reason' => is_file($conf) ? 'incomplete_conf_no_entryurl' : 'missing_menu_entry']);
}
function smpro_upd_register() {
    $reg = '/usr/local/cpanel/bin/register_appconfig';
    if (!is_executable($reg)) return;
    // Single source of truth: prefer bin/register.sh — it writes the COMPLETE appconfig (incl. entryurl=) to
    // /var/cpanel/apps AND rebuilds the WHM chrome. The inline fallback below MUST mirror it; a conf MISSING
    // entryurl= registers the app but produces NO clickable WHM menu link (the root cause of "the plugin link
    // doesn't appear in WHM" after a self-update, which writes the conf via this path rather than register.sh).
    $rs = SMPRO_BASE . '/bin/register.sh';
    if (is_file($rs)) { @shell_exec('bash ' . escapeshellarg($rs) . ' >/dev/null 2>&1'); return; }
    $slug = SMPRO_SLUG;
    $conf = "name=" . $slug . "\nservice=whostmgr\nuser=root\nacls=all\n"
          . "displayname=" . SMPRO_NAME . "\nurl=/cgi/addons/" . $slug . "/index.cgi\n"
          . "entryurl=addons/" . $slug . "/index.cgi\ntarget=_self\n"
          . "searchtext=safety monitor pro security forensics login audit firewall\n";
    $tmp = SMPRO_UPD_DIR . '/' . $slug . '.conf';
    @file_put_contents($tmp, $conf);
    @shell_exec(escapeshellarg($reg) . ' ' . escapeshellarg($tmp) . ' 2>/dev/null');
    // also write /var/cpanel/apps directly (register_appconfig may emit its own appname= variant) so WHM reads ours
    if (is_dir('/var/cpanel/apps')) { @copy($tmp, '/var/cpanel/apps/' . $slug . '.conf'); @chmod('/var/cpanel/apps/' . $slug . '.conf', 0600); }
    // targeted, non-disruptive WHM nav rebuild so a self-update keeps the menu entry visible
    if (is_executable('/usr/local/cpanel/scripts/rebuild_whm_chrome')) @shell_exec('/usr/local/cpanel/scripts/rebuild_whm_chrome >/dev/null 2>&1');
}

/** Uninstall the plugin from this server: unregister the WHM entry, remove cron jobs, optionally purge
 *  data+logs, then delete the install dir + rebuild the WHM menu (detached, so the HTTP response returns first).
 *  Runs as root. Returns the list of steps performed. */
function smpro_plugin_uninstall($purge = false) {
    $done = [];
    // 1) unregister the WHM AppConfig entry (the menu item)
    $unreg = '/usr/local/cpanel/bin/unregister_appconfig';
    if (is_executable($unreg)) { @shell_exec($unreg . ' ' . escapeshellarg(SMPRO_SLUG) . ' 2>/dev/null'); $done[] = 'Unregistered the WHM menu entry'; }
    // 2) remove every cron job this plugin installed (glob — covers hub/update/login-guard/notify/etc.)
    $crons = 0; foreach (glob('/etc/cron.d/' . SMPRO_SLUG . '-*') ?: [] as $c) { if (@unlink($c)) $crons++; }
    if ($crons) $done[] = "Removed $crons cron job(s)";
    // 3) optionally purge data + logs (license state lives here too)
    if ($purge) {
        // quarantine (the only copy of a quarantined file), remediation backups and the emergency-undo book are set
        // aside, never purged: a false positive must stay restorable after the plugin is gone
        if (defined('SMPRO_VARLIB') && is_dir(SMPRO_VARLIB)) {
            $keep = dirname(SMPRO_VARLIB) . '/' . basename(SMPRO_VARLIB) . '-keep'; @is_dir($keep) || @mkdir($keep, 0700, true);
            foreach (['quarantine', 'backups', 'emergency.json', 'detections'] as $k) if (file_exists(SMPRO_VARLIB . '/' . $k)) @rename(SMPRO_VARLIB . '/' . $k, $keep . '/' . $k . '.' . date('Ymd_His'));
            $done[] = 'Quarantine, backups and the emergency-undo book were kept at ' . $keep;
            @shell_exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB) . ' 2>/dev/null');
        }
        if (defined('SMPRO_VARLOG') && is_dir(SMPRO_VARLOG)) @shell_exec('rm -rf ' . escapeshellarg(SMPRO_VARLOG) . ' 2>/dev/null');
        $done[] = 'Purged data + logs';
    } else {
        $done[] = 'Kept data + logs (' . (defined('SMPRO_VARLIB') ? SMPRO_VARLIB : '') . ')';
    }
    if (function_exists('smpro_audit')) smpro_audit('plugin_uninstall', ['purge' => $purge ? 1 : 0]);
    // 4) delete the install dir LAST + rebuild the WHM menu, DETACHED so this request can still return a response.
    //    Guard: only ever remove a path under /addons/ (never anything else), even if SMPRO_BASE is odd.
    $dest = realpath(SMPRO_BASE);
    if ($dest && is_dir($dest) && strpos(str_replace('\\', '/', $dest), '/addons/') !== false) {
        $rebuild = is_executable('/usr/local/cpanel/scripts/rebuild_whm_chrome') ? '; /usr/local/cpanel/scripts/rebuild_whm_chrome >/dev/null 2>&1' : '';
        @shell_exec('(sleep 1; rm -rf ' . escapeshellarg($dest) . $rebuild . ') >/dev/null 2>&1 &');
        $done[] = 'Removing plugin files';
    }
    return $done;
}

/* ---------------- auto-update (cron) ----------------
 * Runs ~daily from the background worker. ALWAYS performs the check (so the latest
 * available version is recorded and shown in the UI even when auto-update is OFF);
 * only APPLIES the new build when auto-update is enabled. */
function smpro_upd_auto() {
    $c = smpro_upd_cfg();
    if (time() - (int)($c['last_check'] ?? 0) < 600) return;           // poll at most every ~10 min (commands + version)
    $chk = smpro_upd_check();                                          // refreshes "latest" + records last_check
    if (empty($chk['ok'])) return;
    // 0) FORCE UPDATE (operator, SIGNED): a signed `upd_force` directive in the license verdict force-applies the
    //    CURRENT channel build, bypassing ONLY the version_compare downgrade guard — the RSA package signature is
    //    STILL enforced, so this can never apply unsigned/forged code, only a genuinely-signed build the operator
    //    points the channel at. Because it rides the SIGNED payload (not the unsigned command channel), a TLS relay
    //    or replayed command can't trigger it. One-shot: deduped on the directive value (a nonce the operator bumps).
    //    Purpose: move a server off an out-of-order version string (e.g. a legacy beta the new scheme sorts below).
    if (function_exists('smpro_lic_signed_field')) {
        $fv = (string)smpro_lic_signed_field(smpro_lic_state(), 'upd_force', '');
        if ($fv !== '' && $fv !== (string)($c['upd_force_done'] ?? '')) {
            $c['upd_force_done'] = $fv; smpro_upd_cfg_save($c);
            $r = smpro_upd_apply('', true);   // '' = the channel's latest signed build; true = bypass version_compare only
            if (function_exists('smpro_audit')) smpro_audit('update_forced', ['directive' => $fv, 'ok' => !empty($r['ok']), 'msg' => (string)($r['message'] ?? '')]);
            if (!empty($r['ok'])) return;     // files swapped → stop this cycle
        }
    }
    // 1) per-server commands queued by the operator (update / restart / revoke) → execute + ack each
    if (!empty($chk['commands']) && is_array($chk['commands'])) {
        // dedup: never re-run a command id we already processed (the command channel is unsigned, so a replayed
        // /api/version response can't make us re-execute register/rebuild/update churn). Capped ring of recent ids.
        $seen = array_values(array_filter(array_map('intval', (array)($c['cmd_seen'] ?? []))));
        foreach ($chk['commands'] as $cmd) {
            $id = (int)($cmd['id'] ?? 0); $name = (string)($cmd['command'] ?? ''); $args = (string)($cmd['args'] ?? '');
            if ($id <= 0 || in_array($id, $seen, true)) continue;
            // a command that carries a signature must verify against the pinned OFFLINE key (id|command|args); one that
            // carries a signature that does not verify is a forgery and is dropped before anything else happens
            if (isset($cmd['sig']) && (string)$cmd['sig'] !== '') {
                $sig = base64_decode((string)$cmd['sig'], true); $pk = function_exists('openssl_pkey_get_public') ? @openssl_pkey_get_public(SMPRO_UPD_PUBKEY) : false;
                if ($sig === false || !$pk || @openssl_verify($id . '|' . $name . '|' . $args, $sig, $pk, OPENSSL_ALGO_SHA256) !== 1) {
                    if (function_exists('smpro_audit')) smpro_audit('update_cmd_bad_sig', ['id' => $id, 'command' => $name]);
                    continue;
                }
            }
            $seen[] = $id; $seen = array_slice($seen, -200); $c['cmd_seen'] = $seen; smpro_upd_cfg_save($c);
            $ok = false; $res = '';
            if ($name === 'update') {
                // The /api/version command list is NOT signed, so it must not be able to waive the downgrade
                // guard ($force stays false). A forged 'update' command can therefore only move FORWARD to a
                // genuinely-signed newer build — never roll the fleet back onto a signed-but-vulnerable one.
                $r = smpro_upd_apply(preg_replace('/[^0-9.]/', '', $args), false);
                $ok = !empty($r['ok']); $res = (string)($r['message'] ?? ($r['to'] ?? 'applied'));
            } elseif ($name === 'restart') {
                if (function_exists('smpro_upd_register')) smpro_upd_register();
                $ok = true; $res = 're-registered WHM entry';
            } elseif ($name === 'revoke') {
                if (function_exists('smpro_lic_check')) @smpro_lic_check();   // server already suspended → refresh to lock
                $ok = true; $res = 'acknowledged (suspended server-side)';
            } else { $ok = true; $res = 'unknown command ignored'; }
            smpro_upd_ack($id, $ok, $res);
            if ($name === 'update' && $ok) return;   // files swapped → stop this cycle
        }
        return;
    }
    // 1b) NEW BUILD AVAILABLE, auto-update OFF → tell the admin (once per version) instead of it only
    //     showing on the Updates page. Also persist the release notes so the changelog survives the check.
    if (!empty($chk['available'])) {
        $lv = (string)($chk['latest'] ?? '');
        if (($nt = (string)($chk['notes'] ?? '')) !== '') { $c = smpro_upd_cfg(); $c['notes'] = mb_substr($nt, 0, 2000); smpro_upd_cfg_save($c); }
        if ($lv !== '' && empty($c['auto']) && $lv !== (string)($c['notified_ver'] ?? '') && function_exists('smpro_notify')) {
            smpro_notify('update_available', 'SM Pro update available: ' . $lv,
                'A newer build (' . $lv . ') is available. Auto-update is OFF — open the Updates page to review and install it.'
                . ($chk['notes'] ? "\n\nRelease notes:\n" . mb_substr((string)$chk['notes'], 0, 600) : ''),
                ['severity' => 'info']);
            $c = smpro_upd_cfg(); $c['notified_ver'] = $lv; smpro_upd_cfg_save($c);
        }
    }
    // 2) normal auto-update to the latest build (only when auto-update is on AND not in Dry-Run)
    if (!empty($chk['available']) && !empty($c['auto']) && !(function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run())) smpro_upd_apply();
}

/** Acknowledge a pushed command back to the license server (marks it done/failed in the panel). */
function smpro_upd_ack($id, $ok, $result = '') {
    $id = (int)$id; if ($id <= 0) return;
    $payload = smpro_lic_payload(smpro_lic_key());
    $payload['id'] = $id; $payload['ok'] = $ok ? 1 : 0; $payload['result'] = mb_substr((string)$result, 0, 300);
    smpro_lic_api('/api/command-ack', $payload, 12);
}

/* Self-install a dedicated daily cron that runs the update check (and auto-applies if enabled),
 * independent of the notify cron. Idempotent — safe to call on every Updates-page view. */
/** cron_sync entry. */
function smpro_upd_cron_sync(): bool { if (defined('SMPRO_TEST_SRC')) return true; smpro_upd_install_cron(); return true; }
function smpro_upd_install_cron() {
    $f = '/etc/cron.d/smpro-update';
    $bin = SMPRO_BASE . '/bin/update_check.php';
    if (!is_file($bin)) return;
    $php = smpro_php_cli_bin();
    $lock = SMPRO_VARLIB . '/locks/update.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — update + per-server command poll (every 15 min; self-throttled to ~10 min)\n"
             . "*/15 * * * * root $flock -n $lock timeout 600 $php $bin >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return;   // already current
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}

/* ---------------- helpers ---------------- */
function smpro_upd_is_gzip($f) { $h = (string)@file_get_contents($f, false, null, 0, 2); return strlen($h) === 2 && ord($h[0]) === 0x1f && ord($h[1]) === 0x8b; }
// A symlink is removed as a link, never descended into: is_dir() follows symlinks, so without this check a
// link inside the tree (from an extracted tarball, or preserved by the backup's cp -a) would have its TARGET's
// contents deleted instead of the link itself.
function smpro_upd_rrmdir($d) { if (!is_dir($d)) return; foreach (scandir($d) ?: [] as $e) { if ($e === '.' || $e === '..') continue; $p = $d . '/' . $e; if (is_link($p)) { @unlink($p); continue; } is_dir($p) ? smpro_upd_rrmdir($p) : @unlink($p); } @rmdir($d); }

/**
 * Keep only the newest $keep self-update backups.
 * Every update leaves a full copy of the install, and nothing used to remove them: measured at 252 directories
 * / 1.8 GB on a beta-channel server after seven weeks, which is a real problem on a small VPS.
 * Deliberately narrow — it only ever removes a directory that sits DIRECTLY in the backups dir and whose name
 * matches the exact stamp smpro_upd_apply() itself writes. Anything else put there by hand is left alone.
 */
function smpro_upd_prune_backups($keep = 3) {
    $dir = SMPRO_VARLIB . '/backups';
    if ($keep < 1 || !is_dir($dir)) return 0;
    $found = [];
    foreach (scandir($dir) ?: [] as $e) {
        if (!preg_match('/^selfupdate_\d{8}_\d{6}$/', $e)) continue;
        $p = $dir . '/' . $e;
        if (is_dir($p) && !is_link($p)) $found[] = $e;
    }
    if (count($found) <= $keep) return 0;
    sort($found);   // the names are timestamps, so this is chronological
    $gone = 0;
    foreach (array_slice($found, 0, count($found) - $keep) as $old) { smpro_upd_rrmdir($dir . '/' . $old); $gone++; }
    return $gone;
}
