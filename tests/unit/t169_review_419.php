<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t169 - third review round: the remaining places where root acted by path inside an account folder, a home move
 * that went on after a failed copy, a quarantine of a file that had changed since it was reported, backups that
 * overwrote each other, a crontab installed from a file that was not fully written, cron files written in place.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$fa = $src('modules/forensics-audit.php');
has($fa, "if (!smpro_acct_restore(\$ru, \$bak, \$file, 0644)) return", 'A1: a deleted file is put back as the account');
ok(strpos($fa, '@copy($bak, $file)') === false, 'A2: ...not by a root copy that follows a link at the freed name');
$lr = $src('includes/learn.php');
has($lr, "smpro_acct_restore((string)\$m[1], \$kept, (string)\$hit['orig'],", 'A3: Learned Defense restores as the account');
ok(strpos($lr, "@chown(\$hit['orig']") === false, 'A4: ...and no longer hands the file over by name');
$im = $src('includes/intrusion.php');
has($im, "\$rootOk = \$pu === '' && \$p && !preg_match('#^/home[0-9]*/#', (string)\$p);", 'A5: in the emergency undo root acts by path only outside every account home');
has($im, "if (\$pu !== '') smpro_acct_put(\$pu, (string)\$f, \$c, 0644);", 'A6: ...inside a home the owner\'s own rules are kept by a write as the account');
$iv = $src('includes/investigate.php');
ok(substr_count($iv, "\$ok = smpro_acct_sh((string)\$r['user'], '[ ! -L \"\$1\" ] && mv -- \"\$1\" \"\$2\"', [\$path, \$to], null, 60)['code'] === 0;") === 3 && strpos($iv, '$ok = @rename($path, $to);') === false, 'A7: plugins, themes, drop-ins and mu-plugins are switched off by a move the account makes');
has($iv, "\$ok = smpro_acct_restore(\$uUser, (string)\$e['to'], (string)\$e['from'], 0644, 0, false);", 'A8: undo of a file kept in the store goes back as the account');
$cc = $src('includes/ccfix.php');
ok(strpos($cc, "@file_put_contents(\$kf, '', LOCK_EX)") === false && strpos($cc, "smpro_acct_put((string)\$a['user'], \$kf, '', 0600)") !== false, 'A9: the key file is emptied as the account');
$ds = $src('modules/disk-storage.php');
has($ds, "smpro_acct_sh(\$cu, 'find \"\$1\" -mindepth 1 -not -name .gitignore -not -name index.php -delete 2>/dev/null; true', [\$d], null, 120);", 'A10: a cache folder is emptied as the account');
ok(strpos($src('includes/spqueue.php'), "@chown(\$d, \$owner['uid'])") === false, 'A11: the answer folder is made by the account, not made by root and handed over');

$hm = $src('bin/home_move.php');
has($hm, "if (!in_array(\$rrc, [0, 24], true)) {", 'B1: a copy that did not finish stops the move before the account is switched');
has($hm, "\$GLOBALS['hm_rsync_rc'] = (isset(\$st) && empty(\$st['running'])) ? (int)(\$st['exitcode'] ?? -1) : -1;", 'B2: the exit status of the copy is kept');
has($lr, "if (\$expectSha !== '' && !hash_equals(\$expectSha, \$sha)) return", 'B3: only the file that was reported is quarantined');
has($lr, "bin2hex(random_bytes(3)) . '-' . preg_replace('/[^A-Za-z0-9._-]/', '_', basename(\$safe));", 'B4: every kept copy has a name of its own');
has($ds, "date('Ymd_His') . '_' . bin2hex(random_bytes(3)) . '_'", 'B5: deleted-file backups cannot overwrite each other');
has($cc, "@file_put_contents(\$tmp, \$body) !== strlen(\$body)", 'B6: a crontab is installed only from a file that was written in full');
ok(preg_match('/(curl|wget|base64|\/tmp\/|\/dev\/shm|python|perl|\bnc |bash -c)/i', '0 3 * * * rsync -a /home/u/a /backup') === 0, 'B7: a routine rsync job is not a fetch/decode line');
has($cc, "python|perl|\\bnc |bash -c)/i", 'B8: ...and the product uses that pattern');

has($src('includes/helpers.php'), "\$tmpc = dirname(\$path) . '/.' . basename(\$path) . '.tmp';", 'C1: a cron file is written beside itself and renamed in');
has($src('includes/update.php'), "if (\$__free !== false && \$__free < 300 * 1048576) {", 'C2: an update does not start without room on the disk');
$un = is_file(SMPRO_BASE . '/packaging/uninstall.sh') ? $src('packaging/uninstall.sh') : '';
if ($un === '') tap_skip('C3: uninstall --purge keeps what cannot be recreated', 'the uninstall script is not part of this tree');
else ok(strpos($un, 'for item in quarantine backups detections emergency.json learn php_harden; do') !== false && strpos($un, 'for item in') < strpos($un, 'rm -rf "$DATA" "$LOGDIR"'), 'C3: uninstall --purge moves quarantine and backups aside before deleting');
has($src('includes/fwblock.php') . $src('includes/fwallow.php'), "smpro_csf_deny_unlock(\$dl);", 'C4: the remaining CSF list rewrites are done under the shared lock');

// beta420: an address sending CRITICAL malicious-upload requests does not wait for the general floor
$im2 = $src('includes/intrusion.php');
has($im2, "'auto_block_critical_threshold' => 3,", 'D1: a separate, low floor for critical upload requests');
has($im2, "if ((\$e['ip'] ?? '') === '' || strtoupper((string)(\$e['severity'] ?? '')) !== 'CRITICAL' || (string)(\$e['kind'] ?? '') !== 'Malicious Upload') continue;", 'D2: only CRITICAL Malicious Upload requests count towards it');
has($im2, "foreach (\$events as \$e) {   // counted over the whole hour", 'D3: counted over the hour that was read (the real case sent three, ten minutes apart)');
ok(strpos($im2, 'foreach ($critOf as $cip => $cn)') < strpos($im2, "if (smpro_im_allowlisted(\$ip)) continue;", strpos($im2, 'foreach ($critOf as $cip => $cn)')), 'D4: such an address still passes the allow-list and home-region guards');
