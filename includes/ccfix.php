<?php
/**
 * includes/ccfix.php — Compromise Check: the fixes, and the scheduled scan.
 *
 * FIXES. Each server check and each account door may carry one or more fix targets ('fixes' => [[op, args...]]).
 * The page renders them as buttons; the POST handler runs smpro_cx_apply(). Rules that hold for every op:
 *   - the operator is root (smpro_require_root) and the request carries a valid CSRF token;
 *   - every argument is validated by a strict pattern - nothing from the browser reaches a shell unvalidated;
 *   - anything removed or rewritten is BACKED UP FIRST under SMPRO_VARLIB/backups/compcheck/<stamp>/ and the
 *     result names the backup (standing rule: never strip a file without keeping the original);
 *   - the op re-reads the live file and acts on what it finds NOW (a line identified by its sha1), so a stale
 *     page cannot delete the wrong line;
 *   - the result is audited with the actor and the target;
 *   - an op that cannot be done safely by a program (a reseller ACL, an uid-0 user, a tampered template, a
 *     hidden process) has no button - the "what to do" text is the fix.
 *
 * SCHEDULE. smpro_cx_sched_cfg() holds the plan; /etc/cron.d/smpro-compcheck runs bin/compcheck_tick.php every
 * ten minutes, which runs the scan when it is due, stores the report under SMPRO_VARLIB/reports/compcheck/ and
 * notifies through the product's channels (type compromise_check) according to the plan's "tell me when".
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_CX_BACKUPS')) define('SMPRO_CX_BACKUPS', SMPRO_VARLIB . '/backups/compcheck');
if (!defined('SMPRO_CX_SCHED'))   define('SMPRO_CX_SCHED',   SMPRO_VARLIB . '/compcheck_schedule.json');
if (!defined('SMPRO_CX_REPORTS')) define('SMPRO_CX_REPORTS', SMPRO_VARLIB . '/reports/compcheck');
if (!defined('SMPRO_CX_CRON'))    define('SMPRO_CX_CRON',    '/etc/cron.d/smpro-compcheck');

/* ------------------------------------------------------------------ what each op is, for the page */

/** Ops the page may offer: label, confirmation text, and the argument patterns. */
function smpro_cx_ops(): array {
    static $ops = null;
    if ($ops !== null) return $ops;
    $user = '/^[a-zA-Z0-9._-]{1,64}$/'; $sha = '/^[0-9a-f]{40}$/';
    $ops = [
        'cphulk_on'    => ['label' => 'Enable cPHulk', 'confirm' => 'Turn cPHulk on and whitelist your current address first so this session cannot be locked out?', 'args' => []],
        'im_comp_on'   => ['label' => 'Turn the reset on', 'confirm' => 'Tell Imunify360 to reset the password of an account it finds compromised?', 'args' => []],
        'sshd_harden'  => ['label' => 'Keys only for root', 'confirm' => 'Set PasswordAuthentication no and PermitRootLogin prohibit-password, validate with sshd -t, restart sshd. Only offered while /root/.ssh/authorized_keys holds a key. Keep this session open and test a new one afterwards.', 'args' => []],
        'line_rm'      => ['label' => 'Remove this line', 'confirm' => 'Remove this line from the file? The original is backed up first.', 'args' => ['file' => '/^\/[A-Za-z0-9._\/-]{1,200}$/', 'sha' => $sha]],
        'preload_empty'=> ['label' => 'Empty the file', 'confirm' => 'Empty /etc/ld.so.preload (original backed up)? Then treat the server as compromised.', 'args' => []],
        'wheel_rm'     => ['label' => 'Remove from wheel/sudo', 'confirm' => 'Take this user out of the wheel and sudo groups?', 'args' => ['user' => $user]],
        'rootkey_rm'   => ['label' => 'Remove this key', 'confirm' => 'Remove this key from /root/.ssh/authorized_keys (original backed up)? Be sure it is not the one you are using.', 'args' => ['sha' => $sha]],
        'roottok_revoke'=> ['label' => 'Revoke', 'confirm' => 'Revoke this WHM API token? It stops working at once and cannot be brought back - anything using it must be given a new one.', 'args' => ['name' => '/^[A-Za-z0-9._-]{1,128}$/']],
        'roottok_disable'=> ['label' => 'Disable (expire now)', 'confirm' => 'Give this WHM API token an expiry in the past? It stops opening anything immediately, but it stays in the list with its name and history - use this when you are not yet sure what uses it.', 'args' => ['name' => '/^[A-Za-z0-9._-]{1,128}$/']],
        'ftp_delete'   => ['label' => 'Delete the login, keep the files', 'confirm' => 'Delete this FTP sub-account? Only the LOGIN goes: its home folder and every file in it stay exactly where they are (cPanel is told destroy=0), and the FTP password file is backed up first.', 'args' => ['user' => $user, 'login' => '/^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}$/']],
        'fwd_delete'   => ['label' => 'Delete forwarder', 'confirm' => 'Delete this forwarder?', 'args' => ['user' => $user, 'address' => '/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}$/', 'target' => '/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}$/']],
        'cron_clean'   => ['label' => 'Remove fetch/decode lines', 'confirm' => 'Remove every cron line of this account that fetches or decodes code (crontab backed up first)? Routine lines stay.', 'args' => ['user' => $user]],
        'cron_line_off'=> ['label' => 'Switch off', 'confirm' => 'Switch this cron line off? It stays in the crontab as a comment (# SMPRO-OFF ...), stops running at once, and one click puts it back. The crontab is backed up first.', 'args' => ['user' => $user, 'sha' => $sha]],
        'cron_line_rm' => ['label' => 'Remove', 'confirm' => 'Remove this one cron line? The crontab is backed up first; the other lines stay.', 'args' => ['user' => $user, 'sha' => $sha]],
        'cron_line_on' => ['label' => 'Put back', 'confirm' => 'Put this switched-off cron line back into service?', 'args' => ['user' => $user, 'sha' => $sha]],
        'sshkey_clear' => ['label' => 'Remove all keys', 'confirm' => 'Remove every authorised SSH key of this account (file backed up first)? The customer re-adds theirs in cPanel.', 'args' => ['user' => $user]],
        'token_revoke' => ['label' => 'Revoke', 'confirm' => 'Revoke this cPanel API token? It stops working at once and cannot be brought back - anything using it must be given a new one.', 'args' => ['user' => $user, 'name' => '/^[A-Za-z0-9._-]{1,128}$/']],
        'token_disable'=> ['label' => 'Disable (expire now)', 'confirm' => 'Give this account token an expiry in the past? It stops opening anything immediately and stays in the list with its name and history. Done through the token store cPanel itself uses, then read back through the public API to confirm.', 'args' => ['user' => $user, 'name' => '/^[A-Za-z0-9._-]{1,128}$/']],
        'rc_clean'     => ['label' => 'Remove the lines', 'confirm' => 'Remove the fetch/decode lines from this account\'s shell start-up files (backed up first)?', 'args' => ['user' => $user]],
    ];
    return $ops;
}

/* ------------------------------------------------------------------ plumbing */

/**
 * May root write to this file inside an account's home? Only a REGULAR file (lstat, never following a link) owned
 * by that account. The account controls its home: ~/.ssh/authorized_keys could be a symlink to root's own
 * authorized_keys, ~/.bashrc to /etc/profile - and a routine operator click ("remove all keys") would then have
 * root truncating root's file. Refused with the reason, never followed.
 */
function smpro_cx_account_file_ok(string $path, int $uid): string {
    $st = @lstat($path);
    if (!is_array($st)) return 'missing';
    if (($st['mode'] & 0170000) !== 0100000) return 'not a regular file (a symlink or special file) - refused';
    if ((int)$st['uid'] !== $uid) return 'owned by uid ' . (int)$st['uid'] . ', not the account - refused';
    return '';
}

function smpro_cx_run(string $cmd, int $t = 60): string {
    return function_exists('smpro_run') ? (string)smpro_run($cmd, $t) : (string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>&1');
}

/** Copy $file into a fresh backup folder; returns the backup path or '' when it could not be kept (then nothing is changed). */
function smpro_cx_backup(string $file): string {
    if (!@is_file($file)) return '';
    $dir = SMPRO_CX_BACKUPS . '/' . date('Ymd_His') . '_' . substr(sha1($file . microtime(true)), 0, 6);
    if (!@is_dir($dir) && !@mkdir($dir, 0700, true)) return '';
    $to = $dir . '/' . basename($file) . '.' . substr(sha1($file), 0, 8);   // ORIGIN.txt beside it names the full path
    if (!@copy($file, $to)) return '';
    @chmod($to, 0600);
    @file_put_contents($dir . '/ORIGIN.txt', $file . "\n" . date('c') . "\n");
    return $to;
}

/** Remove from $file every non-comment line whose sha1(trim) is $sha. Returns [removed count, backup path]. */
function smpro_cx_line_rm(string $file, string $sha): array {
    $lines = @file($file, FILE_IGNORE_NEW_LINES);
    if (!is_array($lines)) return [0, ''];
    $keep = []; $n = 0;
    foreach ($lines as $l) { if (sha1(trim($l)) === $sha) { $n++; continue; } $keep[] = $l; }
    if ($n === 0) return [0, ''];
    $bk = smpro_cx_backup($file); if ($bk === '') return [0, ''];
    $perm = @fileperms($file) & 0777; $own = @fileowner($file); $grp = @filegroup($file);
    if (@file_put_contents($file, implode("\n", $keep) . ($keep ? "\n" : ''), LOCK_EX) === false) return [0, $bk];
    @chmod($file, $perm ?: 0644); if ($own !== false) @chown($file, $own); if ($grp !== false) @chgrp($file, $grp);
    return [$n, $bk];
}

/** Files line_rm may touch: root's persistence files only. */
function smpro_cx_line_rm_allowed(string $file): bool {
    if (strpos($file, '..') !== false) return false;
    foreach (['/etc/sudoers', '/etc/sudoers.d/', '/var/spool/cron/root', '/etc/crontab', '/etc/anacrontab', '/etc/cron.d/', '/etc/cron.hourly/', '/etc/cron.daily/', '/etc/cron.weekly/', '/etc/cron.monthly/',
              '/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/profile', '/etc/bashrc', '/etc/profile.d/'] as $p) {
        if ($file === $p || (substr($p, -1) === '/' && strpos($file, $p) === 0)) return true;
    }
    return false;
}

/* ------------------------------------------------------------------ apply */

/**
 * Apply one fix. $args come from the browser and are validated here against smpro_cx_ops().
 * @return array{ok:bool,msg:string,backup?:string}
 */
function smpro_cx_apply(string $op, array $args, string $actor = ''): array {
    $ops = smpro_cx_ops();
    if (!isset($ops[$op])) return ['ok' => false, 'msg' => 'unknown fix'];
    $a = [];
    foreach ($ops[$op]['args'] as $k => $pat) {
        $v = (string)($args[$k] ?? '');
        if (!preg_match($pat, $v)) return ['ok' => false, 'msg' => 'refused: argument "' . $k . '" is not in the expected form'];
        $a[$k] = $v;
    }
    $r = ['ok' => false, 'msg' => ''];
    try {
        switch ($op) {
            case 'cphulk_on':
                $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
                if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) smpro_cx_run('/usr/local/cpanel/bin/whmapi1 create_cphulk_record list_name=white ip=' . escapeshellarg($ip) . ' comment=' . escapeshellarg('SM Pro Compromise Check operator') . ' --output=json', 30);
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/whmapi1 enable_cphulk --output=json', 60), true);
                $st = json_decode(smpro_cx_run('/usr/local/cpanel/bin/whmapi1 cphulk_status --output=json', 30), true);
                $r = !empty($st['data']['is_enabled']) ? ['ok' => true, 'msg' => 'cPHulk is on' . ($ip ? '; ' . $ip . ' whitelisted' : '')] : ['ok' => false, 'msg' => 'cPHulk did not come on: ' . (string)($o['metadata']['reason'] ?? 'no reason given')];
                break;
            case 'im_comp_on':
                $bin = @is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : 'imunify360-agent';
                smpro_cx_run($bin . ' config update ' . escapeshellarg('{"CONTROL_PANEL":{"compromised_user_password_reset":true}}'), 60);
                @unlink(SMPRO_CACHE . '/memo_im_config_show.json');   // the page reads a memo of this; it is stale now
                $im = json_decode(smpro_cx_run($bin . ' config show', 30), true);
                $on = !empty($im['CONTROL_PANEL']['compromised_user_password_reset']);
                $r = $on ? ['ok' => true, 'msg' => 'Imunify360 will now reset a compromised account\'s password'] : ['ok' => false, 'msg' => 'Imunify360 did not accept the setting'];
                break;
            case 'sshd_harden':
                $keys = @is_readable('/root/.ssh/authorized_keys') ? array_filter(array_map('trim', (array)@file('/root/.ssh/authorized_keys')), fn($l) => $l !== '' && $l[0] !== '#') : [];
                if (!$keys) { $r = ['ok' => false, 'msg' => 'refused: /root/.ssh/authorized_keys holds no key - you would be locked out']; break; }
                $cfg = '/etc/ssh/sshd_config';
                $bk = smpro_cx_backup($cfg); if ($bk === '') { $r = ['ok' => false, 'msg' => 'could not back up sshd_config - nothing changed']; break; }
                $s = (string)@file_get_contents($cfg);
                foreach (['PasswordAuthentication' => 'no', 'PermitRootLogin' => 'prohibit-password'] as $k => $v) {
                    $s = preg_replace('/^\s*#?\s*' . $k . '\s+\S+.*$/mi', $k . ' ' . $v, $s, -1, $c);
                    if (!$c) $s = rtrim($s) . "\n" . $k . ' ' . $v . "\n";
                }
                @file_put_contents($cfg, $s, LOCK_EX);
                $t = trim(smpro_cx_run('sshd -t 2>&1', 20));
                if ($t !== '') { @copy($bk, $cfg); $r = ['ok' => false, 'msg' => 'sshd -t rejected the change, original restored: ' . $t]; break; }
                smpro_cx_run('systemctl restart sshd 2>&1 || service sshd restart 2>&1', 30);
                $pa = trim(smpro_cx_run('sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|passwordauthentication) "', 20));
                $r = ['ok' => (bool)preg_match('/passwordauthentication no/i', $pa), 'msg' => 'sshd now: ' . str_replace("\n", ', ', $pa) . '. Open a NEW session now to confirm your key works.', 'backup' => $bk];
                break;
            case 'line_rm':
                if (!smpro_cx_line_rm_allowed($a['file'])) { $r = ['ok' => false, 'msg' => 'refused: that file is not one this fix may edit']; break; }
                [$n, $bk] = smpro_cx_line_rm($a['file'], $a['sha']);
                if ($n === 0) { $r = ['ok' => false, 'msg' => $bk === '' ? 'the line is no longer in the file (or the backup could not be kept) - nothing changed' : 'nothing removed']; break; }
                if (strpos($a['file'], '/etc/sudoers') === 0) {
                    $v = trim(smpro_cx_run('visudo -c 2>&1', 20));
                    if (preg_match('/parse error|syntax error/i', $v)) { @copy($bk, $a['file']); $r = ['ok' => false, 'msg' => 'visudo rejected the result, original restored: ' . $v, 'backup' => $bk]; break; }
                }
                $r = ['ok' => true, 'msg' => $n . ' line(s) removed from ' . $a['file'], 'backup' => $bk];
                break;
            case 'preload_empty':
                $bk = smpro_cx_backup('/etc/ld.so.preload'); if ($bk === '') { $r = ['ok' => false, 'msg' => 'could not back up the file - nothing changed']; break; }
                @file_put_contents('/etc/ld.so.preload', '', LOCK_EX);
                $r = ['ok' => trim((string)@file_get_contents('/etc/ld.so.preload')) === '', 'msg' => '/etc/ld.so.preload emptied. Treat the server as compromised: restore from a backup taken before the entry appeared.', 'backup' => $bk];
                break;
            case 'wheel_rm':
                if ($a['user'] === 'root') { $r = ['ok' => false, 'msg' => 'refused']; break; }
                foreach (['wheel', 'sudo'] as $g) smpro_cx_run('gpasswd -d ' . escapeshellarg($a['user']) . ' ' . $g . ' 2>&1', 20);
                $still = trim(smpro_cx_run('id -nG ' . escapeshellarg($a['user']) . ' 2>/dev/null', 10));
                $r = ['ok' => !preg_match('/\b(wheel|sudo)\b/', $still), 'msg' => $a['user'] . ' groups now: ' . ($still ?: '(user gone)')];
                break;
            case 'rootkey_rm':
                [$n, $bk] = smpro_cx_line_rm('/root/.ssh/authorized_keys', $a['sha']);
                $r = $n ? ['ok' => true, 'msg' => 'key removed from /root/.ssh/authorized_keys', 'backup' => $bk] : ['ok' => false, 'msg' => 'that key is no longer in the file - nothing changed'];
                break;
            case 'roottok_revoke':
                if (strpos($a['name'], 'reverse_trust_') === 0) { $r = ['ok' => false, 'msg' => 'refused: that is a cPanel transfer token']; break; }
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/whmapi1 api_token_revoke token_name=' . escapeshellarg($a['name']) . ' --output=json', 30), true);
                $r = !empty($o['metadata']['result']) ? ['ok' => true, 'msg' => 'token ' . $a['name'] . ' revoked'] : ['ok' => false, 'msg' => (string)($o['metadata']['reason'] ?? 'WHM refused')];
                break;
            case 'roottok_disable':
                if (strpos($a['name'], 'reverse_trust_') === 0) { $r = ['ok' => false, 'msg' => 'refused: that is a cPanel transfer token']; break; }
                // An expiry in the past is cPanel's own way of closing a token while keeping its name and history.
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/whmapi1 api_token_update token_name=' . escapeshellarg($a['name']) . ' expires_at=' . (time() - 60) . ' --output=json', 30), true);
                $r = !empty($o['metadata']['result'])
                    ? ['ok' => true, 'msg' => 'token ' . $a['name'] . ' now expires in the past: it opens nothing, and its name and history stay in the list. Revoke it once you know nothing needs it.']
                    : ['ok' => false, 'msg' => (string)($o['metadata']['reason'] ?? 'WHM refused')];
                break;
            case 'ftp_delete':
                foreach (['/etc/proftpd/' . $a['user'], '/etc/pure-ftpd/' . $a['user']] as $pf) if (@is_file($pf)) smpro_cx_backup($pf);
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/uapi --output=json --user=' . escapeshellarg($a['user']) . ' Ftp delete_ftp user=' . escapeshellarg($a['login']) . ' destroy=0', 60), true);
                $ok = !empty($o['result']['status']);
                $r = $ok ? ['ok' => true, 'msg' => 'FTP login ' . $a['login'] . ' removed. Its folder and files were NOT touched (destroy=0) - only the way in is gone.'] : ['ok' => false, 'msg' => implode('; ', (array)($o['result']['errors'] ?? ['cPanel refused']))];
                break;
            case 'fwd_delete':
                $dom = substr($a['address'], strrpos($a['address'], '@') + 1);
                if (@is_file('/etc/valiases/' . $dom)) smpro_cx_backup('/etc/valiases/' . $dom);
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/uapi --output=json --user=' . escapeshellarg($a['user']) . ' Email delete_forwarder address=' . escapeshellarg($a['address']) . ' forwarder=' . escapeshellarg($a['target']), 60), true);
                $ok = !empty($o['result']['status']);
                $r = $ok ? ['ok' => true, 'msg' => 'forwarder ' . $a['address'] . ' → ' . $a['target'] . ' deleted'] : ['ok' => false, 'msg' => implode('; ', (array)($o['result']['errors'] ?? ['cPanel refused']))];
                break;
            case 'cron_clean':
                $cf = '/var/spool/cron/' . $a['user'];
                $lines = @file($cf, FILE_IGNORE_NEW_LINES); if (!is_array($lines)) { $r = ['ok' => false, 'msg' => 'no crontab']; break; }
                $keep = []; $n = 0;
                foreach ($lines as $l) { $t = trim($l); if ($t !== '' && $t[0] !== '#' && smpro_cx_cron_suspicious($t, $a['user'])) { $n++; continue; } $keep[] = $l; }
                if ($n === 0) { $r = ['ok' => false, 'msg' => 'no fetch/decode line found now - nothing changed']; break; }
                $bk = smpro_cx_backup($cf); if ($bk === '') { $r = ['ok' => false, 'msg' => 'could not back up the crontab - nothing changed']; break; }
                $tmp = tempnam(sys_get_temp_dir(), 'smprocron'); @file_put_contents($tmp, implode("\n", $keep) . ($keep ? "\n" : ''));
                smpro_cx_run('crontab -u ' . escapeshellarg($a['user']) . ' ' . escapeshellarg($tmp) . ' 2>&1', 20); @unlink($tmp);
                $r = ['ok' => true, 'msg' => $n . ' cron line(s) removed for ' . $a['user'], 'backup' => $bk];
                break;
            case 'cron_line_off': case 'cron_line_rm': case 'cron_line_on':
                $r = smpro_cx_cron_line($a['user'], $a['sha'], substr($op, 10));
                break;
            case 'sshkey_clear':
                $pw = function_exists('posix_getpwnam') ? @posix_getpwnam($a['user']) : null;
                if (!is_array($pw)) { $r = ['ok' => false, 'msg' => 'no such account']; break; }
                $kf = (string)$pw['dir'] . '/.ssh/authorized_keys';
                if (($why = smpro_cx_account_file_ok($kf, (int)$pw['uid'])) !== '') { $r = ['ok' => false, 'msg' => 'authorized_keys is ' . $why . ' - inspect the account by hand']; break; }
                $bk = smpro_cx_backup($kf); if ($bk === '') { $r = ['ok' => false, 'msg' => 'no key file, or the backup could not be kept - nothing changed']; break; }
                @file_put_contents($kf, '', LOCK_EX); @chown($kf, (int)$pw['uid']); @chgrp($kf, (int)$pw['gid']); @chmod($kf, 0600);
                $r = ['ok' => true, 'msg' => 'all authorised keys of ' . $a['user'] . ' removed', 'backup' => $bk];
                break;
            case 'token_disable':
                // The public UAPI Tokens module has list/revoke/rename only; the expiry lives in the store class cPanel's
                // own screens write through. Called with cPanel's perl, then READ BACK through the public API: the
                // change counts only when the list says the token now expires in the past.
                $perl = '/usr/local/cpanel/3rdparty/bin/perl';
                if (!is_executable($perl)) { $r = ['ok' => false, 'msg' => 'cPanel perl is not where it should be; disable is not possible here - revoke instead']; break; }
                $when = time() - 60;
                $code = 'use Cpanel::Security::Authn::APITokens::Write::cpanel; my $w = Cpanel::Security::Authn::APITokens::Write::cpanel->new({ user => $ARGV[0] }); $w->update_token({ name => $ARGV[1], expires_at => ' . $when . ' }); $w->save_changes_to_disk(); print "ok\n";';
                $o = smpro_cx_run($perl . ' -e ' . escapeshellarg($code) . ' ' . escapeshellarg($a['user']) . ' ' . escapeshellarg($a['name']) . ' 2>&1', 60);
                $chk = json_decode(smpro_cx_run('/usr/local/cpanel/bin/uapi --output=json --user=' . escapeshellarg($a['user']) . ' Tokens list', 60), true);
                $now = null; foreach ((array)($chk['result']['data'] ?? []) as $tk) if ((string)($tk['name'] ?? '') === $a['name']) $now = $tk;
                if ($now === null) { $r = ['ok' => false, 'msg' => 'after the call the token is not in the list any more - look at the tokens of this account in cPanel: ' . trim($o)]; break; }
                $exp = (int)($now['expires_at'] ?? 0);
                $r = ($exp > 0 && $exp < time())
                    ? ['ok' => true, 'msg' => 'token ' . $a['name'] . ' of ' . $a['user'] . ' now expires in the past (read back from cPanel): it opens nothing, its name and history stay. Revoke it once you know nothing needs it.']
                    : ['ok' => false, 'msg' => 'cPanel did not take the expiry (the list still says ' . ($exp ? date('Y-m-d H:i', $exp) : 'never') . '): ' . trim($o) . ' - revoke instead'];
                break;
            case 'token_revoke':
                $o = json_decode(smpro_cx_run('/usr/local/cpanel/bin/uapi --output=json --user=' . escapeshellarg($a['user']) . ' Tokens revoke name=' . escapeshellarg($a['name']), 60), true);
                $ok = !empty($o['result']['status']);
                $r = $ok ? ['ok' => true, 'msg' => 'token ' . $a['name'] . ' of ' . $a['user'] . ' revoked'] : ['ok' => false, 'msg' => implode('; ', (array)($o['result']['errors'] ?? ['cPanel refused']))];
                break;
            case 'rc_clean':
                $pw = function_exists('posix_getpwnam') ? @posix_getpwnam($a['user']) : null;
                if (!is_array($pw)) { $r = ['ok' => false, 'msg' => 'no such account']; break; }
                $n = 0; $bks = [];
                foreach (['.bashrc', '.bash_profile', '.profile'] as $rc) {
                    $p = (string)$pw['dir'] . '/' . $rc;
                    if (smpro_cx_account_file_ok($p, (int)$pw['uid']) !== '') continue;   // a link or a foreign owner is never written through
                    $lines = @file($p, FILE_IGNORE_NEW_LINES); if (!is_array($lines)) continue;
                    $keep = []; $k = 0;
                    foreach ($lines as $l) { $t = trim($l); if ($t !== '' && $t[0] !== '#' && preg_match(smpro_cx_rc_pattern(), $t)) { $k++; continue; } $keep[] = $l; }
                    if (!$k) continue;
                    $bk = smpro_cx_backup($p); if ($bk === '') continue;
                    @file_put_contents($p, implode("\n", $keep) . "\n", LOCK_EX); @chown($p, (int)$pw['uid']); @chgrp($p, (int)$pw['gid']);
                    $n += $k; $bks[] = $bk;
                }
                $r = $n ? ['ok' => true, 'msg' => $n . ' line(s) removed from the shell start-up files of ' . $a['user'], 'backup' => implode(', ', $bks)] : ['ok' => false, 'msg' => 'no fetch/decode line found now - nothing changed'];
                break;
        }
    } catch (\Throwable $e) {
        $r = ['ok' => false, 'msg' => 'failed: ' . $e->getMessage()];
    }
    if (function_exists('smpro_audit')) @smpro_audit('compromise_fix', ['op' => $op, 'args' => $a, 'ok' => $r['ok'] ? 1 : 0, 'msg' => $r['msg'], 'backup' => $r['backup'] ?? '', 'by' => $actor]);
    return $r;
}

/** The same fetch/decode pattern the account door check uses for shell start-up lines. */
function smpro_cx_rc_pattern(): string {
    return '/(curl|wget)\b.*\|\s*(ba)?sh|base64\s+(-d|--decode)|\/dev\/tcp\/|\bnc\b|\bsocat\b|nohup\s|setsid\s/i';
}

/** Is this cron line one the account door check would call fetching/decoding? (own-domain fetches are routine) */
function smpro_cx_cron_suspicious(string $l, string $user): bool {
    if (!preg_match('/(curl|wget|base64|\/tmp\/|\/dev\/shm|python|perl|nc |bash -c)/i', $l)) return false;
    $ownDoms = function_exists('smpro_cc_domains_of') ? smpro_cc_domains_of($user) : [];
    if (preg_match('#(curl|wget).*?https?://([^/\s"\x27]+)#i', $l, $m)) {
        $h = strtolower(preg_replace('/^www\./', '', $m[2]));
        foreach ($ownDoms as $d) if ($h === $d || substr($h, -strlen('.' . $d)) === '.' . $d) return false;
    }
    return true;
}

/**
 * One cron line of one account, identified by sha1(trim(line)): 'off' turns it into "# SMPRO-OFF <line>" (stops, kept,
 * reversible), 'rm' removes it, 'on' turns a switched-off line back into a live one. The crontab is backed up first and
 * written back through crontab(1) so cron reloads it; every other line is untouched.
 * @return array{ok:bool,msg:string,backup?:string}
 */
function smpro_cx_cron_line(string $user, string $sha, string $mode): array {
    $cf = '/var/spool/cron/' . $user;
    $lines = @file($cf, FILE_IGNORE_NEW_LINES); if (!is_array($lines)) return ['ok' => false, 'msg' => 'no crontab'];
    $out = []; $n = 0;
    foreach ($lines as $l) {
        $t = trim($l);
        if ($mode === 'on') {
            if (preg_match('/^#\s*SMPRO-OFF\s(.+)$/', $t, $m) && sha1(trim($m[1])) === $sha) { $out[] = trim($m[1]); $n++; continue; }
        } elseif ($t !== '' && $t[0] !== '#' && sha1($t) === $sha) {
            $n++; if ($mode === 'off') $out[] = '# SMPRO-OFF ' . $t;
            continue;
        }
        $out[] = $l;
    }
    if ($n === 0) return ['ok' => false, 'msg' => 'that line is no longer in the crontab (changed since the page was drawn) - nothing changed'];
    $bk = smpro_cx_backup($cf); if ($bk === '') return ['ok' => false, 'msg' => 'could not back up the crontab - nothing changed'];
    $tmp = tempnam(sys_get_temp_dir(), 'smprocron'); @file_put_contents($tmp, implode("\n", $out) . ($out ? "\n" : ''));
    $o = smpro_cx_run('crontab -u ' . escapeshellarg($user) . ' ' . escapeshellarg($tmp) . ' 2>&1', 20); @unlink($tmp);
    if (stripos($o, 'error') !== false) return ['ok' => false, 'msg' => 'crontab refused the new file: ' . trim($o) . ' - the original is untouched', 'backup' => $bk];
    $what = ['off' => 'switched off (kept as a comment)', 'rm' => 'removed', 'on' => 'put back'][$mode];
    return ['ok' => true, 'msg' => '1 cron line of ' . $user . ' ' . $what, 'backup' => $bk];
}

/* ------------------------------------------------------------------ scheduled scan */

function smpro_cx_sched_cfg(): array {
    $j = @is_file(SMPRO_CX_SCHED) ? json_decode((string)@file_get_contents(SMPRO_CX_SCHED), true) : null;
    return smpro_cx_sched_normalize(is_array($j) ? $j : []);
}

/** Defaults + validation, shared by the loader and the page's POST. */
function smpro_cx_sched_normalize(array $c): array {
    $c += ['enabled' => false, 'every' => 'daily', 'hour' => 4, 'dow' => 1, 'scope' => 'both', 'users' => [], 'days' => 30,
           'tell' => 'issues', 'last_run' => 0, 'last_report' => '', 'last_summary' => '', 'keep' => 30];
    $c['enabled'] = !empty($c['enabled']);
    $c['every'] = in_array($c['every'], ['daily', 'weekly'], true) ? $c['every'] : 'daily';
    $c['hour'] = max(0, min(23, (int)$c['hour'])); $c['dow'] = max(0, min(6, (int)$c['dow']));
    $c['scope'] = in_array($c['scope'], ['server', 'accounts', 'both'], true) ? $c['scope'] : 'both';
    $c['users'] = array_values(array_unique(array_filter(array_map('strval', (array)$c['users']), fn($u) => preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u))));
    $c['days'] = in_array((int)$c['days'], [7, 30, 90, 365], true) ? (int)$c['days'] : 30;
    $c['tell'] = in_array($c['tell'], ['always', 'issues', 'critical'], true) ? $c['tell'] : 'issues';
    $c['last_run'] = (int)$c['last_run']; $c['keep'] = max(5, (int)$c['keep']);
    return $c;
}

function smpro_cx_sched_save(array $c): bool {
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $tmp = SMPRO_CX_SCHED . '.tmp';
    if (@file_put_contents($tmp, json_encode($c, JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    if (!@rename($tmp, SMPRO_CX_SCHED)) return false;
    return smpro_cx_cron_sync($c);
}

/** The product provisions its own cron: present while the plan is on, removed when it is off. */
function smpro_cx_cron_sync(array $c = []): bool {
    $c = $c ?: smpro_cx_sched_cfg();
    if (!$c['enabled']) { if (@is_file(SMPRO_CX_CRON) && !defined('SMPRO_TEST_SRC')) @unlink(SMPRO_CX_CRON); return true; }
    if (defined('SMPRO_TEST_SRC')) return true;   // a test never installs a live cron (smpro_cron_install has the same guard)
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';   // cron's PATH may not resolve a bare php
    $script = SMPRO_BASE . '/bin/compcheck_tick.php';
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true); $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $line = "# Safety Monitor Pro - Compromise Check scheduled scan (the tick decides whether a run is due)\n*/10 * * * * root " . $flock . " -n " . $lockDir . "/compcheck.lock timeout 580 " . $php . ' ' . $script . " >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install(SMPRO_CX_CRON, $line) : (@file_put_contents(SMPRO_CX_CRON, $line) !== false && @chmod(SMPRO_CX_CRON, 0644));
}

/** Is a run due now? Daily at HH, or weekly on DOW at HH; never twice inside the same slot. */
function smpro_cx_due(array $c, int $now = 0): bool {
    if (!$c['enabled']) return false;
    $now = $now ?: time();
    if ((int)date('G', $now) !== $c['hour']) return false;
    if ($c['every'] === 'weekly' && (int)date('w', $now) !== $c['dow']) return false;
    $slot = mktime($c['hour'], 0, 0, (int)date('n', $now), (int)date('j', $now), (int)date('Y', $now));
    return (int)$c['last_run'] < $slot;
}

/** Run the planned scan, store the report, notify. Returns the report summary. */
function smpro_cx_run_scheduled(array $c = [], bool $force = false): array {
    $c = $c ?: smpro_cx_sched_cfg();
    // The slot is claimed first: a scan killed by the cron's timeout (a 300-s account scan on a slow box) used to
    // leave last_run untouched, so the same slot ran - and notified - at every 10-minute tick of that hour.
    if (!$force) { $c['last_run'] = time(); smpro_cx_sched_save($c); }
    $rep = ['at' => time(), 'scope' => $c['scope'], 'days' => $c['days'], 'users' => $c['users'], 'server' => [], 'accounts' => [], 'partial' => false, 'scanned' => 0];
    if ($c['scope'] !== 'accounts') $rep['server'] = smpro_cc_server_checks();
    if ($c['scope'] !== 'server') {
        $since = time() - $c['days'] * 86400;
        if ($c['users']) {
            $all = smpro_cc_accounts();
            foreach ($c['users'] as $u) if (isset($all[$u])) { $rep['accounts'][] = smpro_cc_account_doors($all[$u], $since); $rep['scanned']++; }
        } else {
            $s = smpro_cc_scan_accounts($c['days'], 300);
            $rep['accounts'] = $s['rows']; $rep['partial'] = $s['partial']; $rep['scanned'] = $s['scanned'];
        }
    }
    $crit = count(array_filter($rep['server'], fn($x) => $x['status'] === 'critical'));
    $warn = count(array_filter($rep['server'], fn($x) => $x['status'] === 'warning'));
    $flagged = array_values(array_filter($rep['accounts'], fn($r) => $r['flags'] > 0));
    $doors = array_sum(array_map(fn($r) => $r['flags'], $flagged));
    $rep['summary'] = ['critical' => $crit, 'warning' => $warn, 'flagged_accounts' => count($flagged), 'doors' => $doors];
    // keep only what matters in the stored report: non-OK server rows and flagged accounts (the full page is a click away)
    $rep['server'] = array_values(array_filter($rep['server'], fn($x) => $x['status'] !== 'ok'));
    $rep['accounts'] = $flagged;
    @is_dir(SMPRO_CX_REPORTS) || @mkdir(SMPRO_CX_REPORTS, 0700, true);
    $id = date('Ymd_His', $rep['at']); $file = SMPRO_CX_REPORTS . '/' . $id . '.json';
    @file_put_contents($file, json_encode($rep), LOCK_EX); @chmod($file, 0600);
    // prune
    $files = glob(SMPRO_CX_REPORTS . '/*.json') ?: []; sort($files);
    while (count($files) > max(5, (int)$c['keep'])) @unlink(array_shift($files));
    // notify
    $sum = $crit . ' critical, ' . $warn . ' warning on the server; ' . count($flagged) . ' account(s) with ' . $doors . ' new door(s)';
    $tell = ($c['tell'] === 'always') || ($c['tell'] === 'issues' && ($crit || $warn || $flagged)) || ($c['tell'] === 'critical' && ($crit || $flagged));
    if ($tell && function_exists('smpro_notify')) {
        $body = "Scheduled Compromise Check - " . date('Y-m-d H:i', $rep['at']) . "\n" . $sum . "\n";
        foreach ($rep['server'] as $x) $body .= "\n[" . strtoupper($x['status']) . '] ' . $x['title'] . ' - ' . $x['finding'];
        foreach (array_slice($flagged, 0, 15) as $r) { $body .= "\n" . $r['user'] . ' (' . $r['domain'] . '): '; $body .= implode('; ', array_map(fn($f) => $f['label'], array_filter($r['findings'], fn($f) => $f['flag']))); }
        if (count($flagged) > 15) $body .= "\n… and " . (count($flagged) - 15) . ' more account(s)';
        $body .= "\n\nOpen WHM > Safety Monitor Pro > Compromise Check to see the evidence and fix each item.";
        @smpro_notify('compromise_check', 'Compromise Check: ' . $sum, $body, ['severity' => $crit ? 'critical' : ($warn || $flagged ? 'high' : 'info')]);
    }
    $c['last_run'] = $rep['at']; $c['last_report'] = $id; $c['last_summary'] = $sum;
    smpro_cx_sched_save($c);
    if (function_exists('smpro_audit')) @smpro_audit('compromise_check_scheduled', ['summary' => $sum, 'report' => $id, 'forced' => $force ? 1 : 0]);
    return $rep;
}

/** Stored reports, newest first: [id, at, summary]. */
function smpro_cx_reports(): array {
    $out = [];
    foreach (glob(SMPRO_CX_REPORTS . '/*.json') ?: [] as $f) {
        $j = json_decode((string)@file_get_contents($f), true); if (!is_array($j)) continue;
        $out[] = ['id' => basename($f, '.json'), 'at' => (int)($j['at'] ?? 0), 'summary' => (array)($j['summary'] ?? []), 'scope' => (string)($j['scope'] ?? '')];
    }
    usort($out, fn($a, $b) => $b['at'] <=> $a['at']);
    return $out;
}

function smpro_cx_report_get(string $id): ?array {
    if (!preg_match('/^\d{8}_\d{6}$/', $id)) return null;
    $j = json_decode((string)@file_get_contents(SMPRO_CX_REPORTS . '/' . $id . '.json'), true);
    return is_array($j) ? $j : null;
}
