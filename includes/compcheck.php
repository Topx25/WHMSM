<?php
/**
 * compcheck.php — Compromise Check: is this server, and are these accounts, showing the marks a break-in leaves?
 *
 * WHERE THIS COMES FROM. Two things cPanel's own support material says, and one thing the attackers in it did:
 *
 *   - A compromised account is recovered by restoring a clean backup and then rotating EVERY credential on it:
 *     the cPanel password, every mailbox, every FTP sub-account, database users, SSH keys, site admin logins -
 *     because the password is only one of the doors (support.cpanel.net, "What can be done if a cPanel account
 *     is compromised?").
 *   - In the community thread behind that article, two accounts each gained an FTP sub-account named
 *     "root@domain" that nobody had created. Attackers who hold a password add a second door so they keep
 *     access after the password changes - and people rarely look at FTP sub-accounts, forwarders, cron
 *     entries or SSH keys when they reset a password.
 *   - At server level, CVE-2026-41940 (April 2026) let anyone open a cPanel/WHM session WITHOUT a password on
 *     an unpatched server. Such a session is recorded by cPanel as an ordinary password success, so every
 *     login-based report here would call it "a leaked password". The first question is therefore the version.
 *
 * So this check looks at the persistence a break-in leaves rather than at logins: the doors that were ADDED.
 * Everything here is read from the server's own files by modification time - no per-account API calls, so a
 * server with 1,300 accounts is scanned in seconds. It is read-only. The actions live where they already are:
 * the Threat Report's reset, the account's own cPanel for removing a sub-account or a key.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ------------------------------------------------------------------ server level */

/**
 * cPanel builds that carry the fix for each critical CVE this check gates on, per release track.
 * A track absent from a list was not given a fix for that CVE: either it is newer than every fixed track
 * (patched) or older than the oldest one (unsupported, unpatched).
 */
function smpro_cc_cves(): array {
    return [
        ['cve' => 'CVE-2026-41940', 'what' => 'authentication bypass - a cPanel/WHM session could be opened without the password',
         'fixed' => [86 => [0, 41], 110 => [0, 97], 118 => [0, 63], 126 => [0, 54], 130 => [0, 19], 132 => [0, 29], 134 => [0, 20], 136 => [0, 5]], 'newer_ok_from' => 138],
        ['cve' => 'CVE-2026-65643', 'what' => 'a cPanel account holder able to add a parked or addon domain could create arbitrary files and run code as root',
         'fixed' => [110 => [0, 141], 134 => [0, 53], 136 => [0, 37], 138 => [0, 2]], 'newer_ok_from' => 140],
    ];
}
function smpro_cc_cve_fixed_builds(): array {   // kept for callers of the first gate
    $c = smpro_cc_cves()[0];
    return ['cve' => $c['cve'], 'what' => $c['what'], 'fixed' => array_map(fn($x) => $x[1], $c['fixed']), 'newer_ok_from' => $c['newer_ok_from']];
}

function smpro_cc_cpanel_version(): string { return trim((string)@file_get_contents('/usr/local/cpanel/version')); }

/** Is the installed build at or past the fix for one CVE? ['ok'=>bool|null,'version'=>..,'why'=>..] (null = unreadable). */
function smpro_cc_version_state(string $version = '', int $which = 0): array {
    $v = $version !== '' ? $version : smpro_cc_cpanel_version();
    $t = smpro_cc_cves()[$which] ?? smpro_cc_cves()[0];
    if (!preg_match('/^11\.(\d+)\.(\d+)\.(\d+)$/', $v, $m)) return ['ok' => null, 'version' => $v, 'why' => 'the version string could not be read'];
    $track = (int)$m[1]; $minor = (int)$m[2]; $build = (int)$m[3];
    if (isset($t['fixed'][$track])) {
        [$fm, $fb] = $t['fixed'][$track];
        $ok = ($minor > $fm) || ($minor === $fm && $build >= $fb);
        $fixed = '11.' . $track . '.' . $fm . '.' . $fb;
        return ['ok' => $ok, 'version' => $v, 'why' => $ok ? ($v . ' is at or past the fixed build ' . $fixed) : ($v . ' is BELOW the fixed build ' . $fixed . ' - update cPanel now')];
    }
    if ($track >= $t['newer_ok_from']) return ['ok' => true, 'version' => $v, 'why' => 'release track 11.' . $track . ' is newer than every track the fix was issued for'];
    $oldest = min(array_keys($t['fixed']));
    return ['ok' => false, 'version' => $v, 'why' => 'release track 11.' . $track . ' is older than the oldest track that received a fix (11.' . $oldest . ') - it is unsupported and unpatched'];
}

function smpro_cc_run(string $cmd, int $t = 20): string { return smpro_run($cmd, $t, ['stderr' => 'discard']); }

/** The server-level checks. Each: ['id','title','status'=>ok|warning|critical|info,'finding','why','evidence'=>[]]. */
function smpro_cc_server_checks(): array {
    $out = [];
    // 1. the bypass
    $vs = smpro_cc_version_state(); $t = smpro_cc_cve_fixed_builds();
    $out[] = ['id' => 'cve', 'title' => 'cPanel & WHM is past the authentication-bypass fix (' . $t['cve'] . ')',
              'status' => $vs['ok'] === true ? 'ok' : ($vs['ok'] === false ? 'critical' : 'warning'),
              'finding' => 'Installed: ' . ($vs['version'] ?: 'unknown') . ' - ' . $vs['why'],
              'why' => $t['what'] . '. On an unpatched server every "successful login" in these reports may have been no login at all.',
              'evidence' => ['/usr/local/cpanel/version = ' . $vs['version']]];
    $vs2 = smpro_cc_version_state('', 1); $t2 = smpro_cc_cves()[1];
    $out[] = ['id' => 'cve2', 'title' => 'cPanel & WHM is past the account-to-root fix (' . $t2['cve'] . ')',
              'status' => $vs2['ok'] === true ? 'ok' : ($vs2['ok'] === false ? 'critical' : 'warning'),
              'finding' => 'Installed: ' . ($vs2['version'] ?: 'unknown') . ' - ' . $vs2['why'],
              'why' => $t2['what'] . '. On an unpatched server any one customer account is a root account.', 'evidence' => []];
    // 1b. what the exploit toolkits left behind, from the published post-compromise checklists
    foreach (smpro_cc_persistence_checks() as $pc) $out[] = $pc;
    // 2. cPHulk
    $hOn = function_exists('smpro_cphulk_enabled') ? (bool)smpro_cphulk_enabled() : !empty(json_decode(smpro_cc_run('/usr/local/cpanel/bin/whmapi1 cphulk_status --output=json'), true)['data']['is_enabled']);
    $out[] = ['id' => 'cphulk', 'title' => 'cPHulk brute-force protection is on', 'status' => $hOn ? 'ok' : 'warning',
              'finding' => $hOn ? 'enabled' : 'disabled - password guessing against cPanel, WHM, webmail, FTP, SSH and mail is not rate-limited',
              'why' => 'cPHulk is also what the door wall (Country Login Lock) uses to refuse other countries before the password.', 'evidence' => [],
              'fixes' => $hOn ? [] : [['op' => 'cphulk_on']]];
    // 3. Imunify's compromised-user handling
    $imBin = @is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : 'imunify360-agent';   // the CGI PATH does not carry /usr/bin reliably
    // prints JSON (the --json flag is refused by this subcommand); 0.4-0.7 s per call, so kept for five minutes
    $im = function_exists('smpro_memo') ? smpro_memo('im_config_show', 300, fn() => json_decode(smpro_cc_run($imBin . ' config show', 30), true)) : json_decode(smpro_cc_run($imBin . ' config show', 30), true);
    if (is_array($im) && isset($im['CONTROL_PANEL'])) {
        $cp = (array)$im['CONTROL_PANEL'];
        $on = !empty($cp['compromised_user_password_reset']);
        $out[] = ['id' => 'im_comp', 'title' => 'Imunify360 resets the password of an account it finds compromised', 'status' => $on ? 'ok' : 'warning',
                  'finding' => ($on ? 'on' : 'off') . (!empty($cp['compromised_user_admin_notification']) ? ', admin is notified' : ', admin is NOT notified'),
                  'why' => 'Imunify360 identifies compromised accounts from what they do (mail bursts, malware writes) and can reset the password itself; turned off, the account keeps working for the attacker until someone notices.',
                  'evidence' => ['imunify360-agent config show: CONTROL_PANEL.compromised_user_password_reset=' . json_encode($cp['compromised_user_password_reset'] ?? null)],
                  'fixes' => $on ? [] : [['op' => 'im_comp_on']]];
    } else {
        $out[] = ['id' => 'im_comp', 'title' => 'Imunify360 compromised-user handling', 'status' => 'info', 'finding' => 'Imunify360 is not installed (or did not answer)', 'why' => '', 'evidence' => []];
    }
    // 4. root's own doors
    $keys = @is_readable('/root/.ssh/authorized_keys') ? array_values(array_filter(array_map('trim', (array)@file('/root/.ssh/authorized_keys')), fn($l) => $l !== '' && $l[0] !== '#')) : [];
    $kmt = @filemtime('/root/.ssh/authorized_keys') ?: 0;
    $out[] = ['id' => 'rootkeys', 'title' => 'SSH keys that open root', 'status' => count($keys) > 3 ? 'warning' : 'info',
              'finding' => count($keys) . ' key(s) in /root/.ssh/authorized_keys' . ($kmt ? ', last changed ' . date('Y-m-d H:i', $kmt) : ''),
              'why' => 'A key added by an intruder survives every password change. Every entry here must be one you can name.',
              'evidence' => array_map(fn($k) => mb_substr(preg_replace('/^(\S+\s+\S{0,24})\S*/', '$1…', $k), 0, 120), array_slice($keys, 0, 10)),
              'fixes' => array_map(fn($k) => ['op' => 'rootkey_rm', 'sha' => sha1(trim($k)), 'what' => mb_substr(preg_replace('/^(\S+\s+\S{0,16})\S*/', '$1…', $k), 0, 60)], array_slice($keys, 0, 10))];
    // root's WHM tokens from cPanel's own store (same layout as the per-account files); the API is the fallback
    $tf = '/var/cpanel/authn/api_tokens_v2/whostmgr/root.json';
    $tok = @is_readable($tf) ? json_decode((string)@file_get_contents($tf), true) : null;
    $toks = is_array($tok) && isset($tok['tokens']) ? (array)$tok['tokens'] : [];
    if (!$toks && !@is_readable($tf)) { $tok = json_decode(smpro_cc_run('/usr/local/cpanel/bin/whmapi1 api_token_list --output=json'), true); $toks = (array)($tok['data']['tokens'] ?? []); }
    // The FILE is keyed by the token's hash and carries the name inside the record; the API is keyed by the name.
    // Keyed by hash, every "is this one cPanel's own?" test below failed and every token was reported as one the
    // operator created, named by a 128-character hash. Key both sources by the NAME, which is what a person reads,
    // what the logs record, and what the revoke/disable API takes.
    $byName = [];
    foreach ($toks as $k => $x) { $n = (string)($x['name'] ?? ''); if ($n === '') $n = (string)$k; $byName[$n] = (array)$x; }
    $toks = $byName;
    // cPanel creates "reverse_trust_<uuid>" tokens itself for server-to-server transfers; they are not the operator's.
    $mine = array_filter($toks, fn($x, $n) => strpos((string)$n, 'reverse_trust_') !== 0, ARRAY_FILTER_USE_BOTH);
    $trust = count($toks) - count($mine);
    // Each token gets its own line: what it can do, who made it and from where, whether it expires, when it was last
    // used. "32 tokens" says nothing an operator can act on; these five facts are what decides keep or revoke.
    $ev = [];
    foreach ($mine as $n => $x) $ev[] = $n . ' — ' . smpro_cc_token_line((string)$n, (array)$x, true);
    if ($trust) {
        $lu = smpro_cc_token_last_use(); $seen = 0; $last = 0; $from = [];
        foreach ($toks as $n => $x) { if (strpos((string)$n, 'reverse_trust_') !== 0) continue; if (isset($lu[$n])) { $seen++; if ($lu[$n][0] > $last) $last = $lu[$n][0]; if ($lu[$n][1] !== '') $from[$lu[$n][1]] = true; } }
        $ev[] = $trust . ' × reverse_trust_* — made by cPanel itself for server-to-server transfers (each one can do EVERYTHING root can). '
              . ($seen ? $seen . ' of them were used, last ' . date('Y-m-d H:i', $last) . ($from ? ' from ' . implode(', ', array_slice(array_keys($from), 0, 3)) : '') . '. A transfer that is finished does not need its token: revoke in WHM > Manage API Tokens the ones whose partner server you no longer transfer with.' : 'None of them has been used in the kept log. A transfer token nobody uses is a root password left lying about.');
    }
    $out[] = ['id' => 'roottok', 'title' => 'WHM API tokens for root', 'status' => count($mine) > 0 ? 'info' : ($trust > 0 ? 'info' : 'ok'),
              'finding' => count($mine) . ' token(s) you created' . ($trust ? ', plus ' . $trust . ' reverse_trust_* token(s) cPanel made for transfers (each has every WHM permission and never expires)' : '') . ' — the line for each one below says what it can do, who made it, when it expires and when it was last used.',
              'why' => 'An API token is a root password that never expires and is not rotated by a password change. Each one must be accounted for: what it can do, who made it, whether it is still used.', 'evidence' => $ev,
              'fixes' => array_merge(
                  array_map(fn($n) => ['op' => 'roottok_revoke', 'name' => (string)$n, 'what' => 'revoke ' . $n], array_keys($mine)),
                  array_map(fn($n) => ['op' => 'roottok_disable', 'name' => (string)$n, 'what' => 'disable ' . $n], array_keys($mine)))];
    $uid0 = [];
    foreach ((array)@file('/etc/passwd', FILE_IGNORE_NEW_LINES) as $l) { $f = explode(':', $l); if (isset($f[2]) && $f[2] === '0' && $f[0] !== 'root') $uid0[] = $f[0]; }
    $out[] = ['id' => 'uid0', 'title' => 'Only root has uid 0', 'status' => $uid0 ? 'critical' : 'ok',
              'finding' => $uid0 ? 'extra uid-0 users: ' . implode(', ', $uid0) : 'no other uid-0 user', 'why' => 'A second uid-0 user is a classic backdoor.', 'evidence' => $uid0];
    // 5. resellers with everything
    $allAcl = [];
    foreach ((array)@file('/var/cpanel/resellers', FILE_IGNORE_NEW_LINES) as $l) { if (preg_match('/^([^:]+):(.*)$/', $l, $m) && preg_match('/\ball\b/', $m[2])) $allAcl[] = $m[1]; }
    $out[] = ['id' => 'resellers', 'title' => 'Resellers holding the "all" privilege', 'status' => $allAcl ? 'warning' : 'ok',
              'finding' => $allAcl ? implode(', ', $allAcl) . ' - each is effectively root' : 'none', 'why' => 'A reseller with the "all" ACL can do what root can, including open every account.', 'evidence' => []];
    // 6. sshd password auth for root
    $pa = trim(smpro_cc_run('sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|passwordauthentication) "'));
    $out[] = ['id' => 'sshd', 'title' => 'SSH: root login and password authentication', 'status' => (preg_match('/permitrootlogin yes/i', $pa) && preg_match('/passwordauthentication yes/i', $pa)) ? 'warning' : 'ok',
              'finding' => $pa !== '' ? str_replace("\n", ', ', $pa) : 'sshd -T did not answer',
              'why' => 'Root by password over SSH is the door every botnet knocks on. Keys only, or no root at all.', 'evidence' => [],
              'fixes' => (preg_match('/passwordauthentication yes/i', $pa) && $keys) ? [['op' => 'sshd_harden']] : []];
    return $out;
}

/**
 * Root-level persistence, from the post-compromise checklists published after the 2026 cPanel/Plesk exploits
 * (WebPros' own five items, hosting providers' guides, the watchTowr analysis). Read-only; every item names its file.
 */
function smpro_cc_persistence_checks(): array {
    $out = [];
    // (python -c / perl -e with inline code are everyday cPanel and CloudLinux lines - not a signal by themselves)
    $fetchPat = '/(curl|wget)\b.*\|\s*(ba)?sh\b|base64\s+(-d|--decode)|\/dev\/tcp\/|(^|[\s;|&])(nc|ncat|socat)\s|nohup\s|setsid\s|\/dev\/shm\/|\/tmp\/[a-z0-9._-]+\s*&/i';

    // a) /etc/ld.so.preload - the first item on WebPros' list: a library forced into EVERY process
    $pre = @is_file('/etc/ld.so.preload') ? array_values(array_filter(array_map('trim', (array)@file('/etc/ld.so.preload')), fn($l) => $l !== '' && $l[0] !== '#')) : [];
    $out[] = ['id' => 'preload', 'title' => 'No library is forced into every process (/etc/ld.so.preload)', 'status' => $pre ? 'critical' : 'ok',
              'finding' => $pre ? implode(', ', $pre) : 'file absent or empty',
              'why' => 'Rootkits and the 2026 exploit toolkits hide by loading themselves into every process through this file. Anything listed here that you did not put there is a compromise.', 'evidence' => $pre,
              'fixes' => $pre ? [['op' => 'preload_empty']] : []];

    // b) sudoers: who else is root by another name
    $sudo = []; $vendor = []; $sudoFix = [];
    $wheel = trim((string)@shell_exec('getent group wheel sudo 2>/dev/null | cut -d: -f4 | tr "\n" ","'), ',');
    foreach (array_merge(['/etc/sudoers'], glob('/etc/sudoers.d/*') ?: []) as $f) {
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES) as $l) {
            $l = trim($l); if ($l === '' || $l[0] === '#' || strpos($l, 'Defaults') === 0 || preg_match('/^(root|%\S*)\s/', $l)) continue;
            if (!preg_match('/^(\S+)\s.*ALL\s*=/', $l, $m)) continue;
            if (preg_match('/^(wp-toolkit|imunify\S*|cloudlinux\S*|lve\S*|cagefs\S*|cpanel\S*|nobody)$/', $m[1])) { $vendor[] = basename($f) . ': ' . $l; continue; }   // shipped by cPanel / CloudLinux / Imunify
            $sudo[] = basename($f) . ': ' . $l; $sudoFix[] = ['op' => 'line_rm', 'file' => $f, 'sha' => sha1($l), 'what' => basename($f) . ': ' . mb_substr($l, 0, 50)];
        }
    }
    foreach (array_filter(array_map('trim', explode(',', $wheel ?? ''))) as $wu) if ($wu !== '' && $wu !== 'root') $sudoFix[] = ['op' => 'wheel_rm', 'user' => $wu, 'what' => $wu . ' out of wheel/sudo'];
    $out[] = ['id' => 'sudoers', 'title' => 'Nobody but root has sudo', 'status' => ($sudo || $wheel !== '') ? 'warning' : 'ok',
              'finding' => ($sudo ? count($sudo) . ' sudoers rule(s) for non-root users' : 'no user rules') . ($wheel !== '' ? '; wheel/sudo members: ' . $wheel : '; wheel/sudo groups empty') . ($vendor ? '; ' . count($vendor) . ' vendor rule(s) noted (WP Toolkit / CloudLinux / Imunify ship them)' : ''),
              'why' => 'A NOPASSWD sudo rule for a low user is a root backdoor that survives every password reset.', 'evidence' => array_merge($sudo, $vendor), 'fixes' => $sudoFix];

    // c) system cron locations (root's crontab and /etc/cron.d are the most abused after a root compromise)
    $cronHits = []; $cronFix = [];
    $files = array_merge(['/var/spool/cron/root', '/etc/crontab', '/etc/anacrontab'], glob('/etc/cron.d/*') ?: [], glob('/etc/cron.{hourly,daily,weekly,monthly}/*', GLOB_BRACE) ?: []);
    foreach ($files as $f) {
        if (!@is_file($f)) continue;
        if (strpos(basename($f), 'smpro-') === 0) continue;                                      // our own workers
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES) as $l) { $l = trim($l); if ($l === '' || $l[0] === '#') continue; if (preg_match($fetchPat, $l)) { $cronHits[] = $f . ': ' . mb_substr($l, 0, 140); $cronFix[] = ['op' => 'line_rm', 'file' => $f, 'sha' => sha1($l), 'what' => basename($f) . ': ' . mb_substr($l, 0, 50)]; } }
    }
    $out[] = ['id' => 'syscron', 'title' => 'No system cron entry fetches or decodes code', 'status' => $cronHits ? 'critical' : 'ok',
              'finding' => $cronHits ? count($cronHits) . ' entr' . (count($cronHits) === 1 ? 'y' : 'ies') . ' pulling from the network or decoding payloads' : 'root crontab, /etc/crontab, /etc/cron.d and the hourly/daily/weekly/monthly folders are clean of fetch/decode patterns',
              'why' => 'The commonest re-infection path: a cron line that re-downloads the backdoor after you delete it. Patterns: curl/wget piped into a shell, base64 -d, /dev/tcp, nc/socat, /dev/shm.', 'evidence' => array_slice($cronHits, 0, 12), 'fixes' => array_slice($cronFix, 0, 12)];

    // d) shell start-up files for root and for the system: the "phone home on every login" persistence
    $rcHits = []; $rcFix = [];
    foreach (array_merge(['/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/profile', '/etc/bashrc'], glob('/etc/profile.d/*') ?: []) as $f) {
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES) as $l) { $l = trim($l); if ($l === '' || $l[0] === '#') continue; if (preg_match($fetchPat, $l) || strpos($l, '0xa59ac734') !== false) { $rcHits[] = $f . ': ' . mb_substr($l, 0, 140); $rcFix[] = ['op' => 'line_rm', 'file' => $f, 'sha' => sha1($l), 'what' => basename($f) . ': ' . mb_substr($l, 0, 50)]; } }
    }
    $out[] = ['id' => 'shellrc', 'title' => 'Root\'s shell start-up files do not fetch or decode code', 'status' => $rcHits ? 'critical' : 'ok',
              'finding' => $rcHits ? count($rcHits) . ' line(s) in shell start-up files' : '.bashrc, .bash_profile, .profile, /etc/profile, /etc/bashrc, /etc/profile.d are clean',
              'why' => 'A line in .bashrc runs every time root opens a shell - the toolkits seen in 2026 used exactly this to phone home.', 'evidence' => array_slice($rcHits, 0, 8), 'fixes' => array_slice($rcFix, 0, 8)];

    // e) cPanel's login template: a tampered main.tmpl steals every password typed into cPanel
    $tmpl = '/usr/local/cpanel/base/unprotected/cpanel/main.tmpl';
    $tHits = [];
    if (@is_readable($tmpl)) { $s = (string)@file_get_contents($tmpl); foreach (['XMLHttpRequest', 'fetch(', 'document.cookie', 'localStorage', 'navigator.sendBeacon', 'atob(', 'eval('] as $needle) if (strpos($s, $needle) !== false) $tHits[] = $needle; }
    $out[] = ['id' => 'tmpl', 'title' => 'The cPanel login page template is not tampered with', 'status' => $tHits ? 'critical' : 'ok',
              'finding' => $tHits ? 'main.tmpl contains ' . implode(', ', $tHits) . ' - a login page that sends what is typed somewhere' : (@is_readable($tmpl) ? 'main.tmpl carries no script that could exfiltrate credentials' : 'template not readable'),
              'why' => 'Seen in the 2026 campaign: JavaScript added to the login template to copy every password typed into cPanel to the attacker. rpm -V / upcp would not necessarily flag it.', 'evidence' => $tHits ? [$tmpl] : []];

    // f) ransomware markers from the same campaign
    // In PHP, not find: `find /etc /root /home -maxdepth 2` took 3.7 s on a 73-account server. The marker sits
    // beside what was encrypted, so the top of each tree is enough to know.
    // Bounded: a production /root held a session directory of 4.8 MILLION files, which alone cost 1.8 s per
    // render. No directory is read past $perDir entries and the whole sweep stops at $total - and says so.
    $sorryHits = []; $seen = 0; $perDir = 3000; $total = 30000; $sorryPartial = false;
    $look = function (string $dir, int $depth) use (&$look, &$sorryHits, &$seen, $perDir, $total, &$sorryPartial) {
        if (count($sorryHits) >= 5 || $seen >= $total) { if ($seen >= $total) $sorryPartial = true; return; }
        $h = @opendir($dir); if (!$h) return; $here = 0;
        while (($e = readdir($h)) !== false) {
            if ($e === '.' || $e === '..') continue;
            if (++$here > $perDir || ++$seen > $total) { $sorryPartial = true; break; }
            $p = $dir . '/' . $e;
            if (substr($e, -6) === '.sorry' && @is_file($p)) { $sorryHits[] = $p; if (count($sorryHits) >= 5) break; }
            elseif ($depth > 1 && @is_dir($p) && !@is_link($p)) $look($p, $depth - 1);
        }
        closedir($h);
    };
    $look('/etc', 2); $look('/root', 2);
    foreach (glob('/home/*', GLOB_ONLYDIR) ?: [] as $hd) { if (count($sorryHits) >= 5) break; $look($hd, 1); }
    $sorry = implode("\n", $sorryHits);
    // A marker under an account home is that ACCOUNT's finding (any customer can create ~/x.sorry and must not be able
    // to raise a server-wide critical); one under /etc or /root is the server's.
    $sorrySys = array_filter($sorryHits, fn($p) => strpos($p, '/home/') !== 0);
    $out[] = ['id' => 'sorry', 'title' => 'No ransomware markers (*.sorry)', 'status' => $sorrySys ? 'critical' : ($sorry !== '' ? 'warning' : 'ok'),
              'finding' => $sorry !== '' ? 'found: ' . str_replace("\n", ', ', $sorry) : ('none under /etc, /root or the top of the home directories' . ($sorryPartial ? ' (a directory too large to read fully was skipped past its first entries)' : '')),
              'why' => 'The extension the 2026 cPanel ransomware left on encrypted files.', 'evidence' => $sorry !== '' ? explode("\n", $sorry) : []];

    // g) cPanel's own indicator-of-compromise script for the auth bypass: we point at it rather than re-implement it
    $ioc = '/usr/local/cpanel/scripts/ioc_checksessions_files.sh';
    $out[] = ['id' => 'ioc', 'title' => 'cPanel\'s session IOC script (CVE-2026-41940) has been run', 'status' => 'info',
              'finding' => @is_file($ioc) ? 'present at ' . $ioc . ' - run it as root; it reports CRITICAL / WARNING / ATTEMPT per session file' : 'not shipped on this build - cPanel publishes it in the CVE-2026-41940 advisory (support.cpanel.net); download and run it as root',
              'why' => 'The only authoritative test of whether the bypass was USED here (whatever the version is now) is cPanel\'s own script over /var/cpanel/sessions. This check does not replace it.', 'evidence' => []];

    // h) what listens, and who owns it
    $listen = [];
    foreach (explode("\n", (string)@shell_exec('timeout 10 ss -tlnpH 2>/dev/null')) as $l) {
        if (!preg_match('/^\S+\s+\S+\s+\S+\s+(\S+):(\d+)\s+.*users:\(\("([^"]+)"/', $l, $m)) continue;
        $port = (int)$m[2]; $prog = strtolower(trim(explode(' ', $m[3])[0]));   // ss prints 15 chars of the name, then " - accept" / " (SSL\"
        $known = ['sshd', 'cpsrvd', 'httpd', 'nginx', 'exim', 'dovecot', 'imap-login', 'pop3-login', 'managesieve-login', 'lmtp', 'proftpd', 'pure-ftpd', 'mysqld', 'mariadbd', 'named', 'lfd', 'imunify360-webshield', 'imunify360-agent', 'imunify-auditd', 'pdns_server', 'lsphp', 'litespeed', 'lshttpd', 'php-fpm', 'cpdavd', 'cphulkd', 'spamd', 'memcached', 'redis-server', 'dnsadmin', 'queueprocd', 'tailwatchd', 'chronyd', 'rpcbind', 'master', 'wafd', 'modsec-sdbm', 'systemd-resolve', 'cpanellogd', 'cpanel_php_fpm', 'ossec-remoted', 'ossec-authd', 'cagefsctl', 'sw-cp-server', 'smtpd', 'postfix', 'dovecot-auth', 'mailmanctl', 'tomcat', 'java', 'clamd', 'zabbix_agentd', 'node_exporter'];
        $addr = trim($m[1], '[]');
        if ($addr === '127.0.0.1' || $addr === '::1') continue;
        $shell = in_array($prog, ['node', 'python3', 'python', 'python2', 'perl', 'php', 'sh', 'bash', 'dash', 'nc', 'ncat', 'socat', 'busybox'], true);
        $isKnown = false; foreach ($known as $k) if ($k === $prog || strpos($k, $prog) === 0) { $isKnown = true; break; }
        if ($shell || !$isKnown) $listen[] = $prog . ' on ' . $addr . ':' . $port;
    }
    $listen = array_values(array_unique($listen));
    $out[] = ['id' => 'listen', 'title' => 'Every public listener is a known service', 'status' => $listen ? 'warning' : 'ok',
              'finding' => $listen ? implode('; ', array_slice($listen, 0, 8)) : 'only known services listen on public addresses',
              'why' => 'A shell, an interpreter or an unnamed binary listening on a public port is a backdoor until proven otherwise.', 'evidence' => $listen];

    // i) hidden processes: pids in /proc that ps does not report
    $procPids = []; foreach (glob('/proc/[0-9]*') ?: [] as $d) $procPids[(int)basename($d)] = 1;
    $psPids = []; foreach (explode("\n", (string)@shell_exec('timeout 10 ps -eo pid= 2>/dev/null')) as $p) { $p = (int)trim($p); if ($p) $psPids[$p] = 1; }
    $hidden = array_keys(array_diff_key($procPids, $psPids));
    $hidden = array_values(array_filter($hidden, fn($p) => $p > 300 && @is_dir('/proc/' . $p)));   // re-check: the gap between the two reads creates false hits
    $out[] = ['id' => 'hidden', 'title' => 'No process is hidden from ps', 'status' => count($hidden) > 3 ? 'critical' : 'ok',
              'finding' => count($hidden) > 3 ? count($hidden) . ' pid(s) exist in /proc but ps does not list them: ' . implode(', ', array_slice($hidden, 0, 8)) : 'ps and /proc agree',
              'why' => 'A rootkit that hooks ps (through ld.so.preload or a kernel module) hides its processes from every tool except a raw /proc walk.', 'evidence' => []];
    return $out;
}

/** What to do about each server check when it is not OK, and about each kind of account door. Exact places, exact commands. */
function smpro_cc_fix(string $id): string {
    static $m = [
        'cve'      => 'WHM > cPanel & WHM Update, or as root: /scripts/upcp --force. If the fixed build cannot be reached on this track, set the release tier to a supported one in WHM > Update Preferences first. Then run cPanel\'s session IOC script (below) because an unpatched period may already have been used.',
        'cve2'     => 'Update the same way: WHM > cPanel & WHM Update or /scripts/upcp --force. Until it is done, every customer account is a root account - treat the server as exposed.',
        'cphulk'   => 'WHM > Security Center > cPHulk Brute Force Protection > Enable (or in this product: Firewall > The door > Arm). Whitelist your own office address first so a typo cannot lock you out.',
        'im_comp'  => 'Imunify360 > Settings > General > "Compromised user password reset" ON. Command line: imunify360-agent config update \'{"CONTROL_PANEL": {"compromised_user_password_reset": true}}\'.',
        'rootkeys' => 'Open /root/.ssh/authorized_keys and delete every line you cannot name by owner. Keep the file itself (the product\'s own key is listed with its comment). Then restart nothing - sshd reads the file on each login.',
        'roottok'  => 'WHM > Development > Manage API Tokens: revoke every token you did not create. The reverse_trust_* tokens are cPanel\'s own transfer tokens and are safe.',
        'uid0'     => 'Any user other than root with uid 0 is a backdoor: userdel the account (after noting its home and shell history for the investigation) and check /etc/passwd again. Rotate the root password afterwards.',
        'resellers'=> 'WHM > Resellers > Edit Reseller Nameservers and Privileges: remove the "all" ACL from every reseller that is not you. A reseller never needs it.',
        'sshd'     => 'In /etc/ssh/sshd_config set PasswordAuthentication no and PermitRootLogin prohibit-password (or no, with a sudo user). Add your key first, test a second session, then: systemctl restart sshd.',
        'preload'  => 'Read the file: cat /etc/ld.so.preload. If you did not install the library listed, the server is rooted: empty the file (: > /etc/ld.so.preload), then treat it as a full compromise - restore from a backup made before the entry appeared, or reinstall. Do not just delete the .so and move on.',
        'sudoers'  => 'Remove the user rule with visudo (or delete its file in /etc/sudoers.d/) and take the user out of wheel/sudo: gpasswd -d USER wheel. Rules for wp-toolkit, CloudLinux and Imunify are shipped by their packages and are listed for the record only.',
        'syscron'  => 'Open the file named in the evidence and delete the line, then find what created it: stat the file for its birth time, and check /var/log/secure and the product\'s User Investigation for that minute. A cron line that fetches code means the payload it fetched is also on disk - scan with Imunify360 (imunify360-agent malware on-demand start --path=/).',
        'shellrc'  => 'Edit the file named in the evidence and remove the line; compare it with the package copy (rpm -V bash; diff against /etc/skel/.bashrc). Then open a NEW root shell and check nothing phoned home: ss -tnp | grep -v 127.0.0.1 while idle.',
        'tmpl'     => 'Restore cPanel\'s copy: /scripts/upcp --force rewrites /usr/local/cpanel/base/unprotected/cpanel/main.tmpl. Every password typed into cPanel while the template was tampered is known to the attacker - reset all of them from Firewall > Threat Report.',
        'sorry'    => 'Do not pay and do not delete the markers yet. Stop the encryption first (find the process: ps auxf, look for a recent unknown binary; kill it), then restore from the last clean backup. The files listed are the map of what was touched.',
        'ioc'      => 'Download the script from cPanel\'s CVE-2026-41940 advisory and run it as root: bash ioc_checksessions_files.sh. CRITICAL / WARNING lines name the session files that carry injected root records - if any appear, treat the server as compromised whatever the current version is.',
        'listen'   => 'Identify the process: ss -tlnp | grep :PORT then ls -l /proc/PID/exe and /proc/PID/cwd. A shell or interpreter listening on a public port that you did not start is a backdoor: kill it, delete its binary (after copying it for the investigation), and look for the cron/rc line that restarts it (the two checks above).',
        'hidden'   => 'A process ps cannot see is a rootkit: run rkhunter / chkrootkit, check /etc/ld.so.preload and lsmod for unknown modules. Do not clean it in place - restore from a backup taken before the compromise, or reinstall the server.',
        'ftp'      => 'cPanel > FTP Accounts > delete the sub-account (or remove its line from /etc/proftpd/USER as root). Then reset the account\'s passwords from Firewall > Threat Report.',
        'forwarder'=> 'cPanel > Forwarders > delete it. Mail already copied to the outside address is gone; change the mailbox password too.',
        'cron'     => 'cPanel > Cron Jobs > delete the line (or crontab -u USER -e). Scan the account for the payload: imunify360-agent malware on-demand start --path=/home/USER.',
        'sshkey'   => 'cPanel > SSH Access > Manage SSH Keys > delete/deauthorize the key, or remove the line from ~/.ssh/authorized_keys.',
        'contact'  => 'cPanel > Contact Information > put the customer\'s real address back. Password-reset links have been going to the attacker until then.',
        'mailbox'  => 'cPanel > Email Accounts > change the password (or delete a mailbox the customer never created). A created mailbox is a door AND a spam source.',
        'token'    => 'cPanel > Manage API Tokens > revoke it. An API token keeps working after every password change.',
        'shellrc_acct' => 'Remove the line from the account\'s ~/.bashrc / ~/.bash_profile / ~/.profile and scan the home with Imunify360.',
    ];
    return $m[$id] ?? '';
}

/* ------------------------------------------------------------------ account level */

/** When each API token was last USED, from cPanel's own token log: name => [unixtime, address]. One pass over the
 *  tail of the file; a token that never appears was never used (that is a fact worth showing, not an absence). */
function smpro_cc_token_last_use(): array {
    static $m = null; if ($m !== null) return $m;
    $m = [];
    $f = '/usr/local/cpanel/logs/api_tokens_log';
    if (!@is_readable($f)) return $m;
    foreach (explode("\n", (string)smpro_cc_run('tail -n 20000 ' . escapeshellarg($f), 20)) as $l) {
        if ($l === '' || !preg_match("/^\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})/", $l, $t)) continue;
        if (!preg_match("/Token Name: \['([^']{1,128})'\]/", $l, $n)) continue;
        $ip = preg_match("/Host: \['([0-9a-fA-F:.]{3,45})'\]/", $l, $h) ? $h[1] : '';
        $ts = (int)strtotime($t[1]);
        $k = $n[1];
        if (!isset($m[$k]) || $ts > $m[$k][0]) $m[$k] = [$ts, $ip];
    }
    return $m;
}
/** Who created each token and from which address, from cPanel's own access log: name => [unixtime, address, user]. */
function smpro_cc_token_created_by(): array {
    static $m = null; if ($m !== null) return $m;
    $m = [];
    foreach (['/usr/local/cpanel/logs/access_log'] as $f) {
        if (!@is_readable($f)) continue;
        foreach (explode("\n", (string)smpro_cc_run('grep -a api_token_create ' . escapeshellarg($f) . ' 2>/dev/null | grep -av "\\.svg" | tail -n 500', 25)) as $l) {
            if (!preg_match('#^(\S+) - (\S+) \[([0-9]{2}/[0-9]{2}/[0-9]{4}:[0-9:]{8})#', $l, $a)) continue;
            if (!preg_match('/token_name=([A-Za-z0-9._%-]{1,128})/', $l, $n)) continue;
            $d = DateTime::createFromFormat('m/d/Y:H:i:s', $a[3], new DateTimeZone('UTC'));
            $m[rawurldecode($n[1])] = [$d ? (int)$d->getTimestamp() : 0, $a[1], $a[2]];
        }
    }
    return $m;
}
/** One readable line about a token: what it can do, when it was made and by whom, when it expires, when it was last
 *  used. Every part is read from cPanel's own files; a part that cannot be read is said to be unknown, never left out. */
function smpro_cc_token_line(string $name, array $tk, bool $whm): string {
    $ct = (int)($tk['create_time'] ?? 0);
    $exp = $tk['expires_at'] ?? null;
    $acls = (array)($tk['acls'] ?? []);
    $full = !empty($tk['has_full_access']) || isset($acls['all']);
    $wl = $tk['whitelist_ips'] ?? null;
    $made = smpro_cc_token_created_by()[$name] ?? null;
    $use  = smpro_cc_token_last_use()[$name] ?? null;
    $p = [];
    $p[] = 'can do: ' . ($full ? ($whm ? 'EVERYTHING root can do in WHM' : 'everything the account can do') : ($acls ? count($acls) . ' permission(s): ' . implode(', ', array_slice(array_keys($acls), 0, 4)) . (count($acls) > 4 ? '…' : '') : ($whm ? 'permissions unreadable' : 'the account\'s own features')));
    $p[] = 'made: ' . ($ct ? date('Y-m-d H:i', $ct) : 'unknown');
    $p[] = 'by: ' . ($made ? ($made[2] !== '' ? $made[2] . ' from ' . $made[1] : $made[1]) . ($made[0] ? ' on ' . date('Y-m-d H:i', $made[0]) : '') : 'not in the log kept on this server');
    $p[] = 'expires: ' . ($exp ? date('Y-m-d H:i', (int)$exp) . ((int)$exp < time() ? ' (already expired - it no longer opens anything)' : '') : 'NEVER');
    $p[] = 'last used: ' . ($use ? date('Y-m-d H:i', $use[0]) . ($use[1] !== '' ? ' from ' . $use[1] : '') : 'never seen in the token log');
    if ($wl) $p[] = 'only from: ' . implode(', ', array_slice((array)$wl, 0, 3));
    return implode(' · ', $p);
}

/** Every cPanel account with its home and main domain. */
function smpro_cc_accounts(): array {
    $out = [];
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) {
        $u = basename($f);
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u) || !function_exists('posix_getpwnam')) continue;
        $pw = @posix_getpwnam($u); if (!is_array($pw)) continue;
        $dom = '';
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES) as $l) if (strpos($l, 'DNS=') === 0) { $dom = trim(substr($l, 4)); break; }
        $out[$u] = ['user' => $u, 'home' => (string)$pw['dir'], 'domain' => $dom, 'uid' => (int)$pw['uid']];
    }
    ksort($out);
    return $out;
}

/**
 * When a door was CREATED, by whom, from where - from cPanel's access log, which records the API call that made
 * it (execute/Ftp/add_ftp?user=..&domain=.., Email/add_pop, Cron add_line, Tokens, SSH, ContactInformation).
 * File modification times cannot say this: on a real server 65 of 90 FTP files shared one mtime because cPanel
 * had rewritten them all in one pass, and every account looked as if it had just gained an FTP sub-account.
 * Read once per request (one grep over the log), then answered per account from memory.
 *   ['user' => ['ftp' => [login => [ts, ip]], 'mailbox' => [[ts, ip]], 'cron' => [[ts, ip]], 'token' => [[ts, ip]],
 *              'sshkey' => [[ts, ip]], 'contact' => [[ts, ip]], 'forwarder' => [[ts, ip]]]]
 */
function smpro_cc_creation_index(): array {
    static $idx = null;
    if ($idx !== null) return $idx;
    $idx = [];
    $log = '/usr/local/cpanel/logs/access_log';
    if (!@is_readable($log)) return $idx;
    $pat = 'execute/Ftp/add_ftp|execute/Email/add_pop|execute/Email/add_forwarder|cpanel_jsonapi_func=(addftp|addpop|addforward|add_line)|execute/Cron/add_line|execute/Tokens/create|execute/SSH/(import|authorize)|execute/ContactInformation/(set|unset)';
    $raw = smpro_cc_run('grep -a -E ' . escapeshellarg($pat) . ' ' . escapeshellarg($log) . ' | tail -n 20000', 30);
    foreach (explode("\n", $raw) as $ln) {
        if (!preg_match('#^(\S+) (?:- |proxy )?(\S+) \[(\d\d)/(\d\d)/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\] "\w+ (\S+)#', $ln, $m)) continue;
        $ip = $m[1]; $user = $m[2]; $url = $m[10];
        $ts = gmmktime((int)$m[6], (int)$m[7], (int)$m[8], (int)$m[3], (int)$m[4], (int)$m[5]);
        $off = ((int)substr($m[9], 0, 3)) * 3600 + ((int)substr($m[9], 3, 2)) * 60 * ((int)substr($m[9], 0, 3) < 0 ? -1 : 1);
        $ts -= $off;
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $user)) continue;
        $kind = '';
        if (preg_match('#Ftp/add_ftp|func=addftp#', $url)) {
            $kind = 'ftp';
            $login = '';
            if (preg_match('/[?&]user=([^&]+)/', $url, $u)) { $login = rawurldecode($u[1]); if (strpos($login, '@') === false && preg_match('/[?&]domain=([^&]+)/', $url, $d)) $login .= '@' . rawurldecode($d[1]); }
            $idx[$user]['ftp'][strtolower($login !== '' ? $login : '?')] = [$ts, $ip];
            continue;
        }
        if (preg_match('#Email/add_pop|func=addpop#', $url))                  $kind = 'mailbox';
        elseif (preg_match('#Email/add_forwarder|func=addforward#', $url))    $kind = 'forwarder';
        elseif (preg_match('#Cron/add_line|func=add_line#', $url))           $kind = 'cron';
        elseif (preg_match('#Tokens/create#', $url))                          $kind = 'token';
        elseif (preg_match('#SSH/(import|authorize)#', $url))                 $kind = 'sshkey';
        elseif (preg_match('#ContactInformation/#', $url))                    $kind = 'contact';
        if ($kind !== '') $idx[$user][$kind][] = [$ts, $ip];
    }
    return $idx;
}

/** The newest creation event of a kind for an account inside the window: [ts, ip] or null. */
function smpro_cc_created(string $user, string $kind, int $since, string $login = ''): ?array {
    $idx = smpro_cc_creation_index();
    if ($kind === 'ftp') {
        $e = $idx[$user]['ftp'][strtolower($login)] ?? null;
        return ($e && $e[0] >= $since) ? $e : null;
    }
    $best = null;
    foreach ((array)($idx[$user][$kind] ?? []) as $e) if ($e[0] >= $since && ($best === null || $e[0] > $best[0])) $best = $e;
    return $best;
}

/** Is a file's mtime shared by most accounts' files of the same kind? Then it is a server-wide rewrite, not a change. */
function smpro_cc_mtime_is_rewrite(string $glob, int $mt): bool {
    static $memo = [];
    if (!isset($memo[$glob])) {
        $c = []; $n = 0;
        foreach (glob($glob) ?: [] as $f) { $k = intdiv((int)@filemtime($f), 60); $c[$k] = ($c[$k] ?? 0) + 1; $n++; }
        $memo[$glob] = ['n' => $n, 'c' => $c];
    }
    $m = $memo[$glob];
    return $m['n'] >= 10 && (($m['c'][intdiv($mt, 60)] ?? 0) * 2) > $m['n'];
}

/** The domains of one account, from cPanel's own map. */
function smpro_cc_domains_of(string $user): array {
    static $map = null;
    if ($map === null) {
        $map = [];
        foreach ((array)@file('/etc/userdatadomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            if (!preg_match('/^([^:]+):\s*([^=]+)==/', (string)$ln, $m)) continue;
            $map[trim($m[2])][] = strtolower(trim($m[1]));
        }
    }
    return $map[$user] ?? [];
}

/**
 * The doors added on one account, with when. Cheap: file mtimes and small files only.
 * Returns ['user','findings'=>[ ['kind','label','when','detail','flag'=>bool] ],'newest'=>ts,'flags'=>n]
 */
function smpro_cc_account_doors(array $acct, int $since): array {
    $u = $acct['user']; $home = $acct['home']; $f = [];
    $add = function (string $kind, string $label, int $when, string $detail, bool $flag, array $fix = []) use (&$f) { $f[] = ['kind' => $kind, 'label' => $label, 'when' => $when, 'detail' => $detail, 'flag' => $flag, 'fix' => $fix]; };

    // FTP sub-accounts: /etc/proftpd/<user> (also pure-ftpd), one line per login; the file's mtime is the last change.
    foreach (['/etc/proftpd/' . $u, '/etc/pure-ftpd/' . $u] as $pf) {
        if (!@is_file($pf)) continue;
        $mt = (int)@filemtime($pf);
        foreach ((array)@file($pf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            $c = explode(':', (string)$ln);
            $login = (string)($c[0] ?? '');
            if ($login === '' || $login === $u || strpos($login, '@') === false) continue;      // the main login and log-only entries are not sub-accounts
            $sus = (bool)preg_match('/^(root|admin|administrator|test|backup|support|cpanel|ftp|www|webmaster)@/i', $login);
            $cr  = smpro_cc_created($u, 'ftp', $since, $login);
            $rewrite = smpro_cc_mtime_is_rewrite(dirname($pf) . '/*', $mt);
            $when = $cr ? $cr[0] : $mt;
            $detail = 'home ' . (string)($c[5] ?? '') . ($cr ? ' - created ' . date('Y-m-d H:i', $cr[0]) . ' from ' . $cr[1] : ($rewrite ? ' - (the FTP files were rewritten server-wide on ' . date('Y-m-d H:i', $mt) . ', so the file date says nothing about this login)' : ' - the FTP list changed ' . date('Y-m-d H:i', $mt)));
            $add('ftp', 'FTP sub-account ' . $login, $when, $detail, $sus || $cr !== null || (!$rewrite && $mt >= $since), ['op' => 'ftp_delete', 'user' => $u, 'login' => $login]);
        }
    }
    // Mail forwarders to somewhere else: /etc/valiases/<domain>
    foreach (smpro_cc_domains_of($u) as $dom) {
        $vf = '/etc/valiases/' . $dom;
        if (!@is_file($vf)) continue;
        $mt = (int)@filemtime($vf);
        foreach ((array)@file($vf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            if (!preg_match('/^([^:]+):\s*(.+)$/', (string)$ln, $m) || $m[1] === '*') continue;
            $targets = array_map('trim', explode(',', $m[2]));
            foreach ($targets as $tg) {
                if (preg_match('/^:(fail|blackhole|defer)/', $tg) || strpos($tg, '@') === false) continue;
                $td = strtolower(substr($tg, strrpos($tg, '@') + 1));
                if (in_array($td, smpro_cc_domains_of($u), true)) continue;                 // internal
                $cr = smpro_cc_created($u, 'forwarder', $since);
                $add('forwarder', 'Mail forwarder ' . $m[1] . ' → ' . $tg, $cr ? $cr[0] : $mt, 'copies of this mailbox\'s mail leave the server - ' . ($cr ? 'a forwarder was added ' . date('Y-m-d H:i', $cr[0]) . ' from ' . $cr[1] : 'the forwarder list changed ' . date('Y-m-d H:i', $mt)), $cr !== null || $mt >= $since, ['op' => 'fwd_delete', 'user' => $u, 'address' => $m[1] . (strpos($m[1], '@') === false ? '@' . $dom : ''), 'target' => $tg]);
            }
        }
    }
    // Cron
    $cf = '/var/spool/cron/' . $u;
    if (@is_file($cf)) {
        $mt = (int)@filemtime($cf); $lines = array_values(array_filter(array_map('trim', (array)@file($cf, FILE_IGNORE_NEW_LINES)), fn($l) => $l !== '' && $l[0] !== '#'));
        $ownDoms = smpro_cc_domains_of($u);
        $isSus = function (string $l) use ($ownDoms): bool {
            if (!preg_match('/(curl|wget|base64|\/tmp\/|\/dev\/shm|python|perl|nc |bash -c)/i', $l)) return false;
            // a fetch of the account's OWN site (a CMS cron over HTTP) is routine; a fetch from anywhere else is not
            if (preg_match('#(curl|wget).*?https?://([^/\s"\x27]+)#i', $l, $m)) { $h = strtolower(preg_replace('/^www\./', '', $m[2])); foreach ($ownDoms as $d) if ($h === $d || substr($h, -strlen('.' . $d)) === '.' . $d) return false; }
            return true;
        };
        $sus = 0; foreach ($lines as $l) if ($isSus($l)) $sus++;
        $cr = smpro_cc_created($u, 'cron', $since);
        if ($lines) $add('cron', count($lines) . ' cron entr' . (count($lines) === 1 ? 'y' : 'ies') . ($sus ? ', ' . $sus . ' fetching/decoding' : ''), $cr ? $cr[0] : $mt, ($cr ? 'an entry was added ' . date('Y-m-d H:i', $cr[0]) . ' from ' . $cr[1] : 'crontab changed ' . date('Y-m-d H:i', $mt)) . ($sus ? ' - ' . implode(' | ', array_slice(array_filter($lines, $isSus), 0, 2)) : ''), $sus > 0 || $cr !== null || $mt >= $since, $sus ? ['op' => 'cron_clean', 'user' => $u] : []);
    }
    // SSH keys
    $kf = $home . '/.ssh/authorized_keys';
    if (@is_link($kf)) {
        $add('sshkey', 'authorized_keys is a SYMLINK -> ' . (string)@readlink($kf), (int)@lstat($kf)['mtime'], 'a link here makes root act on another file when it edits this one; nothing is offered to run on it', true);
    } elseif (@is_file($kf)) {
        $mt = (int)@filemtime($kf); $n = count(array_filter(array_map('trim', (array)@file($kf, FILE_IGNORE_NEW_LINES)), fn($l) => $l !== '' && $l[0] !== '#'));
        $cr = smpro_cc_created($u, 'sshkey', $since);
        if ($n) $add('sshkey', $n . ' SSH key(s) authorised', $cr ? $cr[0] : $mt, $cr ? 'a key was added through cPanel ' . date('Y-m-d H:i', $cr[0]) . ' from ' . $cr[1] : 'authorized_keys changed ' . date('Y-m-d H:i', $mt), $cr !== null || $mt >= $since, ['op' => 'sshkey_clear', 'user' => $u]);
    }
    // Shell start-up files in the account's home: the same phone-home persistence, one account down
    $rcHits = [];
    foreach (['.bashrc', '.bash_profile', '.profile'] as $rc) {
        $p = $home . '/' . $rc; if (@is_link($p) || !@is_file($p) || @filesize($p) > 65536) continue;
        foreach ((array)@file($p, FILE_IGNORE_NEW_LINES) as $l) { $l = trim($l); if ($l === '' || $l[0] === '#') continue; if (preg_match('/(curl|wget)\b.*\|\s*(ba)?sh|base64\s+(-d|--decode)|\/dev\/tcp\/|\bnc\b|\bsocat\b|nohup\s|setsid\s/i', $l)) $rcHits[] = $rc . ': ' . mb_substr($l, 0, 100); }
    }
    if ($rcHits) $add('shellrc', count($rcHits) . ' shell start-up line(s) fetching/decoding code', (int)@filemtime($home . '/.bashrc'), implode(' | ', array_slice($rcHits, 0, 2)), true, ['op' => 'rc_clean', 'user' => $u]);
    // Contact e-mail (where password-reset mails go)
    $ci = $home . '/.cpanel/contactinfo';
    if (@is_file($ci)) {
        $mt = (int)@filemtime($ci); $em = '';
        foreach ((array)@file($ci, FILE_IGNORE_NEW_LINES) as $l) if (preg_match('/^email=(.*)$/', $l, $m)) { $em = trim($m[1]); break; }
        $cr = smpro_cc_created($u, 'contact', $since);
        if ($cr || $mt >= $since) $add('contact', 'Contact e-mail changed' . ($em !== '' ? ' → ' . $em : ''), $cr ? $cr[0] : $mt, 'password-reset links now go there - changed ' . date('Y-m-d H:i', $cr ? $cr[0] : $mt) . ($cr ? ' from ' . $cr[1] : ''), true);
    }
    // Mailboxes added (the domain's shadow lists them with a last-change day)
    foreach (smpro_cc_domains_of($u) as $dom) {
        $sf = $home . '/etc/' . $dom . '/shadow';
        if (!@is_file($sf)) continue;
        foreach ((array)@file($sf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            $c = explode(':', (string)$ln);
            $day = isset($c[2]) && ctype_digit($c[2]) ? (int)$c[2] * 86400 : 0;
            if ($day >= $since && $day > 0) $add('mailbox', 'Mailbox ' . (string)$c[0] . '@' . $dom . ' password set/changed', $day, 'on ' . date('Y-m-d', $day) . ' (routine unless nobody did it)', false);
        }
    }
    // Mailboxes CREATED in the window (the access log records add_pop) - a new door, unlike a password change
    foreach ((array)(smpro_cc_creation_index()[$u]['mailbox'] ?? []) as $e) if ($e[0] >= $since) $add('mailbox', 'Mailbox created', $e[0], 'added ' . date('Y-m-d H:i', $e[0]) . ' from ' . $e[1], true);
    // API tokens the account issued (cheap file read, not the API). The file is {"tokens": {hash: {name, create_time, ...}}}.
    $tf = '/var/cpanel/authn/api_tokens_v2/cpanel/' . $u . '.json';
    if (@is_file($tf)) {
        $j = json_decode((string)@file_get_contents($tf), true);
        foreach ((array)($j['tokens'] ?? []) as $hash => $tk) {
            $ct = (int)($tk['create_time'] ?? 0); $name = (string)($tk['name'] ?? substr((string)$hash, 0, 8));
            $exp = $tk['expires_at'] ?? null; $dead = $exp !== null && (int)$exp > 0 && (int)$exp < time();
            $add('token', 'API token ' . $name . (!empty($tk['has_full_access']) ? ' (full access)' : '') . ($dead ? ' — expired' : ''), $ct,
                 smpro_cc_token_line($name, (array)$tk, false) . ' — a password that no reset rotates',
                 $ct >= $since && !$dead, ['op' => 'token_revoke', 'user' => $u, 'name' => $name]);
        }
    }
    usort($f, fn($a, $b) => $b['when'] <=> $a['when']);
    $newest = $f ? max(array_column($f, 'when')) : 0;
    return ['user' => $u, 'domain' => $acct['domain'], 'findings' => $f, 'newest' => $newest, 'flags' => count(array_filter($f, fn($x) => $x['flag']))];
}

/** All accounts, flagged first. Bounded by time so a huge server still answers. */
function smpro_cc_scan_accounts(int $days = 30, int $budgetSec = 40): array {
    $since = time() - max(1, $days) * 86400; $t0 = microtime(true);
    $rows = []; $scanned = 0; $partial = false;
    foreach (smpro_cc_accounts() as $a) {
        if (microtime(true) - $t0 > $budgetSec) { $partial = true; break; }
        $rows[] = smpro_cc_account_doors($a, $since); $scanned++;
    }
    usort($rows, fn($x, $y) => ($y['flags'] <=> $x['flags']) ?: ($y['newest'] <=> $x['newest']));
    return ['rows' => $rows, 'scanned' => $scanned, 'partial' => $partial, 'days' => $days, 'since' => $since, 'took' => round(microtime(true) - $t0, 2)];
}
