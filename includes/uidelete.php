<?php
/**
 * includes/uidelete.php - "who deleted these files?", answered from evidence rather than from a guess.
 *
 * A deletion is the hardest thing to investigate on a hosting account, because the thing that would prove it is
 * the thing that is gone. What survives is scattered across half a dozen logs written by different programs in
 * different formats, and none of them is complete on its own:
 *
 *   cPanel File Manager   /usr/local/cpanel/logs/access_log   - the API call, with the account and the IP
 *   FTP                   /var/log/messages, /var/log/xferlog - DELE / RMD, with the login name and the IP
 *   SSH / SFTP            /var/log/secure, sftp-server        - the session; the file only when logging is verbose
 *   The website itself    the domain access logs              - a request that ran code which deleted files
 *   THIS PLUGIN           /var/log/smpro/audit.log            - cleanup, quarantine, auto-purge
 *   The filesystem        parent directory mtime, ~/.trash    - a window, and sometimes the files themselves
 *
 * Two rules run through all of it.
 *
 * FIRST: a source that could not be read is never reported as a source that was read and found nothing. Every
 * collector says whether its log existed and was readable, and the report carries that list. "No FTP deletions"
 * and "the FTP log is not readable by this process" are opposite findings, and confusing them is how an
 * investigation ends by blaming the wrong person.
 *
 * SECOND: this plugin looks at itself first. SM Pro has features that delete files - quarantine, cleanup and the
 * auto-purge that once removed source files on a cache-name match. An investigation that cannot name its own
 * tooling as a suspect is not an investigation.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** A source's own account of itself, so "nothing found" can be told apart from "nothing looked at". */
function smpro_uid_source(string $name, string $path, string $why = ''): array {
    if ($path === '')            return ['name' => $name, 'path' => '', 'state' => 'n/a',        'why' => $why ?: 'not present on this server'];
    if (!@file_exists($path))    return ['name' => $name, 'path' => $path, 'state' => 'missing',  'why' => 'the file does not exist on this server'];
    if (!@is_readable($path))    return ['name' => $name, 'path' => $path, 'state' => 'unreadable', 'why' => 'exists but this process cannot read it'];
    return ['name' => $name, 'path' => $path, 'state' => 'read', 'why' => ''];
}

/** Read a bounded tail of a log, filtered to lines that could matter. Never loads a whole log into memory. */
function smpro_uid_grep(string $file, array $needles, int $tail = 200000, int $cap = 4000, int $timeout = 20): array {
    if (!@is_readable($file) || !$needles) return [];
    $pat = implode('|', array_map(fn($n) => preg_quote($n, '/'), $needles));
    $cmd = 'tail -n ' . (int)$tail . ' ' . escapeshellarg($file)
         . ' | grep -aE ' . escapeshellarg($pat) . ' | tail -n ' . (int)$cap;
    $raw = (string)@shell_exec('timeout ' . (int)$timeout . ' sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null');
    return $raw === '' ? [] : array_filter(explode("\n", $raw), fn($l) => trim($l) !== '');
}

/* ============================== the collectors ============================== */

/**
 * cPanel File Manager and the file APIs.
 *
 * This is the one that usually holds the answer, because it records the account AND the address on the same line.
 * What it does NOT record is which file: a delete is a POST and cPanel logs only the request line, so the target
 * lives in a body nobody kept. So this reports the ACT and the actor precisely and says the filename is not in
 * this source rather than inventing one.
 */
function smpro_uid_cpanel(string $account, int $fromTs, int $toTs): array {
    $log = '/usr/local/cpanel/logs/access_log';
    $src = smpro_uid_source('cPanel File Manager', $log);
    $rows = [];
    if ($src['state'] === 'read') {
        // Every cPanel call that removes something. Kept as literals so the list can be read and argued with.
        $ops = ['fileop', 'Fileman', 'unlink', 'delete_files', 'emptytrash', 'trash', 'rmdir'];
        foreach (smpro_uid_grep($log, $ops) as $ln) {
            if (!preg_match('#^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)#', $ln, $m)) continue;
            [$all, $ip, $who, $when, $method, $path] = $m;
            if ($account !== '' && $who !== $account) continue;
            $ts = function_exists('smpro_ui_parse_apachetime') ? smpro_ui_parse_apachetime($when) : (int)@strtotime($when);
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            // A read of the File Manager is not a deletion. Only the calls that remove something count.
            $isDel = (stripos($path, 'op=unlink') !== false) || (stripos($path, 'op=trash') !== false)
                  || (stripos($path, 'emptytrash') !== false) || (stripos($path, 'delete_files') !== false)
                  || (stripos($path, 'fileop') !== false && stripos($path, 'op=') !== false && stripos($path, 'op=copy') === false && stripos($path, 'op=move') === false)
                  || preg_match('#/execute/Fileman/(?:unlink|trash|emptytrash)#i', $path);
            if (!$isDel) continue;
            $target = '';
            if (preg_match('#[?&](?:file|files|sourcefiles|doubledot|path|dir)=([^&\s"]+)#i', $path, $tm)) $target = rawurldecode($tm[1]);
            $rows[] = ['ts' => $ts, 'source' => 'cPanel File Manager', 'actor' => $who, 'actor_ip' => $ip,
                       'action' => $method . ' ' . preg_replace('/\?.*$/', '', $path),
                       'target' => $target !== '' ? $target : '(the filename is not recorded in this log — cPanel logs the request line only, and a delete sends its targets in the body)',
                       'confidence' => 'confirmed', 'evidence' => trim($ln)];
        }
    }
    return ['source' => $src, 'rows' => $rows];
}

/**
 * FTP. Unlike cPanel this one DOES name the file, which is why an FTP deletion is usually the easiest to prove.
 * pure-ftpd writes to syslog; xferlog is checked too because some builds use it and only it.
 */
function smpro_uid_ftp(string $account, int $fromTs, int $toTs): array {
    $out = ['sources' => [], 'rows' => []];
    $yr = (int)date('Y');
    foreach (['/var/log/messages', '/var/log/syslog', '/var/log/xferlog', '/var/log/proftpd/proftpd.log'] as $log) {
        $src = smpro_uid_source('FTP (' . basename($log) . ')', $log);
        $out['sources'][] = $src;
        if ($src['state'] !== 'read') continue;
        foreach (smpro_uid_grep($log, ['DELE', 'RMD', 'delete', 'rmdir']) as $ln) {
            if (!preg_match('/\b(DELE|RMD|rmdir|delete)\b/i', $ln)) continue;
            $ip = ''; if (preg_match('/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/', $ln, $im)) $ip = $im[1];
            $who = ''; if (preg_match('/\[([A-Za-z0-9._-]+)\]\s*\[?(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $um)) $who = $um[1];
            if ($who === '' && preg_match('/user\s+\[?([A-Za-z0-9._-]+)\]?/i', $ln, $um)) $who = $um[1];
            // The account owns its own FTP users, which are "account" or "name@domain" - match either.
            if ($account !== '' && $who !== '' && $who !== $account && strpos($who, $account . '@') !== 0 && !preg_match('/^' . preg_quote($account, '/') . '_/', $who)) continue;
            $ts = 0;
            if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = smpro_syslog_ts($tm[1], $yr);
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2}T?\s?\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = (int)@strtotime(str_replace('T', ' ', $tm[1]));
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            $target = '';
            if (preg_match('/(?:DELE|RMD)\s+(\S+)/i', $ln, $fm)) $target = $fm[1];
            elseif (preg_match('#(/home/\S+)#', $ln, $fm)) $target = $fm[1];
            $out['rows'][] = ['ts' => $ts, 'source' => 'FTP', 'actor' => $who ?: '(not named on this line)', 'actor_ip' => $ip,
                              'action' => 'FTP delete', 'target' => $target, 'confidence' => 'confirmed', 'evidence' => trim($ln)];
        }
    }
    return $out;
}

/**
 * SSH and SFTP.
 *
 * Honest about its limits: a shell `rm` leaves NO record anywhere unless auditd or shell accounting was already
 * running, and SFTP names the file only when the server was started with verbose logging. So this collects the
 * SESSIONS that were open in the window - which is a lead, not a proof - plus any SFTP remove line that does
 * exist, and labels the two differently so nobody reads a session as a deletion.
 */
function smpro_uid_ssh(string $account, int $fromTs, int $toTs): array {
    $out = ['sources' => [], 'rows' => []];
    $yr = (int)date('Y');
    foreach (['/var/log/secure', '/var/log/auth.log'] as $log) {
        $src = smpro_uid_source('SSH / SFTP (' . basename($log) . ')', $log);
        $out['sources'][] = $src;
        if ($src['state'] !== 'read') continue;
        foreach (smpro_uid_grep($log, ['sftp', 'Accepted', 'session opened']) as $ln) {
            $ts = 0;
            if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = smpro_syslog_ts($tm[1], $yr);
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2}T?\s?\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = (int)@strtotime(str_replace('T', ' ', $tm[1]));
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            $ip = ''; if (preg_match('/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $im)) $ip = $im[1];
            $who = ''; if (preg_match('/for\s+(?:invalid user\s+)?([A-Za-z0-9._-]+)\s+from/', $ln, $um)) $who = $um[1];
            if ($who === '' && preg_match('/session opened for user\s+([A-Za-z0-9._-]+)/', $ln, $um)) $who = $um[1];
            if ($account !== '' && $who !== '' && $who !== $account) continue;

            // An sftp-server line that actually names a removal is proof. A session is only a lead.
            if (preg_match('/sftp.*\b(remove|rmdir)\b\s+"?([^"\s]+)/i', $ln, $rm)) {
                $out['rows'][] = ['ts' => $ts, 'source' => 'SFTP', 'actor' => $who ?: $account, 'actor_ip' => $ip,
                                  'action' => 'SFTP ' . strtolower($rm[1]), 'target' => $rm[2],
                                  'confidence' => 'confirmed', 'evidence' => trim($ln)];
            } else {
                $out['rows'][] = ['ts' => $ts, 'source' => 'SSH/SFTP session', 'actor' => $who ?: $account, 'actor_ip' => $ip,
                                  'action' => 'session open',
                                  'target' => '(a shell session. A shell `rm` writes no log anywhere unless auditd or shell accounting was already running, so this is a lead, not proof)',
                                  'confidence' => 'circumstantial', 'evidence' => trim($ln)];
            }
        }
    }
    return $out;
}

/**
 * THIS PLUGIN. Checked first in the report and never omitted.
 *
 * SM Pro quarantines, cleans and auto-purges. An auto-purge matching on cache NAMES once removed
 * OpenCart and Twig SOURCE files across 92 sites. An investigation that cannot name its own tooling as a suspect
 * will confidently blame a customer for something the panel did.
 */
function smpro_uid_smpro(string $account, int $fromTs, int $toTs): array {
    $log = defined('SMPRO_AUDIT_LOG') ? SMPRO_AUDIT_LOG : '/var/log/smpro/audit.log';
    $src = smpro_uid_source('SM Pro itself (audit log)', $log);
    $rows = [];
    if ($src['state'] === 'read') {
        foreach (smpro_uid_grep($log, ['purge', 'quarantine', 'clean', 'delete', 'remove', 'restore']) as $ln) {
            $j = json_decode(trim($ln), true);
            $ts = is_array($j) ? (int)($j['ts'] ?? @strtotime((string)($j['time'] ?? ''))) : 0;
            if (!$ts && preg_match('/"?(?:ts|time)"?\s*[:=]\s*"?(\d{9,11})/', $ln, $tm)) $ts = (int)$tm[1];
            if (!$ts && preg_match('/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = (int)@strtotime($tm[1]);
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            if ($account !== '' && stripos($ln, $account) === false) continue;
            $act = is_array($j) ? (string)($j['event'] ?? $j['action'] ?? 'action') : 'action';
            $rows[] = ['ts' => $ts, 'source' => 'SM Pro', 'actor' => is_array($j) ? (string)($j['actor'] ?? 'the panel') : 'the panel',
                       'actor_ip' => is_array($j) ? (string)($j['ip'] ?? '') : '',
                       'action' => $act, 'target' => is_array($j) ? (string)($j['path'] ?? $j['file'] ?? '') : '',
                       'confidence' => 'confirmed', 'evidence' => trim(substr($ln, 0, 400))];
        }
    }
    return ['source' => $src, 'rows' => $rows];
}

/**
 * The filesystem. Two things it can still say after the files are gone.
 *
 * A directory's mtime is the moment its last entry was created, renamed or removed - so it dates the deletion
 * even when no log names it, which on a shell `rm` is the only evidence that exists. And cPanel's File Manager
 * moves to ~/.trash rather than unlinking, so the "deleted" files are often still sitting there with the time
 * they were put there.
 */
function smpro_uid_filesystem(string $account, int $fromTs, int $toTs, int $maxDirs = 40): array {
    // From /etc/passwd, not from a guessed /home/<account>: a cPanel server can have several home partitions
    // (/home2, /home3), and looking in the wrong one would report "nothing changed" about a directory that does
    // not exist - the same false negative this whole file exists to avoid.
    $home = '';
    if ($account !== '' && function_exists('posix_getpwnam')) { $pw = @posix_getpwnam($account); if (is_array($pw) && !empty($pw['dir'])) $home = (string)$pw['dir']; }
    if ($home === '' && $account !== '' && @is_dir(smpro_user_home($account))) $home = smpro_user_home($account);
    $src = smpro_uid_source('The account\'s files', $home, 'the account has no home directory on this server');
    $out = ['source' => $src, 'dirs' => [], 'trash' => [], 'trash_dir' => ''];
    if ($src['state'] !== 'read') return $out;

    // Directories whose contents changed inside the window. -maxdepth keeps this bounded on a large account.
    $cmd = 'find ' . escapeshellarg($home) . ' -maxdepth 5 -type d -newermt ' . escapeshellarg('@' . $fromTs)
         . ' ! -newermt ' . escapeshellarg('@' . $toTs) . ' -printf ' . escapeshellarg('%T@ %p\n') . ' 2>/dev/null | sort -rn | head -n ' . (int)$maxDirs;
    foreach (explode("\n", (string)@shell_exec('timeout 25 sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null')) as $ln) {
        $ln = trim($ln); if ($ln === '') continue;
        $p = explode(' ', $ln, 2); if (count($p) !== 2) continue;
        $out['dirs'][] = ['ts' => (int)(float)$p[0], 'dir' => $p[1]];
    }

    $trash = rtrim($home, '/') . '/.trash';
    if (@is_dir($trash)) {
        $out['trash_dir'] = $trash;
        $tc = 'find ' . escapeshellarg($trash) . ' -maxdepth 3 -printf ' . escapeshellarg('%T@ %s %p\n') . ' 2>/dev/null | sort -rn | head -n 60';
        foreach (explode("\n", (string)@shell_exec('timeout 20 sh -c ' . escapeshellarg($tc) . ' 2>/dev/null')) as $ln) {
            $ln = trim($ln); if ($ln === '') continue;
            $p = explode(' ', $ln, 3); if (count($p) !== 3) continue;
            $out['trash'][] = ['ts' => (int)(float)$p[0], 'size' => (int)$p[1], 'path' => $p[2]];
        }
    }
    return $out;
}

/* ============================== deleted MAIL ==============================
 * Mail is a different investigation from files, with a different trail, and the file collectors above see none
 * of it: messages do not live in the document root and no File Manager call touches them.
 *
 * What Dovecot records BY DEFAULT is the disconnect summary of every IMAP/POP session:
 *
 *   imap(user)<pid><session>: Logged out in=123 out=456 deleted=0 expunged=37 ...
 *
 * That is the whole answer to "how many, by whom, from where, and when" - the session line above it carries the
 * address. What it does NOT carry is WHICH messages, because naming them needs the mail_log plugin, which cPanel
 * does not enable. So this reports the counts as fact, reports whether mail_log is on, and says exactly what
 * turning it on would add - rather than leaving an operator to conclude from silence that nothing was deleted.
 * ========================================================================= */

/** Is Dovecot's per-message logging on? The difference between "37 messages were expunged" and naming them. */
function smpro_uid_maillog_enabled(): array {
    $conf = ['/etc/dovecot/dovecot.conf', '/etc/dovecot/conf.d/90-plugin.conf', '/etc/dovecot/conf.d/10-logging.conf'];
    foreach ($conf as $f) {
        if (!@is_readable($f)) continue;
        $txt = (string)@file_get_contents($f, false, null, 0, 200000);
        if (preg_match('/mail_log_events|mail_log\b/', $txt)) return ['on' => true, 'where' => $f];
    }
    // cPanel keeps its own overrides here, and this is where an operator would add it.
    if (@is_dir('/etc/dovecot/conf.d')) {
        foreach ((array)@glob('/etc/dovecot/conf.d/*.conf') as $f) {
            if (!@is_readable($f)) continue;
            if (preg_match('/mail_log_events/', (string)@file_get_contents($f, false, null, 0, 200000))) return ['on' => true, 'where' => $f];
        }
    }
    return ['on' => false, 'where' => ''];
}

/** Every mailbox this account owns, so a session line can be tied to the account that asked about it. */
function smpro_uid_mailboxes(string $account, string $home): array {
    $out = [$account];
    $dir = rtrim($home, '/') . '/mail';
    foreach ((array)@glob($dir . '/*', GLOB_ONLYDIR) as $d) {
        $domain = basename($d);
        foreach ((array)@glob($d . '/*', GLOB_ONLYDIR) as $b) $out[] = basename($b) . '@' . $domain;
    }
    return array_values(array_unique($out));
}

/**
 * Deletions from a mailbox: the sessions that did them, the messages when Dovecot was told to name them, and
 * whatever is still sitting in Trash.
 */
function smpro_uid_mail(string $account, int $fromTs, int $toTs, string $home = ''): array {
    $out = ['sources' => [], 'rows' => [], 'maillog' => smpro_uid_maillog_enabled(), 'trash' => [], 'boxes' => 0];
    $yr = (int)date('Y');
    $boxes = $home !== '' ? smpro_uid_mailboxes($account, $home) : [$account];
    $out['boxes'] = count($boxes);
    $mine = array_flip(array_map('strtolower', $boxes));

    foreach (['/var/log/maillog', '/var/log/mail.log', '/var/log/dovecot.log'] as $log) {
        $src = smpro_uid_source('Mailbox activity (' . basename($log) . ')', $log);
        $out['sources'][] = $src;
        if ($src['state'] !== 'read') continue;

        // Sessions carry the address; the disconnect summary carries the counts. They are different lines, so the
        // address is remembered per session id and attached when the summary arrives.
        $ipOf = [];
        foreach (smpro_uid_grep($log, ['expunged=', 'deleted=', 'imap-login', 'pop3-login', 'expunge', 'mail_log'], 300000, 8000, 25) as $ln) {
            $ts = 0;
            if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = smpro_syslog_ts($tm[1], $yr);
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2}T?\s?\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = (int)@strtotime(str_replace('T', ' ', $tm[1]));
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;

            $user = ''; if (preg_match('/\b(?:imap|pop3|lmtp)\(([^)<]+)/i', $ln, $um)) $user = strtolower(trim($um[1]));
            if ($user === '' && preg_match('/\buser=<([^>]+)>/i', $ln, $um)) $user = strtolower($um[1]);
            $sid = ''; if (preg_match('/<([A-Za-z0-9+\/=]{8,})>\s*:/', $ln, $sm)) $sid = $sm[1];
            $ip = ''; if (preg_match('/\brip=(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $im)) $ip = $im[1];
            if ($ip === '' && preg_match('/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $im)) $ip = $im[1];

            if ($user !== '' && !isset($mine[$user])) continue;             // another account's mailbox
            if ($ip !== '' && $sid !== '') $ipOf[$sid] = $ip;
            if ($ip === '' && $sid !== '' && isset($ipOf[$sid])) $ip = $ipOf[$sid];

            // 1) The default-on evidence: a session that expunged or deleted messages.
            if (preg_match('/\b(?:expunged|deleted)=(\d+)/', $ln, $cm)) {
                $exp = 0; $del = 0;
                if (preg_match('/\bexpunged=(\d+)/', $ln, $e)) $exp = (int)$e[1];
                if (preg_match('/\bdeleted=(\d+)/', $ln, $d)) $del = (int)$d[1];
                if ($exp + $del <= 0) continue;                             // a session that deleted nothing is noise
                $out['rows'][] = ['ts' => $ts, 'source' => 'Mailbox session', 'actor' => $user ?: $account, 'actor_ip' => $ip,
                    'action' => 'session removed ' . ($exp + $del) . ' message(s)' . ($exp ? ' (' . $exp . ' expunged)' : ''),
                    'target' => '(Dovecot records HOW MANY per session by default, not which. Turn on the mail_log plugin to get the mailbox, the subject and the sender for each one.)',
                    'confidence' => 'confirmed', 'evidence' => trim($ln)];
                continue;
            }
            // 2) The extra evidence, only present if mail_log was enabled: an individual message, by name.
            if (preg_match('/\b(expunge|delete)\b/i', $ln) && preg_match('/(?:box|mailbox)=([^\s,]+)/i', $ln, $bm)) {
                $subj = ''; if (preg_match('/subject=([^,]+)/i', $ln, $sm2)) $subj = trim($sm2[1]);
                $out['rows'][] = ['ts' => $ts, 'source' => 'Mailbox message', 'actor' => $user ?: $account, 'actor_ip' => $ip,
                    'action' => 'message expunged', 'target' => trim($bm[1]) . ($subj !== '' ? ' — ' . $subj : ''),
                    'confidence' => 'confirmed', 'evidence' => trim($ln)];
            }
        }
    }

    // Folders and whole addresses are different losses from individual messages, and the person asking usually
    // means one of those: "the Archive folder is gone", "the sales@ mailbox is gone".
    $out['folders']  = smpro_uid_mail_folders($account, $fromTs, $toTs, $home, $boxes);
    $out['accounts'] = smpro_uid_mail_accounts($account, $fromTs, $toTs, $home);
    $out['sources']  = array_merge($out['sources'], $out['folders']['sources'], $out['accounts']['sources']);
    foreach ($out['folders']['named'] as $f)
        $out['rows'][] = ['ts' => $f['ts'], 'source' => 'Mail folder', 'actor' => $f['mailbox'], 'actor_ip' => $f['ip'],
                          'action' => 'folder deleted', 'target' => $f['folder'], 'confidence' => 'confirmed', 'evidence' => $f['evidence']];
    foreach ($out['accounts']['deleted'] as $a)
        $out['rows'][] = ['ts' => $a['ts'], 'source' => 'Email account', 'actor' => $a['actor'], 'actor_ip' => $a['ip'],
                          'action' => $a['kind'] . ' deleted', 'target' => $a['address'] !== '' ? $a['address'] : '(the address is not in this log line)',
                          'confidence' => 'confirmed', 'evidence' => $a['evidence']];

    // Trash is where a webmail "delete" usually puts things first - often the messages are simply still there.
    if ($home !== '') {
        $globs = [rtrim($home, '/') . '/mail/*/*/.Trash/cur', rtrim($home, '/') . '/mail/.Trash/cur'];
        foreach ($globs as $g) {
            foreach ((array)@glob($g, GLOB_ONLYDIR) as $dir) {
                $cmd = 'find ' . escapeshellarg($dir) . ' -maxdepth 1 -type f -newermt ' . escapeshellarg('@' . $fromTs)
                     . ' ! -newermt ' . escapeshellarg('@' . $toTs) . ' -printf ' . escapeshellarg('%T@ %s %p\n')
                     . ' 2>/dev/null | sort -rn | head -n 40';
                foreach (explode("\n", (string)@shell_exec('timeout 20 sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null')) as $ln) {
                    $ln = trim($ln); if ($ln === '') continue;
                    $p = explode(' ', $ln, 3); if (count($p) !== 3) continue;
                    $out['trash'][] = ['ts' => (int)(float)$p[0], 'size' => (int)$p[1], 'path' => $p[2]];
                }
            }
        }
    }
    return $out;
}

/**
 * FOLDERS that are gone, by name.
 *
 * Two independent ways to name one, because neither is complete:
 *
 *  1. Dovecot's mail_log plugin writes "Mailbox deleted: INBOX.Archive" - the name, exactly, with the session and
 *     therefore the address. Only present where the plugin is enabled.
 *  2. The account's own subscription list. Every folder a mail client subscribed to is named in the maildir's
 *     `subscriptions` file, and a folder that is still listed there while its directory is GONE from disk is a
 *     folder that used to exist. This is on by default and needs no plugin, which makes it the one that usually
 *     answers the question - but it dates the loss only as far as the subscription file's own timestamp, so it is
 *     reported as a name without a precise time rather than dressed up as an event.
 */
function smpro_uid_mail_folders(string $account, int $fromTs, int $toTs, string $home, array $boxes): array {
    $out = ['named' => [], 'missing' => [], 'sources' => []];

    // 1) named outright, where the plugin is on
    foreach (['/var/log/maillog', '/var/log/mail.log', '/var/log/dovecot.log'] as $log) {
        if (!@is_readable($log)) continue;
        $yr = (int)date('Y');
        foreach (smpro_uid_grep($log, ['Mailbox deleted', 'mailbox_delete', 'Mailbox renamed'], 300000, 3000, 20) as $ln) {
            $ts = 0;
            if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = smpro_syslog_ts($tm[1], $yr);
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2}T?\s?\d{2}:\d{2}:\d{2})/', $ln, $tm)) $ts = (int)@strtotime(str_replace('T', ' ', $tm[1]));
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            $user = ''; if (preg_match('/\b(?:imap|pop3)\(([^)<]+)/i', $ln, $um)) $user = strtolower(trim($um[1]));
            if ($user !== '' && !in_array($user, array_map('strtolower', $boxes), true)) continue;
            $name = ''; if (preg_match('/Mailbox (?:deleted|renamed)[:\s]+([^\s,]+)/i', $ln, $nm)) $name = trim($nm[1]);
            if ($name === '') continue;
            $ip = ''; if (preg_match('/\brip=(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $im)) $ip = $im[1];
            $out['named'][] = ['ts' => $ts, 'folder' => $name, 'mailbox' => $user ?: $account, 'ip' => $ip, 'evidence' => trim($ln)];
        }
    }

    // 2) subscribed, but no longer on disk
    if ($home !== '') {
        foreach ((array)@glob(rtrim($home, '/') . '/mail/*/*', GLOB_ONLYDIR) as $md) {
            $sub = $md . '/subscriptions';
            $src = smpro_uid_source('Folder list (' . basename(dirname($md)) . '/' . basename($md) . ')', $sub);
            $out['sources'][] = $src;
            if ($src['state'] !== 'read') continue;
            $mtime = (int)@filemtime($sub);
            foreach (preg_split('/\r?\n/', (string)@file_get_contents($sub, false, null, 0, 65536)) as $line) {
                $f = trim($line);
                if ($f === '' || strcasecmp($f, 'INBOX') === 0) continue;
                // Maildir++ stores INBOX.Archive as the directory ".INBOX.Archive" (or ".Archive" under some
                // layouts), so both spellings are checked before calling a folder gone.
                $bare = preg_replace('/^INBOX\./i', '', $f);
                if (@is_dir($md . '/.' . $f) || @is_dir($md . '/.' . $bare)) continue;
                $out['missing'][] = [
                    'folder' => $f,
                    'mailbox' => basename($md) . '@' . basename(dirname($md)),
                    'list_changed' => $mtime,
                    'in_window' => ($mtime >= $fromTs && $mtime <= $toTs),
                ];
                if (count($out['missing']) >= 200) break 2;
            }
        }
    }
    return $out;
}

/**
 * EMAIL ACCOUNTS that are gone, by address.
 *
 * cPanel's UAPI puts its arguments in the query string, so unlike a File Manager delete this one usually DOES
 * name what it removed - the address is in the log line. That is checked first, and then the account's own
 * mail-user files are used to catch a removal that happened some other way: cPanel keeps every address for a
 * domain in ~/etc/<domain>/passwd, so an address whose maildir still exists while the passwd entry is gone is an
 * account that was deleted without its mail being cleaned up, and the reverse - an entry with no maildir - is one
 * whose mail was removed.
 */
function smpro_uid_mail_accounts(string $account, int $fromTs, int $toTs, string $home): array {
    $out = ['deleted' => [], 'orphan_maildirs' => [], 'sources' => []];

    $log = '/usr/local/cpanel/logs/access_log';
    $src = smpro_uid_source('cPanel email-account changes', $log);
    $out['sources'][] = $src;
    if ($src['state'] === 'read') {
        foreach (smpro_uid_grep($log, ['delete_pop', 'delete_forwarder', 'deletepop', 'delmailuser', 'Email/delete'], 200000, 3000, 20) as $ln) {
            if (!preg_match('#^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)#', $ln, $m)) continue;
            [$all, $ip, $who, $when, $method, $path] = $m;
            if ($account !== '' && $who !== $account) continue;
            $ts = function_exists('smpro_ui_parse_apachetime') ? smpro_ui_parse_apachetime($when) : (int)@strtotime($when);
            if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            $addr = '';
            if (preg_match('#[?&]email=([^&\s"]+)#i', $path, $em)) $addr = rawurldecode($em[1]);
            if ($addr !== '' && preg_match('#[?&]domain=([^&\s"]+)#i', $path, $dm) && strpos($addr, '@') === false)
                $addr .= '@' . rawurldecode($dm[1]);
            if ($addr === '' && preg_match('#[?&]user=([^&\s"]+)#i', $path, $em)) $addr = rawurldecode($em[1]);
            $kind = stripos($path, 'forwarder') !== false ? 'forwarder' : 'email account';
            $out['deleted'][] = ['ts' => $ts, 'address' => $addr, 'kind' => $kind, 'actor' => $who, 'ip' => $ip,
                                 'evidence' => trim($ln)];
        }
    }

    // The account's own record of which addresses exist, against what is on disk.
    if ($home !== '') {
        foreach ((array)@glob(rtrim($home, '/') . '/etc/*', GLOB_ONLYDIR) as $edir) {
            $domain = basename($edir);
            $pw = $edir . '/passwd';
            $psrc = smpro_uid_source('Email accounts for ' . $domain, $pw);
            $out['sources'][] = $psrc;
            $listed = [];
            if ($psrc['state'] === 'read')
                foreach (preg_split('/\r?\n/', (string)@file_get_contents($pw, false, null, 0, 262144)) as $line)
                    if (($u = trim(explode(':', $line, 2)[0])) !== '') $listed[strtolower($u)] = 1;

            // A maildir with no entry in passwd: the address was deleted, and this is its mail, still on disk.
            foreach ((array)@glob(rtrim($home, '/') . '/mail/' . $domain . '/*', GLOB_ONLYDIR) as $md) {
                $u = strtolower(basename($md));
                if ($u === '' || isset($listed[$u])) continue;
                $out['orphan_maildirs'][] = [
                    'address' => $u . '@' . $domain, 'path' => $md, 'ts' => (int)@filemtime($md),
                    'in_window' => (@filemtime($md) >= $fromTs && @filemtime($md) <= $toTs),
                ];
                if (count($out['orphan_maildirs']) >= 200) break 2;
            }
        }
    }
    return $out;
}

/* ============================== the report ============================== */

/**
 * Everything above, correlated, plus what is known about each address that appears in it.
 *
 * The point of the correlation is the question the operator actually has: not "what happened" but "who, from
 * where, and is that person supposed to be here". So every actor address is looked up (country, provider, whether
 * it is a rented machine), marked as one this account has signed in from before or one it has NOT, and given its
 * own timeline from every other source on the server.
 */
function smpro_uid_report(string $account, int $fromTs, int $toTs): array {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', $account);
    $sources = []; $rows = [];

    $cp = smpro_uid_cpanel($account, $fromTs, $toTs);   $sources[] = $cp['source']; $rows = array_merge($rows, $cp['rows']);
    $ft = smpro_uid_ftp($account, $fromTs, $toTs);      $sources = array_merge($sources, $ft['sources']); $rows = array_merge($rows, $ft['rows']);
    $sh = smpro_uid_ssh($account, $fromTs, $toTs);      $sources = array_merge($sources, $sh['sources']); $rows = array_merge($rows, $sh['rows']);
    $sm = smpro_uid_smpro($account, $fromTs, $toTs);    $sources[] = $sm['source']; $rows = array_merge($rows, $sm['rows']);
    $fs = smpro_uid_filesystem($account, $fromTs, $toTs); $sources[] = $fs['source'];
    // Mail is its own trail, and the file collectors above see none of it: messages do not live in the document
    // root and no File Manager call touches them. Asking "who deleted this" without it would answer confidently
    // about files and silently about mail.
    $ml = smpro_uid_mail($account, $fromTs, $toTs, (string)($fs['source']['state'] === 'read' ? $fs['source']['path'] : ''));
    $sources = array_merge($sources, $ml['sources']);
    $rows = array_merge($rows, $ml['rows']);

    usort($rows, fn($a, $b) => $b['ts'] <=> $a['ts']);
    if (count($rows) > 500) $rows = array_slice($rows, 0, 500);

    // Which addresses this account normally signs in from. An address that deleted files and has never signed in
    // before is a different story from one the customer uses every day, and the report should not make the
    // operator work that out by eye.
    $known = [];
    if (function_exists('smpro_ui_logins'))
        foreach (smpro_ui_logins($account, max(0, $fromTs - 90 * 86400), $toTs) as $lg)
            if (($lg['actor_ip'] ?? '') !== '' && stripos((string)$lg['action'], 'fail') === false) $known[$lg['actor_ip']] = 1;

    $actors = [];
    foreach ($rows as $r) {
        $ip = (string)($r['actor_ip'] ?? '');
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (!isset($actors[$ip])) {
            $intel = function_exists('smpro_ip_intel') ? (array)smpro_ip_intel($ip) : [];
            $actors[$ip] = [
                'ip' => $ip, 'n' => 0, 'first' => $r['ts'], 'last' => $r['ts'],
                'country'  => (string)($intel['country'] ?? ''), 'provider' => (string)($intel['provider'] ?? ''), 'asn' => (string)($intel['asn'] ?? ''),
                'machine'  => function_exists('smpro_ip_is_datacenter') ? (bool)smpro_ip_is_datacenter($intel) : false,
                'known'    => isset($known[$ip]),
                'blocked'  => function_exists('smpro_csf_denied') ? (bool)smpro_csf_denied($ip) : false,
                'allowed'  => function_exists('smpro_fw_allow_covers') ? (smpro_fw_allow_covers($ip) !== '') : false,
                'sources'  => [],
            ];
        }
        $actors[$ip]['n']++;
        $actors[$ip]['first'] = min($actors[$ip]['first'], $r['ts']);
        $actors[$ip]['last']  = max($actors[$ip]['last'],  $r['ts']);
        $actors[$ip]['sources'][(string)$r['source']] = 1;
    }
    // Everything else the server saw that address do - the answer to "was this a one-off or a session".
    foreach ($actors as $ip => &$a) {
        $a['sources'] = array_keys($a['sources']);
        $a['activity'] = function_exists('smpro_ip_auth_attempts')
            ? array_slice(smpro_ip_auth_attempts($ip, max(0, $fromTs - 7 * 86400), $toTs + 3600, 60), 0, 60) : [];
    }
    unset($a);
    uasort($actors, fn($x, $y) => $y['n'] <=> $x['n']);

    // What the evidence supports, said plainly - including when it supports nothing.
    $confirmed = array_values(array_filter($rows, fn($r) => $r['confidence'] === 'confirmed'));
    $unread = array_values(array_filter($sources, fn($s) => $s['state'] === 'unreadable'));
    $verdict = 'none';
    if ($confirmed)      $verdict = 'confirmed';
    elseif ($rows)       $verdict = 'circumstantial';
    elseif ($fs['dirs']) $verdict = 'fs_only';

    return [
        'account' => $account, 'from' => $fromTs, 'to' => $toTs,
        'rows' => $rows, 'actors' => array_values($actors), 'sources' => $sources, 'filesystem' => $fs, 'mail' => $ml,
        'verdict' => $verdict, 'unreadable' => $unread,
        'counts' => ['events' => count($rows), 'confirmed' => count($confirmed), 'actors' => count($actors),
                     'dirs' => count($fs['dirs']), 'trash' => count($fs['trash']),
                     'mail' => count($ml['rows']), 'mail_trash' => count($ml['trash']), 'mailboxes' => (int)$ml['boxes'],
                     'folders_gone' => count($ml['folders']['missing']) + count($ml['folders']['named']),
                     'addresses_gone' => count($ml['accounts']['deleted']) + count($ml['accounts']['orphan_maildirs'])],
    ];
}

/** One sentence saying what the evidence does and does not support. Never "nothing happened" when nothing was read. */
function smpro_uid_verdict_text(array $rep): string {
    $n = $rep['counts'];
    $unread = count($rep['unreadable']);
    // Mail is called out on its own line. A report that says "9 deletions" without saying that seven of them were
    // MESSAGES sends the operator looking for missing files that were never missing.
    // Named losses lead, because they are the answer: "the Archive folder" and "sales@" are what the person asking
    // actually lost, and a count of events is not a substitute for a name.
    $named = '';
    if (!empty($n['folders_gone']))   $named .= ' ' . (int)$n['folders_gone'] . ' mail folder(s) are named as gone.';
    if (!empty($n['addresses_gone'])) $named .= ' ' . (int)$n['addresses_gone'] . ' email address(es) are named as removed.';

    $mail = '';
    if (!empty($n['mail'])) {
        $mail = ' ' . (int)$n['mail'] . ' of them are mailbox events across ' . (int)($n['mailboxes'] ?? 0) . ' mailbox(es).';
        if (empty($rep['mail']['maillog']['on']))
            $mail .= ' Dovecot is recording HOW MANY messages each session removed, but not WHICH — naming them needs the'
                   . ' mail_log plugin, which is off on this server. Turn it on and this becomes mailbox, subject and sender per message.';
    }
    $tail = $unread ? ' ' . $unread . ' source(s) could not be read, so this is not a complete picture — see the source list.' : '';
    switch ($rep['verdict']) {
        case 'confirmed':
            return $n['confirmed'] . ' deletion(s) are recorded, from ' . $n['actors'] . ' address(es).' . $named . $mail . $tail;
        case 'circumstantial':
            return 'No log names a deletion, but ' . $n['events'] . ' session(s) were open in this window that could have made one. '
                 . 'A shell `rm` writes no record anywhere unless auditd or shell accounting was already running.' . $named . $mail . $tail;
        case 'fs_only':
            return 'No log records a deletion, but ' . $n['dirs'] . ' director(ies) changed inside this window, which dates it even '
                 . 'though nothing names it.' . $tail;
        default:
            if ($named !== '') return trim($named) . ' No log records the act itself in this window.' . $tail;
            return $unread
                ? 'Nothing was found — but ' . $unread . ' of the sources could not be read, so this is "not seen", not "did not happen".'
                : 'Every source was read and none of them records a deletion in this window. Widen the dates before concluding it did not happen.';
    }
}
