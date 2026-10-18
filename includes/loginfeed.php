<?php
/**
 * loginfeed.php — where a SUCCESSFUL sign-in is actually recorded.
 *
 * Every login check in this plugin used to read /usr/local/cpanel/logs/login_log and look for "SUCCEEDED LOGIN".
 * On current cPanel that string is never written: login_log holds FAILED and DEFERRED lines only, and a session
 * that is granted is recorded in session_log as a NEW line instead. The result was the worst kind of wrong —
 * Account Audit said "0 successful logins", the foreign-login report found nobody, and Country Login Lock scanned
 * and matched nothing. All three looked like an all-clear. None of them could see a success at all.
 *
 * So the feed is one function, used by every consumer, and it reads BOTH:
 *   login_log     [ts] lvl [svc] IP - user "REQ" SUCCEEDED LOGIN svc     (older cPanel, and still possible)
 *   session_log   [ts] lvl [svc] IP NEW user:token key=val,key=val       (current cPanel)
 *
 * Not every NEW line is a person typing a password, and that distinction decides whether an event is a finding:
 *   password  the login form, or a mailbox opening its own webmail — somebody presented the credential.
 *   operator  WHM's "Log in as User", root opening an account, an account opening one of its own mailboxes.
 *   api       a session minted through the API by root.
 *   restored  a session re-opened for the same identity that already had one.
 * Only 'password' is ever treated as a compromise. Reporting an operator's own jump into an account as a foreign
 * sign-in would have the plugin accuse its owner every time they open a customer's cPanel.
 */
if (!defined('SMPRO_BOOT')) { header('HTTP/1.0 403 Forbidden'); exit; }

/** Overridable for the test lab, exactly like the Account Audit log constants. */
function smpro_lf_session_log(): string {
    return defined('SMPRO_LF_SESSION_LOG') ? SMPRO_LF_SESSION_LOG : '/usr/local/cpanel/logs/session_log';
}
function smpro_lf_login_log(): string {
    return defined('SMPRO_LF_LOGIN_LOG') ? SMPRO_LF_LOGIN_LOG : '/usr/local/cpanel/logs/login_log';
}

/**
 * What each source could tell us. A caller that cannot read a source must say "could not look", never "nothing
 * happened", so the state of every source travels with the results.
 */
function smpro_lf_sources(): array {
    $out = [];
    foreach (['session' => smpro_lf_session_log(), 'login' => smpro_lf_login_log()] as $k => $p) {
        $out[$k] = ['path' => $p, 'ok' => false, 'state' => 'missing'];
        if (!@file_exists($p))      { continue; }
        if (!@is_readable($p))      { $out[$k]['state'] = 'unreadable'; continue; }
        $out[$k]['ok'] = true; $out[$k]['state'] = 'read'; $out[$k]['size'] = (int)@filesize($p);
    }
    return $out;
}

/**
 * Read the tail of a log without loading the whole file. Returns '' when the file could not be read.
 *
 * The shell is tried first because tail is fast on a multi-megabyte log, but it is not trusted to be there:
 * shell_exec can be disabled, and a host without /usr/bin/tail would otherwise return an empty string that a
 * caller cannot tell apart from a log with nothing in it. Falling back to reading the file here means "could
 * not look" only ever happens when the file itself cannot be opened.
 */
function smpro_lf_tail(string $path, int $lines): string {
    if ($path === '' || !@is_readable($path)) return '';
    $lines = max(1, (int)$lines);
    if (function_exists('shell_exec')) {
        $out = (string)@shell_exec('timeout 30 tail -n ' . $lines . ' ' . escapeshellarg($path) . ' 2>/dev/null');
        if ($out !== '') return $out;
    }
    $fh = @fopen($path, 'rb');
    if (!$fh) return '';
    $buf = []; $n = 0;
    while (($line = fgets($fh)) !== false) {
        $buf[] = $line;
        if (++$n > $lines) { array_shift($buf); $n--; }
    }
    fclose($fh);
    return implode('', $buf);
}

/**
 * One session_log NEW line → a login record, or [] when the line is not a granted session.
 *
 * PURGE / EXPIRE lines are session endings and are deliberately not logins.
 */
function smpro_lf_parse_session(string $line): array {
    $line = trim($line);
    if ($line === '' || strpos($line, ' NEW ') === false) return [];
    if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+NEW\s+([^:\s]+):(\S+)(.*)$/', $line, $m)) return [];
    $when = $m[1]; $daemon = $m[2]; $ip = $m[3]; $user = $m[4]; $tail = $m[6];

    $kv = [];
    if (preg_match_all('/(\w+)=([^,\s]*)/', $tail, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $p) $kv[strtolower($p[1])] = $p[2];
    }
    // The bracketed daemon is who wrote the line; app= is the session that was created. "root logged into
    // whostmgrd and opened a customer's cPanel" writes [whostmgrd] with app=cpaneld, and the meaningful name
    // for the event is the session that resulted.
    $service = (string)($kv['app'] ?? $daemon);
    if (strpos($service, '::') !== false) $service = 'api';

    // 'internal' and an empty address both mean the session was minted on the box, not reached over the network.
    if ($ip === 'internal' || $ip === '-') $ip = '';
    if ($ip === '' && !empty($kv['address'])) $ip = (string)$kv['address'];
    if ($ip !== '' && !filter_var($ip, FILTER_VALIDATE_IP)) $ip = '';

    $method  = strtolower((string)($kv['method'] ?? ''));
    $path    = strtolower((string)($kv['path'] ?? ''));
    $creator = (string)($kv['creator'] ?? '');
    $userTok = preg_replace('/[^a-zA-Z0-9._@-]/', '', $user);

    /*
     * A PASSWORD LOGIN IS `handle_form_login` WITH `path=form`, AND NOTHING ELSE.
     *
     * The method alone is not enough, and believing it was produced false compromise signals on a live server.
     * cPanel reuses handle_form_login for sessions that are DERIVED from an authentication that already happened:
     *
     *   path=form                     somebody typed the password into the login form.  THIS is the finding.
     *   path=loadsession, creator=X   a session opened on behalf of X. The account owner opening one of their own
     *                                 mailboxes, or root opening a customer's cPanel. No password was presented.
     *   path=xfercpanel               WHM's "Log in as User".
     *
     * Counted by method, one live server reported 68 of these as "the account password was accepted" — including
     * "an account <- root", which is the operator opening a customer account, and a dozen "mailbox <- its own cPanel account".
     * With Country Login Lock armed, that is an operator being blocked and evicted for doing their job.
     *
     * Webmail has its own methods, and they were falling through to 'other' — which the feed's default filter
     * discards. Webmail is the commonest compromise route on shared hosting; it must never be the one that is
     * silently dropped.
     */
    if (!empty($kv['possessed']) && $kv['possessed'] !== '0')          $kind = 'operator';
    elseif (strpos($method, 'create_webmail_session_for_self') === 0)  $kind = 'password';   // the mailbox itself
    elseif (strpos($method, 'create_webmail_session') === 0)           $kind = 'operator';   // opened for a mailbox
    elseif ($method === 'handle_auth_transfer')                        $kind = 'operator';
    elseif ($method === 'create_user_session')                         $kind = 'api';
    elseif ($method === 'handle_form_login')                           $kind = ($path === 'form') ? 'password' : 'restored';
    elseif ($method === '')                                            $kind = 'unknown';
    else                                                               $kind = 'other';

    // Belt and braces: whatever the method says, a session somebody ELSE created is not this identity proving
    // who it is. Never let that be reported as an accepted password.
    if (($kind === 'password' || $kind === 'restored')
        && $creator !== '' && strcasecmp($creator, (string)$userTok) !== 0) $kind = 'operator';

    return [
        'ts'      => @strtotime($when) ?: 0,
        'ip'      => $ip,
        // Webmail signs in as a mailbox, so '@' is part of the identity. Stripping it turned
        // a mailbox address into the same string without its "@" — a name that matches no account and no mailbox, and
        // an operator cannot act on because it does not exist.
        'user'    => $userTok,
        'service' => $service,
        'method'  => $method,
        'kind'    => $kind,
        'creator' => $creator,
        'path'    => $path,
        'source'  => smpro_lf_session_log(),
        'raw'     => $line,
    ];
}

/** One login_log line → a login record, or [] when it is not a SUCCEEDED/SUCCESS LOGIN. */
function smpro_lf_parse_login(string $line): array {
    $line = trim($line);
    if ($line === '' || !preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $line)) return [];
    if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $line, $m)) return [];
    $ip = $m[3];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = '';
    return [
        'ts'      => @strtotime($m[1]) ?: 0,
        'ip'      => $ip,
        'user'    => preg_replace('/[^a-zA-Z0-9._@-]/', '', rawurldecode($m[4])),
        'service' => $m[2],
        'method'  => 'login_log',
        'kind'    => 'password',
        'creator' => '',
        'source'  => smpro_lf_login_log(),
        'raw'     => $line,
    ];
}

/**
 * The address a cPanel / webmail login really came from, when cPanel recorded it as 127.0.0.1.
 *
 * WHY. Imunify360 WebShield (and the cpanel.<domain> service-subdomain proxy) sit in front of cpsrvd and hand it
 * every connection from 127.0.0.1. cPanel's own logs then say every login is local, and everything built on them
 * went blind at once: a password used from a rented server in Singapore read as "this server", so the foreign
 * sign-in alert, the Country Login Lock and the threat report all passed it by - on a server that was being
 * taken over while all three were switched on.
 *
 * The front proxy logged the login request ("POST /login/?login_only=1" answered 200) with the real address. The
 * session_log line and that request share the same second; one distinct address in a 2-second window is a join,
 * several are candidates and are said to be candidates - never guessed.
 */
function smpro_lf_front_logins(): array {
    static $idx = null;
    if ($idx !== null) return $idx;
    $idx = [];
    if (!function_exists('smpro_front_logs_all')) { $fl = __DIR__ . '/frontlogs.php'; if (is_file($fl)) require_once $fl; }
    $logs = function_exists('smpro_front_logs_all') ? smpro_front_logs_all() : [];   // discovered from the running configuration
    if (!$logs) return $idx;
    $cmd = 'timeout 15 grep -a -h -F ' . escapeshellarg('POST /login/?login_only=1');
    foreach ($logs as $f) $cmd .= ' ' . escapeshellarg($f);
    $out = (string)@shell_exec($cmd . ' 2>/dev/null | tail -n 20000');
    foreach (explode("\n", $out) as $ln) {
        if (!preg_match('/^(?:\S+:\d+\s+)?([0-9a-fA-F.:]+)\s+-\s+\S+\s+\[([^\]]+)\]\s+"POST \/login\/\?login_only=1[^"]*"\s+(\d{3})/', trim($ln), $m)) continue;
        if ($m[3] !== '200' && $m[3] !== '401') continue;                 // 200 = accepted, 401 = refused password
        $ip = $m[1]; if (!filter_var($ip, FILTER_VALIDATE_IP) || in_array($ip, ['127.0.0.1', '::1'], true)) continue;
        $ts = @strtotime(preg_replace('#^(\d+)/(\w+)/(\d+):#', '$1 $2 $3 ', $m[2])) ?: 0;
        if ($ts > 0) $idx[$ts][$m[3]][$ip] = 1;
    }
    return $idx;
}
/** [ip, how] for a loopback-recorded login at $ts, or ['', reason]. */
function smpro_lf_real_login_ip(int $ts, string $status = '200'): array {
    if ($ts <= 0) return ['', ''];
    $idx = smpro_lf_front_logins(); $cand = [];
    for ($d = -2; $d <= 2; $d++) foreach (array_keys($idx[$ts + $d][$status] ?? []) as $ip) $cand[$ip] = 1;
    if (count($cand) === 1) return [(string)array_key_first($cand), 'front proxy log (Imunify WebShield / cPanel proxy), same second'];
    if (count($cand) > 1) return ['', 'one of ' . implode(', ', array_keys($cand)) . ' (several logins in the same second)'];
    return ['', ''];
}

/**
 * One cPanel login_log line with the visitor's address in place of 127.0.0.1, when the front proxy logged the same
 * attempt in the same second (FAILED/DEFERRED <-> 401, SUCCEEDED <-> 200). The line keeps its exact format, so
 * every parser downstream reads it unchanged - and every one of them (login guard, break-in timeline, country lock,
 * threat report, Login Monitor, AI review) stops treating a password-guessing attacker as "this server".
 * A line that cannot be resolved to exactly one address is returned untouched.
 */
function smpro_login_line_real(string $line): string {
    if (strpos($line, '127.0.0.1') === false && strpos($line, '::1') === false) return $line;
    $status = preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|FAILURE/i', $line) ? '401'
            : (preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $line) ? '200' : '');
    if ($status === '') return $line;
    if (preg_match('/^(\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+)(127\.0\.0\.1|::1)(\s)/', $line, $m)) { $pre = $m[1]; $when = $m[2]; $old = $m[3]; $post = $m[4]; }
    elseif (preg_match('/^()(127\.0\.0\.1|::1)(\s+\S+\s+\S+\s+\[([^\]]+)\])/', $line, $m)) { $pre = ''; $old = $m[2]; $when = $m[4]; $post = ''; }
    else return $line;
    $ts = function_exists('smpro_login_ts') ? smpro_login_ts($when) : (int)(@strtotime($when) ?: 0);
    [$ip] = smpro_lf_real_login_ip($ts, $status);
    if ($ip === '') return $line;
    return $pre . $ip . substr($line, strlen($pre) + strlen($old));
}
/** A text block of login_log lines, each resolved. */
function smpro_login_log_resolve(string $raw): string {
    if ($raw === '' || (strpos($raw, '127.0.0.1') === false && strpos($raw, '::1') === false)) return $raw;
    return implode("\n", array_map('smpro_login_line_real', explode("\n", $raw)));
}
/** The tail of cPanel's login_log, resolved. '' = could not read (same contract as smpro_lf_tail). */
function smpro_login_log_tail(int $lines): string {
    return smpro_login_log_resolve(smpro_lf_tail(smpro_lf_login_log(), $lines));
}

/**
 * Every successful sign-in in the window, from both logs, newest last.
 *
 * $kinds limits what is returned; the default is the one that matters — a password was accepted. Pass [] for
 * everything, including the operator's own jumps into accounts.
 *
 * The return always carries 'sources', so a caller can tell "no successful logins" apart from "the log this
 * server records them in could not be read".
 */
function smpro_lf_success(int $sinceTs = 0, int $lines = 20000, array $kinds = ['password']): array {
    $src = smpro_lf_sources();
    $out = ['ok' => false, 'events' => [], 'sources' => $src, 'scanned' => 0, 'msg' => ''];

    foreach ([['session', 'smpro_lf_parse_session'], ['login', 'smpro_lf_parse_login']] as $s) {
        [$key, $fn] = $s;
        if (empty($src[$key]['ok'])) continue;
        $raw = smpro_lf_tail($src[$key]['path'], $lines);
        if ($raw === '' && (int)($src[$key]['size'] ?? 0) > 0) {
            $out['sources'][$key]['ok'] = false;
            $out['sources'][$key]['state'] = 'unreadable';   // empty read of a non-empty file is a failed read
            continue;
        }
        $out['ok'] = true;
        foreach (explode("\n", $raw) as $line) {
            if ($line === '') continue;
            $out['scanned']++;
            $e = $fn($line);
            if (!$e) continue;
            if ($sinceTs > 0 && $e['ts'] > 0 && $e['ts'] < $sinceTs) continue;
            if ($kinds !== [] && !in_array($e['kind'], $kinds, true)) continue;
            if (in_array((string)$e['ip'], ['127.0.0.1', '::1'], true) && in_array((string)$e['kind'], ['password', 'restored'], true)) {
                [$rip, $how] = smpro_lf_real_login_ip((int)$e['ts']);
                $e['ip_local'] = $e['ip'];
                if ($rip !== '') { $e['ip'] = $rip; $e['ip_how'] = $how; }
                elseif ($how !== '') $e['ip_how'] = $how;
            }
            $out['events'][] = $e;
        }
    }

    if (!$out['ok']) {
        $out['msg'] = 'Neither session_log nor login_log could be read, so no sign-in was checked — this is '
                    . '"not seen", not "nothing happened".';
        return $out;
    }
    usort($out['events'], fn($a, $b) => $a['ts'] <=> $b['ts']);
    return $out;
}

/** Plain words for where successes are being read from, for a page that has to explain an empty result. */
function smpro_lf_source_words(array $sources): string {
    $say = [];
    foreach ($sources as $k => $s) {
        $say[] = ($k === 'session' ? 'session_log' : 'login_log') . ': ' . (string)($s['state'] ?? '?');
    }
    return implode(', ', $say);
}
