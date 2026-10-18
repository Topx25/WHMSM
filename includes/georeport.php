<?php
/**
 * includes/georeport.php — which accounts are being signed into from countries you do not allow, and the
 * one response that actually ends it: change the password.
 *
 * Blocking the address stops that address. It does not stop the person, because what they have is the password,
 * and a password that is known stays known. So this pairs the report with the only action that closes it — and
 * treats the new passwords as the dangerous material they are.
 *
 * HOW THE PASSWORDS ARE HANDLED, and why.
 *
 * A file on disk holding working passwords for every account on the server is a single object whose theft is a
 * total compromise — worse than the incident it was created to fix. So there is no such file. Instead:
 *
 *   - the new passwords exist in ONE response, handed back once, for the operator to save or send;
 *   - the record kept on disk carries the account, the reason, the date and who did it — and NEVER the password;
 *   - nothing re-displays them. If that one export is lost, the passwords are reset again. That is the correct
 *     trade: a lost export costs five minutes, a leaked password file costs every account on the server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_GR_LOG')) define('SMPRO_GR_LOG', SMPRO_VARLOG . '/password_resets.log');

/**
 * Accounts signed into from a country that is not on their allow-list, over the last $days.
 *
 * Built on the SAME allow-list the Country Login Lock uses (per account where one is set, otherwise the server's),
 * so the report and the lock can never disagree about what "allowed" means.
 *
 * A SUCCESSFUL sign-in is the finding. A failed one from anywhere is background noise — reported separately and
 * never counted as a compromise, because it is not one.
 */
function smpro_gr_scan(int $days = 7, int $maxLines = 60000): array {
    if (!function_exists('smpro_gl_cfg')) { $gl = __DIR__ . '/geologin.php'; if (@is_file($gl)) require_once $gl; }
    $cfg = function_exists('smpro_gl_cfg') ? smpro_gl_cfg() : ['countries' => [], 'per_account' => []];

    if (!function_exists('smpro_login_line_real')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $log = function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log';
    $out = ['ok' => true, 'accounts' => [], 'scanned' => 0, 'days' => $days,
            'allowed' => $cfg['countries'], 'source' => ['path' => $log, 'state' => 'read'], 'unknown_cc' => 0];

    if (!@is_readable($log)) {
        // "Nothing found" and "could not look" are different answers, and only one of them means the accounts
        // are fine. This says which.
        $out['ok'] = false;
        $out['source']['state'] = @file_exists($log) ? 'unreadable' : 'missing';
        $out['msg'] = 'login_log could not be read, so nothing was checked — this is "not seen", not "nothing happened".';
        return $out;
    }
    if (!$cfg['countries'] && !$cfg['per_account']) {
        $out['ok'] = false;
        $out['msg'] = 'No country list is set yet. Set the allowed countries in Country Login Lock first — without one, every country is "not allowed" and the report would flag the whole server.';
        return $out;
    }

    $cut = time() - max(1, $days) * 86400;
    // The operator can reset the counter: everything before that moment was archived and is not counted again.
    // The logs themselves are never touched - only where this report starts reading from.
    $since = smpro_gr_counter_since();
    if ($since > $cut) { $cut = $since; $out['counter_since'] = $since; }

    // The finding of this report is an ACCEPTED password. Current cPanel does not write that to login_log at all —
    // it records the granted session in session_log — so a report built on login_log alone reported every server
    // as clean no matter who had signed in. Successes come from the shared feed; login_log supplies the failures.
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $feed = function_exists('smpro_lf_success') ? smpro_lf_success($cut, $maxLines) : ['ok' => false, 'events' => []];
    $out['source']['successes'] = function_exists('smpro_lf_source_words') ? smpro_lf_source_words((array)($feed['sources'] ?? [])) : '';

    $raw = (string)@shell_exec('timeout 30 tail -n ' . (int)$maxLines . ' ' . escapeshellarg($log) . ' 2>/dev/null');
    if (function_exists('smpro_login_log_resolve')) $raw = smpro_login_log_resolve($raw);
    $failedOk = @is_readable($log) && !($raw === '' && (int)@filesize($log) > 0);
    if (!$failedOk) $out['source']['state'] = 'unreadable';
    if (!$failedOk && empty($feed['ok'])) {
        $out['ok'] = false;
        $out['msg'] = 'Neither session_log nor login_log could be read — nothing was checked. This is "not seen", not "nothing happened".';
        return $out;
    }
    if (empty($feed['ok'])) {
        $out['ok'] = false;
        $out['msg'] = 'session_log could not be read, so SUCCESSFUL sign-ins were not checked. Failed attempts below are complete; the compromises are not.';
    }

    $rows = [];
    foreach ((array)$feed['events'] as $e) {
        if ($e['ip'] === '') continue;
        $rows[] = ['ts' => (int)$e['ts'], 'ip' => $e['ip'], 'user' => (string)$e['user'], 'ok' => true];
    }
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $line, $m)) continue;
        if (!filter_var($m[2], FILTER_VALIDATE_IP)) continue;
        if (preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $m[4])) continue;
        if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID/i', $m[4])) continue;
        $rows[] = ['ts' => @strtotime($m[1]) ?: 0, 'ip' => $m[2], 'user' => rawurldecode($m[3]), 'ok' => false];
    }

    $acc = [];
    foreach ($rows as $row) {
        $ip = $row['ip']; $ok = (bool)$row['ok'];
        $ts = (int)$row['ts'];
        if ($ts && $ts < $cut) continue;
        $out['scanned']++;

        $u = preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)$row['user']);
        if ($u === '' || !function_exists('smpro_is_cpanel_user') || !smpro_is_cpanel_user($u)) {
            if ($u === '') continue;
        }
        $cc = function_exists('smpro_gl_country') ? smpro_gl_country($ip) : '';
        if ($cc === '') { $out['unknown_cc']++; continue; }          // never treated as "not allowed"
        $allowed = function_exists('smpro_gl_allowed_for') ? smpro_gl_allowed_for($u, $cfg) : $cfg['countries'];
        if (in_array($cc, $allowed, true)) continue;
        if (function_exists('smpro_gl_exempt') && smpro_gl_exempt($ip) !== '') continue;

        if (!isset($acc[$u])) $acc[$u] = ['user' => $u, 'ok' => 0, 'failed' => 0, 'ips' => [], 'ccs' => [], 'ccs_ok' => [], 'ccs_failed' => [],
                                          'first' => $ts ?: time(), 'last' => $ts ?: time(), 'allowed' => $allowed];
        $acc[$u][$ok ? 'ok' : 'failed']++;
        $acc[$u]['ips'][$ip] = ['ip' => $ip, 'cc' => $cc, 'n' => (int)($acc[$u]['ips'][$ip]['n'] ?? 0) + 1];
        $acc[$u]['ccs'][$cc] = (int)($acc[$u]['ccs'][$cc] ?? 0) + 1;
        // Kept apart: "US (12)" under an account that was signed into once from the US and knocked on eleven
        // times from there read as twelve break-ins. The country that matters is the one the password worked from.
        $acc[$u][$ok ? 'ccs_ok' : 'ccs_failed'][$cc] = (int)($acc[$u][$ok ? 'ccs_ok' : 'ccs_failed'][$cc] ?? 0) + 1;
        $acc[$u]['first'] = min($acc[$u]['first'], $ts ?: time());
        $acc[$u]['last']  = max($acc[$u]['last'],  $ts ?: time());
    }

    foreach ($acc as &$a) {
        $a['ips'] = array_values($a['ips']);
        arsort($a['ccs']); arsort($a['ccs_ok']); arsort($a['ccs_failed']);
        // An accepted password is the compromise. Failures alone are somebody knocking, which is not the same thing.
        $a['severity'] = $a['ok'] > 0 ? 'compromised' : 'attempted';
    }
    unset($a);
    uasort($acc, fn($x, $y) => [$y['severity'] === 'compromised', $y['ok']] <=> [$x['severity'] === 'compromised', $x['ok']]);
    $out['accounts'] = array_values($acc);
    return $out;
}

/* ------------------------------------------------------------------ the counter
 * The report counts from a window's start, or from the last time the operator reset the counter - whichever is
 * later. A reset first ARCHIVES the report as it stands (JSON + text, in the reports store) so nothing is lost,
 * then records the moment. The login logs are never modified: the counter is a watermark on where the report
 * reads from, and the archive is the only thing written.
 */
function smpro_gr_counter_file(): string { return SMPRO_VARLIB . '/georeport_counter.json'; }
function smpro_gr_archive_dir(): string { return SMPRO_VARLIB . '/reports/threat'; }

function smpro_gr_counter_since(): int {
    $j = @is_file(smpro_gr_counter_file()) ? json_decode((string)@file_get_contents(smpro_gr_counter_file()), true) : null;
    return is_array($j) ? (int)($j['since'] ?? 0) : 0;
}

/** Archive the given report (the page's merged result), then move the counter to now. Returns what was written. */
function smpro_gr_counter_reset(array $report, string $by): array {
    $dir = smpro_gr_archive_dir();
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $id = date('Ymd_His');
    $report['archived_at'] = time(); $report['archived_by'] = $by; $report['counter_since_before'] = smpro_gr_counter_since();
    $json = $dir . '/' . $id . '.json'; $txt = $dir . '/' . $id . '.txt';
    if (@file_put_contents($json, json_encode($report, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX) === false)
        return ['ok' => false, 'msg' => 'The report could not be archived, so the counter was NOT reset.'];
    @file_put_contents($txt, smpro_gr_archive_text($report), LOCK_EX);
    @chmod($json, 0600); @chmod($txt, 0600);
    $prev = smpro_gr_counter_since();
    if (@file_put_contents(smpro_gr_counter_file(), json_encode(['since' => time(), 'by' => $by, 'archive' => $id, 'previous' => $prev]), LOCK_EX) === false)
        return ['ok' => false, 'msg' => 'The report was archived (' . $id . ') but the counter could not be written.'];
    if (function_exists('smpro_audit')) @smpro_audit('georeport_counter_reset', ['by' => $by, 'archive' => $id, 'accounts' => count((array)($report['accounts'] ?? []))]);
    return ['ok' => true, 'id' => $id, 'msg' => 'Archived as ' . $id . ' (' . count((array)($report['accounts'] ?? [])) . ' account(s)) and the counter now starts from ' . date('Y-m-d H:i') . '. The logs were not touched.'];
}

/** The archives, newest first. */
function smpro_gr_archives(): array {
    $out = [];
    foreach (array_reverse(glob(smpro_gr_archive_dir() . '/*.json') ?: []) as $f) {
        $j = json_decode((string)@file_get_contents($f), true);
        if (!is_array($j)) continue;
        $n = 0; $in = 0;
        foreach ((array)($j['accounts'] ?? []) as $a) { $n++; if (($a['ok'] ?? 0) > 0) $in++; }
        $out[] = ['id' => basename($f, '.json'), 'at' => (int)($j['archived_at'] ?? @filemtime($f)), 'by' => (string)($j['archived_by'] ?? ''),
                  'accounts' => $n, 'signed_in' => $in, 'days' => (int)($j['days'] ?? 0)];
    }
    return $out;
}

function smpro_gr_archive_get(string $id): ?array {
    $id = preg_replace('/[^0-9_]/', '', $id);
    if ($id === '') return null;
    $j = json_decode((string)@file_get_contents(smpro_gr_archive_dir() . '/' . $id . '.json'), true);
    return is_array($j) ? $j : null;
}

/** The report as text, for the archive and for reading later. */
function smpro_gr_archive_text(array $r): string {
    $l = ['THREAT REPORT - archived ' . date('Y-m-d H:i:s', (int)($r['archived_at'] ?? time())) . ' by ' . (string)($r['archived_by'] ?? ''),
          'Window: last ' . (int)($r['days'] ?? 0) . ' day(s)' . (!empty($r['counter_since']) ? ', counted since ' . date('Y-m-d H:i', (int)$r['counter_since']) : ''),
          'Allowed countries: ' . implode(', ', (array)($r['allowed'] ?? [])), ''];
    $l[] = sprintf('%-34s %-10s %-10s %-40s %s', 'ACCOUNT', 'ACCEPTED', 'FAILED', 'SIGNED IN FROM', 'LAST');
    foreach ((array)($r['accounts'] ?? []) as $a) {
        $ok = []; foreach ((array)($a['ccs_ok'] ?? []) as $cc => $n) $ok[] = "$cc ($n)";
        $l[] = sprintf('%-34s %-10s %-10s %-40s %s', substr((string)$a['user'], 0, 34), (int)($a['ok'] ?? 0), (int)($a['failed'] ?? 0), substr(implode(', ', $ok), 0, 40), !empty($a['last']) ? date('Y-m-d H:i', (int)$a['last']) : '');
        foreach ((array)($a['ips'] ?? []) as $ip) $l[] = '      ' . (string)$ip['ip'] . ' (' . (string)$ip['cc'] . ') x' . (int)$ip['n'];
    }
    return implode("\n", $l) . "\n";
}

/** A password a person can read out over the phone, and that still resists guessing. */
function smpro_gr_password(int $len = 20): string {
    // No look-alikes: O/0, l/1/I. A password that is mistyped twice gets replaced by a weak one somebody chose.
    $alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    $sym   = '!@#%^*-_=+?';
    $set   = $alpha . $sym;
    $out = '';
    for ($i = 0; $i < $len; $i++) $out .= $set[random_int(0, strlen($set) - 1)];
    // Guarantee the shape cPanel's own strength check wants, rather than hoping the random draw produced it.
    $out[0] = $alpha[random_int(0, 25)];
    $out[1] = strtolower($alpha[random_int(0, 25)]);
    $out[2] = (string)random_int(2, 9);
    $out[3] = $sym[random_int(0, strlen($sym) - 1)];
    return str_shuffle($out);
}

/**
 * Which cPanel account an identity belongs to.
 *
 * A login identity is either an account name or a mailbox ("user@domain"). A mailbox has no cPanel password to
 * reset; its OWNER does, and resetting the owner resets every mailbox on it. So every action that takes an
 * identity resolves it here first. The domain -> owner map is cPanel's own /etc/userdatadomains.
 *
 * Returns ['account' => 'owner', 'mailbox' => 'user@domain' | ''] or account '' when it belongs to nobody here.
 */
function smpro_gr_owner_of(string $identity, string $mapFile = '/etc/userdatadomains'): array {
    $identity = trim($identity);
    if ($identity === '') return ['account' => '', 'mailbox' => ''];
    if (strpos($identity, '@') === false) {
        $ok = !function_exists('smpro_is_cpanel_user') || smpro_is_cpanel_user($identity);
        return ['account' => $ok ? $identity : '', 'mailbox' => ''];
    }
    $dom = strtolower(substr($identity, strpos($identity, '@') + 1));
    if ($dom === '' || !@is_readable($mapFile)) return ['account' => '', 'mailbox' => $identity];
    foreach ((array)@file($mapFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
        $ln = (string)$ln;
        if (stripos($ln, $dom . ':') !== 0) continue;
        $rest  = explode(':', $ln, 2)[1] ?? '';
        $owner = trim(explode('==', $rest)[0] ?? '');
        if ($owner !== '' && (!function_exists('smpro_is_cpanel_user') || smpro_is_cpanel_user($owner))) return ['account' => $owner, 'mailbox' => $identity];
        break;
    }
    return ['account' => '', 'mailbox' => $identity];
}

/** Change one cPanel account's password through WHM's own API, and verify the API said it worked. */
function smpro_gr_set_password(string $user, string $pass): array {
    $user = preg_replace('/[^a-zA-Z0-9._@-]/', '', $user);
    if ($user === '') return ['ok' => false, 'msg' => 'invalid account'];
    $bin = '/usr/local/cpanel/bin/whmapi1';
    if (!@is_executable($bin)) return ['ok' => false, 'msg' => 'whmapi1 is not available on this server'];

    // The password never reaches the process table. `--input=json` makes whmapi1 read the WHOLE call from stdin,
    // so `ps` — readable by every account on a shared box — shows only the flags. Passing it as an argument would
    // publish every customer's new password to every customer, for the life of the call.
    //
    // (An earlier draft of this used `password=STDIN`, which whmapi1 does not support: it would have set every
    // account's password to the literal string "STDIN" and reported success. Checked against the real binary.)
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $cmd  = escapeshellarg($bin) . ' --input=json --output=json passwd';
    $ph = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($ph)) return ['ok' => false, 'msg' => 'could not run whmapi1'];
    @fwrite($pipes[0], json_encode(['user' => $user, 'password' => $pass], JSON_UNESCAPED_SLASHES));
    @fclose($pipes[0]);
    $stdout = (string)@stream_get_contents($pipes[1]); @fclose($pipes[1]);
    @fclose($pipes[2]);
    @proc_close($ph);

    $j = json_decode($stdout, true);
    $ok = is_array($j) && (int)($j['metadata']['result'] ?? 0) === 1;
    $why = is_array($j) ? (string)($j['metadata']['reason'] ?? '') : 'no answer from whmapi1';
    return ['ok' => $ok, 'msg' => $ok ? 'password changed' : ($why ?: 'whmapi1 refused the change')];
}

/**
 * Reset several accounts at once.
 *
 * Returns the new passwords ONCE, in this response. They are not written anywhere and cannot be asked for again:
 * the caller shows or exports them, and after that they exist only wherever the operator put them.
 */
function smpro_gr_reset_bulk(array $users, string $reason, string $by, bool $allMailboxes = false): array {
    // EXACTLY WHAT WAS TICKED. An operator ticked four identities and the passwords of far more changed: a ticked
    // mailbox reset its owning cPanel account AND every mailbox on it, and a ticked account reset every mailbox on
    // it as well. Each ticked identity now changes only itself:
    //   - a mailbox (name@domain) -> that one mailbox, through its owner's API; the account and its other
    //     mailboxes are not touched;
    //   - a cPanel account -> the account password only.
    // Resetting every mailbox of a ticked ACCOUNT is a separate, explicit choice ($allMailboxes, unticked by default
    // on the page), and even then it never reaches the siblings of a ticked mailbox.
    $res = ['ok' => true, 'done' => [], 'failed' => [], 'secrets' => [], 'mailboxes' => [], 'at' => time(), 'plan' => []];
    $users = array_values(array_unique(array_filter(array_map(
        fn($u) => preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)$u), $users))));
    if (!$users) return ['ok' => false, 'msg' => 'No account given.', 'done' => [], 'failed' => [], 'secrets' => []];
    if (count($users) > 200) return ['ok' => false, 'msg' => 'At most 200 identities in one reset - nothing was changed.', 'done' => [], 'failed' => [], 'secrets' => []];
    $reason = trim(preg_replace('/\s+/', ' ', $reason));
    if ($reason === '') return ['ok' => false, 'msg' => 'A reason is required — it is what the record is for.', 'done' => [], 'failed' => [], 'secrets' => []];

    // resolve every identity first; nothing changes until the whole plan is known
    $plan = [];   // [kind => account|mailbox, id, owner]
    foreach ($users as $u) {
        $o = smpro_gr_owner_of($u);
        if ($o['account'] === '') {
            $res['failed'][] = ['user' => $u, 'msg' => $o['mailbox'] !== '' ? 'no account on this server owns that mailbox\'s domain' : 'not a cPanel account on this server'];
            continue;
        }
        $plan[] = $o['mailbox'] !== '' ? ['kind' => 'mailbox', 'id' => $u, 'owner' => $o['account']] : ['kind' => 'account', 'id' => $u, 'owner' => $u];
    }
    $res['plan'] = $plan;

    foreach ($plan as $p) {
        $pw = smpro_gr_password();
        if ($p['kind'] === 'mailbox') {
            $r = smpro_gr_set_mail_password($p['owner'], $p['id'], $pw);
            $note = $reason . ' (mailbox only)';
        } else {
            $r = smpro_gr_set_password($p['id'], $pw);
            $note = $reason . ' (account password only)';
        }
        if (empty($r['ok'])) {
            $res['failed'][] = ['user' => $p['id'], 'msg' => (string)$r['msg']];
            smpro_gr_record($p['id'], $note, $by, false, (string)$r['msg']);
            continue;
        }
        $res['done'][] = $p['id'];
        if ($p['kind'] === 'mailbox') $res['mailboxes'][] = $p['id'];
        $res['secrets'][] = ['user' => $p['id'], 'password' => $pw];   // returned once, stored nowhere
        smpro_gr_record($p['id'], $note, $by, true, '');

        // only on an explicit request, and only for a ticked ACCOUNT
        if ($allMailboxes && $p['kind'] === 'account') {
            foreach (smpro_gr_mailboxes($p['id']) as $box) {
                if (in_array($box, $res['done'], true)) continue;
                $mpw = smpro_gr_password();
                $mr  = smpro_gr_set_mail_password($p['id'], $box, $mpw);
                if (!empty($mr['ok'])) {
                    $res['secrets'][] = ['user' => $box, 'password' => $mpw];
                    $res['mailboxes'][] = $box; $res['done'][] = $box;
                    smpro_gr_record($box, $reason . ' (mailbox of ' . $p['id'] . ', "all mailboxes" chosen)', $by, true, '');
                } else {
                    $res['failed'][] = ['user' => $box, 'msg' => (string)$mr['msg']];
                    smpro_gr_record($box, $reason . ' (mailbox of ' . $p['id'] . ', "all mailboxes" chosen)', $by, false, (string)$mr['msg']);
                }
            }
        }
    }
    $res['ok'] = $res['done'] !== [];
    return $res;
}

/**
 * The record that is kept: who, why, when, by whom, and whether it worked.
 *
 * Deliberately NO password. This file is meant to be readable months later by somebody asking "why was this
 * customer's password changed?" — a question that never requires knowing what it was changed to.
 */
function smpro_gr_record(string $user, string $reason, string $by, bool $ok, string $error = ''): bool {
    $dir = dirname(SMPRO_GR_LOG);
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $line = json_encode([
        'at'     => date('c'),
        'user'   => $user,
        'reason' => $reason,
        'by'     => $by,
        'result' => $ok ? 'changed' : 'failed',
        'error'  => $ok ? '' : $error,
        'note'   => 'password not stored by design',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    $w = function_exists('smpro_log_append') ? smpro_log_append(SMPRO_GR_LOG, $line, 10485760, 3) : @file_put_contents(SMPRO_GR_LOG, $line, FILE_APPEND | LOCK_EX);
    @chmod(SMPRO_GR_LOG, 0600);
    if (function_exists('smpro_audit')) smpro_audit('password_reset', ['user' => $user, 'ok' => $ok ? 1 : 0, 'by' => $by, 'reason' => $reason]);
    return $w !== false;
}

/** The record, newest first, for showing on the page. */
function smpro_gr_history(int $limit = 200): array {
    if (!@is_readable(SMPRO_GR_LOG)) return [];
    $raw = (string)@shell_exec('timeout 10 tail -n ' . (int)$limit . ' ' . escapeshellarg(SMPRO_GR_LOG) . ' 2>/dev/null');
    $out = [];
    foreach (array_reverse(explode("\n", $raw)) as $l) {
        $l = trim($l); if ($l === '') continue;
        $j = json_decode($l, true);
        if (is_array($j)) $out[] = $j;
    }
    return $out;
}

/** The one-time export, as a file the operator saves. Built in memory; never written to this server's disk. */
function smpro_gr_export(array $secrets, string $reason, string $by): string {
    $lines = [];
    $lines[] = '# SM Pro — password reset ' . date('Y-m-d H:i T');
    $lines[] = '# Reason: ' . $reason;
    $lines[] = '# By: ' . $by;
    $lines[] = '#';
    $lines[] = '# THIS IS THE ONLY COPY. These passwords are not stored on the server and cannot be shown again.';
    $lines[] = '# Send each one to its owner, then delete this file.';
    $lines[] = '#';
    $lines[] = 'account,password';
    foreach ($secrets as $s) {
        $p = (string)$s['password'];
        // Quote for CSV: a generated password can contain a comma or a quote.
        $lines[] = $s['user'] . ',"' . str_replace('"', '""', $p) . '"';
    }
    return implode("\n", $lines) . "\n";
}

/* =====================================================================================================
 * COMPROMISED ACCOUNTS — who should have their password changed, and on what evidence.
 *
 * The bulk reset already existed, but it could only ever be fed by one source: a successful login from a
 * country outside the allow-list. That source is silent unless an allow-list has been configured, and it is
 * blind to the commonest case of all — an account entered with the correct password from an ordinary country,
 * which is what a stolen or guessed password looks like. On a real incident this week the report offered zero
 * accounts while malware was sitting in dozens of them.
 *
 * So the question this answers is not "did someone log in from abroad" but "is there evidence this account was
 * under someone else's control". Malware found inside an account is that evidence, whether or not it has since
 * been cleaned: something put it there, and whatever did still holds whatever it used to get in.
 *
 * Every source reports three states, never two: found / found nothing / COULD NOT LOOK. A source that cannot run
 * must never be summarised as "no accounts affected" — that reads as an all-clear and it is not one.
 * ===================================================================================================== */

/**
 * Is a flagged file still a threat, right now?
 *
 * "The file exists" is not the question, and answering it as though it were produced a report saying 44 accounts
 * still had malware on disk when NONE of them did: 34 were a vendor JavaScript library the scanner had already
 * cleaned and put back, and 10 were files that had been truncated to zero bytes. An empty file cannot execute,
 * and a file whose contents no longer match what was flagged is not what was flagged.
 *
 * Returns one of:
 *   'live'     - present, non-empty, and still byte-for-byte what the scanner flagged
 *   'emptied'  - present but zero bytes; whatever was there is gone
 *   'changed'  - present but no longer matches the recorded hash: cleaned, or replaced by the real file
 *   'gone'     - not on disk
 *   'unknown'  - present, non-empty, and the scanner recorded no hash to compare against
 *
 * Only 'live' and 'unknown' are counted as something still on the disk. The others are history, and history is
 * still a reason to change the password - something put that file there - but it is not a reason to tell an
 * operator there is code running on their server when there is not.
 */
function smpro_gr_threat_state(string $file, string $hash = '', int $recordedSize = 0): string {
    if ($file === '' || !@is_file($file)) return 'gone';
    $size = (int)@filesize($file);
    if ($size === 0) return 'emptied';
    if ($hash === '') return 'unknown';
    // Size first: it is free, and a cleaned file almost always changes length. Hashing is only paid for when
    // the length still matches, which keeps this cheap on a server with thousands of detections.
    if ($recordedSize > 0 && $size !== $recordedSize) return 'changed';
    $cur = @hash_file('sha256', $file);
    return ($cur !== false && strcasecmp((string)$cur, $hash) === 0) ? 'live' : 'changed';
}

/** Accounts with malware detections, from the local scanner. Returns ['ok'=>bool,'accounts'=>[user=>info],'msg'=>string]. */
function smpro_gr_malware_accounts(int $days = 30, int $limit = 5000): array {
    $out = ['ok' => true, 'accounts' => [], 'source' => 'imunify', 'state' => 'read', 'msg' => ''];

    $bin = '';
    foreach (['imunify360-agent', 'imunify-antivirus'] as $c) {
        $p = trim((string)@shell_exec('command -v ' . escapeshellarg($c) . ' 2>/dev/null'));
        if ($p !== '') { $bin = $p; break; }
    }
    if ($bin === '') {
        $out['ok'] = false; $out['state'] = 'absent';
        $out['msg'] = 'No malware scanner is installed, so this source could not be consulted. That is "not checked", not "clean".';
        return $out;
    }

    $raw = (string)@shell_exec('timeout 60 ' . escapeshellarg($bin) . ' malware malicious list --limit ' . (int)$limit . ' --json 2>/dev/null');
    $j = json_decode($raw, true);
    if (!is_array($j) || !isset($j['items']) || !is_array($j['items'])) {
        $out['ok'] = false; $out['state'] = 'unreadable';
        $out['msg'] = 'The malware scanner returned nothing usable, so this source could not be consulted — not "clean".';
        return $out;
    }

    $cut = time() - max(1, $days) * 86400;
    foreach ($j['items'] as $it) {
        if (!is_array($it)) continue;
        $u = preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)($it['username'] ?? ''));
        if ($u === '') continue;
        $created = (int)($it['created'] ?? 0);
        if ($created > 0 && $created < $cut) continue;
        $file = (string)($it['file'] ?? '');
        // "Still on disk" separates an account that needs a file REMOVED from one that only needs its password
        // changed. Both need the password changed; only one is still serving the attacker's code - and deciding
        // that on "the file exists" reported 44 accounts as still infected when none of them were.
        $state = smpro_gr_threat_state($file, (string)($it['hash'] ?? ''), (int)($it['size'] ?? 0));
        $live  = ($state === 'live' || $state === 'unknown');
        if (!isset($out['accounts'][$u])) {
            $out['accounts'][$u] = ['detections' => 0, 'live' => 0, 'cleaned' => 0, 'newest' => 0,
                                    'kinds' => [], 'sample' => '', 'states' => []];
        }
        $a = &$out['accounts'][$u];
        $a['detections']++;
        $a['states'][$state] = (int)($a['states'][$state] ?? 0) + 1;
        if ($live) { $a['live']++; if ($a['sample'] === '') $a['sample'] = $file; }
        else        { $a['cleaned']++; }
        if ($created > $a['newest']) $a['newest'] = $created;
        $k = (string)($it['type'] ?? '');
        if ($k !== '' && count($a['kinds']) < 4 && !in_array($k, $a['kinds'], true)) $a['kinds'][] = $k;
        if ($a['sample'] === '' && $file !== '') $a['sample'] = $file;
        unset($a);
    }
    ksort($out['accounts']);
    return $out;
}

/**
 * Every account there is evidence for, with the evidence attached. $days bounds both sources.
 *
 * Returns ['accounts' => [user => ['reasons'=>[...], 'why'=>'one line', 'newest'=>ts, 'live'=>n]],
 *          'sources'  => [name => ['ok'=>bool,'msg'=>string]], 'blind' => bool]
 *
 * 'blind' is true when a source could not run. The caller MUST show that: an empty list from a blind scan is
 * not an all-clear, and a page that renders the two the same way is the bug this codebase keeps fixing.
 */
function smpro_gr_compromised(int $days = 30): array {
    $res = ['accounts' => [], 'sources' => [], 'blind' => false, 'days' => $days];

    /* --- malware found inside the account ------------------------------------------------------------ */
    $mw = smpro_gr_malware_accounts($days);
    $res['sources']['malware'] = ['ok' => $mw['ok'], 'msg' => $mw['msg'], 'state' => $mw['state']];
    if (!$mw['ok']) $res['blind'] = true;
    foreach ($mw['accounts'] as $u => $a) {
        $res['accounts'][$u]['reasons'][] = [
            'kind'   => 'malware',
            // Says which state, not just a count. "1 still on disk" for an empty file and for a file the
            // scanner itself cleaned and restored are both true statements about existence and both false
            // statements about danger.
            'detail' => $a['detections'] . ' malware detection' . ($a['detections'] === 1 ? '' : 's')
                        . ($a['live'] > 0
                            ? ', ' . $a['live'] . ' still live on disk'
                            : ', none still live (' . smpro_gr_state_words((array)($a['states'] ?? [])) . ')'),
            'when'   => $a['newest'],
            'sample' => $a['sample'],
        ];
        $res['accounts'][$u]['live'] = ($res['accounts'][$u]['live'] ?? 0) + $a['live'];
        $res['accounts'][$u]['newest'] = max((int)($res['accounts'][$u]['newest'] ?? 0), $a['newest']);
    }

    /* --- a successful login from outside the allowed countries --------------------------------------- */
    if (function_exists('smpro_gr_scan')) {
        $gs = smpro_gr_scan(max(1, min(90, $days)));
        $res['sources']['foreign_login'] = ['ok' => !empty($gs['ok']), 'msg' => (string)($gs['msg'] ?? ''),
                                            'state' => (string)($gs['source']['state'] ?? '')];
        if (empty($gs['ok'])) $res['blind'] = true;
        foreach ((array)($gs['accounts'] ?? []) as $u => $a) {
            $u = preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)$u);
            if ($u === '') continue;
            $cc = is_array($a) ? implode(', ', array_slice(array_keys((array)($a['ccs'] ?? [])), 0, 4)) : '';
            $res['accounts'][$u]['reasons'][] = [
                'kind'   => 'foreign_login',
                'detail' => 'signed in from ' . ($cc !== '' ? $cc : 'a country outside the allow-list'),
                'when'   => (int)(is_array($a) ? ($a['last'] ?? 0) : 0),
                'sample' => '',
            ];
            $res['accounts'][$u]['newest'] = max((int)($res['accounts'][$u]['newest'] ?? 0),
                                                 (int)(is_array($a) ? ($a['last'] ?? 0) : 0));
        }
    }

    /* --- one readable line per account, and the account must still exist ------------------------------ */
    foreach ($res['accounts'] as $u => $a) {
        if (function_exists('smpro_user_home') && smpro_user_home($u) === '') { unset($res['accounts'][$u]); continue; }
        $res['accounts'][$u]['reasons'] = (array)($a['reasons'] ?? []);
        $res['accounts'][$u]['live']    = (int)($a['live'] ?? 0);
        $res['accounts'][$u]['newest']  = (int)($a['newest'] ?? 0);
        $res['accounts'][$u]['why']     = implode(' · ', array_map(fn($r) => (string)$r['detail'], $res['accounts'][$u]['reasons']));
    }
    // Worst first: still-live malware, then most recent evidence.
    uasort($res['accounts'], function ($x, $y) {
        if ($x['live'] !== $y['live']) return $y['live'] <=> $x['live'];
        return $y['newest'] <=> $x['newest'];
    });
    return $res;
}

/* =====================================================================================================
 * MAILBOXES.
 *
 * Resetting a cPanel account's password does NOT change its mailbox passwords. They are separate credentials,
 * and webmail accepts the mailbox one. So an operator who reset the account, twice, and kept receiving
 * "signed in from another country - webmail as someone@their-domain" was not looking at a stale alert and had
 * not done anything wrong: the credential actually being used had never been touched.
 *
 * A mailbox password is also enough to send mail from this server, which is how an account becomes a spam
 * source without its website being touched at all.
 * ===================================================================================================== */

/** Every mailbox on an account, as "user@domain". Empty means none, or that they could not be listed. */
function smpro_gr_mailboxes(string $user): array {
    $user = preg_replace('/[^a-zA-Z0-9._@-]/', '', $user);
    if ($user === '' || !is_executable('/usr/bin/uapi')) return [];
    $raw = (string)@shell_exec('timeout 30 uapi --output=json --user=' . escapeshellarg($user)
                             . ' Email list_pops 2>/dev/null');
    $j = json_decode($raw, true);
    $out = [];
    foreach ((array)($j['result']['data'] ?? []) as $row) {
        $e = is_array($row) ? (string)($row['email'] ?? '') : (string)$row;
        // list_pops returns the system account itself as "user" with no domain - not a real mailbox.
        if ($e === '' || strpos($e, '@') === false) continue;
        $out[] = $e;
    }
    return $out;
}

/**
 * Change one mailbox password.
 *
 * Passed through stdin with --input=json, never on the command line. `ps` is readable by every account on a
 * shared server, so a password in an argument is a password handed to 1800 strangers for the life of the call.
 */
function smpro_gr_set_mail_password(string $user, string $email, string $pass): array {
    $user = preg_replace('/[^a-zA-Z0-9._@-]/', '', $user);
    [$local, $dom] = array_pad(explode('@', $email, 2), 2, '');
    if ($user === '' || $local === '' || $dom === '') return ['ok' => false, 'msg' => 'invalid mailbox'];
    if (!is_executable('/usr/bin/uapi')) return ['ok' => false, 'msg' => 'uapi is not available on this server'];

    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $cmd  = 'timeout 40 /usr/bin/uapi --input=json --output=json --user=' . escapeshellarg($user) . ' Email passwd_pop';
    $ph = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($ph)) return ['ok' => false, 'msg' => 'could not run uapi'];
    @fwrite($pipes[0], json_encode(['email' => $local, 'domain' => $dom, 'password' => $pass], JSON_UNESCAPED_SLASHES));
    @fclose($pipes[0]);
    $stdout = (string)@stream_get_contents($pipes[1]);
    @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($ph);

    $j  = json_decode($stdout, true);
    $ok = is_array($j) && (int)($j['result']['status'] ?? 0) === 1;
    $why = '';
    if (!$ok && is_array($j)) $why = implode('; ', array_map('strval', (array)($j['result']['errors'] ?? [])));
    return ['ok' => $ok, 'msg' => $ok ? 'mailbox password changed' : ($why ?: 'uapi refused the change')];
}

/** Plain words for what became of the flagged files, so a count never has to be interpreted. */
function smpro_gr_state_words(array $states): string {
    $say = ['live' => 'still live', 'emptied' => 'emptied', 'changed' => 'cleaned or replaced',
            'gone' => 'removed', 'unknown' => 'present, nothing to compare against'];
    $out = [];
    foreach ($states as $k => $n) if ($n > 0) $out[] = $n . ' ' . ($say[$k] ?? $k);
    return $out ? implode(', ', $out) : 'nothing found on disk';
}
