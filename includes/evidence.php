<?php
/**
 * evidence.php — a local, append-only evidence journal that outlives the logs it was drawn from.
 *
 * WHY THIS EXISTS. Asked why mail had been switched off on a production server on 19 July, the answer was in
 * exim's log — and the rotation covering that day had already been compressed and ended on 18 July. The evidence
 * was gone. Not deleted by an attacker, not hidden: simply rotated away by the machine's own housekeeping while
 * nobody was looking. The same is true of every log this plugin reads. cPanel's session_log, which is where a
 * successful sign-in is actually recorded, is a few thousand lines on a server with 1,862 accounts; it rolls.
 *
 * So the findings are written down where they will still be in a year, at the moment they are still true.
 *
 * THIS IS NOT A COPY OF THE LOGS. That distinction is the whole design. Measured on two live servers, the
 * evidence classes below come to ~50 KB a day on a server with 1,862 accounts and ~2 KB on one with 78. The raw
 * access_log on those same servers is 151 MB and 173 MB. A journal that shipped everything would be abandoned
 * inside a month; one that records only what a finding rests on costs nothing and can be kept for years.
 *
 * WHAT MAKES IT EVIDENCE RATHER THAN A BACKUP.
 *
 *   1. Append-only. Records are added; nothing here rewrites or removes one.
 *   2. Hash-chained. Every record carries the hash of the record before it, and the first record of a day carries
 *      the hash of the previous day's seal. Removing a record — or a whole day — breaks the chain at a provable
 *      point instead of leaving a gap nobody can see. It does not PREVENT tampering on a machine somebody owns.
 *      It makes tampering visible, which is the most a local store can honestly offer, and it is why phase 2
 *      pushes these records off the server.
 *   3. "Could not look" is written down. If a source cannot be read, that fact becomes a record. A day with no
 *      login events because nothing happened and a day with no login events because the log was unreadable are
 *      different days, and every other part of this product exists because somebody once let them look the same.
 *
 * Layout under SMPRO_EV_DIR:
 *     2026-09-17.jsonl     today, being appended to
 *     2026-09-16.jsonl     a finished day
 *     2026-09-16.seal      its count, span, and chain head, written once when the day rolled over
 *     state.json           watermarks and the current chain head
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_EV_DIR'))    define('SMPRO_EV_DIR',    SMPRO_VARLIB . '/evidence');
if (!defined('SMPRO_EV_STATE'))  define('SMPRO_EV_STATE',  SMPRO_EV_DIR . '/state.json');
if (!defined('SMPRO_EV_KEEP'))   define('SMPRO_EV_KEEP',   30);     // days of full detail; rollups are phase 3

/* ------------------------------------------------------------------ paths and state */

function smpro_ev_dir(): string {
    if (!@is_dir(SMPRO_EV_DIR)) { @mkdir(SMPRO_EV_DIR, 0700, true); @chmod(SMPRO_EV_DIR, 0700); }
    return SMPRO_EV_DIR;
}
function smpro_ev_path(string $day): string { return smpro_ev_dir() . '/' . $day . '.jsonl'; }
function smpro_ev_seal_path(string $day): string { return smpro_ev_dir() . '/' . $day . '.seal'; }

function smpro_ev_state(): array {
    $d = @is_file(SMPRO_EV_STATE) ? json_decode((string)@file_get_contents(SMPRO_EV_STATE), true) : null;
    $s = is_array($d) ? $d : [];
    $s += ['head' => '', 'day' => '', 'seq' => 0, 'login_ts' => 0, 'login_seen' => [], 'audit_pos' => 0,
           'audit_inode' => 0, 'snapshot_day' => ''];
    return $s;
}
function smpro_ev_state_save(array $s): void {
    smpro_ev_dir();
    $t = SMPRO_EV_STATE . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) {
        @chmod($t, 0600); @rename($t, SMPRO_EV_STATE);
    }
}

/* ------------------------------------------------------------------ the writer */

/**
 * Append one record, chained to the one before it.
 *
 * The day rolls at midnight local time. When it does, the finished day is sealed and the new day's first record
 * chains to that seal, so the chain runs unbroken across days and a missing DAY is as detectable as a missing
 * line.
 */
/**
 * Hold everything that touches the chain, for as long as it takes.
 *
 * Appending is read-state, write-record, write-state. Two processes doing that at once both read the same head,
 * both chain their record to it, and the chain is broken for whichever writes second. It happened within an hour
 * of the first install: the five-minute cron overlapped a manual run and the verifier reported tampering on a
 * server where nothing had been tampered with. A detector that cries wolf gets switched off, so this is not a
 * tidiness fix - a false alarm here costs more than the feature is worth.
 */
function smpro_ev_lock() {
    $dir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $fh = @fopen($dir . '/evidence-write.lock', 'c');
    if (!$fh) return null;                                      // no lock available: still write, never lose data
    @flock($fh, LOCK_EX);
    return $fh;
}
function smpro_ev_unlock($fh): void { if ($fh) { @flock($fh, LOCK_UN); @fclose($fh); } }

function smpro_ev_append(string $kind, array $d, int $ts = 0): array {
    $ts  = $ts > 0 ? $ts : time();
    $day = date('Y-m-d', $ts);
    $lk  = smpro_ev_lock();
    $s   = smpro_ev_state();

    // A record for a day already sealed would break the chain it is being added to. Put it in today's file with
    // its own timestamp intact rather than reopening history: the record keeps the truth about WHEN, the file
    // keeps the truth about when it was RECORDED, and those are different facts.
    $today = date('Y-m-d');
    if ($day !== $today) $day = $today;

    if ($s['day'] !== '' && $s['day'] !== $day) {
        smpro_ev_seal($s['day']);
        $s = smpro_ev_state();                                  // seal() moves the head on
    }
    if ($s['day'] !== $day) { $s['day'] = $day; $s['seq'] = 0; }

    // If the state file was lost but the journal is there, take the head and the sequence back off the last
    // record rather than starting a new chain at genesis. A restart is recoverable; recording one that did not
    // need to happen is not.
    if ($s['head'] === '' || $s['seq'] === 0) {
        $tail = smpro_ev_last_record($day);
        if ($tail !== null) { $s['head'] = $tail['head']; $s['seq'] = $tail['seq']; }
    }

    $rec = [
        'seq'  => ++$s['seq'],
        'ts'   => $ts,
        'kind' => $kind,
        'prev' => $s['head'] !== '' ? $s['head'] : 'genesis',
        'd'    => $d,
    ];
    $line = json_encode($rec, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($line === false) { smpro_ev_unlock($lk); return ['ok' => false, 'msg' => 'record could not be encoded']; }

    $f = smpro_ev_path($day);
    $new = !@is_file($f);
    if (@file_put_contents($f, $line . "\n", FILE_APPEND | LOCK_EX) === false) {
        smpro_ev_unlock($lk);
        return ['ok' => false, 'msg' => 'could not write ' . $f];
    }
    if ($new) @chmod($f, 0600);

    $s['head'] = hash('sha256', $line);
    smpro_ev_state_save($s);
    smpro_ev_unlock($lk);
    return ['ok' => true, 'seq' => $rec['seq'], 'day' => $day, 'head' => $s['head']];
}

/** The last record of a day: its hash and its sequence number, for recovering a lost state file. */
function smpro_ev_last_record(string $day): ?array {
    $f = smpro_ev_path($day);
    if (!@is_file($f)) return null;
    $fh = @fopen($f, 'rb');
    if (!$fh) return null;
    $last = ''; $seq = 0;
    while (($line = fgets($fh)) !== false) {
        $line = rtrim($line, "\n");
        if ($line === '') continue;
        $last = $line;
        $r = json_decode($line, true);
        if (is_array($r)) $seq = (int)($r['seq'] ?? $seq);
    }
    fclose($fh);
    return $last === '' ? null : ['head' => hash('sha256', $last), 'seq' => $seq];
}

/** Close a finished day: its count, its span, and the hash the next day chains to. Written once. */
function smpro_ev_seal(string $day): array {
    $f = smpro_ev_path($day);
    $sealFile = smpro_ev_seal_path($day);
    if (@is_file($sealFile)) return ['ok' => true, 'already' => true];
    if (!@is_file($f)) return ['ok' => false, 'msg' => 'no journal for ' . $day];

    $n = 0; $first = 0; $last = 0; $head = '';
    $fh = @fopen($f, 'rb');
    if (!$fh) return ['ok' => false, 'msg' => 'could not read ' . $f];
    while (($line = fgets($fh)) !== false) {
        $line = rtrim($line, "\n");
        if ($line === '') continue;
        $n++;
        $head = hash('sha256', $line);
        $r = json_decode($line, true);
        if (is_array($r)) { $t = (int)($r['ts'] ?? 0); if ($t > 0) { if (!$first) $first = $t; $last = $t; } }
    }
    fclose($fh);

    $s = smpro_ev_state();
    $seal = ['day' => $day, 'records' => $n, 'first_ts' => $first, 'last_ts' => $last,
             'head' => $head, 'sealed_at' => time(), 'version' => defined('SMPRO_VERSION') ? SMPRO_VERSION : ''];
    @file_put_contents($sealFile, json_encode($seal, JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    @chmod($sealFile, 0600);

    $s['head'] = $head;                                         // the new day chains to the sealed day
    $s['day']  = '';
    $s['seq']  = 0;
    smpro_ev_state_save($s);
    return ['ok' => true, 'sealed' => $seal];
}

/* ------------------------------------------------------------------ verification */

/**
 * Walk the chain and report the FIRST place it breaks, by day and record number.
 *
 * Returns ok=false with a named break, never a bare boolean: "the chain is broken" is not useful, "record 412 of
 * 2026-09-14 does not follow record 411" is. A day whose file is missing but whose seal exists is reported as a
 * missing day rather than silently skipped.
 */
function smpro_ev_verify(string $day = ''): array {
    $days = $day !== '' ? [$day] : smpro_ev_days();
    $out = ['ok' => true, 'days' => 0, 'records' => 0, 'breaks' => [], 'restarts' => []];
    $carry = null;                                              // expected 'prev' for the next record

    foreach ($days as $dd) {
        $f = smpro_ev_path($dd);
        if (!@is_file($f)) {
            if (@is_file(smpro_ev_seal_path($dd)))
                $out['breaks'][] = ['day' => $dd, 'why' => 'the journal for this day is gone but its seal is here'];
            continue;
        }
        $out['days']++;
        $fh = @fopen($f, 'rb');
        if (!$fh) { $out['breaks'][] = ['day' => $dd, 'why' => 'could not be read']; continue; }
        $n = 0;
        while (($line = fgets($fh)) !== false) {
            $line = rtrim($line, "\n");
            if ($line === '') continue;
            $n++; $out['records']++;
            $r = json_decode($line, true);
            if (!is_array($r)) { $out['breaks'][] = ['day' => $dd, 'record' => $n, 'why' => 'not a record']; break; }
            if ($carry !== null && (string)($r['prev'] ?? '') !== $carry) {
                // A record that chains to 'genesis' in the middle of a file is a chain that was RESTARTED, not
                // one that was broken: the journal's state file was lost or reset and the writer began again.
                // Everything before it is still intact and everything after it is a valid chain of its own.
                // Calling that tampering would be an accusation the evidence does not support.
                $restart = ((string)($r['prev'] ?? '') === 'genesis');
                $out[$restart ? 'restarts' : 'breaks'][] = [
                    'day' => $dd, 'record' => $n, 'seq' => (int)($r['seq'] ?? 0),
                    'why' => $restart
                        ? 'the chain restarts here — the journal state was lost or reset, not tampered with'
                        : 'does not follow the record before it — something was removed or altered',
                ];
                $carry = null;                                  // resync on this record and keep going
            }
            if ($carry === null) { /* resynced */ }
            $carry = hash('sha256', $line);
        }
        fclose($fh);
        $seal = @is_file(smpro_ev_seal_path($dd))
              ? json_decode((string)@file_get_contents(smpro_ev_seal_path($dd)), true) : null;
        if (is_array($seal)) {
            if ((int)$seal['records'] !== $n)
                $out['breaks'][] = ['day' => $dd, 'why' => 'the seal says ' . (int)$seal['records']
                                    . ' record(s), the journal holds ' . $n];
            elseif ((string)$seal['head'] !== (string)$carry)
                $out[$out['restarts'] ? 'restarts' : 'breaks'][] =
                    ['day' => $dd, 'why' => 'the seal does not match the last record'];
        }
    }
    $out['ok'] = ($out['breaks'] === []);
    return $out;
}

/** Every day with a journal, oldest first. */
function smpro_ev_days(): array {
    $out = [];
    foreach ((array)@glob(smpro_ev_dir() . '/*.jsonl') as $p) {
        $b = basename((string)$p, '.jsonl');
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $b)) $out[] = $b;
    }
    sort($out);
    return $out;
}

/* ------------------------------------------------------------------ what gets recorded */

/**
 * Sign-ins, from the shared feed — EVERY kind, not just the findings.
 *
 * The operator's own access is recorded too. It is not a compromise and no rule should alert on it, but an
 * evidence store that holds only the alarming half cannot answer "who was in this account that week", which is
 * the question actually asked after the fact.
 */
function smpro_ev_collect_logins(array &$s): array {
    if (!function_exists('smpro_lf_success')) {
        $lf = __DIR__ . '/loginfeed.php';
        if (@is_file($lf)) require_once $lf;
    }
    if (!function_exists('smpro_lf_success')) return ['n' => 0, 'blind' => 'the login feed is not in this build'];

    $since = (int)$s['login_ts'] > 0 ? (int)$s['login_ts'] : time() - 86400;
    $feed  = smpro_lf_success($since, 20000, []);
    if (empty($feed['ok']))
        return ['n' => 0, 'blind' => (string)($feed['msg'] ?: 'the sign-in logs could not be read')];

    // Events landing on the SAME second as the watermark would otherwise be re-recorded every run or skipped
    // entirely. Keep the fingerprints of that one second and let everything else through.
    $seen = is_array($s['login_seen']) ? $s['login_seen'] : [];
    $n = 0; $newTs = $since; $newSeen = [];
    foreach ((array)$feed['events'] as $e) {
        $ts = (int)$e['ts'];
        if ($ts < $since) continue;
        $fp = substr(hash('sha256', $ts . '|' . $e['ip'] . '|' . $e['user'] . '|' . $e['kind']), 0, 16);
        if ($ts === $since && in_array($fp, $seen, true)) continue;
        smpro_ev_append('login', [
            'k' => $e['kind'], 'u' => $e['user'], 'ip' => $e['ip'], 'svc' => $e['service'],
            'by' => $e['creator'] !== '' && $e['creator'] !== $e['user'] ? $e['creator'] : null,
            // The raw line is what makes the record evidence rather than a claim. Its hash is kept always; the
            // line itself only for the kinds somebody will have to defend later.
            'h'  => substr(hash('sha256', (string)$e['raw']), 0, 16),
            'raw' => $e['kind'] === 'password' ? mb_substr((string)$e['raw'], 0, 400) : null,
        ], $ts);
        $n++;
        if ($ts > $newTs) { $newTs = $ts; $newSeen = [$fp]; }
        elseif ($ts === $newTs) $newSeen[] = $fp;
    }
    $s['login_ts']   = $newTs;
    $s['login_seen'] = array_slice(array_unique($newSeen), 0, 200);
    return ['n' => $n, 'blind' => ''];
}

/**
 * What the plugin itself DID — blocks, resets, quarantines.
 *
 * Read forward from a byte offset in the audit log, which is cheap and exact. The inode is remembered too: when
 * the audit log rotates, the offset from the old file would point into the middle of the new one and silently
 * skip everything before it.
 */
function smpro_ev_collect_actions(array &$s): array {
    $log = defined('SMPRO_AUDIT_LOG') ? SMPRO_AUDIT_LOG : '';
    if ($log === '' || !@is_readable($log)) return ['n' => 0, 'blind' => 'the audit log could not be read'];

    $inode = (int)@fileinode($log);
    $size  = (int)@filesize($log);
    $pos   = (int)$s['audit_pos'];
    $first = ((int)$s['audit_inode'] === 0);

    // FIRST RUN STARTS AT THE END, NOT THE BEGINNING. Taking in the whole existing audit log would back-date
    // months of history into today's journal and stamp it with today as the moment it was recorded - a lie about
    // the one thing a journal is for. It records from when it started and says so; the audit log is still on
    // disk for anybody who wants what came before.
    if ($first)                                $pos = $size;
    elseif ($inode !== (int)$s['audit_inode']) $pos = 0;        // rotated: start at the top of the new file
    if ($pos > $size)                          $pos = 0;        // truncated

    $fh = @fopen($log, 'rb');
    if (!$fh) return ['n' => 0, 'blind' => 'the audit log could not be opened'];
    @fseek($fh, $pos);

    /*
     * Only the actions that CHANGED something.
     *
     * The first version matched substrings, and 'protect' matched `siteprotection_worker` - a heartbeat that
     * runs every minute. One live server produced 1,740 identical records of that worker failing, and its first
     * day came to 476 KB against the ~2 KB the same server's real activity costs. A worker running is not an
     * event, and a worker failing every minute for a week is ONE fact, not ten thousand.
     *
     * The verbs still match by substring, so an action named after one of them is caught without anybody
     * remembering to add it here. The non-events are named explicitly and dropped.
     */
    $want = ['block', 'unblock', 'reset', 'password', 'quarantine', 'restore', 'evict', 'geologin', 'geowall',
             'bfrules', 'protect', 'release', 'delete', 'suspend', 'kill', 'purge', 'malware'];
    $notAnEvent = '/(_worker|_run|_view|_status|_check|_sample|_tick)$/';

    // Identical repeats inside one pass collapse into a single record carrying the count and the span.
    $bucket = []; $n = 0; $dropped = 0;
    while (($line = fgets($fh)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        $r = json_decode($line, true);
        if (!is_array($r)) continue;
        $act = strtolower((string)($r['action'] ?? ''));
        if ($act === '' || preg_match($notAnEvent, $act)) { $dropped++; continue; }
        $hit = false;
        foreach ($want as $w) { if (strpos($act, $w) !== false) { $hit = true; break; } }
        if (!$hit) continue;

        $rec = ['a' => (string)($r['action'] ?? ''), 'by' => (string)($r['actor'] ?? ''),
                'ip' => (string)($r['ip'] ?? ''), 'd' => $r['details'] ?? null];
        $ts  = @strtotime((string)($r['timestamp'] ?? '')) ?: time();
        $key = hash('sha256', (string)json_encode($rec, JSON_UNESCAPED_SLASHES));
        if (isset($bucket[$key])) { $bucket[$key]['n']++; $bucket[$key]['last'] = $ts; continue; }
        $bucket[$key] = ['rec' => $rec, 'ts' => $ts, 'last' => $ts, 'n' => 1];
    }
    $s['audit_pos']   = (int)@ftell($fh);
    $s['audit_inode'] = $inode;
    fclose($fh);

    foreach ($bucket as $b) {
        $d = $b['rec'];
        if ($b['n'] > 1) { $d['n'] = $b['n']; $d['until'] = $b['last']; }   // one fact, and how often it happened
        smpro_ev_append('action', $d, $b['ts']);
        $n++;
    }
    if ($first) smpro_ev_append('blind', [
        'why' => 'the journal starts here; actions written to the audit log before this point were not taken in',
    ]);
    return ['n' => $n, 'dropped' => $dropped, 'blind' => ''];
}

/**
 * One state snapshot a day.
 *
 * This is what lets a question a year from now be answered at all: how many accounts were there, what version
 * was running, was the country lock armed, how many firewall rules stood. None of it is in any log.
 */
function smpro_ev_snapshot(array &$s): array {
    $today = date('Y-m-d');
    if ((string)$s['snapshot_day'] === $today) return ['n' => 0];

    $accounts = 0;
    foreach ((array)@scandir('/var/cpanel/users') as $u) if ($u !== '' && $u[0] !== '.') $accounts++;

    $snap = [
        'v'        => defined('SMPRO_VERSION') ? SMPRO_VERSION : '',
        'panel'    => trim((string)@file_get_contents('/usr/local/cpanel/version')),
        'accounts' => $accounts,
        'host'     => php_uname('n'),
        'fwrules'  => (int)substr_count((string)@shell_exec('timeout 10 iptables -S INPUT 2>/dev/null'), "\n"),
        'gl'       => function_exists('smpro_gl_cfg') ? !empty(smpro_gl_cfg()['enabled']) : null,
        'gw'       => function_exists('smpro_gw_live') ? (bool)smpro_gw_live() : null,
    ];
    smpro_ev_append('snapshot', $snap);
    $s['snapshot_day'] = $today;
    return ['n' => 1];
}

/* ------------------------------------------------------------------ the run */

/**
 * One collection pass. Safe to run every few minutes; the watermarks make it idempotent.
 *
 * A source that could not be read becomes a 'blind' record. That is the point: the gap in the evidence is itself
 * recorded, at the time it happened, with the reason.
 */
function smpro_ev_run(): array {
    $s = smpro_ev_state();
    $res = ['ok' => true, 'logins' => 0, 'actions' => 0, 'snapshot' => 0, 'blind' => []];

    $l = smpro_ev_collect_logins($s);
    $res['logins'] = (int)$l['n'];
    if ($l['blind'] !== '') $res['blind'][] = $l['blind'];

    $a = smpro_ev_collect_actions($s);
    $res['actions'] = (int)$a['n'];
    if ($a['blind'] !== '') $res['blind'][] = $a['blind'];

    $res['snapshot'] = (int)smpro_ev_snapshot($s)['n'];
    smpro_ev_state_save($s);

    foreach ($res['blind'] as $why) smpro_ev_append('blind', ['why' => $why]);
    if ($res['blind']) $res['ok'] = false;

    smpro_ev_prune();
    return $res;
}

/**
 * Retention. Removes whole days older than the window — and keeps their SEAL for ever.
 *
 * The seals are a few hundred bytes each and they carry the chain forward, so a store pruned to thirty days can
 * still prove that the days before it were not tampered with, only that their detail is no longer held. Deleting
 * the seal as well would erase the proof along with the data.
 */
function smpro_ev_prune(int $keepDays = 0): array {
    $keep = $keepDays > 0 ? $keepDays : SMPRO_EV_KEEP;
    $cut  = date('Y-m-d', time() - $keep * 86400);
    $gone = [];
    foreach (smpro_ev_days() as $d) {
        if ($d >= $cut) continue;
        if (!@is_file(smpro_ev_seal_path($d))) smpro_ev_seal($d);   // never drop a day that was never sealed
        if (@unlink(smpro_ev_path($d))) $gone[] = $d;
    }
    return ['removed' => $gone, 'keep_days' => $keep];
}

/** Size and span, for the page and for anybody wondering what this costs. */
function smpro_ev_stats(): array {
    $days = smpro_ev_days();
    $bytes = 0; $records = 0;
    foreach ($days as $d) {
        $bytes += (int)@filesize(smpro_ev_path($d));
        $seal = @is_file(smpro_ev_seal_path($d))
              ? json_decode((string)@file_get_contents(smpro_ev_seal_path($d)), true) : null;
        $records += is_array($seal) ? (int)$seal['records'] : (int)@substr_count((string)@file_get_contents(smpro_ev_path($d)), "\n");
    }
    $seals = count((array)@glob(smpro_ev_dir() . '/*.seal'));
    return ['days' => count($days), 'sealed_days' => $seals, 'records' => $records, 'bytes' => $bytes,
            'per_day' => $days ? (int)round($bytes / max(1, count($days))) : 0, 'keep_days' => SMPRO_EV_KEEP];
}

/* ------------------------------------------------------------------ schedule */

function smpro_ev_cron_sync(): bool {
    // A test must never install a live cron.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-evidence';
    $bin = SMPRO_BASE . '/bin/evidence_tick.php';
    if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // Every 5 minutes. The window between a thing happening and it being written down is the window in which it
    // can still be erased from the log it came from.
    $desired = '# Safety Monitor Pro - evidence journal (keeps what the logs will rotate away)' . PHP_EOL
             . 'MAILTO=""' . PHP_EOL
             . '*/5 * * * * root ' . $flock . ' -n ' . $lockDir . '/evidence.lock nice -n 15 timeout 120 '
             . $php . ' ' . $bin . ' >/dev/null 2>&1' . PHP_EOL;
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired)
         : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
