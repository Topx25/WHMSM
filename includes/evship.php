<?php
/**
 * evship.php - get the evidence journal off the server it was written on.
 *
 * WHY. The local journal in evidence.php is hash-chained, so removing a record leaves a provable break. But it
 * sits on a machine somebody has root on, and root can rewrite the whole chain from scratch - every record, every
 * seal, the state file - and the result verifies perfectly. A local store makes casual tampering visible; it
 * cannot survive an attacker who owns the box. Only a copy the server cannot reach back into can do that.
 *
 * HOW IT TRAVELS, AND WHY NOT THE OBVIOUS WAY. The first version of this posted signed batches to a small PHP
 * endpoint the customer installed on another server. That was wrong twice over. The customer had to create a
 * directory, set its mode, copy a file, invent an unguessable path and carry a key - and a requirement the
 * customer builds by hand is one that gets built wrong. And underneath that, it could not have worked anyway:
 *
 *     hub.php:13 - "WHM addon CGIs cannot accept direct inbound calls."
 *
 * The project had already solved server-to-server traffic: the licence server is an authenticated RELAY, and
 * hub.php seals every payload with AES-256-GCM under a key derived from an ECDH exchange plus both endpoints'
 * identity plus an optional passphrase THE RELAY NEVER SEES. So evidence rides that. Nothing is installed,
 * no port is opened, no key is handled by a person, and the relay carries ciphertext it cannot read - which also
 * means the vendor running the relay is not holding customers' evidence.
 *
 * ITS OWN QUEUE, AND WHY THAT IS NOT OPTIONAL. The relay's existing channels are 'cmd', 'result' and 'status'.
 * Evidence must not share them: smpro_hub_render_request() fetches dir='result' with max=25 and DISCARDS every
 * item whose 'req' does not match its own - and fetching consumes. An evidence batch on that channel would be
 * silently eaten by anybody opening the remote panel. Lost evidence, no error, nobody the wiser. So evidence has
 * its own dir, and if the relay does not accept it this refuses to send rather than falling back to a channel
 * that would swallow it.
 *
 * WHAT IT NEVER DOES. It never deletes a local record because the vault took it. Retention does that on its own
 * schedule, whether or not shipping works - otherwise a vault that quietly stopped accepting would take the local
 * copy with it, and the first anyone knew would be when both were needed.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_EVSHIP_STATE')) define('SMPRO_EVSHIP_STATE', SMPRO_VARLIB . '/evship_state.json');
if (!defined('SMPRO_EVSHIP_MAX'))   define('SMPRO_EVSHIP_MAX',   300);      // records per batch
/** The relay channel evidence travels on. Never 'result' - see the note above. */
if (!defined('SMPRO_EVSHIP_DIR'))   define('SMPRO_EVSHIP_DIR',   'evidence');

function smpro_ev_ship_state(): array {
    $d = @is_file(SMPRO_EVSHIP_STATE) ? json_decode((string)@file_get_contents(SMPRO_EVSHIP_STATE), true) : null;
    $s = is_array($d) ? $d : [];
    $s += ['sent' => [], 'last_ok' => 0, 'last_try' => 0, 'fails' => 0, 'last_error' => ''];
    return $s;
}
function smpro_ev_ship_state_save(array $s): void {
    $t = SMPRO_EVSHIP_STATE . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) {
        @chmod($t, 0600); @rename($t, SMPRO_EVSHIP_STATE);
    }
}

/**
 * Where this server's evidence goes: the link to the hub that holds the vault.
 *
 * There is nothing to configure. A server that has been paired as a Member already knows its hub, already has a
 * derived key, and already has a granted permission set. Evidence is sent only on a link whose grant includes
 * 'evidence' - so turning it on is the same single click as every other permission, on the machine that receives
 * it, by the person who owns both.
 */
function smpro_ev_ship_link(): array {
    if (!function_exists('smpro_hub_links')) return ['ok' => false, 'why' => 'the multi-server hub is not in this build'];
    if (function_exists('smpro_hub_active') && !smpro_hub_active())
        return ['ok' => false, 'why' => 'the multi-server hub is off on this server'];
    foreach (smpro_hub_links('member') as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        if (!in_array('evidence', (array)($L['perms_grant'] ?? []), true)) continue;
        $lid = (int)($L['link_id'] ?? 0);
        if ($lid <= 0) continue;
        // A link with no derived key cannot be used: hub.php refuses to seal without one rather than putting
        // plaintext through the relay, and evidence is exactly the payload that must never travel in the clear.
        if (function_exists('smpro_hub_enckey') && smpro_hub_enckey($lid) === '')
            return ['ok' => false, 'why' => 'the link to the vault has no encryption key yet', 'link' => $lid];
        return ['ok' => true, 'link' => $lid];
    }
    return ['ok' => false, 'why' => 'no hub has been granted the evidence permission on this server'];
}

/**
 * The next batch for one day: the raw lines, exactly as written, plus the hash the first of them chains to.
 *
 * The lines travel verbatim so the vault can recompute the chain itself. A summary the sending server produced
 * would be a claim about the evidence rather than the evidence.
 */
function smpro_ev_ship_batch(string $day, int $afterSeq, int $max = 0): array {
    $max = $max > 0 ? $max : SMPRO_EVSHIP_MAX;
    $f = smpro_ev_path($day);
    if (!@is_file($f)) return ['ok' => false, 'msg' => 'no journal for ' . $day, 'records' => []];
    $fh = @fopen($f, 'rb');
    if (!$fh) return ['ok' => false, 'msg' => 'could not read ' . $day, 'records' => []];

    $lines = []; $prev = ''; $from = 0; $to = 0;
    while (($line = fgets($fh)) !== false) {
        $line = rtrim($line, "\n");
        if ($line === '') continue;
        $r = json_decode($line, true);
        if (!is_array($r)) continue;
        $seq = (int)($r['seq'] ?? 0);
        if ($seq <= $afterSeq) { $prev = hash('sha256', $line); continue; }   // already at the vault
        if (!$lines) { $from = $seq; if ($prev === '') $prev = (string)($r['prev'] ?? 'genesis'); }
        $lines[] = $line; $to = $seq;
        if (count($lines) >= $max) break;
    }
    fclose($fh);
    return ['ok' => true, 'records' => $lines, 'from' => $from, 'to' => $to, 'prev' => $prev, 'day' => $day];
}

/** Days holding anything the vault has not acknowledged, oldest first. */
function smpro_ev_ship_pending(array $sent): array {
    $out = [];
    foreach (smpro_ev_days() as $d) {
        $tail = smpro_ev_last_record($d);
        if ($tail !== null && $tail['seq'] > (int)($sent[$d] ?? 0)) $out[] = $d;
    }
    return $out;
}

/**
 * Send what is waiting. Returns what went, what did not, and why - never a bare boolean.
 *
 * $dry builds and seals the batches and sends nothing, so the wiring can be checked on a live server without a
 * single record leaving it.
 */
function smpro_ev_ship_run(bool $dry = false): array {
    $res = ['ok' => true, 'dry' => $dry, 'days' => 0, 'records' => 0, 'batches' => 0, 'msg' => '', 'errors' => []];

    $link = smpro_ev_ship_link();
    if (empty($link['ok'])) { $res['msg'] = (string)$link['why']; return $res; }   // not an error: not set up
    $lid = (int)$link['link'];

    $st = smpro_ev_ship_state();
    $st['last_try'] = time();

    foreach (smpro_ev_ship_pending((array)$st['sent']) as $day) {
        $res['days']++;
        for ($guard = 0; $guard < 40; $guard++) {                  // bounded: a cron run must end
            $b = smpro_ev_ship_batch($day, (int)($st['sent'][$day] ?? 0));
            if (empty($b['ok']) || !$b['records']) break;

            $sealed = smpro_hub_seal($lid, [
                'kind' => 'evidence', 'v' => 1,
                'host' => php_uname('n'), 'day' => $day,
                'from_seq' => $b['from'], 'to_seq' => $b['to'], 'prev' => $b['prev'],
                'records' => $b['records'], 'sent_at' => time(),
                'version' => defined('SMPRO_VERSION') ? SMPRO_VERSION : '',
            ]);
            // hub.php returns '' rather than shipping plaintext through the relay. Evidence is the last payload
            // that should ever be the exception to that, so an unsealed batch is simply not sent.
            if ($sealed === '') {
                $res['ok'] = false;
                $res['errors'][] = 'the batch could not be sealed, so nothing was sent in the clear';
                break 2;
            }

            $res['batches']++;
            if ($dry) { $res['records'] += count($b['records']); $st['sent'][$day] = (int)$b['to']; continue; }

            [$ok, $d] = smpro_hub_api('send', ['link_id' => $lid, 'dir' => SMPRO_EVSHIP_DIR, 'body' => $sealed]);
            if (!$ok) {
                $why = 'the relay refused ' . $day . ' ' . $b['from'] . '-' . $b['to']
                     . (is_array($d) && !empty($d['message']) ? ': ' . $d['message'] : '');
                // NEVER retry onto another channel. 'result' is fetched with max=25 by the remote panel, which
                // discards what does not match its own request id - and fetching consumes. Evidence put there
                // would be eaten silently by anyone opening a remote page.
                $res['ok'] = false; $res['errors'][] = $why;
                $st['fails']++; $st['last_error'] = $why;
                break 2;
            }

            $st['sent'][$day] = (int)$b['to'];
            $res['records'] += count($b['records']);
            $st['fails'] = 0; $st['last_error'] = ''; $st['last_ok'] = time();
        }
    }

    if (!$dry) smpro_ev_ship_state_save($st);
    if ($res['errors']) {
        // The gap explains itself in the journal, and travels with the next batch once the link is back.
        if (function_exists('smpro_ev_append')) @smpro_ev_append('blind', ['why' => 'evidence shipping failed: ' . $res['errors'][0]]);
        $res['msg'] = $res['errors'][0];
    } elseif ($res['records'] === 0) {
        $res['msg'] = 'Nothing new to send.';
    } else {
        $res['msg'] = $res['records'] . ' record(s) sent in ' . $res['batches'] . ' batch(es).';
    }
    return $res;
}

/* ------------------------------------------------------------------ the vault side */

/**
 * HUB: collect what the members have sent, verify each batch against what is already held, and store it.
 *
 * EVERY RULE THAT MATTERS IS HERE, because every one of them is a thing the SENDING server must not be able to do:
 *
 *   - Append only. A member may add records. It may never replace, reorder or remove one it already sent. A batch
 *     contradicting what is held is not an error to retry, it is a finding: the original is kept, the rejected
 *     version is written beside it, and the member has no way to reach either.
 *   - The vault stamps the time. A clock on a machine somebody has taken over is not evidence of anything, so the
 *     member's own 'sent_at' is kept only as a claim.
 *   - The chain is re-verified here, against what the vault already holds - so a gap is detected where the member
 *     cannot suppress the detection.
 */
function smpro_ev_vault_dir(): string {
    $d = SMPRO_VARLIB . '/vault';
    if (!@is_dir($d)) { @mkdir($d, 0700, true); @chmod($d, 0700); }
    return $d;
}

function smpro_ev_vault_store(int $lid, array $batch): array {
    $day = (string)($batch['day'] ?? '');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) return ['ok' => false, 'msg' => 'batch names no valid day'];
    $records = (array)($batch['records'] ?? []);
    if (!$records) return ['ok' => false, 'msg' => 'batch is empty'];

    $dir = smpro_ev_vault_dir() . '/' . (int)$lid;
    if (!@is_dir($dir) && !@mkdir($dir, 0700, true)) return ['ok' => false, 'msg' => 'vault storage is not writable'];
    $file = $dir . '/' . $day . '.jsonl';

    $have = 0; $head = ''; $known = [];
    if (@is_file($file)) {
        foreach ((array)@file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $r = json_decode((string)$line, true);
            if (!is_array($r)) continue;
            $seq = (int)($r['seq'] ?? 0);
            $known[$seq] = hash('sha256', (string)$line);
            if ($seq > $have) $have = $seq;
            $head = hash('sha256', (string)$line);
        }
    }

    $accept = []; $expect = $head; $restarts = 0;
    foreach ($records as $line) {
        $line = (string)$line;
        $r = json_decode($line, true);
        if (!is_array($r) || !isset($r['seq'], $r['prev'])) return ['ok' => false, 'msg' => 'batch holds something that is not a record'];
        $seq = (int)$r['seq'];

        if (isset($known[$seq])) {
            if ($known[$seq] !== hash('sha256', $line)) {
                @file_put_contents($dir . '/' . $day . '.conflict.jsonl',
                    json_encode(['at' => time(), 'seq' => $seq, 'held' => $known[$seq],
                                 'offered' => hash('sha256', $line), 'offered_raw' => $line], JSON_UNESCAPED_SLASHES) . "\n",
                    FILE_APPEND | LOCK_EX);
                if (function_exists('smpro_audit')) smpro_audit('evidence_conflict', ['link' => $lid, 'day' => $day, 'seq' => $seq]);
                return ['ok' => false, 'conflict' => true, 'have' => $have,
                        'msg' => 'record ' . $seq . ' of ' . $day . ' does not match the copy already held — REJECTED and recorded'];
            }
            $expect = $known[$seq];
            continue;                                              // a harmless resend
        }

        if ($expect !== '' && (string)$r['prev'] !== $expect) {
            if ((string)$r['prev'] !== 'genesis')
                return ['ok' => false, 'have' => $have,
                        'msg' => 'record ' . $seq . ' of ' . $day . ' does not chain onto what the vault holds'];
            // A chain that RESTARTS is accepted - a member may genuinely have lost its state file - but never
            // quietly. Starting a fresh chain is exactly how a gap would be hidden, so every restart is written
            // where the member cannot reach it, and an audit counts them.
            @file_put_contents($dir . '/' . $day . '.restart.jsonl',
                json_encode(['at' => time(), 'seq' => $seq, 'expected' => $expect, 'raw' => $line], JSON_UNESCAPED_SLASHES) . "\n",
                FILE_APPEND | LOCK_EX);
            $restarts++;
            if (function_exists('smpro_audit')) smpro_audit('evidence_chain_restart', ['link' => $lid, 'day' => $day, 'seq' => $seq]);
        }
        $accept[] = $line;
        $expect = hash('sha256', $line);
        if ($seq > $have) $have = $seq;
    }

    foreach ($accept as $line) {
        if (@file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX) === false)
            return ['ok' => false, 'have' => $have, 'msg' => 'could not write to the vault'];
    }
    if ($accept) @chmod($file, 0600);

    @file_put_contents($dir . '/' . $day . '.meta', json_encode([
        'day' => $day, 'have' => $have, 'head' => $expect,
        'received_at' => time(),                                   // the VAULT's clock
        'sender_said' => (int)($batch['sent_at'] ?? 0),             // the member's claim, kept as a claim
        'host' => substr((string)($batch['host'] ?? ''), 0, 120),
        'version' => substr((string)($batch['version'] ?? ''), 0, 40),
        'restarts' => $restarts,
    ], JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    @chmod($dir . '/' . $day . '.meta', 0600);

    return ['ok' => true, 'stored' => count($accept), 'have' => $have, 'day' => $day, 'restarts' => $restarts];
}

/** HUB: pull every waiting evidence batch from every member link and store it. Run from the hub's own cron. */
function smpro_ev_vault_collect(): array {
    $res = ['ok' => true, 'links' => 0, 'batches' => 0, 'records' => 0, 'unopened' => 0, 'errors' => []];
    if (!function_exists('smpro_hub_links') || !function_exists('smpro_hub_api')) {
        $res['ok'] = false; $res['errors'][] = 'the multi-server hub is not in this build'; return $res;
    }
    // The hub derives ITS half of the E2E key here, not at pairing time - the member's public key only arrives
    // when the member approves. Skipping this leaves a link that reports a key and cannot open anything sent on
    // it, which is how the first live run consumed two batches and reported "0 batches, no errors".
    $links = smpro_hub_links('hub');
    if (function_exists('smpro_hub_ensure_secrets')) smpro_hub_ensure_secrets($links);

    foreach ($links as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        $lid = (int)($L['link_id'] ?? 0);
        if ($lid <= 0) continue;
        // Same guard hub.php applies everywhere: a keyless link would let smpro_hub_open() accept raw,
        // relay-supplied JSON, which would let the relay write whatever it liked into the evidence store.
        if (function_exists('smpro_hub_enckey') && smpro_hub_enckey($lid) === '') continue;
        $res['links']++;

        for ($guard = 0; $guard < 40; $guard++) {
            [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => SMPRO_EVSHIP_DIR, 'max' => 10], 20);
            if (!$ok) { $res['errors'][] = 'link ' . $lid . ': the relay could not be read'; $res['ok'] = false; break; }
            $items = (array)($d['items'] ?? []);
            if (!$items) break;
            foreach ($items as $it) {
                $b = smpro_hub_open($lid, (string)($it['body'] ?? ''));

                /*
                 * AN ITEM THAT CANNOT BE OPENED IS NEVER DROPPED SILENTLY.
                 *
                 * fetch CONSUMES: once the relay has handed an item over it is gone, and there is no asking for
                 * it again. The first version of this loop skipped anything that would not decode and counted
                 * nothing - so the first live run pulled two real batches, failed to open them, deleted them from
                 * the relay and reported "1 link, 0 batches, 0 records" with no error at all. Indistinguishable
                 * from a quiet day. That is the exact failure this product exists to remove, written by hand into
                 * the part of it that is supposed to be the last line of defence.
                 *
                 * So: it is counted, it is reported, and the ciphertext is kept. It can be opened later once the
                 * key is right; it cannot be recovered once it is thrown away.
                 */
                if (!is_array($b) || ($b['kind'] ?? '') !== 'evidence') {
                    $res['unopened']++;
                    $res['ok'] = false;
                    $qdir = smpro_ev_vault_dir() . '/' . $lid;
                    if (!@is_dir($qdir)) @mkdir($qdir, 0700, true);
                    @file_put_contents($qdir . '/unopened.jsonl',
                        json_encode(['at' => time(), 'relay_id' => (int)($it['id'] ?? 0),
                                     'why' => is_array($b) ? 'opened, but not an evidence batch' : 'could not be decrypted or was replayed',
                                     'body' => (string)($it['body'] ?? '')], JSON_UNESCAPED_SLASHES) . "
",
                        FILE_APPEND | LOCK_EX);
                    @chmod($qdir . '/unopened.jsonl', 0600);
                    if (function_exists('smpro_audit')) smpro_audit('evidence_unopened', ['link' => $lid, 'relay_id' => (int)($it['id'] ?? 0)]);
                    continue;
                }
                $r = smpro_ev_vault_store($lid, $b);
                $res['batches']++;
                if (!empty($r['ok'])) { $res['records'] += (int)$r['stored']; }
                else { $res['ok'] = false; $res['errors'][] = 'link ' . $lid . ': ' . (string)$r['msg']; }
            }
        }
    }
    if ($res['unopened'] > 0)
        $res['errors'][] = $res['unopened'] . ' batch(es) arrived and could not be opened — kept in the vault as '
                         . 'unopened.jsonl, NOT discarded. Check that this hub derived the link key.';
    return $res;
}

/** For the page: is evidence actually leaving this server, or only configured to? */
function smpro_ev_ship_status(): array {
    $link = smpro_ev_ship_link();
    $st = smpro_ev_ship_state();
    $behind = 0;
    foreach (smpro_ev_ship_pending((array)$st['sent']) as $d) {
        $tail = smpro_ev_last_record($d);
        $behind += $tail ? $tail['seq'] - (int)($st['sent'][$d] ?? 0) : 0;
    }
    return [
        'linked'     => !empty($link['ok']),
        'why'        => (string)($link['why'] ?? ''),
        'last_ok'    => (int)$st['last_ok'],
        'last_try'   => (int)$st['last_try'],
        'fails'      => (int)$st['fails'],
        'last_error' => (string)$st['last_error'],
        'behind'     => $behind,
    ];
}

function smpro_ev_ship_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-evship';
    $bin = SMPRO_BASE . '/bin/evidence_ship.php';
    if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // Every 10 minutes, both directions. The window between a record being written and it being off the server
    // is the window in which somebody with root can still make it never have existed.
    $desired = '# Safety Monitor Pro - move the evidence journal to the vault (member sends, hub collects)' . PHP_EOL
             . 'MAILTO=""' . PHP_EOL
             . '*/10 * * * * root ' . $flock . ' -n ' . $lockDir . '/evship.lock nice -n 15 timeout 300 '
             . $php . ' ' . $bin . ' >/dev/null 2>&1' . PHP_EOL;
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired)
         : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
