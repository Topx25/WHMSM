<?php
/**
 * t72_evship.php — moving the evidence journal off the server that wrote it.
 *
 * The rules being guarded are all things the SENDING server must not be able to do, because the sending server is
 * the one that may have been taken over. A vault that accepts a rewrite is a backup, not evidence.
 *
 * Two of these tests exist because of design mistakes made while building this, and both are the kind that leave
 * no trace when they bite:
 *
 *   - Evidence must have its OWN relay channel. smpro_hub_render_request() fetches dir='result' with max=25 and
 *     discards every item whose 'req' does not match its own — and fetching consumes. An evidence batch on that
 *     channel would be eaten by anybody opening the remote panel. No error, no record, no evidence.
 *   - A batch that cannot be sealed must not be sent. hub.php returns '' rather than putting plaintext through
 *     the relay; evidence is the last payload that should ever be the exception.
 */
$tmp = sys_get_temp_dir() . '/smpro_t72_' . getmypid();
define('SMPRO_EV_DIR',       $tmp . '/journal');
define('SMPRO_EV_STATE',     $tmp . '/journal/state.json');
define('SMPRO_EVSHIP_STATE', $tmp . '/evship_state.json');

require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/evidence.php';
require_once SMPRO_BASE . '/includes/evship.php';

@mkdir($tmp . '/journal', 0700, true);
$day = date('Y-m-d');

/* ---------- U1: the channel is its own, and there is no fallback ---------- */
is_eq(SMPRO_EVSHIP_DIR, 'evidence', 'U1: evidence travels on its own relay channel');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/evship.php'));
hasnt($src, "'dir' => 'result'", 'U1: and never on the channel the remote panel consumes');
has($src, 'NEVER retry onto another channel', 'U1: with the reason a fallback would be silent data loss');
has($src, 'max=25', 'U1: naming the mechanism that would have eaten it');

/* ---------- U2: nothing is ever sent unsealed ---------- */
has($src, "if (\$sealed === '')", 'U2: an unsealed batch is not sent');
has($src, 'nothing was sent in the clear', 'U2: and says so rather than failing quietly');
has($src, "smpro_hub_enckey(\$lid) === ''", 'U2: a link with no derived key is refused outright');

/* ---------- U3: batching reads the journal verbatim ---------- */
smpro_ev_append('login', ['u' => 'alice', 'ip' => '203.0.113.1']);
smpro_ev_append('login', ['u' => 'bob',   'ip' => '203.0.113.2']);
smpro_ev_append('login', ['u' => 'carol', 'ip' => '203.0.113.3']);
$b = smpro_ev_ship_batch($day, 0);
ok(!empty($b['ok']), 'U3: a batch can be built');
is_eq(count($b['records']), 3, 'U3: holding every record not yet sent');
is_eq($b['from'], 1, 'U3: from the first');
is_eq($b['to'], 3, 'U3: to the last');
is_eq($b['prev'], 'genesis', 'U3: chained to what the first record chains to');
$lines = file(smpro_ev_path($day), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
is_eq($b['records'][0], $lines[0], 'U3: the line travels VERBATIM — a summary would be a claim, not evidence');

$b2 = smpro_ev_ship_batch($day, 2);
is_eq(count($b2['records']), 1, 'U3: a later batch carries only what is new');
is_eq($b2['prev'], hash('sha256', $lines[1]), 'U3: chained onto the last one already sent');

/* ---------- U4: the vault stores, and re-verifies the chain itself ---------- */
$r = smpro_ev_vault_store(7, ['day' => $day, 'records' => $b['records'], 'host' => 'member1', 'sent_at' => time()]);
ok(!empty($r['ok']), 'U4: a well-chained batch is stored');
is_eq($r['stored'], 3, 'U4: every record');
is_eq($r['have'], 3, 'U4: and the vault reports how far it has got');

$again = smpro_ev_vault_store(7, ['day' => $day, 'records' => $b['records'], 'host' => 'member1']);
ok(!empty($again['ok']), 'U4: sending the same batch again is accepted');
is_eq($again['stored'], 0, 'U4: and stores nothing twice — a dropped reply must be safe to retry');

/* ---------- U5: THE ONE THAT MATTERS — a rewrite is refused and recorded ---------- */
// A member that has been taken over tries to revise what it already sent.
$forged = json_encode(['seq' => 2, 'ts' => time(), 'kind' => 'login', 'prev' => hash('sha256', $lines[0]),
                       'd' => ['u' => 'somebody-else']], JSON_UNESCAPED_SLASHES);
$c = smpro_ev_vault_store(7, ['day' => $day, 'records' => [$forged], 'host' => 'member1']);
ok(empty($c['ok']), 'U5: a different version of a stored record is REFUSED');
ok(!empty($c['conflict']), 'U5: and reported as a conflict, not a retryable error');
ok(@is_file(smpro_ev_vault_dir() . '/7/' . $day . '.conflict.jsonl'), 'U5: the attempt is kept as evidence of itself');
$held = file(smpro_ev_vault_dir() . '/7/' . $day . '.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
is_eq($held[1], $lines[1], 'U5: and the ORIGINAL is still what the vault holds');

/* ---------- U6: a batch that does not chain is refused ---------- */
$orphan = json_encode(['seq' => 9, 'ts' => time(), 'kind' => 'login', 'prev' => str_repeat('a', 64), 'd' => []], JSON_UNESCAPED_SLASHES);
$o = smpro_ev_vault_store(7, ['day' => $day, 'records' => [$orphan], 'host' => 'member1']);
ok(empty($o['ok']), 'U6: a record that does not chain onto what is held is refused');
has((string)$o['msg'], 'chain', 'U6: naming the reason');

/* ---------- U7: a restart is accepted, but never quietly ---------- */
// A member may genuinely lose its state file. Starting a fresh chain is also exactly how a gap would be hidden,
// so it is written where the member cannot reach it and counted in the vault's own record of the day.
$restart = json_encode(['seq' => 10, 'ts' => time(), 'kind' => 'login', 'prev' => 'genesis', 'd' => ['u' => 'dave']], JSON_UNESCAPED_SLASHES);
$rs = smpro_ev_vault_store(7, ['day' => $day, 'records' => [$restart], 'host' => 'member1']);
ok(!empty($rs['ok']), 'U7: a chain that restarts is accepted');
is_eq($rs['restarts'], 1, 'U7: and counted');
ok(@is_file(smpro_ev_vault_dir() . '/7/' . $day . '.restart.jsonl'), 'U7: written where the member cannot reach it');

/* ---------- U8: the vault stamps the time; the sender only claims one ---------- */
$meta = json_decode((string)@file_get_contents(smpro_ev_vault_dir() . '/7/' . $day . '.meta'), true);
ok(is_array($meta), 'U8: the vault keeps its own record of the delivery');
ok(abs((int)$meta['received_at'] - time()) < 120, 'U8: stamped with the VAULT clock');
ok(array_key_exists('sender_said', $meta), 'U8: the member\'s own claim is kept separately, as a claim');

/* ---------- U9: without a link, shipping is not an error — it is not set up ---------- */
$s = smpro_ev_ship_run(true);
ok(!empty($s['ok']), 'U9: an unpaired server does not report a failure');
ok($s['msg'] !== '', 'U9: it says why nothing was sent');
is_eq($s['records'], 0, 'U9: and sends nothing');

/* ---------- U10: the permission exists, and reads as what it does ---------- */
require_once SMPRO_BASE . '/includes/hub.php';
$perms = smpro_hub_perms_all();
ok(isset($perms['evidence']), 'U10: the member grants an explicit evidence permission');
has((string)$perms['evidence'], 'evidence journal', 'U10: named for what it sends');

/* ---------- U11: a test must never install a live cron ---------- */
ok(smpro_ev_ship_cron_sync() === true, 'U11: cron installation is refused under the test guard');

foreach ((array)glob($tmp . '/vault/7/*') as $f) @unlink($f);
foreach ((array)glob($tmp . '/journal/*') as $f) @unlink($f);

/* ---------- U12: an item that cannot be opened is never dropped in silence ---------- */
// The relay's fetch CONSUMES: once an item is handed over it is gone and cannot be asked for again. The first
// version of the collector skipped anything that would not decode and counted nothing — so its first live run
// pulled two real batches, failed to open them, deleted them from the relay and reported "1 link, 0 batches,
// 0 records" with no error. Indistinguishable from a quiet day, in the part of the product that is supposed to
// be the last line of defence.
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/evship.php'));
has($sh, "\$res['unopened']++",       'U12: an unopenable batch is counted');
has($sh, 'unopened.jsonl',            'U12: and its ciphertext is kept, not thrown away');
has($sh, 'NOT discarded',             'U12: and the run says so out loud');
has($sh, 'smpro_hub_ensure_secrets',  'U12: and the hub derives its half of the key before it tries');
// the counter must be reachable: it has to sit BEFORE the continue, not after it
$posCount = strpos($sh, "\$res['unopened']++");
$posCont  = strpos($sh, 'continue;', $posCount);
ok($posCount !== false && $posCont !== false && $posCount < $posCont,
   'U12: the count happens before the skip — the ordering that caused the incident');
