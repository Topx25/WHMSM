<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/spqueue.php';
/**
 * t75_spq_request_size.php — a request the customer's page is allowed to write must be one the worker reads.
 *
 * THE INCIDENT. The page lets a customer pick up to 200 items. The worker refused any request file over
 * 4,096 bytes, and 200 relative paths are about 8 KB. So a customer who selected a folder wrote a request root
 * refused to read - silently, every minute, for ever. And because the page allows one request at a time, every
 * later request was refused too: "A request is already waiting with your host." Two accounts on a production
 * server sat like that (4,233 and 4,244 bytes); the customers saw "sent", root saw nothing, and the audit log
 * held nothing either, because the skip was designed to be silent.
 *
 * Silent was right for a file the account cannot have written honestly. It was wrong for one that is merely
 * too big. Those are now told apart: hostile shape → skipped without a trace; honest but unusable → answered
 * with the reason and consumed, so the queue is free again.
 */
if (!function_exists('posix_getpwuid')) { ok(true, 'skipped: the queue reader needs posix (Linux) - the lab gate runs this'); exit(0); }
$me   = posix_getpwuid(posix_geteuid())['name'];
$home = SMPRO_VARLIB . '/t75_home';
$rq   = $home . '/.siteprotection/requests';
@mkdir($rq, 0700, true);
foreach (glob($rq . '/*') ?: [] as $f) @unlink($f);

function t75_req(string $dir, string $name, array $items): string {
    $p = $dir . '/' . $name . '.json';
    file_put_contents($p, json_encode(['verb' => 'apply_custom', 'root' => 'public_html', 'items' => $items, 'at' => date('c')]));
    return $p;
}

/* ---------- U1: the page's own ceiling fits ---------- */
$items = [];
for ($i = 0; $i < 200; $i++) $items[] = sprintf('wp-content/plugins/plugin-%03d/includes/class-something-%03d.php', $i, $i);
$p = t75_req($rq, 'aaaaaaaaaaaaaaa1', $items);
$size = filesize($p);
ok($size > 4096, 'U1: a full 200-item selection is bigger than the old 4,096-byte cap (' . $size . ' bytes)');
ok($size < SMPRO_SPQ_MAX_BYTES, 'U1: and smaller than the new one');
$r = smpro_spq_read($me, $home);
is_eq(count($r), 1, 'U1: the worker reads it');
is_eq($r[0]['reject'] ?? '', '', 'U1: with nothing to reject');
is_eq(count($r[0]['items']), 200, 'U1: and every one of the 200 items arrives');
@unlink($p);

/* ---------- U2: a genuinely oversized file is ANSWERED, not dropped ---------- */
$p = t75_req($rq, 'aaaaaaaaaaaaaaa2', array_fill(0, 2000, str_repeat('x', 60)));
ok(filesize($p) > SMPRO_SPQ_MAX_BYTES, 'U2: the fixture exceeds the cap');
$r = smpro_spq_read($me, $home);
is_eq(count($r), 1, 'U2: the worker still returns it');
has((string)$r[0]['reject'], 'too large', 'U2: marked as rejected, with the reason the customer will read');
is_eq($r[0]['items'], [], 'U2: and carrying nothing that could be acted on');
@unlink($p);

/* ---------- U3: unreadable and unknown-verb files are answered too ---------- */
file_put_contents($rq . '/aaaaaaaaaaaaaaa3.json', '{not json');
$r = smpro_spq_read($me, $home);
has((string)($r[0]['reject'] ?? ''), 'could not be read', 'U3: malformed JSON is answered');
@unlink($rq . '/aaaaaaaaaaaaaaa3.json');
file_put_contents($rq . '/aaaaaaaaaaaaaaa4.json', json_encode(['verb' => 'format_disk']));
$r = smpro_spq_read($me, $home);
has((string)($r[0]['reject'] ?? ''), 'not something', 'U3: an unknown verb is answered, never executed');
is_eq($r[0]['verb'], 'format_disk', 'U3: and the verb it asked for is kept for the audit line');
@unlink($rq . '/aaaaaaaaaaaaaaa4.json');

/* ---------- U4: a hostile shape is still skipped WITHOUT a trace ---------- */
// The answer is written into the account's directory. A symlink there must never make root write anywhere.
$target = SMPRO_VARLIB . '/t75_elsewhere.json';
file_put_contents($target, json_encode(['verb' => 'apply_fast']));
@symlink($target, $rq . '/aaaaaaaaaaaaaaa5.json');
if (is_link($rq . '/aaaaaaaaaaaaaaa5.json')) {
    // This FAILED when first run: the reader tested one bit of the mode (0100000) and a symlink (0120000) has
    // it set, so the link passed as a regular file and root read whatever it pointed at.
    is_eq(smpro_spq_read($me, $home), [], 'U4: a symlinked request is ignored, not answered');
    @unlink($rq . '/aaaaaaaaaaaaaaa5.json');
} else {
    ok(true, 'U4: (symlinks unavailable here - skipped)');
}
@unlink($target);
file_put_contents($rq . '/not-our-naming.json', json_encode(['verb' => 'apply_fast']));
is_eq(smpro_spq_read($me, $home), [], 'U4: a file outside the page\'s own naming is ignored');
@unlink($rq . '/not-our-naming.json');

/* ---------- U5: the run loop answers a rejected request instead of running it ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
has($src, "(\$req['reject'] ?? '') !== ''", 'U5: the run loop looks at the rejection');
has($src, "'msg' => (string)\$req['reject']", 'U5: and hands the reason back as the answer');
hasnt($src, "if ((int)\$ls['size'] > 4096) continue;", 'U5: the silent 4,096-byte skip is gone');
ok(SMPRO_SPQ_MAX_BYTES >= 200 * 300, 'U5: the cap is sized from the page\'s own ceiling (200 items), not a guess');
