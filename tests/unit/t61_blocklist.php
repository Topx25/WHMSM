<?php
/**
 * t61_blocklist.php — the shared block-list, and the two promises that make it safe to ship.
 *
 * A pooled block-list is the one feature where somebody else's mistake becomes your outage. So:
 *   1. SCOPE. It carries illegitimate bots only — addresses on datacenter / cloud / hosting networks. Nobody signs
 *      in to a control panel from a rented server, so a rented server failing logins is a machine. A residential,
 *      office or mobile address is never pooled: one of those can be a hundred customers behind one connection.
 *   2. CONSENT. Nothing is blocked without a review the operator saw, and nothing leaves this server unless
 *      sharing was switched on AND the operator pressed send. What would be sent can be shown first, in full.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/fwblock.php');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fwblock.php'));
$pg  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));

/* ---------- B1: a feed is remote input, and it is treated as such ---------- */
ok(function_exists('smpro_fw_block_fetch_raw'), 'B1: the fetch exists');
$feed = ['fetch' => [], 'json' => 'addresses', 'min_servers' => 3];
is_eq(smpro_fw_block_fetch_raw($feed), [], 'B1: no source URL, no rows');
has($src, "if (stripos(\$u, 'https://') !== 0 || filter_var(\$u, FILTER_VALIDATE_URL) === false) continue;", 'B1: https only, and the URL comes from a constant this build carries — never from a request');
has($src, "if (\$body === '' || strlen(\$body) > 8 * 1024 * 1024) continue;", 'B1: a feed that is really a download is refused');
has($src, 'if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;', 'B1: every entry must be an address');
has($src, 'FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE', 'B1: ...a public one — a feed cannot make a server block its own LAN');
has($src, 'if ($n < $min) continue;', 'B1: one server having blocked an address is not evidence');
has($src, "if (is_array(\$e) && isset(\$e['machine']) && empty(\$e['machine'])) continue;", 'B1: an entry the feed itself marks as not-a-machine is dropped');
has($src, 'count($rows) >= 50000', 'B1: and the list cannot grow without bound');

/* ---------- B2: SCOPE — machines only, decided here, not by the feed ---------- */
ok(function_exists('smpro_fw_block_is_machine'), 'B2: this server decides for itself what is a machine');
has($src, "if (!is_array(\$in) || ((\$in['provider'] ?? '') === '' && (\$in['asn'] ?? '') === '')) return false;",
    'B2: an address we cannot classify counts as a PERSON\'s — the careful direction, since it fails towards leaving it alone');
has($src, 'if (!smpro_fw_block_is_machine($ip)) { $out[\'human\'][] = $r; $out[\'checked\']++; continue; }',
    'B2: the review re-checks every address against THIS server\'s intelligence, even though the feed filtered already');
has($src, "if (!smpro_fw_block_is_machine(\$ip)) continue;                 // a person's address is this server's business",
    'B2: and a person\'s address is never shared either');
has($src, 'illegitimate bots that tried to break in, and nothing else', 'B2: the scope is written down where the code is');

/* the classifier the scope rests on, exercised directly */
ok(smpro_ip_is_datacenter(['provider' => 'GOOGLE-CLOUD-PLATFORM - Google LLC', 'asn' => 'AS15169']), 'B2: a cloud provider is a machine');
ok(smpro_ip_is_datacenter(['provider' => 'DIGITALOCEAN-ASN - DigitalOcean, LLC', 'asn' => 'AS14061']), 'B2: ...so is DigitalOcean');
ok(!smpro_ip_is_datacenter(['provider' => 'Example Telecom Residential Broadband', 'asn' => 'AS64500']), 'B2: a home ISP is not');
ok(!smpro_ip_is_datacenter(['provider' => '', 'asn' => '']), 'B2: and nothing known is not');

/* ---------- B3: a verified crawler is refused whatever the list says ---------- */
has($src, "if (!function_exists('smpro_bg_crawler_shield')) { \$bg = __DIR__ . '/botguard.php'; if (@is_file(\$bg)) require_once \$bg; }",
    'B3: the shield is pulled in, not hoped for');
has($src, "if (!empty(\$cs['crawler'])) { \$out['crawler'][] =", 'B3: a real crawler in a feed goes to its own bucket, never to add');
has($src, "if (!array_key_exists(\$ip, \$rdns) && \$rdns !== []) { \$out['complete'] = false; continue; }",
    'B3: an address the resolver did not reach is NOT treated as "no reverse DNS" — a slow resolver must not become a blocked crawler');
has($src, "smpro_bg_crawler_shield(\$ip)['crawler'])) continue;", 'B3: and a crawler is never shared either');

/* ---------- B4: the operator's own decisions outrank the pool ---------- */
has($src, "if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers(\$ip) !== '') { \$out['allowed'][] = \$r;",
    'B4: anything this server allow-listed is skipped');
has($src, "if (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted(\$ip)) { \$out['allowed'][] = \$r;",
    'B4: ...by either allow-list');
has($src, "if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers(\$ip) !== '') continue;",
    'B4: and telling the pool to block what we ourselves trust would be exporting a mistake');

/* ---------- B5: nothing is applied that the operator has not seen ---------- */
has($src, '$rev = smpro_fw_block_review($key);', 'B5: apply runs the review first');
has($src, 'smpro_fw_block_fetch($key);                                  // review what is current', 'B5: against a fresh fetch, not last week\'s cache');
has($src, "\$res = function_exists('smpro_fw_block_ip') ? smpro_fw_block_ip(\$r['ip'], \$marker) : ['ok' => false];",
    'B5: each address goes through the same chokepoint a button press uses — a feed gets no privileges a person does not have');
has($pg, "disabled title=\"Review first", 'B5: and Add is disabled until a review has run');
has($pg, 'add.disabled = !n.add;', 'B5: ...enabled only by a review that found something to add');

/* ---------- B6: reversible, exactly ---------- */
has($src, "if (strpos(\$l, \$marker) !== false && preg_match('/^\\s*([0-9a-fA-F:.]+)/', \$l, \$m)) { \$ours[] = \$m[1]; continue; }",
    'B6: undo removes only lines carrying this list\'s marker');
has($src, 'foreach ($ours as $ip) if (function_exists(\'smpro_csf_denied\') && smpro_csf_denied($ip)) $still++;',
    'B6: and reports what really left the file rather than what it tried to remove');
has($src, "'stuck' => \$still", 'B6: including what it could not');

/* ---------- B7: CONSENT — nothing leaves without it ---------- */
is_eq(smpro_fw_block_cfg()['contribute'], false, 'B7: sharing is OFF on a server that has never been asked');
$off = smpro_fw_block_contribute();
ok($off['ok'] === false && $off['sent'] === 0, 'B7: and contributing with it off sends nothing');
has($off['msg'], 'nothing is ever sent without that', 'B7: ...and says so');
has($src, "if (!smpro_fw_block_contributing())", 'B7: the guard is the first thing the upload does');
has($pg, "=== 'bl_share_preview'", 'B7: the exact payload can be shown before it is sent');
has($pg, 'This is the whole payload. No hostname, no domain, no account name and no log line is part of it.',
    'B7: and the page states what is NOT in it');
has($pg, "if(!confirm('Share these addresses with the pool?", 'B7: sending is still a deliberate press after that');
has($src, "smpro_audit('firewall_blocklist_contribute'", 'B7: every upload is recorded locally');

/* ---------- B8: what is built to be sent carries nothing identifying ---------- */
has($src, "\$out[\$ip] = ['ip' => \$ip, 'kind' => \$kind, 'machine' => true];",
    'B8: an entry is an address and a door — there is no field for anything else');
has($src, 'never the comment itself, which on a', 'B8: the firewall comment is NOT sent — on a cPanel server it names the account and the domain');
has($src, "if (strpos(\$l, \$mineMarker) !== false) continue;", 'B8: and what the pool gave us is never echoed back to it as if we had found it');
foreach (['ssh', 'panel', 'mail', 'ftp', 'web', 'other'] as $kind)
    has($src, "'" . $kind . "'", 'B8: the door "' . $kind . '" is one of a fixed set, not free text from a log');
