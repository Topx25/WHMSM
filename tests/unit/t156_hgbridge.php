<?php
require __DIR__ . '/../support/bootstrap.php';
define('SMPRO_HG_DIR', SMPRO_VARLIB . '/hostguard-test');
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/hgbridge.php';
/** t156 - the HostGuard bridge: policy out, blocks ledger, lock ownership, events in with a decision. */
@mkdir(SMPRO_VARLIB, 0700, true);
ok(smpro_hg_policy_write(true), 'B1: policy.json is written');
$pol = smpro_hg_policy_read();
ok(is_array($pol) && ($pol['format'] ?? '') === 'hostguard-bridge/1' && ($pol['written_by'] ?? '') === 'smpro', 'B1: ...in the shared format, signed smpro');
ok(smpro_hg_policy_write() === false, 'B2: unchanged policy is not rewritten');
ok(smpro_hg_block_record('203.0.113.9', 'block', 'Intrusion Monitor', 'example.test'), 'B3: a block is recorded');
$rs = smpro_hg_blocks_read('203.0.113.9'); ok(count($rs) === 1 && $rs[0]['product'] === 'smpro' && $rs[0]['action'] === 'block', 'B3: ...and read back');
ok(smpro_hg_blocked_by_others('203.0.113.9') === null, 'B4: our own record is not "another product"');
file_put_contents(smpro_hg_blocks_path(), json_encode(['ts' => time(), 'product' => 'wpguard', 'action' => 'block', 'ip' => '203.0.113.10', 'rule' => 'injection', 'site' => 'x.test']) . "\n", FILE_APPEND);
$o = smpro_hg_blocked_by_others('203.0.113.10'); ok(is_array($o) && $o['product'] === 'wpguard', 'B4: another product\'s block is seen');
ok(smpro_hg_locks_write('acct', ['/home/acct/public_html/index.php']), 'B5: our lock list is written');
@mkdir(smpro_hg_locks_dir('acct'), 0755, true);
file_put_contents(smpro_hg_locks_dir('acct') . '/wpguard.json', json_encode(['product' => 'wpguard', 'paths' => ['/home/acct/public_html/wp-config.php', '/home/acct/public_html/wp-content/uploads']]));
ok(smpro_hg_lock_owner('acct', '/home/acct/public_html/wp-config.php') === 'wpguard', 'B6: the owner of a locked file is known');
ok(smpro_hg_lock_owner('acct', '/home/acct/public_html/wp-content/uploads/a.php') === 'wpguard', 'B6: ...and of anything under a locked folder');
ok(smpro_hg_lock_owner('acct', '/home/acct/public_html/index.php') === '', 'B6: our own path has no other owner');
ok(smpro_hg_release_request('acct', 'test', ['wpguard']) && is_file(smpro_hg_locks_dir('acct') . '/release-wpguard.json'), 'B7: a release request is written for the owner');
ok(smpro_hg_event_emit('block_lifted', ['ip' => '203.0.113.10']), 'B8: we can emit an event');
@mkdir(smpro_hg_events_dir('wpguard'), 0755, true);
file_put_contents(smpro_hg_events_dir('wpguard') . '/1000000000-aaaaaaaa.json', json_encode(['format' => 'hostguard-bridge/1', 'product' => 'wpguard', 'ts' => 1000000000, 'type' => 'attack', 'ip' => '203.0.113.11', 'site' => 'x.test', 'rule' => 'injection', 'action_wanted' => 'report']));
$n = smpro_hg_events_ingest(); ok(($n['seen'] ?? 0) === 1, 'B9: another product\'s event is read once');
$n2 = smpro_hg_events_ingest(); ok(($n2['seen'] ?? 0) === 0, 'B9: ...and not again (cursor)');
ok(is_file(smpro_hg_events_dir('wpguard') . '/1000000000-aaaaaaaa.json'), 'B10: the other product\'s file is never deleted by us');
$ev = smpro_hg_events_for_ip('203.0.113.11'); ok(count($ev) === 1 && $ev[0]['decision'] === 'noted' && $ev[0]['from'] === 'wpguard', 'B11: the IP report can read what was reported');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/hgbridge.php'));
has($src, "if (\$rs === 'core_protected' || \$allowed || (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare(\$ip))) {", 'B12: a block request on a customer, allow-listed or infrastructure address is declined');
has($src, "smpro_hg_event_emit('block_declined', ['ip' => \$ip, 'to' => \$e['product'], 'why' =>", 'B12: ...and the sender is told why');
$lg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/login_guard.php'));
has($lg, "if (function_exists('smpro_hg_tick')) { try { smpro_hg_tick(); }", 'B13: the minute worker runs the bridge');
// the lab syncs the shipped tree without docs/; where docs/ exists the contract must be there and name the format
$doc = SMPRO_BASE . '/docs/HOSTGUARD-BRIDGE.md';
ok(!is_dir(SMPRO_BASE . '/docs') || (is_file($doc) && strpos((string)file_get_contents($doc), 'hostguard-bridge/1') !== false), 'B14: the contract is documented for the other products');
has($src, "The full format is in docs/HOSTGUARD-BRIDGE.md.", 'B14: ...and the engine points at it');
