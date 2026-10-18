<?php
/**
 * t40_license_kill_guards.php — the kill-switch must be SOFT/REVERSIBLE/NON-DESTRUCTIVE and must
 * NEVER fire spuriously (catalog I02/I03/I04, S05). The anti-piracy stop only escalates to a real
 * removal after a CONFIRMED tamper persists past 24h; a clean install must do nothing.
 *
 * SAFETY: `rm`/`nohup`/`unregister_appconfig` are recording PATH shims, so even if a guard were
 * wrong, no real deletion happens — and we ASSERT the rm recorder stayed empty (the proof the
 * destructive path was never reached). The positive "it fires when overdue" path needs a fully
 * sandboxed BASE/VARLIB harness and is deferred (tap_skip) — we will not risk rm -rf on a live box.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_TEST_SRC . '/tests/support/lic_sign.php';

$kp = smpro_test_keypair();
define('SMPRO_LIC_PUBKEY', $kp['pub']);
require SMPRO_TEST_BUILD . '/includes/license.php';

ok(defined('SMPRO_LIC_ENFORCE') && SMPRO_LIC_ENFORCE === true, 'enforce is ON (kill paths active, not short-circuited)');

/* ---------- I04 / S08 — self_uninstall on a CLEAN state does nothing ---------- */
smpro_test_rec_reset('rm');
smpro_test_rec_reset('nohup');
$GLOBALS['_smpro_lic_state'] = [];                              // no tamper_at / tlm_at
is_eq(smpro_lic_tamper_at(), 0, 'clean state: tamper_at = 0');
is_eq(smpro_lic_tlm_at(), 0, 'clean state: tlm_at = 0');
is_eq(smpro_self_uninstall(), false, 'I04 self_uninstall(clean state) -> false (guards refuse)');
ok(smpro_test_rec_empty('rm'), 'I04 self_uninstall: rm was NEVER invoked (destructive path not reached)');
ok(smpro_test_rec_empty('nohup'), 'I04 self_uninstall: nohup (detached rm -rf) NEVER invoked');

/* ---------- I03 — kill_tick on a clean state never uninstalls ---------- */
smpro_test_rec_reset('rm');
smpro_lic_kill_tick();
ok(smpro_test_rec_empty('rm'), 'I03 kill_tick(clean state) -> no self-uninstall (rm untouched)');

/* a RECENT tamper (< 24h) must also NOT fire yet (graduated, not instant) */
smpro_test_rec_reset('rm');
$GLOBALS['_smpro_lic_state'] = ['tamper_at' => time() - 3600];  // 1h ago — well under the 24h kill window
is_eq(smpro_self_uninstall(), false, 'I03 self_uninstall: tamper only 1h old (< 24h) -> false (not yet due)');
ok(smpro_test_rec_empty('rm'), 'I03 recent tamper: rm still untouched (24h grace honored)');

/* ---------- S05 — an UNSIGNED network "revoke" must NOT blank state ---------- */
$GLOBALS['_smpro_lic_state'] = ['key' => 'TESTKEY', 'status' => 'active', 'raw' => ['license' => ['payload' => ['x' => 1]]]];
$before = smpro_lic_state();
smpro_lic_run_command(['command' => 'revoke', 'id' => 'c1'], 'TESTKEY');
is_eq(smpro_lic_state(), $before, 'S05 run_command(unsigned revoke) -> state NOT blanked (revocation only via signed status)');

/* an unknown command is a no-op and never destructive */
smpro_test_rec_reset('rm');
smpro_lic_run_command(['command' => 'wipe_everything', 'id' => 'c2'], 'TESTKEY');
ok(smpro_test_rec_empty('rm'), 'I02 run_command(unknown op) -> no destructive action');

/* positive destructive path (tamper overdue -> actually uninstalls) — deferred for safety */
tap_skip('self_uninstall positive fire (tamper > 24h -> rm)', 'needs fully-sandboxed BASE/VARLIB harness; deferred (Phase 4b)');
