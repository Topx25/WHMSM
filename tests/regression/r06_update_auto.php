<?php
/**
 * r06_update_auto.php — closes the t14/r01 upd_auto skips. The unsigned /api/version COMMAND channel must
 * NOT be able to waive the downgrade guard or replay-churn the fleet:
 *   R05 — a forged "update" command calls smpro_upd_apply($ver, force=FALSE) — it can only move forward to a
 *         genuinely-signed newer build, never roll back onto a signed-but-vulnerable one.
 *   R06 — a command id already processed is NOT re-run (cmd_seen dedup ring) on a replayed /api/version response.
 *
 * Mechanism: load license.php WITHOUT smpro_lic_api and update.php WITHOUT smpro_upd_apply (funcs_except),
 * then provide our own stub (canned commands) + spy (records the force arg) — no network, no real apply.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';

/* stub the network license API (returns a forged "update" command) + capture acks */
$GLOBALS['__lic_resp'] = [200, ['ok' => true, 'version' => '1.0.50', 'commands' => [['id' => 1, 'command' => 'update', 'args' => '1.0.50']]]];
$GLOBALS['__acks'] = [];
function smpro_lic_api($path, $payload = [], $timeout = 15) {
    if ($path === '/api/command-ack') { $GLOBALS['__acks'][] = $payload; return [200, ['ok' => true]]; }
    return $GLOBALS['__lic_resp'];
}
/* spy for the destructive applier — records (version, force); never touches files/network */
$GLOBALS['__applies'] = [];
function smpro_upd_apply($version = '', $force = false) { $GLOBALS['__applies'][] = ['version' => $version, 'force' => $force]; return ['ok' => true, 'to' => $version]; }

smpro_plugin_funcs_except('includes/license.php', ['smpro_lic_api']);
smpro_plugin_funcs_except('includes/update.php', ['smpro_upd_apply']);

ok(function_exists('smpro_upd_auto') && function_exists('smpro_upd_check'), 'update.php loaded (auto/check) with smpro_upd_apply excluded');
ok(function_exists('smpro_lic_payload'), 'license.php loaded with smpro_lic_api excluded');

/* sanity: the stub drives upd_check */
$chk = smpro_upd_check();
is_eq($chk['ok'] ?? null, true, 'upd_check: stubbed /api/version -> ok');
is_eq($chk['latest'] ?? null, '1.0.50', 'upd_check: reports the stubbed latest');
is_eq(count($chk['commands'] ?? []), 1, 'upd_check: surfaces the queued command');

/* ---------- R05 — forged "update" command applies with force=FALSE ---------- */
$cfg = smpro_upd_cfg(); $cfg['last_check'] = 0; smpro_upd_cfg_save($cfg);   // the sanity upd_check() above stamped last_check; clear it so auto isn't throttled
$GLOBALS['__applies'] = [];
smpro_upd_auto();
is_eq(count($GLOBALS['__applies']), 1, 'R05 upd_auto: the forged update command triggered exactly one apply');
is_eq($GLOBALS['__applies'][0]['force'] ?? null, false, 'R05 upd_auto: force=FALSE — an unsigned command can NEVER waive the downgrade guard');
is_eq($GLOBALS['__applies'][0]['version'] ?? null, '1.0.50', 'R05 upd_auto: applied the commanded version (forward-only, guard still enforced inside apply)');
ok(count($GLOBALS['__acks']) >= 1, 'R05 upd_auto: the command was acked back to the server');

/* ---------- R06 — the same command id is NOT re-run (dedup ring) ---------- */
$cfg = smpro_upd_cfg(); $cfg['last_check'] = 0; smpro_upd_cfg_save($cfg);   // bypass the 10-min poll throttle
$GLOBALS['__applies'] = [];
smpro_upd_auto();
is_eq(count($GLOBALS['__applies']), 0, 'R06 upd_auto: command id 1 already in cmd_seen -> NOT re-applied (no replay churn)');

/* a NEW command id IS processed (proves the dedup is per-id, not a blanket stop) */
$GLOBALS['__lic_resp'] = [200, ['ok' => true, 'version' => '1.0.50', 'commands' => [['id' => 2, 'command' => 'update', 'args' => '1.0.50']]]];
$cfg = smpro_upd_cfg(); $cfg['last_check'] = 0; smpro_upd_cfg_save($cfg);
$GLOBALS['__applies'] = [];
smpro_upd_auto();
is_eq(count($GLOBALS['__applies']), 1, 'R06 upd_auto: a NEW command id 2 IS applied (dedup is per-id)');
is_eq($GLOBALS['__applies'][0]['force'] ?? null, false, 'R06 upd_auto: still force=FALSE on the new command');

/* ---------- throttle: within 10 min of a check, upd_auto is a no-op ---------- */
$cfg = smpro_upd_cfg(); $cfg['last_check'] = time(); smpro_upd_cfg_save($cfg);
$GLOBALS['__applies'] = [];
smpro_upd_auto();
is_eq(count($GLOBALS['__applies']), 0, 'upd_auto: throttled within 10 min of last_check (no repeated polling)');
