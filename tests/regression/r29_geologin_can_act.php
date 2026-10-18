<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/**
 * r29_geologin_can_act.php — a feature that cannot act must not call itself armed.
 *
 * Country Login Lock shipped with NO execution path at all. smpro_gl_run() was reachable from exactly one
 * place — the page's "Check the last hour" button — and that button sends dryrun=1, because a check must never
 * write. Nothing installed a cron. So no rule could ever be written, however the lock was configured.
 *
 * It was found the only way a thing like this ever is: an operator armed it (enabled=true, dryrun=false,
 * countries EG+SA, SSH and WHM both ticked), signed in over a French VPN, was let straight in — and
 * /etc/csf/csf.deny contained ZERO of its rules. Not a rule that failed to apply. A rule that was never written,
 * and never could have been.
 *
 * This is the product's own failure class turned on itself: something reporting that it is working while doing
 * nothing. These assertions exist so it cannot come back.
 */

/* ---------- R1: something other than a button can run it ---------- */
ok(is_file(SMPRO_BASE . '/bin/geologin_tick.php'), 'R1: there is a worker, so the lock does not depend on a person being on the page');
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geologin_tick.php'));
has($tick, 'smpro_gl_run(false)', 'R1: and the worker does NOT force dry run — the saved setting decides');
hasnt($tick, 'modules/', 'R1: it never loads a page module, so cron can actually require it');

/* ---------- R2: a schedule is installed, and removed with the setting ---------- */
$gl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
has($gl, 'function smpro_gl_cron_sync', 'R2: there is a cron sync');
has($gl, "if (empty(\$cfg['enabled'])) { if (@is_file(\$f)) @unlink(\$f); return true; }",
    'R2: turning the lock off removes the schedule');
$i = strpos($gl, '@rename($t, SMPRO_GL_CFG)');
$j = strpos($gl, 'smpro_gl_cron_sync();');
ok($i !== false && $j !== false && $j > $i, 'R2: saving installs it, so arming is not just a label');

/* ---------- R3: the check button still never writes ---------- */
// The reason the lock could not act was that its only caller forced dry run. That caller must KEEP forcing it —
// a "check" that silently blocks would be its own, worse bug. The fix is a second path, not a changed one.
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fw, "fd.set('fw_action','gl_scan'); fd.set('dryrun','1');", 'R3: the page check still writes nothing');

/* ---------- R4: the badge reports capability, not intent ---------- */
ok(function_exists('smpro_gl_active_really'), 'R4: there is a way to ask whether the lock can actually act');
has($fw, 'smpro_gl_active_really', 'R4: and the page asks it before showing ARMED');
has($fw, "'ARMED' : (\$glOn ? 'not acting' : 'off')",
    'R4: an enabled lock that cannot act says "not acting", not "ARMED"');

$r = smpro_gl_active_really();
ok(is_array($r) && array_key_exists('ok', $r) && array_key_exists('why', $r), 'R4: it answers with a reason, not just a boolean');
if (empty($r['ok'])) isnt_eq(trim((string)$r['why']), '', 'R4: and when it cannot act, the reason is not empty');

/* ---------- R5: each reason it cannot act is a distinct, actionable sentence ---------- */
foreach ([
    'the worker is missing'      => 'a build that shipped without the worker',
    'no scheduled run'           => 'armed but never scheduled — the exact state found on the live server',
    'dry run'                    => 'deliberately reporting only',
] as $needle => $case) {
    has($gl, $needle, 'R5: it distinguishes "' . $case . '"');
}
