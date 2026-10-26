<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t81_safetylock_approve.php — a release request from an account's Safety Lock can be decided by the operator.
 *
 * THE INCIDENT. Accounts pressed "release" in their cPanel; the page said "Your request reached your host.
 * Nothing has changed yet - they decide". Nobody could decide: the WHM page that shows the pending requests and
 * carries the Approve / Decline action existed only in the other working copy, and the packaged product shipped
 * without it. Every release request on a production server waited for ever, and the operator concluded that
 * Safety Lock "does not release".
 *
 * Locked here: the WHM page dispatches ask_decide and rules_save, renders the pending-requests panel, and its
 * JavaScript sends the decision - all in the copy that is actually built.
 */
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));

/* ---------- U1: the actions are dispatched ---------- */
has($mod, "'ask_decide', 'rules_save'], true)", 'U1: ask_decide and rules_save are accepted by the page');
has($mod, "if (\$act === 'ask_decide') {", 'U1: the decision handler exists');
has($mod, "if (\$act === 'rules_save') {", 'U1: the automatic-approval rules can be saved');

/* ---------- U2: the decision is made ABOVE the per-account check, or it is refused as "Invalid cPanel user" ---------- */
$posDecide = strpos($mod, "if (\$act === 'ask_decide') {");
$posUser   = strpos($mod, "if (!smpro_ph_valid_user(\$u)) { echo json_encode(['ok' => false, 'msg' => 'Invalid cPanel user.']); exit; }");
ok($posDecide !== false && $posUser !== false && $posDecide < $posUser, 'U2: a request names its own target, so it is decided before the account check that would refuse it');

/* ---------- U3: approval does the work the request asked for ---------- */
has($mod, "if ((\$ask['verb'] ?? '') === 'unlock_selected') {", 'U3: a one-hour release touches only the chosen items');
has($mod, "smpro_ph_chattr_many('-i', \$paths);", 'U3: and lifts the immutable flag on all of them in one batch');
has($mod, "\$st[\$target] = ['relock_at' => \$until, 'set' => date('c')];", 'U3: and schedules the re-lock in root\'s own state, not the account\'s');
has($mod, "smpro_ph_force_unprotect(\$target, smpro_ph_profile(\$target),", 'U3: a permanent release goes through force-unprotect, the same path as the operator\'s own button');
has($mod, "smpro_spq_ask_clear(\$target);", 'U3: the request is cleared once decided');

/* ---------- U4: the operator can see the requests and press the buttons ---------- */
has($mod, 'Accounts asking to be released', 'U4: the pending-requests panel renders');
has($mod, 'class="tp-btn danger ph-askdec"', 'U4: with an Approve button');
has($mod, "fa.set('ph_action','ask_decide')", 'U4: whose JavaScript sends the decision');
has($mod, "f.set('ph_action','rules_save')", 'U4: and the rules can be saved from the page');

/* ---------- U5: the functions the handler calls exist in THIS tree's includes ---------- */
foreach (['smpro_spq_asks_all' => 'spqueue.php', 'smpro_spq_ask_clear' => 'spqueue.php', 'smpro_spq_resolve' => 'spqueue.php',
          'smpro_spq_state_save' => 'spqueue.php', 'smpro_spr_save' => 'sprules.php', 'smpro_spr_describe' => 'sprules.php',
          'smpro_spr_login_ip' => 'sprules.php', 'smpro_ph_chattr' => 'phlock.php', 'smpro_ph_locked' => 'phlock.php'] as $fn => $file) {
    $src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/' . $file));
    has($src, 'function ' . $fn . '(', 'U5: ' . $fn . ' is in includes/' . $file);
}

/* ---------- U6: the page can actually see the requests: the router loads the queue and the rules ---------- */
// The panel is guarded by function_exists(), so a missing include renders as "no requests" - which is exactly how
// it shipped. Locked: the router loads both, so the guard can never be silently false on the WHM page.
$idx = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
has($idx, "require __DIR__ . '/includes/spqueue.php';", 'U6: index.php loads the release queue for every page');
has($idx, "require __DIR__ . '/includes/sprules.php';", 'U6: and the approval rules');

/* ---------- U12: the customer's address comes from session_log (successes), not login_log (failures only) ---------- */
require_once SMPRO_BASE . '/includes/sprules.php';
$sb = $GLOBALS['__sandbox']; @mkdir($sb . '/cplogs', 0700, true);
$now = date('Y-m-d H:i:s O');
$old = date('Y-m-d H:i:s O', time() - 3 * 86400);
file_put_contents($sb . '/cplogs/session_log',
    "[$old] info [cpaneld] 5.5.5.5 NEW karim:aaaa address=5.5.5.5,app=cpaneld,creator=karim,method=handle_form_login,path=form,possessed=0\n" .
    "[$now] info [cpaneld] 127.0.0.1 NEW karim:bbbb address=127.0.0.1,app=cpaneld,creator=root,method=create_user_session,path=whm,possessed=0\n" .
    "[$now] info [cpaneld] 41.47.1.2 NEW karim:cccc address=41.47.1.2,app=cpaneld,creator=karim,method=handle_form_login,path=form,possessed=0\n" .
    "[$now] info [cpaneld] 9.9.9.9 NEW karimx:dddd address=9.9.9.9,app=cpaneld,creator=karimx,method=handle_form_login,path=form,possessed=0\n" .
    "[$now] info [cpaneld] 8.8.8.8 NEW karim:eeee address=8.8.8.8,app=cpaneld,creator=karim,method=handle_form_login,path=form,possessed=1\n");
file_put_contents($sb . '/cplogs/login_log',
    "[$now] info [cpaneld] 6.6.6.6 - karim \"POST /login/ HTTP/1.1\" FAILED LOGIN cpaneld: user password incorrect\n");
if (true) {
    is_eq(smpro_spr_login_ip('karim', 24, $sb . '/cplogs/session_log', $sb . '/cplogs/login_log'), '41.47.1.2',
          'U12: the newest form login by the account itself wins - not the 3-day-old one, not root\'s session from 127.0.0.1, not another user with the same prefix, not a possessed session, and never a FAILED line');
    is_eq(smpro_spr_login_ip('karim', 24, $sb . '/cplogs/none', $sb . '/cplogs/login_log'), '',
          'U12: with no session_log and only failures in login_log there is NO address - a failed attempt never sets a location');
    file_put_contents($sb . '/cplogs/login_log', "[$now] info [cpaneld] 7.7.7.7 - karim \"POST /login/ HTTP/1.1\" SUCCESS LOGIN cpaneld\n");
    is_eq(smpro_spr_login_ip('karim', 24, $sb . '/cplogs/none', $sb . '/cplogs/login_log'), '7.7.7.7', 'U12: an older build\'s SUCCESS line in login_log still works as the fallback');
}
$src12 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sprules.php'));
has($src12, "/usr/local/cpanel/logs/session_log", 'U12: session_log is the first source');
has($src12, "if (strpos(\$line, 'possessed=1') !== false) continue;", 'U12: possessed sessions are not the customer');

/* ---------- U13: waiting requests get another look from the rules, every ten minutes, quietly ---------- */
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
has($sq, 'function smpro_spq_retry_pending(): int', 'U13: the retry exists');
has($sq, "if ((\$now - (int)(\$last[\$user] ?? 0)) < 600) continue;", 'U13: ...once per ten minutes per request');
has($sq, "\$r = smpro_spq_try_auto((string)\$user, true);", 'U13: ...as a retry');
has($sq, "if (!\$retry && function_exists('smpro_audit')) {", 'U13: a retry that still waits is not audited again (no noise); a grant audits itself');
$w = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/sp_queue.php'));
has($w, 'smpro_spq_retry_pending()', 'U13: the minute worker runs it');

/* ---------- U15: country presets on the rules card (the operator chooses; nothing is a default) ---------- */
$ph = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($ph, 'class="tp-btn rlPreset"', 'U15: preset buttons exist');
has($ph, 'data-cc="EG, SA, AE, KW, QA, BH, OM, JO, LB, SY, IQ, PS, YE, LY, TN, DZ, MA, SD, MR, SO, DJ, KM"', 'U15: the Arab League preset carries all 22 members');
$sr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sprules.php'));
hasnt($sr, "'countries'      => ['EG'", 'U15: the shipped DEFAULT stays empty - a preset is a click, never a built-in market');

/* ---------- U16: Force unprotect reports what it changed, not what it looked at ---------- */
$ph16 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($ph16, "\$unlocked = count(\$r['changed']); \$already = count(\$r['already']);", 'U16: locks removed and already-clear paths are counted apart');
has($ph16, "'nothing was locked'", 'U16: an account with nothing locked says so');
hasnt($ph16, "\$cleared = (int)\$r['done'];", 'U16: the old count (changed + already clear) is gone');

// beta390: Force unprotect sweeps locks this product did not set, and says what it found
$pl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/phlock.php'));
$ph = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($pl, "function smpro_ph_sweep_attrs(\$u, \$maxDepth = 4, \$seconds = 20) {", 'X1: the sweep exists');
has($pl, "if (strpos(\$flags, 'i') === false && strpos(\$flags, 'a') === false) continue;", 'X2: immutable and append-only flags, nothing else');
has($pl, "if (is_link(\$path) || !smpro_ph_inside(\$u, \$path)) continue;", 'X3: never a symlink, never outside the account');
has($ph, "\$sw = function_exists('smpro_ph_sweep_attrs') ? smpro_ph_sweep_attrs(\$u) :", 'X4: Force unprotect runs it after its own list');
has($ph, "' lock(s) set outside this product removed ('", 'X5: ...and the summary names them');
has($ph, "' · the sweep for other locks did not finish (deep tree); run again'", 'X6: an unfinished sweep is said, never silent');
has($ph, "' root-owned item(s) inside the web root (the account cannot edit them; e.g. '", 'X7: root-owned files are reported');

// beta391: an excluded account is kept free unattended; other accounts are never swept here
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
$sqb = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/sp_queue.php'));
has($sq, "function smpro_spq_keep_free(\$perTick = 3, \$everySeconds = 3600) {", 'Y1: the hourly keep-free pass');
has($sq, "        if ((\$row['scope'] ?? 'all') !== 'all') continue;", 'Y2: only accounts excluded from ALL protection');
has($sq, "        \$sw = smpro_ph_sweep_attrs(\$u, 4, 15);", 'Y3: ...are swept with the bounded sweep');
has($sq, "smpro_ph_audit_log(\$u, 'php_harden_kept_free', \$msg,", 'Y4: ...and what was removed is written to the account log');
has($sqb, "\$kept = function_exists('smpro_spq_keep_free') ? smpro_spq_keep_free() : 0;", 'Y5: the worker runs it every minute (a few accounts per tick)');
