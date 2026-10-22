<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t146_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/lvelimits.php';
/** t146 - beta354: the Resource Limit page searches by account OR domain, pages itself, bulk-runs on a selection
 *  and says what to do per row; "Remove all frozen" purges the whole queue through exiqgrep and reports the count
 *  read back from the queue. */
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/resource-limits.php'));
$lv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/lvelimits.php'));
$sp = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/spam-phishing.php'));
hasnt($pg . $lv, 'efadh', 'N1: no customer name');

// A. the advice is chosen from the facts and names the button
$a = smpro_lv_advice(['ep_f' => 100], null, 3, false);
is_eq($a['kind'], 'kill', 'A1: hung processes -> end them');
ok(strpos($a['text'], 'Press "End the hung PHP processes": 3 request(s)') === 0, 'A2: ...with the count and the button');
$a = smpro_lv_advice(['ep_f' => 100], ['ep' => 20, 'lep' => 20, 'nproc' => 1, 'lnproc' => 100], 0, false);
is_eq($a['kind'], 'lift', 'A3: at the ceiling, nothing hung -> lift now');
$a = smpro_lv_advice([], ['ep' => 0, 'lep' => 20, 'nproc' => 0, 'lnproc' => 100], 0, true);
is_eq($a['kind'], 'watch', 'A4: lifted and calm -> wait');
$a = smpro_lv_advice(['ep_f' => 6747, 'pmem_f' => 0], ['ep' => 0, 'lep' => 20, 'nproc' => 0, 'lnproc' => 100], 0, false);
is_eq($a['kind'], 'traffic', 'A5: refusals without hung processes -> traffic, not a reset');
ok(strpos($a['text'], 'refused 6747 time(s)') !== false && strpos($a['text'], 'Bot Guard') !== false, 'A6: ...says so and points at Bot Guard');
is_eq(smpro_lv_advice(['pmem_f' => 67, 'ep_f' => 2], null, 0, false)['kind'], 'memory', 'A7: memory');
is_eq(smpro_lv_advice(['nproc_f' => 5], null, 0, false)['kind'], 'procs', 'A8: processes');
is_eq(smpro_lv_advice(['cpu_f' => 38], null, 0, false)['kind'], 'cpu', 'A9: CPU only -> nothing to reset');
is_eq(smpro_lv_advice(['io_f' => 12, 'cpu_f' => 2], null, 0, false)['kind'], 'io', 'A10: I/O');
is_eq(smpro_lv_advice([], null, 0, false)['kind'], 'none', 'A11: nothing');
$w = smpro_lv_explain(['ep_f' => 6747, 'ep_lim' => 20], ['ep' => 0, 'lep' => 20]);
ok(strpos($w, 'the limit of 20 entry processes was refused 6747 time(s)') !== false, 'A12: history wording, not "0 of 20"');

// B. the page: own search (account or domain), own paging, bulk bar, shared pager kept off
has($pg, 'data-nopage="1"', 'B1: the shared auto-pager is kept off this table');
has($pg, "\$needle = strtolower(\$u . ' ' . implode(' ', \$ud));", 'B2: search needle = account + every domain');
has($pg, 'placeholder="search: account or domain (example.com)"', 'B3: the box says what it searches');
has($pg, "if (q && (tr.getAttribute('data-s')||'').indexOf(q) < 0) return false;", 'B4: search is over the needle');
has($pg, "vis.slice(page * size, (page + 1) * size)", 'B5: paging over the filtered rows');
has($pg, '<option value="25">25 / page</option><option value="50">50 / page</option><option value="100">100 / page</option>', 'B6: page sizes');
has($pg, 'rows.forEach(function(tr){ tr.classList.add(\'hide\'); });', 'B7: every row is rendered; paging only hides');
has($pg, '<input type="checkbox" class="lvSel" value="<?= smpro_h($u) ?>">', 'B8: a checkbox per row');
has($pg, 'id="lvAll" title="select every account shown on this page"', 'B9: select all shown');
foreach (['kill_hung', 'lift', 'putback', 'reset'] as $op) has($pg, 'data-bop="' . $op . '"', 'B10: bulk ' . $op);
has($pg, "var u = users[i++]; var args = {user: u}; if (op === 'lift') args.minutes = document.getElementById('lvBulkMin').value;", 'B11: bulk runs one account at a time');
has($pg, '<div class="lv-todo <?= smpro_h($adv[\'kind\']) ?>"><b>What to do:</b>', 'B12: What to do on every row');
has($pg, "smpro_lv_domains_map()", 'B13: domains from cPanel\'s own map');
has($lv, "foreach ((array)@file('/etc/userdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as \$ln) {", 'B14: /etc/userdomains, one read');
has($pg, '<option value="hung">hung processes now</option>', 'B15: kind filter includes hung');

// C. frozen purge: every id through exiqgrep, honest count, finishes after the tab closes
has($sp, 'function smpro_sp_frozen_ids(string $exim): ?array {', 'C1: helper');
has($sp, "\$out = (string)@shell_exec('timeout 120 ' . \$g . ' -z -i 2>/dev/null');", 'C2: exiqgrep -z -i lists every frozen id, no cap');
has($sp, "if (\$g === '') return null;", 'C3: no exiqgrep -> null (parser fallback), never an empty "nothing frozen"');
has($sp, "\$ids = smpro_sp_frozen_ids(\$exim);\n        if (\$ids === null) {", 'C4: purge uses it, falls back to the parser');
has($sp, "@ignore_user_abort(true); @set_time_limit(1800);   // a started purge finishes even if the page is closed", 'C5: finishes after the tab closes');
has($sp, "\$after = smpro_sp_frozen_ids(\$exim); \$left = \$after === null ? 0 : count(\$after); \$n = max(0, \$before - \$left);", 'C6: count read back from the queue');
has($sp, "if (\$left > 0) { echo json_encode(['ok' => false, 'msg' => 'Removed ' . \$n . ' of ' . \$before", 'C7: anything left is reported as not done');
has($sp, "\$allFrozen = smpro_sp_frozen_ids(\$exim); \$total = \$allFrozen === null ? count(\$frozen) : count(\$allFrozen);", 'C8: the preview announces the real total');
has($sp, "echo json_encode(['ok' => true, 'count' => \$total,", 'C9: ...and sends it');
hasnt($sp, "\$n += count(\$chunk);", 'C10: the count is never assumed from what was sent');
