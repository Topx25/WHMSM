<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t92_perf_memo.php — the render-time fixes: smpro_memo caches per key/ttl and never caches a failure; cPHulk is
 * read from the switch file; no render path calls the two WHM API commands that took seconds inside a CGI.
 */
$n = 0;
$v1 = smpro_memo('t92_a', 60, function () use (&$n) { $n++; return ['x' => 1]; });
$v2 = smpro_memo('t92_a', 60, function () use (&$n) { $n++; return ['x' => 2]; });
is_eq($v1, ['x' => 1], 'U1: first call computes'); is_eq($v2, ['x' => 1], 'U1: second call is served from the memo'); is_eq($n, 1, 'U1: the collector ran once');
$v3 = smpro_memo('t92_a', 60, function () use (&$n) { $n++; return ['x' => 3]; }, true);
is_eq($v3, ['x' => 3], 'U1: fresh=true recomputes'); is_eq($n, 2, 'U1: ...and ran the collector again');
$f = SMPRO_CACHE . '/memo_t92_a.json'; ok(is_file($f), 'U1: the memo lives under the product cache dir'); touch($f, time() - 120);
smpro_memo('t92_a', 60, function () use (&$n) { $n++; return ['x' => 4]; }); is_eq($n, 3, 'U1: an expired memo is recomputed');
$m = 0; smpro_memo('t92_b', 60, function () use (&$m) { $m++; return null; }); smpro_memo('t92_b', 60, function () use (&$m) { $m++; return null; });
is_eq($m, 2, 'U2: a null result is never cached - a failed collection is retried, not remembered');
is_eq(smpro_memo('t92_c', 60, fn() => 'str'), 'str', 'U2: scalars work'); is_eq(smpro_memo('t92_c', 60, fn() => 'other'), 'str', 'U2: ...and are served back');
$h = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($h, "'/var/cpanel/hulkd/enabled'", 'U3: cPHulk is read from the switch file');
foreach (['modules/security-health.php', 'includes/compcheck.php'] as $f2) {
    $s = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f2));
    has($s, 'smpro_cphulk_enabled', 'U3: ' . $f2 . ' uses it');
}
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/security-health.php'));
hasnt($sh, "shell_exec('timeout 15 /usr/local/cpanel/bin/whmapi1 --output=json cphulk_status", 'U3: the 12-second call is gone from Security Health');
$cc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
has($cc, "/var/cpanel/authn/api_tokens_v2/whostmgr/root.json", 'U4: root tokens from the file');
hasnt($cc, "shell_exec('timeout 8 find", 'U4: the ransomware sweep no longer forks find');
has($cc, "substr(\$e, -6) === '.sorry'", 'U4: ...it walks in PHP');
$ar = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/analytics.php'));
has($ar, "smpro_memo_cmd('ar_' . sha1(\$cmd), 600", 'U5: analytics counts are memoised per command text (which carries the window)');
hasnt($ar, "(int)trim(smpro_ar_sh(\$rd(", 'U5: no count bypasses the memo');
/* ---------- U6: the marker walk is bounded and says when it skipped ---------- */
has($cc, "\$perDir = 3000; \$total = 30000;", 'U6: per-directory and total entry bounds');
has($cc, "a directory too large to read fully was skipped past its first entries", 'U6: ...and the finding says so rather than reading like a full sweep');
has($cc, "smpro_memo('im_config_show', 300", 'U6: Imunify config is memoised five minutes');
$cx = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/ccfix.php'));
has($cx, "@unlink(SMPRO_CACHE . '/memo_im_config_show.json');", 'U6: ...and dropped by the fix that changes it');
$tu = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/tuning.php'));
has($tu, "smpro_tun_ver('imunify360-agent version 2>&1 | head -1')", 'U7: Server Tune-up memoises the Imunify version');
has($tu, "smpro_tun_ver('csf -v 2>&1 | head -1')", 'U7: ...and the CSF version');
/* ---------- U8: the audit pages no longer render what the browser does not need ---------- */
$ui = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/user-investigation.php'));
hasnt($ui, '<tr class="ui-detrow" data-i="<?= $i ?>"', 'U8: User Investigation renders no detail row per event');
has($ui, 'function uiBuildDet(i)', 'U8: ...the detail is built in the browser from EV when asked');
has($ui, "var SRC = <?= json_encode(array_map(fn(\$m) => \$m[0], \$srcMeta)", 'U8: ...with the source labels it needs');
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/forensics-audit.php'));
hasnt($fa, "faRem\" type=\"button\"\n              data-act=", 'U8: the finding\'s data is not duplicated on its button');
has($fa, "var tr=b.closest('tr'); if(!tr)return;   // the finding's data lives once, on its row", 'U8: ...the handler reads it from the row');
has($fa, "id=\"faFindPager\"", 'U8: the findings table is paged');
has($fa, "var fPage=0, fPER=60", 'U8: ...60 per page');
/* ---------- U9: server-side rows are gone; the browser builds one page at a time ---------- */
$ui = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/user-investigation.php'));
hasnt($ui, '<tr class="ui-row" data-i="<?= $i ?>"', 'U9: User Investigation renders no event row server-side');
has($ui, 'function uiBuildRow(i)', 'U9: ...the browser builds them'); has($ui, "IDX.slice(page*PER,(page+1)*PER).forEach(function(i){ frag.appendChild(uiBuildRow(i)); })", 'U9: ...one page at a time from the filtered index');
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/forensics-audit.php'));
hasnt($fa, "<?php foreach (\$findings as \$fi => \$f): \$c = \$sevcls", 'U9: Forensics renders no finding row server-side');
has($fa, 'var FIND = <?= json_encode(array_values(array_map(', 'U9: ...the findings travel as JSON');
has($fa, 'function fBuildRow(idx)', 'U9: ...and are built per page');
has($fa, "function fChecked(){var out=[];for(var i=0;i<FIND.length;i++)if(fSel[i])out.push(fRowFor(i));return out;}", 'U9: bulk selection covers every finding, rendered or not');
has($fa, "var tr=(typeof FIND!=='undefined'&&FIND[idx])?fRowFor(idx):null;", 'U9: an AI decision finds its finding even when it is not on the current page');
has($fa, "'raw' => (\$f['raw'] ?? '') !== '' ? base64_encode((string)\$f['raw']) : ''", 'U9: the raw line is carried base64 for the actions, as the row attribute was');
/* ---------- U10: the rules card says when it saved, and names a failure ---------- */
$aa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($aa, 'id="bfrSaved"', 'U10: an inline saved indicator beside the button');
has($aa, "sv.textContent=ok?('\\u2713 Saved '+new Date().toLocaleTimeString()+' \\u00b7 rules '+st):'not saved';", 'U10: ...that says when and in which state');
has($aa, "the server answered HTTP '+r.status+' without a result", 'U10: a non-JSON answer is reported with its status, not swallowed');
has($aa, "The rules are saved but OFF - tick", 'U10: saving with the switch off says so');
/* ---------- U11: the rules-card script is emitted WITH the card, not after a return that skips it ---------- */
$aa2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
$card = strpos($aa2, 'id="bfrOut"'); $js = strpos($aa2, "getElementById('bfrSave').addEventListener"); $ret = strpos($aa2, "<?php if (\$aaTab === 'bruteforce'): smpro_aa_bf_render(");
ok($card !== false && $js !== false && $ret !== false && $js > $card && $js < $ret, 'U11: the Save handler sits inside the card, before the footer-and-return of the tab');
has($aa2, "var AA_CSRF = <?= json_encode(smpro_csrf_generate('aa_delete')) ?>;", 'U11: ...with its own token (the shared one is defined after that return too)');
