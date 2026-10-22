<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t144 - beta351: the Compromise Check page posts url-encoded (multipart was refused by index.cgi), every cron line
 *  has its own switch-off / remove / put-back with a backup first, the Security Health row button is honest about
 *  what it does, and a Bot Guard group says what network it comes from and which button to press. */
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));
$cx = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/ccfix.php'));
$cc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/security-health.php'));
$bg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
$bi = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));

// A. the encoding mismatch that silenced every account fix
has($ix, "stripos(\$__ct, 'multipart/form-data') !== false", 'A1: index.cgi refuses multipart bodies outright');
hasnt($pg, 'new FormData()', 'A2: the fix request no longer builds a multipart body');
has($pg, "var fd = new URLSearchParams(); fd.append('cc_action','fix')", 'A3: url-encoded body');
has($pg, "headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:fd.toString(), credentials:'same-origin'", 'A4: declared as url-encoded');

// B. cron lines, one choice each, backup first
foreach (['cron_line_off', 'cron_line_rm', 'cron_line_on'] as $op) has($cx, "'" . $op . "'", 'B1: op ' . $op . ' registered');
has($cx, "'sha' => \$sha]],", 'B2: per-line ops take the sha1 of the line, never free text');
has($cx, "\$r = smpro_cx_cron_line(\$a['user'], \$a['sha'], substr(\$op, 10));", 'B3: one handler for the three');
has($cx, "\$bk = smpro_cx_backup(\$cf); if (\$bk === '') return ['ok' => false, 'msg' => 'could not back up the crontab - nothing changed'];", 'B4: no backup, no change');
has($cx, "if (\$n === 0) return ['ok' => false, 'msg' => 'that line is no longer in the crontab (changed since the page was drawn) - nothing changed'];", 'B5: a stale sha changes nothing');
has($cx, "'# SMPRO-OFF ' . \$t", 'B6: switch-off keeps the line as a marked comment');
has($cx, "preg_match('/^#\\s*SMPRO-OFF\\s(.+)\$/', \$t, \$m) && sha1(trim(\$m[1])) === \$sha", 'B7: put-back finds the marked line by the sha of its original text');
has($cx, "crontab -u ' . escapeshellarg(\$user) . ' ' . escapeshellarg(\$tmp)", 'B8: written back through crontab(1) so cron reloads');
has($cc, "\$f[array_key_last(\$f)]['lines'] = \$rows;", 'B9: every line travels with the finding');
has($cc, "'state' => \$isSus(\$l) ? 'sus' : 'routine'", 'B10: each line carries its own verdict');
has($cc, "foreach (\$off as \$l) \$rows[] = ['sha' => sha1(\$l), 'text' => \$l, 'state' => 'off'];", 'B11: switched-off lines are listed too');
has($pg, 'data-op="cron_line_off"', 'B12: page offers switch off');
has($pg, 'data-op="cron_line_rm"', 'B13: page offers remove');
has($pg, 'data-op="cron_line_on"', 'B14: page offers put back');
has($pg, "if (!\$stored): ?><span class=\"ops\">", 'B15: a stored report shows no action buttons');
has($cc, 'SWITCH OFF keeps the line in the crontab as a comment', 'B16: the what-to-do text names the three choices');

// C. Security Health row button
has($sh, "(\$applyable?'&#9889; Fix':'How to fix')", 'C1: "Fix" only when a one-click fix is inside, else "How to fix"');
has($sh, "if(b.dataset.hasfix&&d.classList.contains('open')){var ap=d.querySelector('.sh-applybtn');if(ap){ap.scrollIntoView", 'C2: opening a Fix row brings the Apply button into view');

// D. Bot Guard: what it is, what to do
has($bg, '<b>What it is:</b>', 'D1: group row says what the network is');
has($bg, '<b>What to do:</b>', 'D2: group row names the action');
has($bi, 'function smpro_bg_net_kind(array $ips, string $prov, bool $crawler = false): array', 'D3: helper exists');
has($bi, "if (!\$idx) return null;", 'D4: no prefix list -> null, never a guess');
require_once SMPRO_BASE . '/includes/botguard.php';
$k = smpro_bg_net_kind(['203.0.113.5'], 'Google LLC');
is_eq($k['kind'], 'hosting', 'D5: Google LLC by name is hosting when no list is on the box');
ok(strpos($k['text'], 'NOT the Google crawler') !== false, 'D6: says outright it is not Googlebot');
$k = smpro_bg_net_kind(['203.0.113.5'], 'Vodafone Egypt');
is_eq($k['kind'], 'unknown', 'D7: a non-hosting name without the list is unknown, and says why');
ok(strpos($k['text'], 'prefix list is not fetched') !== false, 'D8: the reason is in the text');
$k = smpro_bg_net_kind(['203.0.113.5'], 'Hetzner Online GmbH', true);
is_eq($k['kind'], 'hosting', 'D9: a crawler family from a hosting net is still hosting');
ok(strpos($k['text'], 'normal for a crawler') !== false, 'D10: and not called suspicious for it');
