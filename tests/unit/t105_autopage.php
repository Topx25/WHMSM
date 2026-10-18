<?php
require __DIR__ . '/../support/bootstrap.php';
/** t105 - every long server-rendered table gets paging: the global auto-pager in the layout, the Domain Checker opt-out, and no bare LF inside a CRLF file (a bare LF inside a JS string literal is what broke Bot Guard). */
$lay = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
has($lay, 'window.smproAutoPage=all', 'U1: the layout carries the auto-pager');
has($lay, "if(rowsOf(tbl)<=50) return;", 'U1: ...for tables with more than 50 body rows');
has($lay, "tbl.closest('[data-nopage]')", 'U1: ...with an opt-out');
ok(strpos($lay, 'window.smproPager=function') < strpos($lay, 'window.smproAutoPage=all'), 'U1: the pager is defined before the auto-pager uses it');
$dc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/domain-checker.php'));
has($dc, 'id="dcWrap" data-nopage="1"', 'U2: Domain Checker opts its table out (its scan/export act on visible rows)');
$mixed = [];
foreach (array_merge(glob(SMPRO_BASE . '/modules/*.php'), glob(SMPRO_BASE . '/includes/*.php'), glob(SMPRO_BASE . '/bin/*.php')) as $f) {
    $b = (string)file_get_contents($f);
    if (strpos($b, "\r\n") === false) continue;
    foreach (explode("\r\n", $b) as $ln) if (strpos($ln, "\n") !== false) { $mixed[] = basename($f); break; }
}
is_eq(implode(',', $mixed), '', 'U3: no CRLF file carries a bare LF');
$bg = (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php');
has($bg, "esc(j.urls.join('\\n'))", 'U4: the Bot Guard join uses an escaped newline inside the JS string');
