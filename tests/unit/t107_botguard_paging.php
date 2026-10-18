<?php
require __DIR__ . '/../support/bootstrap.php';
/** t107 - Bot Guard pages on the server: 50 rows per list in the HTML, later pages and filters via the rows action, which is answered before any HTML. */
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
has($m, "if (\$act === 'rows') { \$bgRowsReq = true; }", 'U1: the POST handler defers the rows action');
has($m, "if (empty(\$bgRowsReq)) { echo json_encode(\$out", 'U1: ...and does not answer it there');
ok(strpos($m, "if (!empty(\$bgRowsReq)) {") < strpos($m, "smpro_layout_header('Bot Guard');"), 'U2: the rows action is answered before the layout header (no HTML in the JSON)');
has($m, "\$page = \$print ? \$rows : array_slice(\$rows, 0, 50, true);", 'U3: the page ships the first 50 rows of each list (print keeps all)');
has($m, "array_slice(\$f, \$off, 50, true)", 'U3: a later page is a 50-row slice of the filtered list');
has($m, 'data-nopage="1"', 'U4: the layout auto-pager stays off these tables');
has($m, "document.addEventListener('click',function(ev){var b=ev.target.closest('.bg-tbl button[data-act]');", 'U5: row actions are delegated (rows get replaced)');
hasnt($m, "smproPager({table:'bgTbl-'", 'U5: no client-side pager left');
has($m, "fd.set('bg_action','rows');", 'U5: the page asks the server for pages');
has($m, "preg_replace('/[^a-z]/', '', (string)(\$_POST['mode'] ?? ''))", 'U6: the list name is sanitised');

/* ---------- grouping (beta299) ---------- */
has($m, "\$groupKeyOf = function (\$ip, array \$b) {", 'G1: a group key: crawler name, else verdict + network');
has($m, "return 'n:' . strtolower((string)\$b['name']);", 'G1: named crawlers group by name');
has($m, 'data-gact="block"', 'G2: group rows carry group-level actions');
has($m, "if (\$grp !== '') {", 'G3: the rows action can return the addresses of one group');
has($m, "if (count(\$in) >= 500) break;", 'G3: ...capped');
has($m, '<select id="bgG"', 'G4: the view switch exists');
has($m, "\$bgGrouped = !\$print;", 'G4: print stays per address');
has($m, "querySelectorAll('.bgSel:checked, .bgGrpSel:checked')", 'G5: bulk selection includes whole groups');
