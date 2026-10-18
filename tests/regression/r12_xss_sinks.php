<?php
/**
 * r12_xss_sinks.php — locks the two XSS sinks found by the 2026-09-06 taint pass, and the escaper they rely on.
 *
 * Grep found 316 raw `<?=` echoes; a source-tracing pass narrowed them to 80 whose value could carry attacker
 * text, and reading every one of those left TWO that really did:
 *   • includes/shortcuts.php  — the dashboard "Top Processes" card echoed the top process NAME straight from
 *     `ps -o comm`. A hosted account names its own processes, so a 15-byte payload in a script name landed on the
 *     root operator's dashboard unescaped.
 *   • modules/backup-monitor.php — the job-status badge fell back to the RAW status string when the status was
 *     not in the fixed map, and echoed it unescaped.
 * Both now go through smpro_h(). These assertions read the shipped source, because the pages themselves need a
 * WHM session to render: a regression that removes the escaper is caught here, not on a customer's screen.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');

ok(function_exists('smpro_h'), 'xss: the shared escaper exists');
is_eq(smpro_h('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;', 'xss: smpro_h neutralises a tag');
is_eq(smpro_h("a'b\"c"), 'a&#039;b&quot;c', 'xss: smpro_h escapes both quote kinds (attribute-safe)');

$sc = (string)@file_get_contents(SMPRO_BASE . '/includes/shortcuts.php');
ok($sc !== '', 'xss: shortcuts.php readable');
has($sc, "'top: ' . smpro_h(\$top)", 'xss: dashboard card escapes the ps process name (a hosted user names their own processes)');
hasnt($sc, "'top: ' . \$top)", 'xss: the raw form of that echo is gone');

$bm = (string)@file_get_contents(SMPRO_BASE . '/modules/backup-monitor.php');
ok($bm !== '', 'xss: backup-monitor.php readable');
has($bm, '<span class="b <?= smpro_h($bc) ?>"><?= smpro_h($bl) ?></span>', 'xss: backup job-status badge is escaped (raw status fell through the fixed map)');
hasnt($bm, '<span class="b <?= $bc ?>"><?= $bl ?></span>', 'xss: the raw badge echo is gone');

// The fallback path that made the badge dangerous: an unknown status must still render, escaped, not vanish.
if (preg_match('/\$badge\s*=\s*\[(.*?)\];/s', $bm, $m)) {
    hasnt($m[1], '<?=', 'xss: the badge map itself is data, not markup with echoes');
}
