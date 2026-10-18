<?php
/**
 * r20_render_smoke.php — every page actually renders. Not "the source contains X": rendered.
 *
 * THE GAP THIS CLOSES. The lab has no WHM licence, so the router refuses to render there, and every test until
 * now either called a pure function or asserted on source text. The entire render path was therefore untested,
 * and it shipped broken twice while the lab stayed green:
 *   • 1.1.8 — index.cgi carried CRLF line endings; its shebang could not be executed; HTTP 500 on every page.
 *   • 1.1.10-beta184 — smpro_aa_bf_render() declared `array $back` where the caller passes a string; the
 *     Break-in Report tab died with a TypeError the moment anyone opened it.
 * Both were found by a person clicking the page. Neither is visible to a grep. Both are caught here now.
 *
 * HOW. tests/support/render_one.php boots the same includes index.php boots, in the same order, with the data
 * paths redirected to a sandbox and the stub PATH prepended, then renders one page and prints a marker. Every
 * page runs in its own process — a fatal in one cannot take the suite with it — and all of them run at once, so
 * the sweep costs about as long as the single slowest page. Rendering is GET-only: no POST handler, no
 * state-changing action, ever.
 *
 * @timeout 120   — one process per page; the slowest single page costs more than the default per-file budget.
 *
 * The first assertion renders a deliberate TypeError through the same harness. A detector that cannot fail is
 * not a detector: if that one ever passes, every "renders" assertion below is worthless.
 */
require __DIR__ . '/../support/bootstrap.php';

if (DIRECTORY_SEPARATOR !== '/') {
    ok(true, 'render: (skipped on Windows — the include chain is POSIX-only; the gate host runs this for real)');
    return;
}

$php     = PHP_BINARY;
$harness = SMPRO_BASE . '/tests/support/render_one.php';
$root    = rtrim(sys_get_temp_dir(), '/') . '/smpro_r20_' . getmypid();
// Removed at exit. It was not: 101 of these, ~200 files each, sat in the lab's /tmp until its inodes ran out and
// 63 unrelated tests went red with "Failed opening required /tmp/smpro_defs_..." - the suite reporting its own
// litter as failures everywhere else.
register_shutdown_function(function () use ($root) {
    if (!is_dir($root) || strpos($root, '/smpro_r20_') === false) return;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname()); }
    @rmdir($root);
});
@mkdir($root, 0700, true);
ok(is_file($harness), 'render: the harness is present');

/* ---------- the job list: every built page, plus the query paths that broke or that a search reaches ---------- */
$menu = (string)file_get_contents(SMPRO_BASE . '/includes/menu.php');
preg_match_all("/\['id' => '([a-z0-9-]+)',\s*'label' => '[^']*',\s*'icon' => '[^']*',\s*'built' => (true|false)/", $menu, $mm);
$ids = [];
foreach ($mm[1] as $i => $id) if ($mm[2][$i] === 'true' && is_file(SMPRO_BASE . '/modules/' . $id . '.php')) $ids[] = $id;
$ids = array_values(array_unique($ids));
ok(count($ids) >= 30, 'render: read the built-module list from the menu registry (' . count($ids) . ' pages)');

$jobs = ['__selftest' => ''];                                  // proof the harness can still fail
foreach ($ids as $id) $jobs[$id] = '';
$jobs['account-audit?tab=bruteforce']                    = 'tab=bruteforce';                          // the TypeError that shipped
$jobs['account-audit?do=search']                         = 'do=search&q=203.0.113.9&loglines=20000';  // the search path (panel actions)
$jobs['account-audit?tab=overview']                      = 'tab=overview&days=7';
$jobs['account-audit?tab=webact']                        = 'tab=webact';
$jobs['bot-guard?export=html']                           = 'export=html';                             // the print view

/* ---------- run them all at once ---------- */
// Parallelism is done here, in PHP, with proc_open. The first two attempts drove xargs through a generated
// shell script; both quoted correctly and both returned empty output, and neither could be debugged from inside
// the test. Spawning the processes directly removes every quoting layer: what is passed is what is run.
$results = []; $slow = [];
$queue   = array_keys($jobs);
$running = [];
$MAX     = 14;      // the sweep then costs about as long as the slowest single page
$LIMIT   = 45.0;    // seconds per page, enforced here rather than by an external `timeout`

while ($queue || $running) {
    while ($queue && count($running) < $MAX) {
        $key = array_shift($queue);
        $id  = explode('?', $key)[0];
        $box = $root . '/' . preg_replace('/[^a-z0-9_-]/i', '_', $key);
        $cmd = escapeshellarg($php) . ' ' . escapeshellarg($harness) . ' ' . escapeshellarg($id) . ' '
             . escapeshellarg((string)$jobs[$key]) . ' ' . escapeshellarg($box);
        $pipes = [];
        $proc = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) { $results[$key] = '(could not start a render process)'; continue; }
        stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
        $running[$key] = ['p' => $proc, 'pipes' => $pipes, 'out' => '', 't' => microtime(true)];
    }
    if (!$running) continue;
    usleep(20000);
    foreach (array_keys($running) as $key) {
        $r = &$running[$key];
        $r['out'] .= (string)stream_get_contents($r['pipes'][1]) . (string)stream_get_contents($r['pipes'][2]);
        $st = proc_get_status($r['p']);
        $over = (microtime(true) - $r['t']) > $LIMIT;
        if ($st['running'] && !$over) { unset($r); continue; }
        if ($over && $st['running']) { @proc_terminate($r['p'], 9); $r['out'] .= "\nRENDER_FATAL page did not finish within " . (int)$LIMIT . "s"; }
        $r['out'] .= (string)stream_get_contents($r['pipes'][1]) . (string)stream_get_contents($r['pipes'][2]);
        @fclose($r['pipes'][1]); @fclose($r['pipes'][2]); @proc_close($r['p']);
        $lines = array_values(array_filter(array_map('trim', explode("\n", $r['out'])), fn($l) => $l !== ''));
        $results[$key] = $lines ? (string)end($lines) : '(no output at all)';
        $slow[$key] = (int)round((microtime(true) - $r['t']) * 1000);
        unset($r); unset($running[$key]);
    }
}
arsort($slow);
foreach (array_slice($slow, 0, 3, true) as $key => $ms) ok(true, 'render: slowest — ' . $key . ' ' . $ms . 'ms');

/* ---------- 1. the harness can still see a failure ---------- */
$self = (string)($results['__selftest'] ?? '');
ok(strpos($self, 'RENDER_FATAL') === 0, 'render: the harness REPORTS a deliberate TypeError (proof it can fail) — got: ' . substr($self, 0, 90));
has($self, 'TypeError', 'render: ...and names the error class');

/* ---------- 2. every page renders ---------- */
$fatal = 0;
foreach ($jobs as $key => $qs) {
    if ($key === '__selftest') continue;
    $m = (string)($results[$key] ?? '');
    $good = strpos($m, 'RENDER_OK') === 0;
    if (!$good) $fatal++;
    ok($good, 'render: ' . $key . ($good ? '' : ' — ' . substr($m, 0, 160)));
}
is_eq($fatal, 0, 'render: every page rendered without a fatal');

/* ---------- 3. a page that renders nothing is not a page ---------- */
if (preg_match('/RENDER_OK (\d+)/', (string)($results['dashboard'] ?? ''), $b))
    ok((int)$b[1] > 2000, 'render: the dashboard produced real HTML (' . (int)$b[1] . ' bytes), not an empty shell');
else ok(false, 'render: dashboard marker unreadable — ' . substr((string)($results['dashboard'] ?? ''), 0, 120));

@shell_exec('rm -rf ' . escapeshellarg($root));
