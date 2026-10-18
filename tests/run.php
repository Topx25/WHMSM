<?php
/**
 * run.php — the TAP harness engine. Discovers test files for the selected layers,
 * runs EACH in its own child ea-php82 process (constant-collision isolation) with a
 * per-file timeout, parses the children's TAP, prints a console summary, writes JUnit
 * XML, and exits non-zero on any failure / crash / timeout / plan-mismatch.
 *
 * Invoked by smpro_test.php (which has already done the env + production safety checks and is
 * running under ea-php82, so PHP_BINARY here IS ea-php82). Can also be run directly for
 * local iteration: php run.php --layers unit --filter mmdb
 */
if (!defined('SMPRO_BOOT')) define('SMPRO_BOOT', 1);

$ROOT_TESTS = __DIR__;

/* ---- options ---- */
$opts = $GLOBALS['SMPRO_RUN_OPTS'] ?? null;
if ($opts === null) {
    $opts = ['layers' => null, 'on_box' => false, 'with_db' => false, 'filter' => '', 'junit' => '', 'timeout' => 30, 'tap' => false];
    $argv2 = $argv; array_shift($argv2);
    for ($i = 0; $i < count($argv2); $i++) {
        $a = $argv2[$i];
        if ($a === '--layers')      $opts['layers']  = explode(',', $argv2[++$i] ?? '');
        elseif ($a === '--on-box')  $opts['on_box']  = true;
        elseif ($a === '--with-db') $opts['with_db'] = true;
        elseif ($a === '--filter')  $opts['filter']  = $argv2[++$i] ?? '';
        elseif ($a === '--junit')   $opts['junit']   = $argv2[++$i] ?? '';
        elseif ($a === '--timeout') $opts['timeout'] = (int)($argv2[++$i] ?? 30);
        elseif ($a === '--tap')     $opts['tap']     = true;
    }
}
if (empty($opts['layers'])) {
    $opts['layers'] = ['unit', 'integration', 'security', 'regression'];
    if (!empty($opts['on_box'])) $opts['layers'][] = 'smoke';
}
$timeout = max(5, (int)$opts['timeout']);
$isTty   = function_exists('posix_isatty') && @posix_isatty(STDOUT);
$c = function ($s, $col) use ($isTty) {
    if (!$isTty) return $s;
    $m = ['g' => "\033[32m", 'r' => "\033[31m", 'y' => "\033[33m", 'b' => "\033[1m", 'd' => "\033[2m"];
    return ($m[$col] ?? '') . $s . "\033[0m";
};

/* ---- discover ---- */
$files = [];
foreach ($opts['layers'] as $layer) {
    $layer = trim($layer);
    foreach (glob($ROOT_TESTS . '/' . $layer . '/*.php') ?: [] as $f) {
        if ($opts['filter'] !== '' && strpos(basename($f), $opts['filter']) === false) continue;
        $files[] = $f;
    }
}
sort($files);

if (!$files) {
    fwrite(STDERR, "No test files matched layers=[" . implode(',', $opts['layers']) . "] filter='" . $opts['filter'] . "'\n");
    exit(2);
}

/* ---- run one child, return parsed result ---- */
function smpro_run_file($file, $timeout) {
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p = @proc_open([PHP_BINARY, $file], $desc, $pipes, dirname(dirname($file)), null);
    if (!is_resource($p)) return ['ok' => false, 'err' => 'proc_open failed', 'cases' => [], 'count' => 0, 'fail' => 1, 'skip' => 0, 'out' => '', 'stderr' => '', 'secs' => 0];
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = ''; $err = ''; $start = microtime(true); $timedout = false; $exit = null;
    while (true) {
        $st = proc_get_status($p);
        $out .= stream_get_contents($pipes[1]);
        $err .= stream_get_contents($pipes[2]);
        if (!$st['running']) { $exit = $st['exitcode']; break; }
        if (microtime(true) - $start > $timeout) { $timedout = true; proc_terminate($p, 9); usleep(120000); break; }
        usleep(15000);
    }
    $out .= stream_get_contents($pipes[1]);
    $err .= stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $rc = proc_close($p);
    if ($exit === null) $exit = $rc;
    $secs = microtime(true) - $start;

    $cases = []; $okN = 0; $failN = 0; $skipN = 0; $plan = null;
    foreach (explode("\n", $out) as $line) {
        if (preg_match('/^ok \d+ - (.*?)(?: # SKIP(.*))?$/', $line, $m)) {
            if (isset($m[2])) { $skipN++; $cases[] = ['name' => trim($m[1]), 'status' => 'skip', 'detail' => trim($m[2])]; }
            else { $okN++; $cases[] = ['name' => trim($m[1]), 'status' => 'pass', 'detail' => '']; }
        } elseif (preg_match('/^not ok \d+ - (.*)$/', $line, $m)) {
            $failN++; $cases[] = ['name' => trim($m[1]), 'status' => 'fail', 'detail' => ''];
        } elseif (preg_match('/^1\.\.(\d+)/', $line, $m)) {
            $plan = (int)$m[1];
        } elseif ($line !== '' && $line[0] === '#' && $cases) {
            // A TAP diag line belongs to the case just above it, and for a FAILURE it carries the only
            // explanation there is - the fatal's message and the file:line it happened at. This used to be
            // dropped on the floor: every failure printed its name and nothing else, so an intermittent fault
            // could be seen but never diagnosed, and the run had to be repeated until it happened again.
            $last = count($cases) - 1;
            if ($cases[$last]['status'] === 'fail') {
                $d = trim(ltrim($line, '#'));
                if ($d !== '') $cases[$last]['detail'] = trim($cases[$last]['detail'] . ' ' . $d);
            }
        }
    }
    $count = $okN + $failN + $skipN;
    $errMsg = '';
    if ($timedout)             $errMsg = "TIMEOUT after {$timeout}s";
    elseif ($plan === null)    $errMsg = "no TAP plan (crash? exit=$exit)";
    elseif ($plan !== $count)  $errMsg = "plan mismatch: planned $plan, ran $count";
    $fileOk = ($errMsg === '' && $failN === 0);
    if (!$fileOk && $failN === 0) $failN = 1; // synthetic failure for crash/timeout
    return ['ok' => $fileOk, 'err' => $errMsg, 'cases' => $cases, 'count' => $count, 'fail' => $failN, 'skip' => $skipN, 'out' => $out, 'stderr' => trim($err), 'secs' => $secs];
}

/* ---- run all ---- */
fwrite(STDOUT, $c("Safety Monitor Pro — test lab", 'b') . "  (" . count($files) . " files, layers: " . implode(',', $opts['layers']) . ")\n");
$totAssert = 0; $totFail = 0; $totSkip = 0; $failedFiles = []; $suites = []; $t0 = microtime(true);
foreach ($files as $f) {
    $rel = str_replace($ROOT_TESTS . '/', '', $f);
    // A file may declare a longer budget in its own header (`@timeout 120`). The render sweep needs one: it
    // starts a process per page and the slowest single page already costs most of the default budget. Keeping
    // the number in the file puts it next to the reason for it, instead of in a flag nobody passes.
    $fileTimeout = $timeout;
    $head = (string)@file_get_contents($f, false, null, 0, 3000);
    if (preg_match('/@timeout\s+(\d{1,3})/', $head, $tm)) $fileTimeout = max($timeout, min(300, (int)$tm[1]));
    $r = smpro_run_file($f, $fileTimeout);
    // A timeout on a shared box usually means the box was busy, not that the code hung: the lab runs on a live
    // server, and a file that normally takes 9s has been killed at 30s purely because something else was using
    // the processors. That turned load into a RED build and sent the reader looking for a defect that was not
    // there. A file that runs out of time is therefore given ONE more attempt with a longer budget before the
    // build is failed — a genuine hang still exceeds both and still fails, which is the case the limit is for.
    if (!$r['ok'] && strpos((string)$r['err'], 'TIMEOUT') === 0) {
        fwrite(STDOUT, '       ' . $c('… ' . basename($f) . ' ran out of time (' . $fileTimeout . 's) — retrying once with '
            . ($fileTimeout * 3) . 's in case the box was merely busy', 'd') . PHP_EOL);
        $retry = smpro_run_file($f, $fileTimeout * 3);
        if ($retry['ok']) $retry['err'] = 'slow: needed ' . round($retry['secs']) . 's (over the ' . $fileTimeout . 's budget) — the box is loaded, not the code';
        $r = $retry;
    }
    $totAssert += $r['count']; $totFail += $r['fail']; $totSkip += $r['skip'];
    $suites[] = ['file' => $rel] + $r;
    if ($opts['tap']) fwrite(STDOUT, $r['out']);
    $tag = $r['ok'] ? $c('PASS', 'g') : $c('FAIL', 'r');
    $line = sprintf("  %s  %-44s %3d ok", $tag, $rel, $r['count'] - $r['fail'] - ($r['ok'] ? 0 : 0));
    $line = sprintf("  %s  %-44s %2d/%-2d  %s", $tag, $rel, ($r['count'] - $r['fail']), $r['count'], $c(number_format($r['secs'], 1) . 's', 'd'));
    if ($r['skip']) $line .= ' ' . $c('(' . $r['skip'] . ' skip)', 'y');
    fwrite(STDOUT, $line . "\n");
    // A file that passed only on the longer retry still says so - a build that quietly needed three times
    // the budget is worth knowing about, even though it is not a failure.
    if ($r['ok'] && strpos((string)$r['err'], 'slow:') === 0) fwrite(STDOUT, '       ' . $c('~ ' . $r['err'], 'y') . PHP_EOL);
    if (!$r['ok']) {
        $failedFiles[] = $rel;
        if ($r['err']) fwrite(STDOUT, '       ' . $c('! ' . $r['err'], 'r') . "\n");
        foreach ($r['cases'] as $cs) {
            if ($cs['status'] !== 'fail') continue;
            fwrite(STDOUT, '       ' . $c('✗ ' . $cs['name'], 'r') . PHP_EOL);
            if ($cs['detail'] !== '') fwrite(STDOUT, '         ' . $c($cs['detail'], 'd') . PHP_EOL);
        }
        if ($r['stderr']) foreach (array_slice(explode("\n", $r['stderr']), 0, 8) as $el) fwrite(STDOUT, '       ' . $c('stderr: ' . $el, 'd') . "\n");
    }
}
$elapsed = microtime(true) - $t0;

/* ---- JUnit ---- */
if (!empty($opts['junit'])) {
    $xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n";
    foreach ($suites as $s) {
        $xml .= sprintf("  <testsuite name=\"%s\" tests=\"%d\" failures=\"%d\" skipped=\"%d\" time=\"%.3f\">\n",
            htmlspecialchars($s['file'], ENT_XML1), $s['count'], $s['fail'], $s['skip'], $s['secs']);
        if ($s['err']) $xml .= "    <testcase name=\"(harness)\"><failure message=\"" . htmlspecialchars($s['err'], ENT_XML1) . "\"/></testcase>\n";
        foreach ($s['cases'] as $cs) {
            $xml .= "    <testcase name=\"" . htmlspecialchars($cs['name'], ENT_XML1) . "\">";
            if ($cs['status'] === 'fail') $xml .= "<failure/>";
            elseif ($cs['status'] === 'skip') $xml .= "<skipped/>";
            $xml .= "</testcase>\n";
        }
        $xml .= "  </testsuite>\n";
    }
    $xml .= "</testsuites>\n";
    @mkdir(dirname($opts['junit']), 0755, true);
    @file_put_contents($opts['junit'], $xml);
}

/* ---- summary ---- */
$passN = $totAssert - $totFail - $totSkip;
fwrite(STDOUT, "\n" . $c("────────────────────────────────────────", 'd') . "\n");
$verdict = empty($failedFiles)
    ? $c("GREEN", 'g') . " — all " . count($files) . " files passed"
    : $c("RED", 'r') . " — " . count($failedFiles) . "/" . count($files) . " files failed: " . implode(', ', $failedFiles);
fwrite(STDOUT, sprintf("%s\n%s assertions: %s pass / %s fail / %s skip   in %.1fs\n",
    $verdict,
    $c((string)$totAssert, 'b'),
    $c((string)$passN, 'g'),
    $totFail ? $c((string)$totFail, 'r') : '0',
    $totSkip ? $c((string)$totSkip, 'y') : '0',
    $elapsed));

exit(empty($failedFiles) ? 0 : 1);
