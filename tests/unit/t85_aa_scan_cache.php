<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/breakin.php';
/**
 * t85_aa_scan_cache.php — Account Audit scans once per search, not once per click.
 *
 * Page 2, a column sort, hiding localhost: each re-tailed 50,000 lines, re-ran the regex on every one and looked
 * every address up again. On a busy server that is seconds per click. The parsed result is kept for a few minutes
 * under a key of everything that changes it; "re-scan now" bypasses it.
 */
$calls = 0;
$collect = function () use (&$calls) { $calls++; return [[['ts' => 1, 'ip' => '203.0.113.1', 'kind' => 'failed_login']], 3]; };
$p = ['u' => 'acct', 't' => 'all', 'n' => 50000, 'f' => 0, 'to' => 0, 'q' => ''];
@unlink(SMPRO_CACHE . '/' . smpro_aa_cache_key($p) . '.json');
[$e1, $h1, $m1] = smpro_aa_cached($p, $collect);
ok(!$m1['cached'] && $calls === 1, 'U1: the first search scans');
[$e2, $h2, $m2] = smpro_aa_cached($p, $collect);
ok($m2['cached'] && $calls === 1, 'U1: the next click for the same search does not');
is_eq($e2, $e1, 'U1: and returns the same events');
is_eq($h2, 3, 'U1: with the hidden count');
[$e3, $h3, $m3] = smpro_aa_cached($p + ['x' => 1] , $collect);
$p2 = $p; $p2['n'] = 200000;
[$e4, $h4, $m4] = smpro_aa_cached($p2, $collect);
ok(!$m4['cached'], 'U2: a different window is a different scan');
[$e5, $h5, $m5] = smpro_aa_cached($p, $collect, true);
ok(!$m5['cached'], 'U2: re-scan now bypasses the cache');
ok(smpro_aa_cache_key(['b' => 1, 'a' => 2]) === smpro_aa_cache_key(['a' => 2, 'b' => 1]), 'U3: the key does not depend on parameter order');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($mod, "smpro_aa_cached(['u'=>\$user,'t'=>\$type,'n'=>\$dlog,'f'=>\$from,'to'=>\$to,'q'=>\$search]", 'U4: the page scans through the cache, keyed on the typed dates (an open upper bound is time() and was a new key every click)');
hasnt($mod, "    [\$events, \$hiddenTech] = smpro_aa_collect(", 'U4: and no longer directly');
has($mod, 'paging and sorting do not re-read the log', 'U4: and says so to the operator');
has($mod, "'fresh'=>1", 'U4: with a way to force a fresh scan');
