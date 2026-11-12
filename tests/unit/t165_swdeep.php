<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
require_once SMPRO_BASE . '/includes/sitewatch.php';
/**
 * t165 - Site Watch deep checks (2026-11-11 incident): a core file served gambling spam to search engines on the
 * home page only, a page cache stored the "redirect with no target" answer and every visitor got a white page, a
 * backdoor sat under a cache-tool name, the account's .bashrc was a password lock. Fixtures are the real answers.
 */
// core verify output
$out = "Warning: File doesn't verify against checksum: wp-includes/load.php\nWarning: File should not exist: wp-includes/wp-cache.php\nWarning: File should not exist: wp-cache.php\nError: WordPress installation doesn't verify against checksums.";
$p = smpro_swd_parse_verify($out);
is_eq($p['modified'], ['wp-includes/load.php'], 'C1: a changed core file is read from wp-cli');
is_eq($p['extra'], ['wp-includes/wp-cache.php', 'wp-cache.php'], 'C2: files that should not exist are read');
is_eq($p['error'], '', 'C3: a failed verification with findings is a finding, not an error');
$p2 = smpro_swd_parse_verify("Error: Couldn't get checksums from WordPress.org.");
ok($p2['error'] !== '' && !$p2['clean'], 'C4: no checksums = could not check (honest), never clean');
ok(smpro_swd_parse_verify("Success: WordPress installation verifies against checksums.")['clean'], 'C5: clean install reads clean');

// cloaking - the real shopx answer: 301, no Location, a broken "https: //..." header
$bot = ['code' => 301, 'loc' => '', 'hdr' => "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nhttps: //bad-toto.example/shopx.html\r\n", 'body' => ''];
$v = smpro_swd_cloak_verdict('shop.example', $bot, $bot);
ok(count($v) === 1 && $v[0][0] === 'critical' && strpos($v[0][1], 'no target') !== false, 'K1: redirect with no target = critical, reported once for both');
ok(strpos($v[0][1], 'bad-toto.example') !== false, 'K2: the broken header target is shown');
$okB = ['code' => 200, 'loc' => '', 'hdr' => '', 'body' => '<html><link rel="canonical" href="https://www.shop.example/">Welcome</html>'];
is_eq(smpro_swd_cloak_verdict('shop.example', $okB, $okB), [], 'K3: a normal page (own canonical on www) is clean');
$k4 = smpro_swd_cloak_verdict('shop.example', $okB, ['code' => 302, 'loc' => 'https://spam.example/x', 'hdr' => '', 'body' => '']);
ok(in_array('critical', array_column($k4, 0), true) && count(array_filter($k4, fn($x) => strpos($x[1], 'cloaking') !== false)) === 1, 'K4: search engines redirected away while visitors are not = cloaking');
$spam = ['code' => 200, 'loc' => '', 'hdr' => '', 'body' => '<link rel="amphtml" href="https://rank-x.workers.example/"/><meta name="description" content="DOLANTOGEL adalah pusat bandar toto togel resmi">'];
$k5 = smpro_swd_cloak_verdict('f.shop.example', $spam, $spam);
ok(in_array('critical', array_column($k5, 0), true), 'K5: a gambling spam home page is critical');
ok((bool)array_filter($k5, fn($x) => strpos($x[1], 'amphtml') !== false), 'K6: amphtml to another host is reported');
is_eq(smpro_swd_base_host('a.b.example.co.uk'), 'example.co.uk', 'K7: two-level country suffix');
is_eq(smpro_swd_cloak_verdict('shop.example', ['code' => 301, 'loc' => 'https://shop.example/ar/', 'hdr' => '', 'body' => ''], $okB), [], 'K8: a redirect inside the own site is fine');

$cp = ['code' => 301, 'loc' => 'https://other.example/en/', 'hdr' => '', 'body' => ''];
$k9 = smpro_swd_cloak_verdict('shop.example', $cp, $cp);
ok(count($k9) === 1 && $k9[0][0] === 'warning', 'K9: everyone sent to the same other site (a cPanel redirect) is a warning, said once - not an attack');

// shell lock
$lock = "case \$- in *i*) ;; *) return ;; esac\ntrap 'echo -e \"masukin\"; continue' INT\nexpected_hash=\"77960f\"\nwhile [[ \"\$input_hash\" != \"\$expected_hash\" ]]; do\n read -s input_pass\n input_hash=\$(echo -n \"\$input_pass\" | sha256sum | awk '{print \$1}')\ndone\n";
ok(smpro_swd_is_shell_lock($lock), 'S1: the password-lock .bashrc is found');
ok(!smpro_swd_is_shell_lock("# .bashrc\nif [ -f /etc/bashrc ]; then\n . /etc/bashrc\nfi\nalias ll='ls -l'\n"), 'S2: a normal .bashrc is not');
ok(!smpro_swd_is_shell_lock("read -p 'name: ' n\necho \$n\n"), 'S3: an ordinary read is not a lock');

// wiring + safety
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/swdeep.php'));
has($src, "'timeout 120 su -s /bin/bash ' . escapeshellarg(\$user)", 'W1: core verification runs as the account');
has($src, "could not keep the locked file - nothing changed", 'W2: the locked shell file is kept before it is replaced');
has($src, "'safe' => false, 'event' => \$e['id']]; }\n        if (\$k === 'cloak'", 'W3: switching a plugin off is never automatic');
has($src, "if (!isset(\$ran[\$grp]) || isset(\$now[\$e['id'] ?? ''])) continue;", 'W4: an event is resolved only by a check that really ran');
has($src, "if (\$r === false || strpos(\$r . '/', \$base) !== 0 || \$r === rtrim(\$base, '/')) continue;", 'W5: cache purge stays inside the account cache folder');
$sw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sitewatch.php'));
has($sw, "smpro_swd_run(\$dom, \$doc, \$user, \$coreDue, \$batch, \$prevChecks)", 'W6: Site Watch runs the deep checks');
has($sw, "elseif ((\$deep = smpro_swd_fix(\$dom, \$doc, \$user, \$action, \$arg)) !== null)", 'W7: the cleaning steps go through the Site Watch fix path (audit + log)');
