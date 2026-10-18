<?php
/**
 * r17_shell_lf.php — shell-executed files ship with LF line endings, never CRLF.
 *
 * 2026-09-08: STABLE 1.1.8 and the betas after it shipped index.cgi with CRLF endings after a line-ending
 * "normalisation" on the Windows build box. The kernel read the shebang as "/usr/bin/env bash\r", could not exec
 * it, and cpsrvd answered every WHM page with "Internal Server Error 500". Workers (plain PHP) kept running, so
 * nothing else looked wrong. 1.1.7 had LF. The build gate lints PHP; it never looked at the wrapper. Now it does,
 * and this test keeps the source clean too.
 */
require __DIR__ . '/../support/bootstrap.php';

$files = [SMPRO_BASE . '/index.cgi', SMPRO_BASE . '/packaging/install.sh', SMPRO_BASE . '/packaging/uninstall.sh'];
foreach (glob(SMPRO_BASE . '/bin/*.sh') ?: [] as $f) $files[] = $f;
$n = 0;
foreach ($files as $f) {
    if (!is_file($f)) continue; $n++;
    $b = (string)file_get_contents($f);
    ok(strpos($b, "\r") === false, 'LF: ' . basename($f) . ' has no CR bytes');
    ok(strncmp($b, "#!", 2) === 0 && strpos(substr($b, 0, 80), "\n") !== false && strpos(strtok($b, "\n"), "\r") === false, 'LF: ' . basename($f) . ' shebang line is clean');
}
ok($n >= 2, "LF: checked $n shell-executed files");
$gf = SMPRO_BASE . '/build/obfuscate-and-package.sh';
if (is_file($gf)) {   // build/ is not deployed to the lab; the gate check is asserted where the script exists
    $gate = (string)file_get_contents($gf);
    has($gate, 'no CR line endings in shell-executed files', 'LF: the build gate refuses CR in shell files');
    ok(strpos($gate, 'no CR line endings') < strpos($gate, 'DONE: packaging/smpro-$VER.tar.gz'), 'LF: ...before the package is written');
} else ok(true, 'LF: (build script not present here; gate check asserted on the build box)');
