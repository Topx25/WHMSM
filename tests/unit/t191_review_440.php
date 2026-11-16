<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t191 - two "it will break later, silently" gaps from the code review:
 *  - /tmp resize copied the live /tmp into the new image and never checked the copy moved anything; a copy that
 *    moved NOTHING (staging fs full) would still swap, handing every service an empty /tmp and dropping sessions.
 *  - MySQL tuning wrote innodb_buffer_pool_size etc. into my.cnf with NO validation; a bad value (or a pool bigger
 *    than RAM) made MySQL fail to start at its NEXT restart - weeks later, after a reboot, with nobody linking it.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$dt = $src('includes/disk_tmp.php');
has($dt, "\$srcN = (int)trim((string)@shell_exec('ls -A /tmp 2>/dev/null | head -1000 | wc -l'));", 'T1: the copy result is checked by comparing /tmp with the new image');
has($dt, "if (\$srcN > 0 && \$dstN === 0) {", 'T2: a copy that moved nothing while /tmp has data is the failure case');
// the abort must happen in the pre-swap window (old /tmp still mounted) so the rollback is clean
$iAbort = strpos($dt, "if (\$srcN > 0 && \$dstN === 0) {");
$iSwap  = strpos($dt, "Detach /var/tmp bind FIRST");
ok($iAbort !== false && $iSwap !== false && $iAbort < $iSwap, 'T3: the check aborts BEFORE anything is detached (clean rollback)');
has($dt, "smpro_ds_tmp_rollback_loop('prestage', \$d, \$log)", 'T4: ...via the clean prestage rollback');
// an already-empty /tmp must NOT be treated as a failure (srcN 0 -> the guard does not fire)
ok(strpos($dt, "\$srcN > 0 && \$dstN === 0") !== false && strpos($dt, "\$srcN === 0 && \$dstN === 0") === false, 'T5: an already-empty /tmp copying to an empty image is not a failure');

$tn = $src('includes/tuning.php');
$mc = substr($tn, (int)strpos($tn, "if (\$kind === 'mycnf'"), 3600);
has($mc, "--validate-config", 'M1: the new my.cnf is validated by the server itself');
has($mc, "'mariadbd'", 'M2: ...looking for mysqld or mariadbd');
has($mc, "--help --verbose", 'M3: an older server with no --validate-config is parsed via --help --verbose');
has($mc, "@file_put_contents(\$file, \$c, LOCK_EX);   // restore exactly what was there", 'M4: a rejected file is rolled back to exactly what was there');
has($mc, "return ['ok' => false, 'msg' => 'The server rejected the new my.cnf, so nothing was changed. '", 'M5: ...and the apply refuses, saying why');
// validation sits BETWEEN the write and the success return (so a bad file never counts as applied)
$iWrite = strpos($mc, 'file_put_contents($file, $new, LOCK_EX)');
$iChk   = strpos($mc, '--validate-config');
$iOk    = strpos($mc, "'needs_restart' => 'mysql'");
ok($iWrite !== false && $iChk !== false && $iOk !== false && $iWrite < $iChk && $iChk < $iOk, 'M6: validate runs after the write and before the success return');
has($mc, "(the server validated the file)", 'M7: the success note says the file was validated');
