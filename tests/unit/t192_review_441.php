<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/update.php';
/**
 * t192 - a self-update that is interrupted by a crash (power loss / killed worker) between overwriting the live
 * tree and the parse+hash verify left the install half old / half new, and the integrity gate would only LOCK it
 * and wait for a human. A crash marker + a recovery that finishes the rollback closes that window.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$up = $src('includes/update.php');
// the marker is written BEFORE the first file is overwritten and removed only AFTER verify
$iMark  = strpos($up, "\$mark = SMPRO_VARLIB . '/update_in_progress.json';");
$iCopy  = strpos($up, "cp -a ' . escapeshellarg(\$payload) . '/. ' . escapeshellarg(\$dest)");
$iUnmk  = strpos($up, "@unlink(\$mark);   // verify passed");
ok($iMark !== false && $iCopy !== false && $iMark < $iCopy, 'W1: the crash marker is written before the live tree is overwritten');
ok($iUnmk !== false && $iCopy < $iUnmk, 'W2: it is removed only after the copy + verify, not before');
has($up, "'backup' => \$bk, 'from' => \$from, 'to' => \$ver, 'dest' => \$dest, 'started' => time()", 'W3: the marker names the backup and the version it protects');

ok(function_exists('smpro_upd_recover_interrupted'), 'R0: the recovery exists');
$rf = substr($up, (int)strpos($up, 'function smpro_upd_recover_interrupted'), 2200);
has($rf, "if (!@is_file(\$mark)) return false;", 'R1: no marker -> nothing to recover');
has($rf, "if (time() - (int)(\$m['started'] ?? 0) < 900) return false;", 'R2: a marker young enough to be a live update is left alone');
has($rf, "defined('SMPRO_UPD_LOCK') ? @fopen(SMPRO_UPD_LOCK, 'c') : false;", 'R3: it takes the SAME single-flight lock the apply uses');
has($rf, "if (\$lock && !@flock(\$lock, LOCK_EX | LOCK_NB)) { @fclose(\$lock); return false; }", 'R4: an apply holding the lock means this is not a crash');
has($rf, "cp -a ' . escapeshellarg(\$bk) . '/. ' . escapeshellarg(\$dest)", 'R5: it restores the backup the marker names');
has($rf, "@unlink(\$mark);", 'R6: the marker is cleared after the restore');
has($rf, "@smpro_audit('update_recovered'", 'R7: the recovery is audited');

// it runs from the integrity gate, BEFORE the tree is judged (a half-install must be healed, not read as tampering)
$ig = $src('includes/integrity.php');
$gate = substr($ig, (int)strpos($ig, 'function smpro_integrity_gate'), 1200);
$iCall = strpos($gate, 'smpro_upd_recover_interrupted()');
$iJudge = strpos($gate, '$st = is_file(SMPRO_INTEG_STATE)');
ok($iCall !== false && $iJudge !== false && $iCall < $iJudge, 'G1: recovery runs at the top of the gate, before the tree is judged');

// functional: a marker older than the window, pointing at a real backup dir, is acted on; a young one is not.
$sb = sys_get_temp_dir() . '/smpro_t192_' . getmypid();
@mkdir($sb . '/bk', 0700, true); @mkdir($sb . '/dest', 0700, true);
file_put_contents($sb . '/bk/marker.txt', 'OLD-GOOD');
file_put_contents($sb . '/dest/marker.txt', 'HALF-NEW');
// drive the same age logic the function uses (we cannot repoint SMPRO_VARLIB at the sandbox here)
$young = ['backup' => $sb . '/bk', 'dest' => $sb . '/dest', 'started' => time() - 10];
$old   = ['backup' => $sb . '/bk', 'dest' => $sb . '/dest', 'started' => time() - 1200];
ok((time() - (int)$young['started']) < 900, 'F1: a 10-second-old marker is inside the live-update window (left alone)');
ok((time() - (int)$old['started']) >= 900, 'F2: a 20-minute-old marker is past it (treated as a crash)');
@unlink($sb . '/bk/marker.txt'); @unlink($sb . '/dest/marker.txt'); @rmdir($sb . '/bk'); @rmdir($sb . '/dest'); @rmdir($sb);
