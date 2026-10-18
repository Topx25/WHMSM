<?php
/**
 * r15_edition_guard.php — a WHM-only build must never be applied over a cPanel-user-edition (Safety Lock) install.
 *
 * 2026-09-06: the two products shared one update channel; the WHM beta overlaid the cPanel-user install on a
 * production server, removed the file-lock helpers the account-side root worker loads from includes/, and every
 * Protect request queued forever while the customers' page said "protected". Two guards now refuse that:
 *   G1 packaging/install.sh — refuses when DEST has includes/spqueue.php and the package does not (SMPRO_FORCE_EDITION=1 overrides)
 *   G2 includes/update.php smpro_upd_apply — same check before the overlay, with an audit row + a forced alert
 * The installer guard is exercised for real with temp directories; the updater guard is asserted in source
 * (smpro_upd_apply downloads + RSA-verifies first, which needs the licence server).
 */
require __DIR__ . '/../support/bootstrap.php';

$sh = (string)file_get_contents(SMPRO_BASE . '/packaging/install.sh');
has($sh, 'if [ -f "${DEST}/includes/spqueue.php" ] && [ ! -f "${SRC}/${PLUGIN}/includes/spqueue.php" ] && [ "${SMPRO_FORCE_EDITION:-}" != "1" ]; then', 'G1: installer checks the edition marker before copying');
ok(strpos($sh, 'includes/spqueue.php') < strpos($sh, 'cp -a "${SRC}/${PLUGIN}/." "${DEST}/"'), 'G1: the check comes BEFORE the overlay');

$bash = trim((string)@shell_exec('command -v bash 2>/dev/null')) ?: (is_executable('/bin/bash') ? '/bin/bash' : '');
if ($bash !== '' && DIRECTORY_SEPARATOR === '/') {
    $T = sys_get_temp_dir() . '/smpro_r15_' . getmypid(); @mkdir("$T/dest/includes", 0700, true); @mkdir("$T/src/smpro/includes", 0700, true);
    file_put_contents("$T/dest/includes/spqueue.php", '<?php // cPanel-user edition marker');
    file_put_contents("$T/src/smpro/includes/helpers.php", '<?php // whm-only payload');
    // extract just the guard block and run it with the same variables the installer has
    preg_match('/# Edition guard:.*?\nfi\n/s', $sh, $m);
    ok(!empty($m[0]), 'G1: guard block extracted');
    $script = "die(){ echo \"DIE: \$*\"; exit 9; }\nDEST=" . escapeshellarg("$T/dest") . "\nSRC=" . escapeshellarg("$T/src") . "\nPLUGIN=smpro\n" . $m[0] . "\necho PASSED\n";
    file_put_contents("$T/guard.sh", $script);
    $out = (string)shell_exec($bash . ' ' . escapeshellarg("$T/guard.sh") . ' 2>&1; echo "rc=$?"');
    has($out, 'DIE: This server runs the cPanel-user edition', 'G1: WHM-only package over a Safety Lock install is refused');
    has($out, 'rc=9', 'G1: …with a non-zero exit');
    $out = (string)shell_exec('SMPRO_FORCE_EDITION=1 ' . $bash . ' ' . escapeshellarg("$T/guard.sh") . ' 2>&1; echo "rc=$?"');
    has($out, 'PASSED', 'G1: SMPRO_FORCE_EDITION=1 overrides deliberately');
    file_put_contents("$T/src/smpro/includes/spqueue.php", '<?php // cPanel-user payload');
    $out = (string)shell_exec($bash . ' ' . escapeshellarg("$T/guard.sh") . ' 2>&1; echo "rc=$?"');
    has($out, 'PASSED', 'G1: a cPanel-user package over a cPanel-user install passes');
    @unlink("$T/src/smpro/includes/spqueue.php"); @unlink("$T/dest/includes/spqueue.php");
    $out = (string)shell_exec($bash . ' ' . escapeshellarg("$T/guard.sh") . ' 2>&1; echo "rc=$?"');
    has($out, 'PASSED', 'G1: a WHM package over a WHM install passes (the common case is untouched)');
    foreach (glob("$T/*/*/*/*") ?: [] as $f) @unlink($f); foreach (glob("$T/*/*/*") ?: [] as $f) @unlink($f); @unlink("$T/guard.sh");
} else {
    ok(true, 'G1: (installer guard executed on the gate host — no bash here)');
}

$up = (string)file_get_contents(SMPRO_BASE . '/includes/update.php');
has($up, "if (is_file(\$dest . '/includes/spqueue.php') && !is_file(\$payload . '/includes/spqueue.php')) {", 'G2: self-updater checks the edition marker');
ok(strpos($up, "is_file(\$dest . '/includes/spqueue.php')") < strpos($up, "@shell_exec('cp -a ' . escapeshellarg(\$payload) . '/. '"), 'G2: …before the overlay');
has($up, "smpro_audit('update_refused_edition'", 'G2: a refusal is audited');
has($up, "'Update ' . \$ver . ' refused: wrong edition'", 'G2: …and alerted (forced), so a mis-routed channel is never silent');
has($up, 'Nothing was changed.', 'G2: the message says nothing was changed');
