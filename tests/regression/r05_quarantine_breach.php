<?php
/**
 * r05_quarantine_breach.php — Phase-4 REGRESSION lock for the intrusion.php file-quarantine +
 * breach-exclusion fixes (catalog M4/M5/M6). These are documented past bugs; the asserts below
 * pin the EXACT current behavior so the bugs cannot silently reopen.
 *
 *   R23  smpro_im_quarantine_file  — M5: a quarantine with NO writable backup destination must leave
 *                                    the (possibly false-positive) file UNTOUCHED and report error
 *                                    'no-backup' with stored='' (never blank the only copy).
 *   R24  smpro_im_malice_count     — M6: the UNATTENDED/strict gate (clean_site strict=true requires
 *                                    >=2 indicator families). A 1-family file counts <2 (skipped); a
 *                                    2-family file counts >=2 (eligible). Eligibility proven by a real
 *                                    DRY-RUN smpro_im_quarantine_file() returning a dryrun marker.
 *   R25  smpro_im_emergency_undo   — M4: undoing a php_off action we CREATED (had=false) where the OWNER
 *                                    appended their own rules after ours strips ONLY our prefix and KEEPS
 *                                    the owner's .htaccess content (never delete owner content).
 *   R26  smpro_im_is_wp_plugin /    — breach scan EXCLUSIONS: a file carrying a WP "Plugin Name:" header
 *        smpro_im_breach_excluded     is never auto-quarantined, and /wp-content/cache/ is excluded.
 *
 * intrusion.php has no seams on these targets, so we require the RAW source directly; its SMPRO_IM_*
 * constants land under the sandbox SMPRO_VARLIB (bootstrap), so every fixture write stays in the
 * sandbox. The malice/looks regexes shell out to real grep/timeout (NOT shimmed) over our fixture
 * files — true behavior, no mocking. Dangerous binaries (chattr/rm) are recording PATH shims.
 *
 * SCOPE NOTE: smpro_im_clean_site() and smpro_im_breaches() scan smpro_im_docroots(), which is
 * HARDCODED to /home/<account> and is not overridable from the sandbox. We therefore lock the exact
 * decision predicates those functions delegate to (malice_count gate, is_wp_plugin, breach_excluded,
 * and a real quarantine_file dry-run) rather than driving the full docroot crawl — see the two
 * tap_skip()s at the end.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/intrusion.php';

ok(function_exists('smpro_im_quarantine_file'), 'quarantine/breach engine loaded from raw intrusion.php');

/* sandbox fixture root (always inside SMPRO_VARLIB — never write outside it) */
$fx = SMPRO_VARLIB . '/r05';
@mkdir($fx, 0700, true);
ok(is_dir($fx) && strpos($fx, SMPRO_VARLIB) === 0, 'fixture dir is inside SMPRO_VARLIB sandbox');

/* ============================ R23 — no-backup quarantine leaves file UNTOUCHED ============================ */
/* Force the failure shape M5 fixed: rename() fails AND no .bak exists. We make SMPRO_IM_QUAR a regular FILE,
 * so mkdir(QUAR/<acct>) fails -> the qdir never exists -> copy(...bak) fails (no dir) -> rename($file,$dest)
 * fails (no dir) -> filesize($dest.'.bak') is false -> the no-backup branch returns and the file is left as-is. */
@mkdir(dirname(SMPRO_IM_QUAR), 0700, true);
@file_put_contents(SMPRO_IM_QUAR, "x");                 // QUAR is now a FILE, not a dir -> all writes under it fail
ok(is_file(SMPRO_IM_QUAR), 'R23 setup: SMPRO_IM_QUAR is a regular file (no writable backup dest)');

$victim = $fx . '/victim.php';
$victimBody = "<?php /* not actually a shell — content must survive */ echo 'hello';\n";
file_put_contents($victim, $victimBody);

$r23 = smpro_im_quarantine_file($victim, 'acct1', false);   // dryrun=false: real attempt
is_eq(is_array($r23), true, 'R23 quarantine_file returned an array result');
is_eq($r23['error'] ?? null, 'no-backup', "R23 no writable backup dest -> error 'no-backup'");
is_eq($r23['stored'] ?? null, '', "R23 no-backup -> stored='' (nothing was moved/stored)");
is_eq($r23['backup'] ?? null, '', "R23 no-backup -> backup='' (no .bak was written)");
is_eq(is_file($victim), true, 'R23 the original file still exists (not removed)');
is_eq(file_get_contents($victim), $victimBody, 'R23 the file content is UNTOUCHED (the only copy was never blanked)');

@unlink(SMPRO_IM_QUAR);                                   // restore: QUAR may now be a dir again for later cases

/* ============================ R24 — strict needs >=2 malware families ============================ */
/* malice_count families: exec (eval(/system(/shell_exec...), obfusc (gzinflate/base64_decode($..), input
 * ($_POST[..](..)), upload (move_uploaded_file). clean_site(strict=true) skips files with malice_count < 2. */

/* 1-family fixture: ONLY the 'upload' family (a lone move_uploaded_file) -> count must be exactly 1 -> skipped */
$oneFam = $fx . '/one_family.php';
file_put_contents($oneFam, "<?php\nmove_uploaded_file(\$_FILES['f']['tmp_name'], 'dest.bin');\n");
is_eq(smpro_im_malice_count($oneFam), 1, 'R24 one-family file -> malice_count === 1 (strict gate would SKIP, count < 2)');

/* 2-family fixture: 'exec' (eval() ) + 'obfusc' (gzinflate) -> count must be >=2 -> eligible.
 * (gzinflate is a plain obfusc alternation; we avoid base64_decode's $-anchored variant on purpose.) */
$twoFam = $fx . '/two_family.php';
file_put_contents($twoFam, "<?php\n@eval(gzinflate(base64_decode(\$x)));\n");
$mc2 = smpro_im_malice_count($twoFam);
ok($mc2 >= 2, 'R24 two-family file -> malice_count >= 2 (strict gate ELIGIBLE); got ' . $mc2);

/* eligibility is real: looks_malicious agrees, and a DRY-RUN quarantine returns the dryrun marker w/o touching the file */
is_eq(smpro_im_looks_malicious($twoFam), true, 'R24 two-family file also trips looks_malicious (real grep)');
$r24 = smpro_im_quarantine_file($twoFam, 'acct1', true);    // dryrun=true: eligible -> preview, no move
is_eq($r24['type'] ?? null, 'quarantine', 'R24 dry-run quarantine -> type=quarantine');
is_eq($r24['dryrun'] ?? null, true, 'R24 dry-run quarantine -> dryrun=true (no file touched)');
is_eq($r24['path'] ?? null, $twoFam, 'R24 dry-run quarantine -> path echoes the target');
is_eq(is_file($twoFam), true, 'R24 dry-run left the eligible file in place (preview only)');

/* ============================ R25 — emergency_undo preserves OWNER .htaccess, strips OUR rule ============================ */
/* Build a php_off target we "created" (had=false) where the owner appended their own rule AFTER ours. */
$rule  = smpro_im_harden_rule();
$owner = "\n# OWNER custom rules — must survive undo\n<Files secret.txt>\n  Require all denied\n</Files>\n";
$ht = $fx . '/uploads_htaccess';                          // plain file in the sandbox (stands in for an uploads/.htaccess)
file_put_contents($ht, $rule . $owner);                   // OUR block is the exact prefix, owner content follows

/* inject the emergency manifest the undo reads from SMPRO_IM_EMLOG (sandbox) */
$undoId = 'r25test';
smpro_im_em_manifest_save([
    ['id' => $undoId, 'actions' => [
        ['type' => 'php_off', 'path' => $ht, 'had' => false],     // had=false => WE created the .htaccess
    ]],
]);

$done = smpro_im_emergency_undo($undoId);
is_eq($done, true, 'R25 emergency_undo found and processed the manifest entry');
is_eq(is_file($ht), true, 'R25 .htaccess still exists (owner content present => not deleted)');
$after = (string)@file_get_contents($ht);
hasnt($after, 'smpro Emergency hardening', 'R25 OUR hardening block was STRIPPED from the .htaccess');
has($after, 'OWNER custom rules', 'R25 the OWNER-appended rule was PRESERVED');
has($after, '<Files secret.txt>', 'R25 the owner rule body is intact verbatim');
/* the precise residue is substr(cur, strlen(rule)) == the owner block exactly */
is_eq($after, $owner, 'R25 residue equals EXACTLY the owner block (our prefix removed, nothing else changed)');

/* the manifest entry was consumed (undo is one-shot) */
is_eq(smpro_im_emergency_undo($undoId), false, 'R25 a second undo of the same id -> false (entry already removed)');

/* ============================ R26 — breach scan exclusions ============================ */
/* A real WP plugin header file is never auto-quarantined (is_wp_plugin true => breaches/clean_site `continue`). */
$plugin = $fx . '/akismet.php';
file_put_contents($plugin, "<?php\n/*\nPlugin Name: Akismet Anti-Spam\nDescription: it even names eval( and gzinflate( in its scanner\n*/\n@eval(gzinflate(base64_decode(\$x)));\n");
is_eq(smpro_im_is_wp_plugin($plugin), true, "R26 file with 'Plugin Name:' header -> is_wp_plugin true (excluded from auto-quarantine)");
/* even though that same file trips the malware regexes, the WP-header exclusion takes precedence in the crawl */
ok(smpro_im_malice_count($plugin) >= 2, 'R26 the plugin file DOES trip the malware regexes (so the header guard is what saves it)');

$nonPlugin = $fx . '/plain_shell.php';
file_put_contents($nonPlugin, "<?php\n@system(\$_GET['cmd']);\n");
is_eq(smpro_im_is_wp_plugin($nonPlugin), false, 'R26 a non-plugin PHP file -> is_wp_plugin false (no header)');

/* /wp-content/cache/ is excluded (seed list) regardless of admin config */
is_eq(smpro_im_breach_excluded('/home/u/public_html/wp-content/cache/page/index.php'), true,
    'R26 a /wp-content/cache/ path -> breach_excluded true (seed exclusion)');
is_eq(smpro_im_breach_excluded('/home/u/public_html/app/shell.php'), false,
    'R26 a normal docroot path -> breach_excluded false (would be scanned)');

/* ============================ deferred — full docroot-crawl paths ============================ */
tap_skip('smpro_im_clean_site(strict=true) full crawl', 'scans smpro_im_docroots() which is hardcoded to /home/<account> (not sandbox-overridable); the strict>=2-family gate is locked via malice_count above');
tap_skip('smpro_im_breaches() full crawl', 'correlates account_for()->docroots() (hardcoded /home + /var/cpanel/userdata); the WP-plugin and /wp-content/cache/ exclusions it delegates to are locked above');
