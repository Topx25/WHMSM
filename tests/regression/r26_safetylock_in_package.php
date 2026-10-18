<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r26_safetylock_in_package.php — Safety Lock ships WITH the WHM product, in the same package.
 *
 * It is not a separate product. A licensee installs the WHM plugin and the page appears in their customers'
 * cPanel; register_cpuser.sh says so in its own header: "There is deliberately no manual install step."
 *
 * For a while the build did not honour that. The account-side files existed only in a second working copy and
 * were published to a second channel, so the WHM release genuinely did not contain Safety Lock. The consequences
 * were not cosmetic:
 *
 *   - a server running the account-side plugin could not take a WHM release AT ALL. The edition guard refused
 *     it, correctly — applying it would have removed working protection from every customer on that server.
 *   - so that server sat on its own channel with its own version numbers, and "why is it on 1.1.5 when the
 *     latest is 1.1.10" had no good answer, because the two numbers counted different things.
 *
 * These assertions fail the build if the package is ever built without Safety Lock again.
 */

/* ---------- R1: the files are in THIS tree, not only in some other working copy ---------- */
foreach ([
    'includes/spqueue.php'    => 'the protect/release queue the root worker runs',
    'includes/sprules.php'    => 'the rules that decide what a request may do',
    'includes/cpsidescan.php' => 'the account-side scan',
    'bin/sp_queue.php'        => 'the worker itself',
    'bin/register_cpuser.sh'  => 'what puts the page in the customer\'s cPanel',
    'cpuser/index.live.php'   => 'the page the customer opens',
    'cpuser/stack.php'        => 'its detection stack',
    'cpuser/safetylock.svg'   => 'the icon cPanel requires for the entry',
] as $rel => $what) {
    ok(is_file(SMPRO_BASE . '/' . $rel), 'R1: ' . $rel . ' ships — ' . $what);
}

/* ---------- R2: the one call those files make outside themselves is satisfied here ---------- */
$ign = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/includes/ph_ignore.php'));
has($ign, 'function smpro_ph_perm_has', 'R2: smpro_ph_perm_has is defined in this tree');

/* ---------- R3: registering the account side is automatic, not a second install step ---------- */
$reg = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/bin/register.sh'));
has($reg, 'register_cpuser.sh', 'R3: register.sh installs the account-side plugin after every deploy/update');

/* ---------- R4: the BUILD ships them, which is where this actually went wrong ---------- */
// The files being present in the tree proved nothing last time: the build simply did not copy them.
$bld = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/../build/obfuscate-and-package.sh'));
if ($bld === '') $bld = str_replace(chr(13), '', (string)@file_get_contents(dirname(SMPRO_BASE) . '/build/obfuscate-and-package.sh'));
if ($bld === '') {
    // The lab tests an exported source tree that does not carry build/. Nothing to check there, and skipping is
    // honest; the same assertions run against the working copy where the build actually happens.
    tap_skip('R4: the build ships cpuser/', 'build/ is not part of the exported tree the lab tests; the same assertions run in the working copy, where the build actually happens');
} else {
    has($bld, 'cp -r "$ROOT/cpuser" "$SRC/"', 'R4: the build stages cpuser/ for obfuscation and signing');
    has($bld, 'gen-cpuser-stack.php', 'R4: and regenerates stack.php so a release cannot carry a drifted copy');
    has($bld, 'includes modules bin cpuser lang assets tests',
        'R4: the release gate tests the tree it is about to ship, cpuser/ included');
    has($bld, "! -name '*.php' -exec cp -f {} \"\$DEST/smpro/cpuser/\"",
        'R4: the icon is copied too — obfuscation never sees a non-PHP file');
}

/* ---------- R5: the edition guard still protects against a genuinely incomplete payload ---------- */
// It must keep refusing a package that lacks Safety Lock over an install that has it. The guard was never the
// problem; it was the only thing standing between a licensee and a silent loss of protection.
$upd = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/includes/update.php'));
has($upd, "is_file(\$dest . '/includes/spqueue.php') && !is_file(\$payload . '/includes/spqueue.php')",
    'R5: a payload without Safety Lock is still refused over an install that has it');

/* ---------- R6: shipping the files is not the same as being able to install them ---------- */
// The files all shipped, the installer ran, and it stopped with "SMPRO_CPS_SLUG came back empty" — so the page
// could never be installed from a release build, on any server. R1 above passed the whole time: it asked whether
// the files were present, which they were. What it did not ask was whether they could work.
//
// bin/register_cpuser.sh reads these five names out of defines.php BY TEXT, so they must be literal defines in
// that file and nowhere else.
$def = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/defines.php'));
foreach ([
    'SMPRO_CPS_SLUG'   => 'the directory, the dynamicui conf and the feature flag',
    'SMPRO_CPS_NAME'   => 'what the account holder sees in cPanel',
    'SMPRO_CPS_VENDOR' => 'the admin-helper vendor directory',
    'SMPRO_CPS_ADMIN'  => 'the root helper module',
    'SMPRO_CPS_GROUP'  => 'which cPanel section it appears in',
] as $c => $what) {
    ok((bool)preg_match("/define\('" . $c . "'\s*,\s*'[^']+'\s*\)/", $def),
       'R6: ' . $c . ' is a literal define — ' . $what);
}

// And the installer must still be the thing that reads them, or this assertion drifts away from the real need.
$reg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/register_cpuser.sh'));
has($reg, 'read_define SMPRO_CPS_SLUG', 'R6: the installer reads the slug from defines.php');
has($reg, 'came back empty', 'R6: and refuses loudly rather than installing half a plugin');

// The values must also survive being LOADED, not merely appear in the file. Checked in a child process:
// defines.php is already loaded here under a different path, and requiring it again only produces
// "already defined" notices that say nothing about whether the values are good.
$php  = escapeshellarg(PHP_BINARY);
$boot = sys_get_temp_dir() . '/smpro_r26_' . getmypid() . '.php';
file_put_contents($boot, implode(PHP_EOL, [
    '<?php',
    "define('SMPRO_BOOT', 1);",
    'require ' . var_export(SMPRO_BASE . '/includes/defines.php', true) . ';',
    '$o = [];',
    "foreach (['SMPRO_CPS_SLUG','SMPRO_CPS_NAME','SMPRO_CPS_VENDOR','SMPRO_CPS_ADMIN','SMPRO_CPS_GROUP'] as \$c)",
    '    $o[$c] = defined($c) ? (string)constant($c) : null;',
    'echo json_encode($o);',
]) . PHP_EOL);
$got = json_decode(trim((string)@shell_exec($php . ' ' . escapeshellarg($boot) . ' 2>&1')), true);
@unlink($boot);
ok(is_array($got), 'R6: the constants load in a clean process');
if (is_array($got)) {
    foreach ($got as $c => $v) ok(is_string($v) && $v !== '', 'R6: ' . $c . ' has a value at runtime too');
}

/* ---------- R7: the icon reaches the theme, not just the package ---------- */
// The build takes care to ship safetylock.svg precisely because obfuscation never sees a non-PHP file — and the
// installer then copied only *.php into the theme directory, so the cPanel entry had no icon. Shipping a file
// and installing it are two separate claims, and only one of them was being checked.
$reg2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/register_cpuser.sh'));
is_eq(substr_count($reg2, '"${SRC_DIR}"/*.svg'), 2,
      'R7: the icon is copied in BOTH places the page files are — staging and the theme directory');
has($reg2, 'The icon is not PHP', 'R7: with the reason it is easy to forget written down');
ok(is_file(SMPRO_BASE . '/cpuser/safetylock.svg'), 'R7: and there is an icon to copy');

/* ---------- R8: the queue worker is scheduled, or Protect never completes ---------- */
// Without it a customer presses Protect, the request queues forever, and the page says "protected" — which is
// the exact failure the edition guard exists to prevent, arriving by a different route.
$cs2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
has($cs2, 'smpro_spq_cron_sync', 'R8: the queue worker is in the list of schedules that get re-asserted');
ok(is_file(SMPRO_BASE . '/bin/sp_queue.php'), 'R8: and the worker itself ships');
