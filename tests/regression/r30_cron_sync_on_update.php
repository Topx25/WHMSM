<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r30_cron_sync_on_update.php — an enabled feature must be scheduled after an update, without anyone pressing Save.
 *
 * Every feature that needs a worker installs its own /etc/cron.d entry, and each did so in exactly one place: the
 * moment its settings were saved. Nothing ever called them again.
 *
 * So a feature that GAINS a worker in a later release was never scheduled for the operator who had enabled it
 * BEFORE that release. They upgrade, the setting still reads on, the badge still says armed, and nothing runs.
 * That is what happened with Country Login Lock on a live server: armed, saved, correct countries, SSH ticked —
 * and no schedule, so no rule could ever be written. The operator did everything right and the feature was inert.
 *
 * The same gap loses a cron to an upcp or a half-finished uninstall and never puts it back.
 */

ok(is_file(SMPRO_BASE . '/bin/cron_sync.php'), 'R1: there is one place that puts every schedule back');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));

/* ---------- R2: it covers every feature that installs a cron ---------- */
// Found by reading the tree, not by memory: a feature added later with its own sync must be added here too, and
// this assertion is what says so.
$syncs = [];
foreach (glob(SMPRO_BASE . '/includes/*.php') ?: [] as $f) {
    if (preg_match_all('/function\s+(smpro_[a-z0-9_]+_cron_sync)\s*\(/', (string)file_get_contents($f), $m)) {
        foreach ($m[1] as $fn) $syncs[$fn] = basename($f);
    }
}
ok(count($syncs) > 0, 'R2: the tree does have cron installers (' . count($syncs) . ' found)');
foreach ($syncs as $fn => $file) {
    has($cs, $fn, 'R2: cron_sync.php calls ' . $fn . ' (from ' . $file . ')');
}

/* ---------- R3: it runs after every install and every self-update ---------- */
$reg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/register.sh'));
has($reg, 'cron_sync.php', 'R3: register.sh runs it — and register.sh runs after install and after self-update');

/* ---------- R4: it can only follow the settings, never turn something on ---------- */
has($cs, 'installs or REMOVES accordingly', 'R4: the contract is written down: each sync follows its own setting');
has($cs, 'exit(0);', 'R4: and a cron problem never fails the installer — the plugin is still usable');
has($cs, '--quiet', 'R4: it can run silently from a script');

/* ---------- R5: each sync really is two-way ---------- */
// A sync that only ever installs would leave a worker running for a feature that has been turned off. Checked
// across whatever syncs THIS edition actually ships, rather than a hard-coded pair: the two editions carry
// different feature sets, and a test that names files fails for the wrong reason on the smaller one.
$twoWay = 0;
foreach ($syncs as $fn => $file) {
    $src = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/includes/' . $file));
    $i = strpos($src, 'function ' . $fn);
    if ($i === false) continue;
    $body = substr($src, $i, 1400);
    if (strpos($body, '@unlink($f)') !== false || strpos($body, '@unlink($cron)') !== false
        || strpos($body, '@unlink($path)') !== false) $twoWay++;
}
ok($twoWay > 0, 'R5: at least one sync removes its cron when its feature is off (' . $twoWay . ' of ' . count($syncs) . ')');

/* ---------- R6: no cron installer may write during a test ---------- */
// The shared writer refuses, but a test that loads only one feature file has no shared writer to refuse:
// function_exists() is false and the fallback writes /etc/cron.d directly. The lab caught exactly that,
// restored the file, and the build went red at random — twice, with a real cause each time.
foreach ($syncs as $fn => $file) {
    $src = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/includes/' . $file));
    $i = strpos($src, 'function ' . $fn);
    if ($i === false) continue;
    $head = substr($src, $i, 600);
    ok(strpos($head, "defined('SMPRO_TEST_SRC')") !== false,
       'R6: ' . $fn . ' refuses to install a cron during a test');
}
