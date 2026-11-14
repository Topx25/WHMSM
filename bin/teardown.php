<?php
/**
 * bin/teardown.php - run by uninstall.sh BEFORE the plugin's files are removed.
 *
 * Takes down what would otherwise stay enforcing with nothing left to manage it: the country wall (its watcher is
 * one of the cron jobs an uninstall deletes), the login country list in cPHulk, and this product's lines in the
 * firewall's post-reload script. Prints what it did, one line each; prints "nothing to take down" otherwise.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'geowall', 'geohulk', 'update'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (PHP_SAPI !== 'cli') exit;
if (!function_exists('smpro_teardown_network')) { echo "the teardown step is not part of this build\n"; exit(1); }
$done = smpro_teardown_network('uninstall.sh');
echo $done ? implode("\n", $done) . "\n" : "nothing to take down\n";
