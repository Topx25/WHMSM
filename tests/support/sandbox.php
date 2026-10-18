<?php
/**
 * sandbox.php — per-process temp tree so NO test ever writes to the live /var/lib/smpro.
 * Also the stub-shim "recorder" dir, so call-shape assertions (e.g. "csf was never called")
 * read recorded argv from here.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Recursive delete that never follows symlinks out of the tree. */
function smpro_test_rmrf($dir) {
    if (is_link($dir)) { @unlink($dir); return; }
    if (!is_dir($dir)) { @unlink($dir); return; }
    foreach (scandir($dir) as $f) {
        if ($f === '.' || $f === '..') continue;
        smpro_test_rmrf($dir . '/' . $f);
    }
    @rmdir($dir);
}

/** Create the per-run sandbox tree and register teardown. Returns the base path. */
function smpro_test_mksandbox() {
    $base = rtrim(sys_get_temp_dir(), '/\\') . '/smpro_t_' . getmypid() . '_' . bin2hex(random_bytes(4));
    foreach (['', '/varlib', '/varlog', '/varlib/license', '/varlib/hub', '/varlib/geoip',
              '/varlib/cache', '/varlib/locks', '/varlib/notifications', '/rec'] as $d) {
        @mkdir($base . $d, 0700, true);
    }
    register_shutdown_function(function () use ($base) { smpro_test_rmrf($base); });
    return $base;
}

/** Read a recorder file's lines (argv records written by stub_path shims). [] if none. */
function smpro_test_rec_lines($bin) {
    $f = getenv('SMPRO_TEST_REC') . '/' . $bin . '.calls';
    if (!is_file($f)) return [];
    return array_values(array_filter(explode("\n", (string)@file_get_contents($f)), 'strlen'));
}

/** True if a stubbed binary was NEVER invoked (its recorder is empty/absent). */
function smpro_test_rec_empty($bin) {
    return smpro_test_rec_lines($bin) === [];
}

/** Wipe one or all recorder files (start an assertion window clean). */
function smpro_test_rec_reset($bin = null) {
    $dir = getenv('SMPRO_TEST_REC');
    if (!$dir || !is_dir($dir)) return;
    if ($bin !== null) { @unlink($dir . '/' . $bin . '.calls'); return; }
    foreach (glob($dir . '/*.calls') ?: [] as $f) @unlink($f);
}
