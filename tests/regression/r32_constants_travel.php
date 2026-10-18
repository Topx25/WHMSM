<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r32_constants_travel.php — a file in includes/ must be loadable on its own.
 *
 * Three times in one session, code was moved or merged and its CONSTANTS were left behind:
 *
 *   - SMPRO_CPS_* stayed in the cPanel-user tree when Safety Lock was merged, so the account-side page could
 *     not be installed from any release.
 *   - SMPRO_AA_BFIGN stayed in modules/account-audit.php when fifteen functions moved to includes/breakin.php,
 *     so the break-in rules worker died on its first line — every ten minutes, in every release since, having
 *     never once run.
 *
 * Each was invisible to the tests that existed, because those asked whether the CODE was present. A page module
 * defines its own constants at include time, so everything works from a browser and nothing works from cron —
 * and cron is exactly where these features are supposed to live.
 *
 * This checks the whole class: every SMPRO_ constant an includes/ file uses must be defined somewhere in
 * includes/, or guarded with defined() at the point of use.
 */

$incDir = SMPRO_BASE . '/includes';
$files  = glob($incDir . '/*.php') ?: [];
ok($files !== [], 'R1: there are include files to check (' . count($files) . ')');

/* Everything includes/ defines, plus the boot flag the router sets. */
$declared = ['SMPRO_BOOT' => 1];
foreach ($files as $f) {
    if (preg_match_all("/define\(\s*'(SMPRO_[A-Z0-9_]+)'/", (string)file_get_contents($f), $m)) {
        foreach ($m[1] as $c) $declared[$c] = 1;
    }
}

$offenders = [];
foreach ($files as $f) {
    $base = basename($f);
    // TOKENISED, not matched by regex. A constant NAME also appears inside strings — the iptables comment
    // marker, an .htaccess block delimiter — and a regex counts those as uses, so the first version of this
    // test reported five failures of which none were real. PHP's own tokeniser knows the difference between a
    // constant reference (T_STRING) and the same letters inside a quoted string.
    $toks = @token_get_all((string)file_get_contents($f));
    $src  = str_replace(chr(13), '', (string)file_get_contents($f));
    $prev = null;
    foreach ($toks as $tk) {
        if (!is_array($tk) || $tk[0] !== T_STRING) { if (is_array($tk) && $tk[0] === T_WHITESPACE) continue; $prev = $tk; continue; }
        $c = $tk[1];
        if (strpos($c, 'SMPRO_') !== 0) { $prev = $tk; continue; }
        // A function call of the same shape, or a ->method, is not a constant.
        if (is_array($prev) && in_array($prev[0], [T_FUNCTION, T_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) { $prev = $tk; continue; }
        if (isset($declared[$c]))                                   { $prev = $tk; continue; }
        if (strpos($src, "defined('" . $c . "')") !== false)         { $prev = $tk; continue; }
        $offenders[] = $base . ' uses ' . $c;
        $prev = $tk;
    }
}
$offenders = array_values(array_unique($offenders));
is_eq($offenders, [], 'R2: no include uses a constant nothing in includes/ defines'
                      . ($offenders ? ' — ' . implode('; ', $offenders) : ''));

/* ---------- R3: the two that actually bit, by name ---------- */
// Named as well as covered by the sweep above, because these are the ones that shipped broken and a future
// reader deserves to see them called out rather than inferred from a passing generic assertion.
$bi = str_replace(chr(13), '', (string)file_get_contents($incDir . '/breakin.php'));
has($bi, "if (!defined('SMPRO_AA_BFIGN')) define('SMPRO_AA_BFIGN'",
    'R3: breakin.php defines the ignore-list path it reads');
$def = str_replace(chr(13), '', (string)file_get_contents($incDir . '/defines.php'));
has($def, "define('SMPRO_CPS_SLUG'", 'R3: and the account-side constants are in defines.php');

/* ---------- R4: the workers load clean ---------- */
// The real proof: start each cron worker's include set in a fresh process and see whether it fatals. That is
// what the machine does every few minutes, and it is the thing nobody was checking.
foreach (['breakin.php', 'bfrules.php', 'geologin.php', 'geowall.php', 'georeport.php'] as $mod) {
    if (!is_file($incDir . '/' . $mod)) continue;
    $boot = sys_get_temp_dir() . '/smpro_r32_' . getmypid() . '.php';
    file_put_contents($boot, implode(PHP_EOL, [
        '<?php',
        "define('SMPRO_BOOT', 1);",
        'error_reporting(E_ALL); ini_set("display_errors", "1");',
        'foreach (["defines","env","mmdb","helpers","secret","license","intrusion","fwallow","botguard"] as $m) {',
        '    $f = ' . var_export($incDir, true) . ' . "/" . $m . ".php"; if (is_file($f)) require_once $f;',
        '}',
        'require_once ' . var_export($incDir . '/' . $mod, true) . ';',
        'echo "OK";',
    ]) . PHP_EOL);
    $out = (string)@shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($boot) . ' 2>&1');
    @unlink($boot);
    ok(strpos($out, 'OK') !== false, 'R4: ' . $mod . ' loads outside a browser'
       . (strpos($out, 'OK') !== false ? '' : ' — ' . substr(trim($out), 0, 160)));
}
