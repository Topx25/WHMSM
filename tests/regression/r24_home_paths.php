<?php
/**
 * r24_home_paths.php — an account's home is read, never guessed.
 *
 * A cPanel server spreads accounts across /home, /home1, /home2 … as partitions fill. The test lab itself has
 * three. Any feature that built the path as "/home/" . $user therefore did nothing at all for every account
 * outside the first partition — and reported that as "nothing found", which is indistinguishable from "scanned
 * and clean".
 *
 * It mattered most in the phishing scanner: a server was reported for hosting phishing while the scanner was
 * quietly skipping whole partitions.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');

ok(function_exists('smpro_user_home'), 'R1: there is one shared resolver');
is_eq(smpro_user_home(''), '', 'R1: no account, no path');
is_eq(smpro_user_home('../../etc'), '', 'R1: a traversal attempt resolves to nothing, not to a path');
is_eq(smpro_user_home('no_such_account_' . getmypid()), '', 'R1: an account that does not exist returns empty');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($src, "\$pw = @posix_getpwnam(\$u);", 'R2: it asks the system');
has($src, "foreach ((array)@file('/etc/passwd', FILE_IGNORE_NEW_LINES)", 'R2: ...and falls back to /etc/passwd where posix is unavailable');
has($src, 'NOT "/home/$user"', 'R2: with the reason stated where the function is');
has($src, 'which callers must treat as "cannot look", never as "clean"', 'R2: and the contract for an empty answer');

/* the scanner that needed it most */
$ps = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/phishscan.php'));
hasnt($ps, "'/home/' . \$account", 'R3: the phishing scanner no longer guesses the path');
has($ps, "\$home = function_exists('smpro_user_home') ? smpro_user_home(\$account) : '';", 'R3: it resolves it');
has($ps, '$r = smpro_ps_scan($home);', 'R3: ...and scans what it resolved');
has($ps, 'reported as scanned-and-clean without ever', 'R3: with the failure it caused recorded');

/* ---------- R4: nowhere in the plugin builds an account path by hand any more ---------- */
// 46 occurrences across 15 files did. On this very lab (/home, /home1, /home2) each of them silently skipped
// every account outside the first partition, and reported that as a clean result.
$bad = [];
foreach (['includes', 'modules', 'bin'] as $sub) {
    $dir = SMPRO_BASE . '/' . $sub;
    if (!is_dir($dir)) continue;
    foreach (glob($dir . '/*.php') ?: [] as $f) {
        $txt = str_replace(chr(13), '', (string)file_get_contents($f));
        foreach (explode(chr(10), $txt) as $n => $line) {
            if (preg_match("/'\/home\/'\s*\./", $line))
                $bad[] = basename($sub) . '/' . basename($f) . ':' . ($n + 1);
        }
    }
}
is_eq($bad, [], 'R4: no file builds "/home/" . $user by hand' . ($bad ? ' — found at: ' . implode(', ', $bad) : ''));

ok(function_exists('smpro_user_home'), 'R4: they all go through the one resolver');
$h = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($h, 'static $memo = [];', 'R4: which caches, since it is now called wherever a path used to be built');
