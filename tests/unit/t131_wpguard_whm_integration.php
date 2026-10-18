<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t131 - with the WP Guard WHM plugin installed, SM Pro never alerts on, cleans or deletes the originals in WP Guard's
 *  root-only quarantine (its Undo depends on them), and reads WP Guard's status read-only. Nothing is written to WP Guard. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($src, "if (smpro_wpguard_whm_quarantined(\$p)) return true;", 'S1: the shared trust check covers WP Guard WHM quarantine (alerts, delete, Imunify hand-off)');
has($src, "(int)\$st['uid'] === 0 && ((int)\$st['mode'] & 0022) === 0", 'S2: only a root-owned folder chain closed to the account is trusted');
has($src, "if (!smpro_wpguard_whm()['installed']) return false;", 'S3: never trusted when WP Guard is not installed');
hasnt($src, "'/var/lib/wpguard", 'S4: WP Guard paths are discovered, not fixed');
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/shharden.php'));
has($sh, "' -readonly -cmd '", 'S5: WP Guard database opened read-only');

// live, on the lab as root: a fake quarantine laid out like WP Guard's
if (function_exists('posix_geteuid') && posix_geteuid() === 0 && smpro_wpguard_whm()['installed']) {
    $base = sys_get_temp_dir() . '/t131_' . getmypid(); $q = "$base/.wpguard-quarantine/acct/20261013-cx1";
    mkdir($q, 0700, true); chmod("$base/.wpguard-quarantine", 0700); chmod("$base/.wpguard-quarantine/acct", 0700);
    file_put_contents("$q/x.php", '<?php //'); chmod("$q/x.php", 0);
    is_eq(smpro_wpguard_trusted("$q/x.php"), true, 'L1: a file in a root-only WP Guard quarantine is trusted');
    $q2 = "$base/b/.wpguard/quarantine/z"; mkdir($q2, 0777, true); chmod("$base/b/.wpguard/quarantine", 0777);
    is_eq(smpro_wpguard_trusted("$q2/x.php"), false, 'L3: a folder anyone can write is never trusted');
    is_eq(smpro_wpguard_trusted("$base/elsewhere/x.php"), false, 'L4: an ordinary path is not trusted');
    exec('rm -rf ' . escapeshellarg($base));
}

// WP Guard's per-site plugin copy: <home>/.wpguard/<16hex>/wp-guard.php
has($src, "if (smpro_wpguard_whm_sitecopy(\$p)) return true;", 'S6: the shared trust check covers WP Guard per-site plugin copies');
has($src, "(int)\$st['uid'] !== 0 || ((int)\$st['mode'] & 0022) !== 0", 'S7: file and folders must be root-owned and closed to the account');
has($src, "return is_file(\$path) && smpro_wpguard_verify(\$path);", "S8: and carry WP Guard's own header");
if (function_exists('posix_geteuid') && posix_geteuid() === 0 && smpro_wpguard_whm()['installed']) {
    $h = sys_get_temp_dir() . '/home9'; $acct = "$h/t131u" . getmypid(); $d = "$acct/.wpguard/0123456789abcdef";
    @mkdir($d, 0711, true); chmod("$acct/.wpguard", 0711); chmod($d, 0711);
    $hdr = "<?php\n/**\n * Plugin Name: WP Guard\n * Author: HostGuard\n */\n";
    // the temp dir is not /homeN, so the path pattern must refuse it outright
    file_put_contents("$d/wp-guard.php", $hdr); chmod("$d/wp-guard.php", 0644);
    is_eq(smpro_wpguard_whm_sitecopy("$d/wp-guard.php"), false, 'L5: only an account home path qualifies');
    is_eq(smpro_wpguard_whm_sitecopy('/home/x/.wpguard/0123456789abcdef/other.php'), false, 'L6: only wp-guard.php');
    exec('rm -rf ' . escapeshellarg($h));
    $real = glob('/home*/*/.wpguard/*/wp-guard.php') ?: [];
    if ($real) {
        is_eq(smpro_wpguard_trusted($real[0]), true, 'L7: a real WP Guard site copy on this server is trusted');
    }
}
