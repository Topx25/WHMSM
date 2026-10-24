<?php
/**
 * Safety Monitor Pro - switching off WordPress's visitor-triggered cron.
 *
 * WordPress starts its own scheduled work from ordinary page views unless told not to. On a site that also has a
 * real cron entry that is a second source of the same runs, and on a busy site it is by far the larger one: every
 * visitor can start another. Setting DISABLE_WP_CRON leaves the schedule as the only thing that starts it.
 *
 * This edits a customer's wp-config.php, which is a PHP file the whole site is loaded through. A broken edit does
 * not degrade anything - it takes the site down completely, and it does so for every visitor at once. So on top
 * of the copy-verify-compare contract used for schedules, this one adds the check that matters here: the result
 * is PARSED before it is accepted, and the original is put straight back if it does not parse. A site is never
 * left holding a file this wrote unless PHP itself has confirmed it can read it.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Copies live per account, dated, outside the account's own tree so a site restore cannot remove them. */
function smpro_wpc_backup_dir(string $user): string {
    return SMPRO_VARLIB . '/wpconfig_backups/' . preg_replace('/[^a-z0-9_-]/i', '', $user);
}

/** The account a docroot belongs to, or '' when it is not under a home directory this server owns. */
function smpro_wpc_owner(string $docroot): string {
    if (!preg_match('#^/home\d*/([a-z0-9][a-z0-9_-]{0,31})/#i', rtrim($docroot, '/') . '/', $m)) return '';
    return is_file('/var/cpanel/users/' . $m[1]) ? $m[1] : '';
}

/** What the file says today: true = already off, false = visitors can start it, null = no readable wp-config. */
function smpro_wpc_state(string $docroot) {
    return function_exists('smpro_cc_wp_cron_disabled') ? smpro_cc_wp_cron_disabled($docroot) : null;
}

/** Copy wp-config.php and read the copy back. Returns the path, or '' if it could not be verified. */
function smpro_wpc_backup(string $docroot, string $task): string {
    $src = rtrim($docroot, '/') . '/wp-config.php';
    $user = smpro_wpc_owner($docroot);
    if ($user === '' || !is_file($src)) return '';
    $body = (string)@file_get_contents($src);
    if ($body === '') return '';
    $dir = smpro_wpc_backup_dir($user);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return '';
    $path = $dir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-z0-9_-]/i', '', $task) . '.wp-config.php';
    if (@file_put_contents($path, $body) === false) return '';
    @chmod($path, 0600);
    clearstatcache();
    return (is_file($path) && (string)@file_get_contents($path) === $body) ? $path : '';
}

/** Does PHP consider this text a valid file? The whole site loads through it, so nothing else is good enough. */
function smpro_wpc_parses(string $text): array {
    $tmp = SMPRO_VARLIB . '/wpconfig_backups/.lint_' . getmypid() . '.php';
    if (!is_dir(dirname($tmp))) @mkdir(dirname($tmp), 0700, true);
    if (@file_put_contents($tmp, $text) === false) return ['ok' => false, 'error' => 'Could not stage the file for checking.'];
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    [$rc, $out] = smpro_run_rc(escapeshellarg($php) . ' -l ' . escapeshellarg($tmp), 20, ['stderr' => 'merge']);
    @unlink($tmp);
    return ['ok' => $rc === 0, 'error' => $rc === 0 ? '' : trim($out)];
}

/**
 * Add (or correct) DISABLE_WP_CRON.
 * Returns ['ok','changed','was','backup','error'] - 'was' is what the file said before.
 */
function smpro_wpc_disable(string $docroot, bool $dryRun = false): array {
    $file = rtrim($docroot, '/') . '/wp-config.php';
    $user = smpro_wpc_owner($docroot);
    if ($user === '')            return ['ok' => false, 'error' => 'That path is not inside an account on this server.'];
    if (!is_file($file))         return ['ok' => false, 'error' => 'There is no wp-config.php there, so this is not a WordPress site.'];
    $homeReal = function_exists('smpro_user_home') ? @realpath(smpro_user_home($user)) : false; $real = @realpath($file);
    if (is_link($file) || $real === false || $homeReal === false || strpos($real, $homeReal . '/') !== 0) return ['ok' => false, 'error' => 'wp-config.php is a link or lies outside the account - refused.'];
    $file = $real;
    if (!is_writable($file))     return ['ok' => false, 'error' => 'wp-config.php cannot be written — check its ownership and permissions.'];
    $body = (string)@file_get_contents($file);
    if ($body === '')            return ['ok' => false, 'error' => 'wp-config.php is empty or unreadable; nothing is being changed.'];

    $was = smpro_wpc_state($docroot);
    if ($was === true) return ['ok' => true, 'changed' => false, 'was' => true, 'error' => '',
                               'msg' => 'Already switched off here — nothing to do.'];

    $define = "define('DISABLE_WP_CRON', true);";
    if (preg_match("/define\s*\(\s*['\"]DISABLE_WP_CRON['\"]\s*,\s*(?:false|0|['\"][^'\"]*['\"])\s*\)\s*;/i", $body)) {
        // Present but switched on. Replace that one statement and leave the rest of the line alone.
        $new = preg_replace("/define\s*\(\s*['\"]DISABLE_WP_CRON['\"]\s*,\s*(?:false|0|['\"][^'\"]*['\"])\s*\)\s*;/i", $define, $body, 1);
        $how = 'changed the existing setting';
    } else {
        // Insert above the marker WordPress puts before the part that must stay last. Falling back to the
        // require of wp-settings.php covers a file that has been rearranged; refusing covers one this does not
        // recognise at all, because guessing a position in a file the site loads through is not worth the risk.
        if (preg_match("#/\*\s*That's all,\s*stop editing.*?\*/#is", $body, $m, PREG_OFFSET_CAPTURE)) {
            $at = $m[0][1]; $how = 'added it above WordPress\'s "stop editing" marker';
        } elseif (preg_match("#^\s*require_once\s*[\(\s].*wp-settings\.php#im", $body, $m, PREG_OFFSET_CAPTURE)) {
            $at = $m[0][1]; $how = 'added it above the line that loads WordPress';
        } else {
            return ['ok' => false, 'error' => 'This wp-config.php does not have either of the places this knows to be safe to add to, so it is being left alone. Add the line by hand: ' . $define];
        }
        $new = substr($body, 0, $at)
             . "/* " . SMPRO_NAME . " " . date('Y-m-d') . ": the schedule is the only thing that should start cron. */\n"
             . $define . "\n\n"
             . substr($body, $at);
    }

    $lint = smpro_wpc_parses($new);
    if (empty($lint['ok'])) return ['ok' => false, 'error' => 'The edited file would not parse, so it was not written: ' . $lint['error']];

    if ($dryRun) return ['ok' => true, 'dry_run' => true, 'changed' => true, 'was' => $was, 'how' => $how,
                         'line' => $define, 'error' => ''];

    $backup = smpro_wpc_backup($docroot, 'disable_wp_cron');
    if ($backup === '') return ['ok' => false, 'error' => 'wp-config.php could not be copied, so nothing was changed.'];

    if (@file_put_contents($file, $new) === false) return ['ok' => false, 'backup' => $backup, 'error' => 'The file could not be written.'];
    clearstatcache();

    // Read back what is actually on disk now - not what was meant to be there - and undo it unless PHP agrees it
    // is loadable AND the setting is really in effect.
    $onDisk = (string)@file_get_contents($file);
    $after  = smpro_wpc_parses($onDisk);
    $inEffect = smpro_wpc_state($docroot) === true;
    if (empty($after['ok']) || !$inEffect) {
        @file_put_contents($file, $body);
        return ['ok' => false, 'backup' => $backup,
                'error' => 'The site\'s configuration did not come back as written, so the original was put straight back'
                         . (empty($after['ok']) ? ' (it would not parse: ' . $after['error'] . ')' : '') . '.'];
    }

    if (function_exists('smpro_audit')) smpro_audit('wp_cron_disabled', ['user' => $user, 'docroot' => $docroot, 'backup' => $backup]);
    return ['ok' => true, 'changed' => true, 'was' => $was, 'how' => $how, 'backup' => $backup, 'error' => ''];
}

/** The copies taken for an account, newest first. */
function smpro_wpc_backups(string $docroot): array {
    $user = smpro_wpc_owner($docroot);
    if ($user === '') return [];
    $out = [];
    foreach (glob(smpro_wpc_backup_dir($user) . '/*.wp-config.php') ?: [] as $f) {
        $out[] = ['path' => $f, 'when' => (int)@filemtime($f), 'bytes' => (int)@filesize($f)];
    }
    usort($out, fn($a, $b) => $b['when'] <=> $a['when']);
    return $out;
}

/** Put wp-config.php back from one of this account's own copies. */
function smpro_wpc_undo(string $docroot, string $backupPath): array {
    $user = smpro_wpc_owner($docroot);
    if ($user === '') return ['ok' => false, 'error' => 'That path is not inside an account on this server.'];
    $real = @realpath($backupPath);
    $dir  = @realpath(smpro_wpc_backup_dir($user));
    // The suffix is compared by its own length rather than a number written by hand. Getting that number wrong is
    // silent and one-directional: the check simply never matches, every restore is refused as foreign, and the
    // way back from a bad edit is closed at exactly the moment it is needed. It read -15 for a 14-character
    // suffix until a test tried to undo something.
    $suffix = '.wp-config.php';
    if ($real === false || $dir === false || strpos($real, $dir) !== 0
        || substr($real, -strlen($suffix)) !== $suffix) {
        return ['ok' => false, 'error' => 'That is not one of this site\'s saved copies.'];
    }
    $body = (string)@file_get_contents($real);
    if (trim($body) === '') return ['ok' => false, 'error' => 'That saved copy is empty; it is not being restored.'];
    $lint = smpro_wpc_parses($body);
    if (empty($lint['ok'])) return ['ok' => false, 'error' => 'That saved copy does not parse, so restoring it would take the site down: ' . $lint['error']];
    $safety = smpro_wpc_backup($docroot, 'before_undo');
    $file = rtrim($docroot, '/') . '/wp-config.php';
    if (@file_put_contents($file, $body) === false) return ['ok' => false, 'error' => 'The file could not be written.'];
    if (function_exists('smpro_audit')) smpro_audit('wp_cron_undo', ['user' => $user, 'from' => $real, 'safety' => $safety]);
    return ['ok' => true, 'restored_from' => $real, 'safety_copy' => $safety, 'error' => ''];
}
