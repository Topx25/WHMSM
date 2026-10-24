<?php
/**
 * Safety Monitor Pro - DirectAdmin -> cpmove, the bulk half.
 *
 * Stage three: move the account's actual content into the cpmove tree that migrate_da_convert.php described.
 * There is no format question in moving bytes, but there are two layout facts that were read off a real backup
 * and are not guessable:
 *
 *   1. backup/home.tar.gz and domains/ do NOT overlap. The nested archive holds only the home root - dotfiles,
 *      .htpasswds, .php logs - while the served content lives in the OUTER domains/<domain>/public_html. Copying
 *      one and assuming it covered the other loses either the site or its settings.
 *   2. Mail sits at imap/<domain>/<mailbox>/Maildir/{cur,new,tmp}; cPanel expects ~/mail/<domain>/<mailbox>/
 *      {cur,new,tmp}. The Maildir/ level has to come out, or every mailbox restores empty with its messages
 *      one directory below where the mail server looks.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/**
 * Refuse a conversion that cannot finish.
 *
 * Running out of disk halfway does not simply fail: it leaves a half-built account AND a full filesystem, and a
 * full filesystem on a hosting server takes every site down, not just this migration. The check is deliberately
 * pessimistic - the archive is decompressed once and then repacked, so the peak is well above its own size, and
 * gzip cannot be asked for a reliable uncompressed size above 4 GB.
 */
function smpro_mig_da_space_check(string $archive, string $workRoot, float $factor = 2.5): array {
    $size = (int)@filesize($archive);
    if ($size <= 0) return ['ok' => false, 'why' => 'The archive could not be measured.'];
    $dir = is_dir($workRoot) ? $workRoot : dirname($workRoot);
    $free = (float)@disk_free_space($dir);
    if ($free <= 0) return ['ok' => false, 'why' => 'Free space on ' . $dir . ' could not be read, so this will not start.'];
    $need = (float)$size * $factor;
    $h = function ($b) { return function_exists('smpro_bytes') ? smpro_bytes($b) : round($b / 1073741824, 1) . ' GB'; };
    if ($free < $need) {
        return ['ok' => false, 'need' => $need, 'free' => $free,
            'why' => 'Not enough room on ' . $dir . '. Converting this archive needs about ' . $h($need)
                   . ' (it is decompressed and then repacked) and there is ' . $h($free) . ' free. Nothing has been '
                   . 'started — running out of disk part-way would leave a half-built account and a full filesystem, '
                   . 'which takes every site on the server down, not just this migration.'];
    }
    return ['ok' => true, 'need' => $need, 'free' => $free, 'why' => ''];
}

/**
 * Move the content into cpmove-<user>/homedir.
 * $log is called with a short human line per step so the job card can show progress on a long extraction.
 * Returns ['ok','error','warnings','steps'].
 */
function smpro_mig_da_build_home(string $archive, string $cpmoveRoot, string $user, string $mainDomain, ?callable $log = null): array {
    $say = function ($m) use ($log) { if ($log) $log($m); };
    $warn = []; $steps = 0;
    $home = rtrim($cpmoveRoot, '/') . '/homedir';
    if (!is_dir($home) && !@mkdir($home, 0711, true)) return ['ok' => false, 'error' => 'Could not create homedir/.', 'warnings' => []];

    // 1. The home root, out of the nested archive. Streamed rather than written to disk first: on the reference
    //    backup that member alone would have been an extra multi-GB file with nothing to gain by keeping it.
    $say('Unpacking the account\'s home files');
    $cmd = 'tar xzOf ' . escapeshellarg($archive) . ' ' . escapeshellarg('backup/home.tar.gz')
         . ' 2>/dev/null | tar xz -C ' . escapeshellarg($home) . ' 2>/dev/null';
    [$rc] = smpro_run_rc('sh -c ' . escapeshellarg($cmd), 7200, ['stderr' => 'discard']);
    if (!is_file($home . '/.bashrc') && !is_file($home . '/.bash_profile')) {
        $warn[] = 'The home files did not unpack, so the account comes across without its shell settings, .htaccess rules and saved passwords.';
    } else { $steps++; }

    // 2. The served content and the mailboxes, from the outer archive in one pass - tar is sequential, so asking
    //    for both together costs one read of a multi-GB file instead of two.
    $say('Unpacking websites and mailboxes (the largest part)');
    $stage = rtrim($cpmoveRoot, '/') . '/.da_stage';
    if (!is_dir($stage) && !@mkdir($stage, 0700, true)) return ['ok' => false, 'error' => 'Could not create the staging directory.', 'warnings' => $warn];
    smpro_run('tar xzf ' . escapeshellarg($archive) . ' -C ' . escapeshellarg($stage)
        . ' --wildcards ' . escapeshellarg('domains/*') . ' ' . escapeshellarg('imap/*'), 14400, ['stderr' => 'discard']);

    // 3. Web content. cPanel serves the main domain from ~/public_html; DirectAdmin serves it from
    //    domains/<domain>/public_html. Every other domain keeps its own directory, which is where the userdata
    //    entries written by the converter already point.
    $moved = 0;
    $skip  = ['logs' => 1, 'stats' => 1, 'awstats' => 1];   // rebuilt by the destination; never worth carrying
    foreach (glob($stage . '/domains/*', GLOB_ONLYDIR) ?: [] as $dDir) {
        $dom = basename($dDir);
        if (!is_dir($dDir . '/public_html')) $warn[] = 'Domain ' . $dom . ' has no public_html in the backup, so it comes across with nothing to serve.';

        // EVERY directory beside public_html travels, not just public_html. A DirectAdmin account routinely
        // carries a second docroot - the reference backup had a 5.1 GB public_html-new-project running its own
        // WordPress against its own database, exactly the same size as the live site. Moving only public_html
        // would have dropped half the account while reporting the migration complete.
        foreach (glob($dDir . '/*', GLOB_ONLYDIR) ?: [] as $sub) {
            $name = basename($sub);
            if (isset($skip[$name])) continue;
            if ($name === 'public_html' && $dom === $mainDomain) $dst = $home . '/public_html';
            elseif ($dom === $mainDomain)                        $dst = $home . '/' . $name;
            else                                                 $dst = $home . '/' . $dom . '/' . $name;
            if (!is_dir(dirname($dst))) @mkdir(dirname($dst), 0755, true);
            if (@rename($sub, $dst)) { $moved++; continue; }
            // rename fails across filesystems; copy rather than silently skipping a whole site.
            [$rc2] = smpro_run_rc('cp -a ' . escapeshellarg($sub) . ' ' . escapeshellarg($dst), 7200, ['stderr' => 'discard']);
            if ($rc2 === 0) $moved++;
            else $warn[] = 'The files in ' . $dom . '/' . $name . ' could not be moved into place, so that content would be missing after the restore.';
        }
        if ($moved) $steps++;
    }
    if (!$moved) $warn[] = 'No website content was moved into place. The account would restore with its settings but no site.';

    // 4. Mail. Dropping the Maildir/ level is the whole job here: leave it in and every mailbox restores looking
    //    empty, because the messages sit one directory below where the mail server reads.
    $say('Placing mailboxes');
    $boxes = 0;
    foreach (glob($stage . '/imap/*', GLOB_ONLYDIR) ?: [] as $dDir) {
        $dom = basename($dDir);
        foreach (glob($dDir . '/*', GLOB_ONLYDIR) ?: [] as $bDir) {
            $box = basename($bDir);
            $src = is_dir($bDir . '/Maildir') ? $bDir . '/Maildir' : $bDir;
            $dst = $home . '/mail/' . $dom . '/' . $box;
            if (!is_dir(dirname($dst))) @mkdir(dirname($dst), 0751, true);
            if (@rename($src, $dst)) { $boxes++; continue; }
            [$rc3] = smpro_run_rc('cp -a ' . escapeshellarg($src) . ' ' . escapeshellarg($dst), 3600, ['stderr' => 'discard']);
            if ($rc3 === 0) $boxes++;
            else $warn[] = 'Mailbox ' . $box . '@' . $dom . ' could not be placed and would restore empty.';
        }
    }
    if ($boxes) $steps++;
    // The source server's Dovecot indexes travel with the Maildir and describe a mailbox that no longer exists
    // here. Left in place they make a mailbox read as empty or out of order until Dovecot notices; removed, they
    // are rebuilt from the messages on first access.
    if ($boxes) {
        smpro_run('find ' . escapeshellarg($home . '/mail') . ' -type f \( -name "dovecot.index*" -o -name "dovecot.list.index*" -o -name "dovecot-uidlist" \) -delete', 900, ['stderr' => 'discard']);
    }
    $say($boxes . ' mailbox(es) placed');

    // 5. Database dumps sit beside the metadata in the archive; cPanel reads them from mysql/.
    $say('Placing database dumps');
    $dumps = 0;
    $mysqlDir = rtrim($cpmoveRoot, '/') . '/mysql';
    smpro_run('tar xzf ' . escapeshellarg($archive) . ' -C ' . escapeshellarg($stage)
        . ' --wildcards ' . escapeshellarg('backup/*.sql'), 7200, ['stderr' => 'discard']);
    foreach (glob($stage . '/backup/*.sql') ?: [] as $sql) {
        if (@rename($sql, $mysqlDir . '/' . basename($sql))) { $dumps++; }
        elseif (@copy($sql, $mysqlDir . '/' . basename($sql))) { $dumps++; }
        else $warn[] = 'Database dump ' . basename($sql) . ' could not be placed, so that database would restore empty.';
    }
    if ($dumps) $steps++;

    // Ownership: cPanel fixes this during the restore, but leaving root-owned files in a homedir that a restore
    // might reuse verbatim is not worth the risk.
    smpro_run('chown -R ' . escapeshellarg($user . ':' . $user) . ' ' . escapeshellarg($home), 3600, ['stderr' => 'discard']);
    smpro_run('rm -rf ' . escapeshellarg($stage), 600, ['stderr' => 'discard']);

    return ['ok' => true, 'error' => '', 'warnings' => $warn, 'steps' => $steps,
            'sites' => $moved, 'mailboxes' => $boxes, 'databases' => $dumps];
}

/** Pack the finished tree as the cpmove archive cPanel restores from. */
function smpro_mig_da_pack(string $cpmoveRoot): array {
    $parent = dirname($cpmoveRoot);
    $name   = basename($cpmoveRoot);
    $out    = $parent . '/' . $name . '.tar.gz';
    @unlink($out);
    [$rc] = smpro_run_rc('tar czf ' . escapeshellarg($out) . ' -C ' . escapeshellarg($parent) . ' ' . escapeshellarg($name), 14400, ['stderr' => 'discard']);
    if ($rc !== 0 || !is_file($out)) return ['ok' => false, 'error' => 'The converted account could not be packaged.'];
    return ['ok' => true, 'error' => '', 'archive' => $out, 'bytes' => (int)@filesize($out)];
}
