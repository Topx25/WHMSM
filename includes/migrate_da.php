<?php
/**
 * Safety Monitor Pro — DirectAdmin archive reader.
 *
 * Stage one of the DirectAdmin route: understand the archive before anything is converted. Everything here is
 * READ-ONLY and derived from a real DirectAdmin 1.6x backup, not from documentation — the layout below was
 * mapped from an actual `user.admin.<name>.tar.gz`:
 *
 *   backup/        user.conf, .shadow, crontab.conf, <db>.conf + <db>.sql, email_data/,
 *                  home.tar.gz (a nested archive of the home directory), and one directory per domain holding
 *                  domain.conf, the DNS zone, SSL material, ftp.passwd and email/ (passwd, aliases, quota,
 *                  vacation.conf, autoresponder.conf)
 *   domains/       the served content — public_html, private_html, public_ftp, logs, stats
 *   imap/          the mailboxes themselves
 *
 * The reader exists so the operator sees exactly what an archive holds — accounts, domains, databases,
 * mailboxes — and, just as importantly, what this could NOT read, BEFORE a restore is offered. A converter
 * that silently drops a mailbox is worse than one that refuses, because the loss surfaces days later.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Parse DirectAdmin's key=value config files. Values may be URL-encoded query strings; kept raw here. */
function smpro_mig_da_conf(string $file): array {
    $out = [];
    foreach (explode("\n", (string)@file_get_contents($file)) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $eq = strpos($line, '=');
        if ($eq === false) continue;
        $out[substr($line, 0, $eq)] = substr($line, $eq + 1);
    }
    return $out;
}

/**
 * Extract just the metadata from a DirectAdmin archive into $dest.
 * home.tar.gz and the served content are deliberately excluded — on a real archive those are almost all of the
 * bytes (9.7 GB in the sample, of which the metadata was a few MB), and none of it is needed to describe the
 * account. The whole stream is still read because tar is sequential, so callers must treat this as a slow job.
 */
/**
 * Refuse an archive that would write outside where it is unpacked.
 * A tar member named /etc/passwd or ../../root/.ssh/authorized_keys is extracted to exactly that path unless
 * something stops it, so a backup handed over by a departing customer is untrusted input like any other. tar's
 * own stripping is not relied on — the archive is inspected and rejected before a single byte is written.
 */
function smpro_mig_da_path_check(string $archive, int $timeout = 3600): array {
    $bad = smpro_run('tar tzf ' . escapeshellarg($archive) . ' 2>/dev/null | grep -E ' . escapeshellarg('(^/|(^|/)\.\.(/|$))') . ' | head -n 5',
        $timeout, ['stderr' => 'discard']);
    $bad = trim($bad);
    if ($bad !== '') {
        return ['ok' => false, 'why' => 'This archive contains paths that would write outside the folder it is '
            . 'unpacked into, so it is not being opened: ' . str_replace("\n", ' , ', $bad)];
    }
    return ['ok' => true, 'why' => ''];
}

function smpro_mig_da_extract_meta(string $archive, string $dest, int $timeout = 1800): array {
    if (!is_file($archive)) return ['ok' => false, 'error' => 'Archive not found.'];
    if (!is_dir($dest) && !@mkdir($dest, 0700, true)) return ['ok' => false, 'error' => 'Could not create the working directory.'];
    $cmd = 'tar xzf ' . escapeshellarg($archive) . ' -C ' . escapeshellarg($dest)
         . ' --exclude=' . escapeshellarg('backup/home.tar.gz')
         . ' --wildcards ' . escapeshellarg('backup/*');
    [$rc, $out] = smpro_run_rc($cmd, $timeout, ['stderr' => 'merge']);
    if (!is_dir($dest . '/backup')) return ['ok' => false, 'error' => 'No backup/ directory came out of the archive: ' . trim($out)];
    return ['ok' => true, 'error' => '', 'rc' => $rc];
}

/**
 * Describe an already-extracted DirectAdmin metadata tree.
 * Returns ['ok','account','domains','databases','totals','warnings'].
 * A warning is not cosmetic: it names a part of the account that could not be read, and the caller must show it
 * rather than present the parts that did read as the whole picture.
 */
function smpro_mig_da_describe(string $metaDir): array {
    $b = rtrim($metaDir, '/') . '/backup';
    $warn = [];
    if (!is_dir($b)) return ['ok' => false, 'error' => 'This is not an extracted DirectAdmin backup.', 'warnings' => []];

    $uc = smpro_mig_da_conf($b . '/user.conf');
    if (!$uc) return ['ok' => false, 'error' => 'backup/user.conf is missing or empty, so the account cannot be identified.', 'warnings' => []];

    $account = [
        'username'    => (string)($uc['name'] ?? ''),
        'main_domain' => (string)($uc['domain'] ?? ''),
        'email'       => (string)($uc['email'] ?? ''),
        'package'     => (string)($uc['package'] ?? ''),
        'created'     => (string)($uc['date_created'] ?? ''),
        'source_ip'   => (string)($uc['ip'] ?? ''),
        'suspended'   => (($uc['suspended'] ?? 'no') === 'yes') || (($uc['account'] ?? 'ON') === 'OFF'),
        'quota'       => (string)($uc['quota'] ?? ''),
        'bandwidth'   => (string)($uc['bandwidth'] ?? ''),
        'inodes'      => (string)($uc['inode'] ?? ''),
        'ns1'         => (string)($uc['ns1'] ?? ''),
        'ns2'         => (string)($uc['ns2'] ?? ''),
        'shell'       => (($uc['ssh'] ?? 'OFF') === 'ON'),
        'has_shadow'  => is_file($b . '/.shadow'),
        'has_cron'    => is_file($b . '/crontab.conf'),
    ];
    if ($account['username'] === '')   $warn[] = 'user.conf has no name field, so the account has no username to restore under.';
    if (!$account['has_shadow'])       $warn[] = 'No .shadow in the archive — the account password cannot be carried over and will have to be reset.';

    // Databases arrive as a <name>.conf / <name>.sql pair. A .conf without its .sql is an empty database in
    // waiting: the schema and grants are described but there is no data to load.
    $databases = [];
    foreach (glob($b . '/*.sql') ?: [] as $sql) {
        $name = basename($sql, '.sql');
        $conf = $b . '/' . $name . '.conf';
        $databases[] = ['name' => $name, 'bytes' => (int)@filesize($sql), 'has_grants' => is_file($conf)];
    }
    foreach (glob($b . '/*.conf') ?: [] as $conf) {
        $name = basename($conf, '.conf');
        if (in_array($name, ['user', 'crontab', 'ticket'], true)) continue;
        if (is_file($b . '/' . $name . '.sql')) continue;
        if (!preg_match('/^[A-Za-z0-9_]+$/', $name)) continue;
        $databases[] = ['name' => $name, 'bytes' => 0, 'has_grants' => true];
        $warn[] = 'Database "' . $name . '" has its settings but no .sql dump, so it would be restored empty.';
    }

    // One directory per domain, identified by its domain.conf rather than by the name looking domain-shaped.
    $domains = [];
    foreach (glob($b . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
        $dconf = $dir . '/domain.conf';
        if (!is_file($dconf)) continue;
        $dc = smpro_mig_da_conf($dconf);
        $name = (string)($dc['domain'] ?? basename($dir));

        $mailboxes = 0;
        $pw = $dir . '/email/passwd';
        if (is_file($pw)) {
            foreach (explode("\n", (string)@file_get_contents($pw)) as $l) if (trim($l) !== '' && strpos($l, ':') !== false) $mailboxes++;
        }
        $forwarders = 0;
        $al = $dir . '/email/aliases';
        if (is_file($al)) {
            foreach (explode("\n", (string)@file_get_contents($al)) as $l) if (trim($l) !== '' && strpos($l, ':') !== false) $forwarders++;
        }
        $subs = [];
        if (is_file($dir . '/subdomain.list')) {
            foreach (explode("\n", (string)@file_get_contents($dir . '/subdomain.list')) as $l) { $l = trim($l); if ($l !== '') $subs[] = $l; }
        }
        $hasCert = is_file($dir . '/domain.cert') && is_file($dir . '/domain.key');
        if (($dc['ssl'] ?? 'OFF') === 'ON' && !$hasCert) {
            $warn[] = 'Domain ' . $name . ' has SSL switched on but its certificate is not in the archive, so it would come back on plain HTTP.';
        }
        $domains[] = [
            'domain'     => $name,
            'active'     => (($dc['active'] ?? 'yes') === 'yes'),
            'suspended'  => (($dc['suspended'] ?? 'no') === 'yes'),
            'is_main'    => (($dc['defaultdomain'] ?? 'no') === 'yes'),
            'ssl'        => (($dc['ssl'] ?? 'OFF') === 'ON'),
            'has_cert'   => $hasCert,
            'force_ssl'  => (($dc['force_ssl'] ?? 'no') === 'yes'),
            'php'        => (($dc['php'] ?? 'OFF') === 'ON'),
            'subdomains' => $subs,
            'mailboxes'  => $mailboxes,
            'forwarders' => $forwarders,
            'has_zone'   => is_file($dir . '/' . $name . '.db'),
            'has_ftp'    => is_file($dir . '/ftp.passwd'),
        ];
        if (!$domains[count($domains) - 1]['has_zone']) {
            $warn[] = 'Domain ' . $name . ' has no DNS zone in the archive, so its records would be rebuilt from defaults.';
        }
    }
    if (!$domains) $warn[] = 'No domain directory was found, so nothing would be served after a restore.';

    $totals = [
        'domains'    => count($domains),
        'subdomains' => array_sum(array_map(fn($d) => count($d['subdomains']), $domains)),
        'databases'  => count($databases),
        'db_bytes'   => array_sum(array_map(fn($d) => $d['bytes'], $databases)),
        'mailboxes'  => array_sum(array_map(fn($d) => $d['mailboxes'], $domains)),
        'forwarders' => array_sum(array_map(fn($d) => $d['forwarders'], $domains)),
    ];
    return ['ok' => true, 'error' => '', 'account' => $account, 'domains' => $domains,
            'databases' => $databases, 'totals' => $totals, 'warnings' => $warn];
}

/** Read a DirectAdmin archive end to end: extract the metadata, then describe it. Slow — run it detached. */
function smpro_mig_da_read(string $archive, string $workDir = ''): array {
    $work = $workDir !== '' ? $workDir : SMPRO_VARLIB . '/migrate_work/' . substr(sha1($archive), 0, 12);
    $x = smpro_mig_da_extract_meta($archive, $work);
    if (!$x['ok']) return ['ok' => false, 'error' => $x['error'], 'warnings' => []];
    $d = smpro_mig_da_describe($work);
    $d['work_dir'] = $work;
    return $d;
}
