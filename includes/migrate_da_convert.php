<?php
/**
 * Safety Monitor Pro - DirectAdmin -> cpmove converter (metadata).
 *
 * Stage two of the DirectAdmin route. It writes the parts of a cPanel cpmove archive that DESCRIBE the account,
 * translated from DirectAdmin's own files. The bulk - home directory, mail store, SQL dumps - is copied by the
 * caller; there is no format question in moving bytes, and all of the risk lives here in the translation.
 *
 * The output is handed to cPanel's own restore, so cPanel validates this converter's work rather than this code
 * having the last word on whether an account is correct.
 *
 * Both formats were read from real files, not documentation: DirectAdmin from a live 9.7 GB account backup,
 * cPanel from the output of `pkgacct` on a cPanel 11.136 server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** DirectAdmin writes "unlimited" where cPanel writes 0. Anything else is a number in megabytes. */
/** A hostname and nothing else: labels of letters, digits and hyphens, dots between, at most 253 characters. */
function smpro_mig_da_hostname_ok(string $h): bool {
    return (bool)preg_match('/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/', $h);
}

function smpro_mig_da_num($v, $mult = 1) {
    $v = trim((string)$v);
    if ($v === '' || strcasecmp($v, 'unlimited') === 0) return 0;
    if (!is_numeric($v)) return 0;
    return (int)round((float)$v * $mult);
}

/** cPanel counts "how many are allowed" as a number or the word unlimited; DirectAdmin uses the same shape. */
function smpro_mig_da_max($v) {
    $v = trim((string)$v);
    return ($v === '' || strcasecmp($v, 'unlimited') === 0) ? 'unlimited' : (string)(int)$v;
}

/**
 * Build the cpmove metadata tree from an extracted DirectAdmin backup.
 *
 * $localIp matters: DirectAdmin records the address the account lived on at the SOURCE, and carrying that over
 * produces an account bound to an address this server does not hold - it restores without complaint and then
 * serves nothing. The destination's own IP is written instead, and the original is kept only as a note.
 *
 * Returns ['ok','dest','user','files'=>int,'warnings'=>[]].
 */
function smpro_mig_da_build_meta(string $metaDir, string $destDir, string $localIp = '', array $opt = []): array {
    $b = rtrim($metaDir, '/') . '/backup';
    $warn = [];
    if (!is_dir($b)) return ['ok' => false, 'error' => 'No extracted DirectAdmin backup at that path.', 'warnings' => []];

    $uc = smpro_mig_da_conf($b . '/user.conf');
    $user = (string)($uc['name'] ?? '');
    if ($user === '' || !preg_match('/^[a-z0-9][a-z0-9_-]{0,15}$/i', $user)) {
        return ['ok' => false, 'error' => 'user.conf has no username this server could create an account under.', 'warnings' => []];
    }
    $mainDomain = strtolower(trim((string)($uc['domain'] ?? '')));
    if ($mainDomain === '') return ['ok' => false, 'error' => 'user.conf names no main domain.', 'warnings' => []];
    // The archive is a third party's file: every name in it is untrusted input. A domain is only ever used as a
    // file name below, so it must be a hostname and nothing else - "../../root/.ssh/authorized_keys" is not one.
    if (!smpro_mig_da_hostname_ok($mainDomain)) return ['ok' => false, 'error' => 'user.conf names a main domain that is not a valid hostname.', 'warnings' => []];

    if ($localIp === '') {
        $localIp = trim((string)@file_get_contents('/var/cpanel/mainip'));
        if ($localIp === '') { $localIp = '0.0.0.0'; $warn[] = 'This server\'s main IP could not be read, so the account is written with a placeholder address and must be given one before it will serve.'; }
    }

    $root = rtrim($destDir, '/') . '/cpmove-' . $user;
    foreach (['cp', 'meta', 'mysql', 'userdata', 'dnszones', 'sslcerts', 'sslkeys', 'apache_tls', 'va', 'vf', 'cron', 'homedir'] as $d) {
        if (!is_dir($root . '/' . $d) && !@mkdir($root . '/' . $d, 0700, true)) {
            return ['ok' => false, 'error' => 'Could not create ' . $d . '/ in the working directory.', 'warnings' => $warn];
        }
    }
    $files = 0;
    $put = function ($rel, $content) use ($root, &$files) {
        if ($rel === '' || $rel[0] === '/' || strpos($rel, '..') !== false || strpos($rel, "\0") !== false) return false;   // never outside $root, whatever the archive says
        if (@file_put_contents($root . '/' . $rel, $content) === false) return false;
        @chmod($root . '/' . $rel, 0600); $files++; return true;
    };

    /* ---- cp/<user> - the file cPanel actually reads to recreate the account ---- */
    $created = strtotime((string)($uc['date_created'] ?? '')) ?: time();
    $suspended = (($uc['suspended'] ?? 'no') === 'yes') || (($uc['account'] ?? 'ON') === 'OFF');
    $cp = [
        'DNS'             => $mainDomain,
        'USER'            => $user,
        'OWNER'           => 'root',
        'PLAN'            => (string)($uc['package'] ?? 'default'),
        'CONTACTEMAIL'    => (string)($uc['email'] ?? ''),
        'IP'              => $localIp,
        'BWLIMIT'         => smpro_mig_da_num($uc['bandwidth'] ?? 'unlimited', 1024 * 1024),
        'DISK_BLOCK_LIMIT'=> smpro_mig_da_num($uc['quota'] ?? 'unlimited', 1024),
        'MAXSQL'          => smpro_mig_da_max($uc['mysql'] ?? 'unlimited'),
        'MAXPOP'          => smpro_mig_da_max($uc['nemails'] ?? 'unlimited'),
        'MAXFTP'          => smpro_mig_da_max($uc['ftp'] ?? 'unlimited'),
        'MAXSUB'          => smpro_mig_da_max($uc['nsubdomains'] ?? 'unlimited'),
        'MAXPARK'         => smpro_mig_da_max($uc['domainptr'] ?? '0'),
        'MAXADDON'        => smpro_mig_da_max($uc['vdomains'] ?? '0'),
        'MAXLST'          => smpro_mig_da_max($uc['nemailml'] ?? '0'),
        'STARTDATE'       => $created,
        'SUSPENDED'       => $suspended ? 1 : 0,
        'FEATURELIST'     => 'default',
        'LOCALE'          => (string)($uc['language'] ?? 'en'),
        'MAILBOX_FORMAT'  => 'maildir',
        'HASCGI'          => (($uc['cgi'] ?? 'OFF') === 'ON') ? 1 : 0,
        'BACKUP'          => 1,
        'DEMO'            => 0,
    ];
    $lines = "# Converted from a DirectAdmin backup by " . SMPRO_NAME . ".\n";
    $lines .= "# Source server address was " . (string)($uc['ip'] ?? 'unknown') . "; this account is bound to " . $localIp . " instead.\n";
    foreach ($cp as $k => $v) $lines .= $k . '=' . $v . "\n";
    $put('cp/' . $user, $lines);

    // DirectAdmin's bandwidth and quota are megabytes; cPanel wants bytes and 1 KB blocks. A wrong unit here is
    // invisible at restore time and only shows up as an account that suspends early, so it is called out.
    if (strcasecmp(trim((string)($uc['bandwidth'] ?? '')), 'unlimited') !== 0 && trim((string)($uc['bandwidth'] ?? '')) !== '') {
        $warn[] = 'Bandwidth was converted from ' . $uc['bandwidth'] . ' MB to bytes. Check it against the plan before the account goes live.';
    }
    if (strcasecmp(trim((string)($uc['quota'] ?? '')), 'unlimited') !== 0 && trim((string)($uc['quota'] ?? '')) !== '') {
        $warn[] = 'Disk quota was converted from ' . $uc['quota'] . ' MB to 1 KB blocks. Check it against the plan before the account goes live.';
    }

    /* ---- shadow: the account password, if it travelled ---- */
    if (is_file($b . '/.shadow')) {
        $sh = trim((string)@file_get_contents($b . '/.shadow'));
        // DirectAdmin stores the crypt hash on its own; cPanel expects a shadow line keyed by username.
        if ($sh !== '') { $put('shadow', $user . ':' . $sh . ':' . (int)floor($created / 86400) . ":0:99999:7:::\n"); }
        else $warn[] = 'The .shadow file is empty, so the account password does not carry over and must be reset.';
    } else {
        $warn[] = 'No .shadow in the backup, so the account password does not carry over and must be reset.';
    }

    /* ---- cron ---- */
    if (is_file($b . '/crontab.conf')) $put('cron/' . $user, (string)@file_get_contents($b . '/crontab.conf'));

    /* ---- databases: dumps are copied by the caller; the grants are rebuilt here ---- */
    $grants = "-- Rebuilt from DirectAdmin's per-database settings.\n";
    $dbCount = 0;
    foreach (glob($b . '/*.conf') ?: [] as $conf) {
        $name = basename($conf, '.conf');
        if (in_array($name, ['user', 'crontab', 'ticket'], true) || !preg_match('/^[A-Za-z0-9_]+$/', $name)) continue;
        $dbCount++;
        $put('mysql/' . $name . '.create',
            "CREATE DATABASE IF NOT EXISTS `" . $name . "`;\n");
        $dc = smpro_mig_da_conf($conf);
        foreach ($dc as $k => $v) {
            if ($k === 'accesshosts' || $k === 'db_collation') continue;
            // Each remaining key is a database user; the value is a query string of privileges and passwd.
            parse_str(str_replace('&amp;', '&', $v), $p);
            $pw = (string)($p['passwd'] ?? '');
            if ($pw === '') { $warn[] = 'Database user "' . $k . '" has no password in the backup and will need one set.'; continue; }
            // The hash is carried across as-is so no password is invented. The syntax matters: IDENTIFIED BY
            // PASSWORD was REMOVED in MySQL 8.0, so a grants file written that way is a syntax error there - the
            // databases come back with no user able to reach them, the site is down, and nothing in the restore
            // log calls it a failure. IDENTIFIED WITH ... AS is accepted by MySQL 5.7, MySQL 8 and MariaDB.
            if (!preg_match('/^\*[0-9A-Fa-f]{40}$/', $pw)) {
                $warn[] = 'Database user "' . $k . '" has a password in a format that cannot be carried over, so it needs a new one set before the site can reach its database.';
                continue;
            }
            $grants .= "CREATE USER IF NOT EXISTS '" . addslashes($k) . "'@'localhost' IDENTIFIED WITH mysql_native_password AS '" . addslashes($pw) . "';\n";
            $grants .= "GRANT ALL PRIVILEGES ON `" . $name . "`.* TO '" . addslashes($k) . "'@'localhost';\n";
        }
    }
    if ($dbCount) $put('mysql.sql', $grants);

    /* ---- per-domain: userdata, DNS zone, SSL, forwarders, autoresponders ---- */
    $domCount = 0;
    foreach (glob($b . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
        if (!is_file($dir . '/domain.conf')) continue;
        $dc = smpro_mig_da_conf($dir . '/domain.conf');
        $dom = strtolower(trim((string)($dc['domain'] ?? basename($dir))));
        if (!smpro_mig_da_hostname_ok($dom)) { $warn[] = 'Skipped a domain entry whose name is not a valid hostname (' . mb_substr($dom, 0, 40) . ').'; continue; }
        $domCount++;

        $docroot = smpro_user_home($user) . '/public_html';
        $ud = "---\n"
            . "documentroot: " . $docroot . "\n"
            . "group: " . $user . "\n"
            . "homedir: /home/" . $user . "\n"
            . "ip: " . $localIp . "\n"
            . "owner: root\n"
            . "servername: " . $dom . "\n"
            . "serveralias: www." . $dom . "\n"
            . "user: " . $user . "\n"
            . "usecanonicalname: '" . ((($dc['UseCanonicalName'] ?? 'OFF') === 'ON') ? 'On' : 'Off') . "'\n";
        $put('userdata/' . $dom, $ud);

        if (is_file($dir . '/' . $dom . '.db')) $put('dnszones/' . $dom . '.db', (string)@file_get_contents($dir . '/' . $dom . '.db'));
        else $warn[] = 'Domain ' . $dom . ' has no DNS zone in the backup, so its records will be rebuilt from this server\'s defaults.';

        if (is_file($dir . '/domain.cert') && is_file($dir . '/domain.key')) {
            $crt = (string)@file_get_contents($dir . '/domain.cert');
            $key = (string)@file_get_contents($dir . '/domain.key');
            $cab = is_file($dir . '/domain.cacert') ? (string)@file_get_contents($dir . '/domain.cacert') : '';
            $put('sslcerts/' . $dom, $crt);
            $put('sslkeys/' . $dom, $key);
            // apache_tls/<domain> is what cPanel's restore installs the certificate FROM: private key first,
            // then the certificate, then the issuer chain. Writing only sslcerts/ and sslkeys/ leaves the site
            // on the self-signed certificate cPanel generates for a new account - HTTPS answers, the site
            // serves, and every browser reports the wrong certificate.
            //
            // The name is cPanel's own datastore, not a statement about Apache: it is the same store whether
            // the server runs EA4 Apache, Apache behind ea-nginx, or LiteSpeed, because all three take their
            // TLS from cPanel rather than holding their own copy. Nothing here requires Apache to be installed
            // - this only writes a file into the archive, and cPanel decides where it lands.
            $put('apache_tls/' . $dom, rtrim($key) . "\n" . rtrim($crt) . "\n" . ($cab !== '' ? rtrim($cab) . "\n" : ''));
            if ($cab === '') {
                $warn[] = 'Domain ' . $dom . ' has a certificate but no issuer chain in the backup. It will serve HTTPS, but some clients will not trust it until the chain is supplied or a new certificate is issued.';
            }
        } elseif (($dc['ssl'] ?? 'OFF') === 'ON') {
            $warn[] = 'Domain ' . $dom . ' had SSL enabled but no certificate is in the backup, so it will come back on plain HTTP until one is issued.';
        }

        // Forwarders: DirectAdmin "alias: target" -> cPanel's vf/<domain> "alias: target" (same shape).
        if (is_file($dir . '/email/aliases')) $put('vf/' . $dom, (string)@file_get_contents($dir . '/email/aliases'));
        if (is_file($dir . '/email/vacation.conf')) $put('va/' . $dom, (string)@file_get_contents($dir . '/email/vacation.conf'));

        // Mailbox passwords. DirectAdmin keeps them in email/passwd as "<name>:$6$salt$hash" and ships no shadow
        // file at all; cPanel reads them from homedir/etc/<domain>/shadow as "<name>:<hash>:<days>::::::".
        // Without this the mailboxes restore with their mail intact and nobody able to sign in - and the owner
        // finds out when a customer cannot read their email, not during the migration.
        $pwFile = $dir . '/email/passwd';
        if (is_file($pwFile)) {
            $shadow = ''; $boxes = 0; $day = (int)floor(time() / 86400);
            foreach (explode("\n", (string)@file_get_contents($pwFile)) as $l) {
                $l = trim($l); if ($l === '' || strpos($l, ':') === false) continue;
                [$box, $hash] = array_pad(explode(':', $l, 3), 2, '');
                $box = trim($box); $hash = trim($hash);
                if ($box === '' || $hash === '') continue;
                $shadow .= $box . ':' . $hash . ':' . $day . "::::::\n";
                $boxes++;
            }
            if ($boxes) {
                @mkdir($root . '/homedir/etc/' . $dom, 0755, true);
                $put('homedir/etc/' . $dom . '/shadow', $shadow);
                if (is_file($dir . '/email/quota')) $put('homedir/etc/' . $dom . '/quota', (string)@file_get_contents($dir . '/email/quota'));
                // The matching passwd file carries the account's numeric uid, which does not exist until the
                // account is created - a guessed one is worse than none, so cPanel rebuilds that side itself.
                $warn[] = $boxes . ' mailbox password(s) for ' . $dom . ' were carried over. Sign in to one after the restore to confirm they took, because a mailbox with its mail but a broken login looks completely normal until someone tries to read it.';
            }
        } elseif (is_dir($dir . '/email')) {
            $warn[] = 'No mailbox passwords are in the backup for ' . $dom . ', so every mailbox on it will need a new password set after the restore.';
        }
    }
    if (!$domCount) $warn[] = 'No domain was found in the backup, so the converted account would serve nothing.';

    /* ---- meta/ - what cPanel checks before it will accept the archive ---- */
    $put('meta/version', "2\n");
    $put('meta/hostname', (string)php_uname('n') . "\n");
    $put('meta/mailserver', "dovecot\n");
    $put('meta/homedir_paths', smpro_user_home($user) . "\n");
    $put('version', "2\n");

    return ['ok' => true, 'error' => '', 'dest' => $root, 'user' => $user, 'main_domain' => $mainDomain,
            'files' => $files, 'domains' => $domCount, 'databases' => $dbCount, 'warnings' => $warn];
}
