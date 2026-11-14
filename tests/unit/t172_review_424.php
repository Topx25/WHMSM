<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t172 - the writers that rewrite a file inside an account's folder, a home-move rollback that deleted what was
 * written after the move, a "safe junk" list that offered source folders, and a hunt that overwrote lessons the
 * operator changed while it ran.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

is_eq(smpro_acct_rewrite('root', '/tmp/x', 'y')[0], false, 'A1: a rewrite as root is refused');
$iv = $src('includes/investigate.php');
has($iv, "[\$aok, \$abak, \$awhy] = smpro_acct_rewrite((string)\$user, \$ht, (string)\$new, \$ht . '.smpro-bak-' . date('Ymd_His') . '-' . \$rnd);", 'A2: Site Doctor rewrites .htaccess as the account');
has($src('includes/intrusion.php'), "[\$aok, \$abak] = smpro_acct_rewrite(\$acct, \$ht, (string)\$content,", 'A3: the emergency hardening writes as the account');
$ph = $src('modules/php-harden.php');
has($ph, "if (!smpro_acct_put(\$acct, \$ht, \$content, 0644)) return", 'A4: the upload-folder guard is written as the account (it also runs unattended)');
has($ph, "\$content = \$acct !== '' ? (string)smpro_acct_get(\$acct, \$ht, 2097152) : (string)@file_get_contents(\$ht);", 'A5: ...and the old content is read as the account');
has($src('modules/forensics-audit.php'), "if (\$acct !== '' && function_exists('smpro_acct_put')) return smpro_acct_put(\$acct, \$file, implode(\"\\n\", \$lines) . \"\\n\");", 'A6: a cleaned file is rewritten by the account, keeping its mode');

$real = DIRECTORY_SEPARATOR === '/' && function_exists('posix_geteuid') && posix_geteuid() === 0 && is_array(@posix_getpwnam('nobody'))
     && (is_executable('/usr/sbin/runuser') || is_executable('/sbin/runuser') || is_executable('/usr/bin/runuser'));
if (!$real) tap_skip('B: real rewrite as an unprivileged user', 'needs root on Linux with runuser and the user nobody');
else {
    $pw = posix_getpwnam('nobody');
    $d = sys_get_temp_dir() . '/smpro-rw-' . bin2hex(random_bytes(5)); mkdir($d, 0755); chown($d, $pw['uid']); chgrp($d, $pw['gid']);
    $ht = $d . '/.htaccess';
    [$ok, $bak, $why] = smpro_acct_rewrite('nobody', $ht, "Options -Indexes\n", $ht . '.bak1');
    ok($ok && $bak === '' && file_get_contents($ht) === "Options -Indexes\n", 'B1: a new file is written, with no backup to keep');
    [$ok, $bak, $why] = smpro_acct_rewrite('nobody', $ht, "Options -Indexes\nDeny from all\n", $ht . '.bak2');
    ok($ok && $bak === $ht . '.bak2' && file_get_contents($bak) === "Options -Indexes\n", 'B2: an existing file is kept beside it first');
    ok((stat($bak)['mode'] & 0777) === 0600 && stat($bak)['uid'] === $pw['uid'], 'B3: the kept copy is the account\'s, private');
    unlink($ht); symlink('/etc/hostname', $ht);
    [$ok, $bak, $why] = smpro_acct_rewrite('nobody', $ht, "evil\n", $ht . '.bak3');
    ok(!$ok && $why !== '' && !file_exists($ht . '.bak3'), 'B4: a file that became a link is refused, and nothing of its target is copied');
    ok(trim((string)file_get_contents('/etc/hostname')) !== 'evil', 'B5: the file behind the link is untouched');
    @unlink($ht); @unlink($ht . '.bak2'); @rmdir($d);
}

$hm = $src('bin/home_move.php');
has($hm, "rsync -aHAXS --numeric-ids --update ' . escapeshellarg(\$dst . '/') . ' ' . escapeshellarg(\$src . '/')", 'C1: a rollback copies back what was written after the move');
ok(strpos($hm, "if (preg_match('/rc=(0|24)\\s*\$/', trim(\$rb))) hm_sh('rm -rf ' . escapeshellarg(\$dst), 0);") !== false && strpos($hm, 'else $keptCopy = true;') !== false, 'C2: ...and removes the copy only when that worked');
$ds = $src('modules/disk-storage.php');
ok(strpos($ds, "-o -ipath '*/vendor' -o -ipath '*/library' -o -ipath '*/lib' -o -ipath '*/src' -o -ipath '*/includes'") !== false && strpos($ds, "-not -iname '*.php' -not -iname '*.phtml' -not -iname '*.inc' \\\\( -ipath '*/cache/*'") !== false, 'D1: "safe junk" never lists code files or dependency / source trees');
$lr = $src('includes/learn.php');
has($lr, "\$Lnow = smpro_lr_lessons(); \$allowNow = array_flip(smpro_lr_load('allow'));", 'E1: the hunt reads the lessons and the allow list again before it writes');
has($lr, "smpro_lr_save('lessons', \$Lnow);", 'E2: ...and saves that fresh copy with its own hit counts');
has($lr, "&& !isset(\$allowNow[(string)(\$f['sha'] ?? '')])) {", 'E3: a file marked as not malicious during the hunt is not quarantined by it');
has($src('modules/learned-defense.php'), "(\$L0[\$lid]['state'] ?? 'on') === 'on'", 'E4: a lesson that was switched off no longer selects files for quarantine');
