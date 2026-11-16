<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t187 - every home, not /home alone. On a real server half the accounts live on /home2. Site Doctor answered
 * 'not a valid non-system cPanel account' for each of them and refused every repair; other tools skipped them;
 * several scans never looked there at all.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

foreach (['includes/investigate.php', 'includes/clearcache.php', 'includes/ai.php', 'includes/compcheck.php', 'includes/intrusion.php',
          'includes/maintenance.php', 'includes/phlock.php', 'modules/database-cleanup.php', 'modules/imunify360-reports.php',
          'modules/user-investigation.php', 'modules/disk-storage.php', 'modules/spam-phishing.php', 'modules/forensics-audit.php'] as $f) {
    $s = $src($f);
    ok(!preg_match("#'/home/'\\) [!=]== 0#", $s) && strpos($s, "'#^/home/") === false, 'H: ' . $f . ' has no /home-only path test left');
}
$re = '#^/home\d*/#';
foreach (['/home/a/public_html' => 1, '/home2/a/public_html' => 1, '/home10/a/x' => 1, '/homework/a' => 0, '/etc/home/a' => 0, '/home' => 0] as $p => $want)
    is_eq((int)preg_match($re, $p), $want, 'P: ' . $p . ($want ? ' is' : ' is not') . ' inside a home root');

$cc = $src('includes/clearcache.php');
has($cc, "if (\$home === '' || !preg_match('#^/home\\d*/#', (string)\$home)) return false;", 'C1: an account whose home is on another root is a valid account');
has($cc, "if (!preg_match('#^/home\\d*/#', (string)\$docroot) || strpos(\$docroot, '..') !== false)", 'C2: and its web root is accepted');

ok(function_exists('smpro_home_roots') && function_exists('smpro_home_dirs') && function_exists('smpro_home_glob'), 'R0: the home-root helpers exist');
$roots = smpro_home_roots();
ok(is_array($roots) && count($roots) >= 1, 'R1: there is always at least one root');
foreach ($roots as $r) ok((bool)preg_match('#^/home\d*$#', $r), 'R2: ' . $r . ' is a home root by name');
has($src('includes/helpers.php'), "if (preg_match('#^/home\\d*\$#', (string)\$d) && !is_link(\$d)) \$r[] = (string)\$d;", 'R3: a name that is a link to another root is not walked twice');

has($src('includes/compcheck.php'), "smpro_home_dirs()", 'S1: the compromise check looks in every home');
$fa = $src('modules/forensics-audit.php');
has($fa, "smpro_home_glob('/.ssh/authorized_keys')", 'S2: the SSH-key audit reads the keys of every account');
has($fa, "array_slice(smpro_home_dirs(), 0, 1200)", 'S3: the dot-file audit walks every home');
has($fa, "array_map(fn(\$hr) => \$hr . '/*/public_html', smpro_home_roots())", 'S4: the .htaccess scan covers every web root');
has($src('modules/imunify360-reports.php'), "find \" . implode(' ', smpro_home_roots()) . \" -maxdepth 8", 'S5: the duplicate hunt covers every root');
is_eq(substr_count($src('modules/disk-storage.php'), 'smpro_ds_wrap("find " . $smproHR . " -'), 3, 'S6: the three disk reports cover every root');

$lf = $src('includes/loginfeed.php');
has($lf, "foreach ((\$status === '401' ? [0, 1, 2] : [2]) as \$w) {", 'L1: a failed login is matched by the same second first; a successful one is never narrowed');
has($lf, "smpro_audit('login_unattributed'", 'L2: a login that could not be given to one address is counted and said');
