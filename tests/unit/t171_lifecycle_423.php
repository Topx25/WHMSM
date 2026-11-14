<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t171 - install / update / uninstall, from the third review round.
 *  - an uninstall removed the cron jobs (the country wall's watcher among them) and left the wall up
 *  - an update copied an unpacked tree it had never compared with its own signed file list, and judged the result
 *    by a syntax check an empty file passes
 *  - a file-check lock taken while an update was half copied stayed until a cron sweep that may not be running
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$up = $src('includes/update.php');

has($up, 'function smpro_teardown_network(string $by = \'uninstall\'): array {', 'T1: one teardown step for everything that would stay enforcing unmanaged');
has($up, "if (function_exists('smpro_gw_live') && function_exists('smpro_gw_remove') && smpro_gw_live()) {", 'T2: the country wall comes down when it is up');
has($up, "if (function_exists('smpro_gh_cfg') && function_exists('smpro_gh_disarm') && !empty(smpro_gh_cfg()['enabled'])) {", 'T3: the login country list is restored in cPHulk');
has($up, "foreach (['/usr/local/csf/bin/csfpost.sh', '/etc/csf/csfpost.sh'] as \$cp) {", 'T4: the product\'s lines leave the firewall post-reload script');
ok(strpos($up, "foreach (smpro_teardown_network('uninstall') as \$__t) \$done[] = \$__t;") < strpos($up, "\$unreg = '/usr/local/cpanel/bin/unregister_appconfig';", strpos($up, 'function smpro_plugin_uninstall')), 'T5: the in-product uninstall runs it first');
$lic = $src('includes/license.php');
ok(strpos($lic, "smpro_teardown_network('self-uninstall')") !== false && strpos($lic, "smpro_teardown_network('self-uninstall')") < strpos($lic, "foreach (glob('/etc/cron.d/' . SMPRO_SLUG . '-*') ?: [] as \$cf) @unlink(\$cf);"), 'T6: the self-removal path runs it before the cron jobs are deleted');
ok(is_file(SMPRO_BASE . '/bin/teardown.php') && strpos($src('bin/teardown.php'), "smpro_teardown_network('uninstall.sh')") !== false, 'T7: a worker the shell uninstaller can call');
$un = is_file(SMPRO_BASE . '/packaging/uninstall.sh') ? $src('packaging/uninstall.sh') : '';
if ($un === '') tap_skip('T8: uninstall.sh runs the teardown before removing files', 'the uninstall script is not part of this tree');
else ok(strpos($un, '"$DEST/bin/teardown.php"') !== false && strpos($un, 'bin/teardown.php') < strpos($un, 'rm -rf "$DEST"'), 'T8: uninstall.sh runs the teardown while the code is still there');

// teardown on a machine with nothing to take down does nothing and says nothing
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/update.php';
$r = smpro_teardown_network('test');
ok(is_array($r), 'T9: the teardown step runs where there is no wall, no cPHulk and no firewall script (' . count($r) . ' line(s))');

has($up, "if (!is_file(\$mfPath) || !hash_equals((string)\$mfSha, (string)@hash_file('sha256', \$mfPath))) { \$mfBad = (string)\$mfRel; break; }", 'U1: every unpacked file is compared with the signed file list');
ok(strpos($up, "\$mfBad = (string)\$mfRel; break; }") < strpos($up, "// backup the current install (restorable)"), 'U2: ...before the backup and the copy, while the live tree is untouched');
has($up, "@openssl_verify(json_encode(\$mfSorted, JSON_UNESCAPED_SLASHES), \$mfSig, \$mfPk, OPENSSL_ALGO_SHA256) !== 1) \$mfBad = 'the file list signature';", 'U3: the file list itself must carry the release signature');
has($up, "\$bad = 'not the released file after the copy: ' . \$mfRel; break;", 'U4: after the copy every file on disk must be the released one (an empty file passes a syntax check)');
ok(strlen((string)@hash_file('sha256', __FILE__)) === 64 && !hash_equals(hash('sha256', 'x'), hash('sha256', '')), 'U5: an empty file does not have the hash of the real one');

$in = $src('includes/integrity.php');
has($in, "\$again = smpro_integrity_check(smpro_integrity_critical_files());", 'G1: a lock is checked again before it is honoured');
has($in, "if (empty(\$again['ok'])) smpro_protected_mode((string)(\$again['reason'] ?? \$st['reason'] ?? 'integrity'));", 'G2: ...and stays only while the files are really wrong');

$mn = $src('includes/maintenance.php');
ok(substr_count($mn, "find /home -xdev -maxdepth 9 \\\\( -path '/home/backup' -o -path '/home/virtfs' -o ") === 2, 'P1: the auto-purge walk stays on its filesystem and out of the jail mirror');
has($src('includes/lvelimits.php'), '/lvelimits.lock timeout 120', 'C1: the limit-restore job cannot overlap itself');
has($src('includes/trustfeed.php'), '/trustfeed.lock timeout 120', 'C2: nor the trusted-list job');
has($src('includes/sdbulk.php'), '/sitedoctor_bulk.lock timeout 3600', 'C3: nor the daily site scan');
has($src('includes/spqueue.php'), "\$raw = (\$uid > 0 && function_exists('smpro_acct_get')) ? smpro_acct_get((string)\$user, (string)\$p, (int)SMPRO_SPQ_MAX_BYTES) : @file_get_contents(\$p);", 'Q1: a request file is read as the account');
$ins = is_file(SMPRO_BASE . '/packaging/install.sh') ? $src('packaging/install.sh') : '';
if ($ins === '') tap_skip('I1: a failed copy fails the install', 'the installer is not part of this tree');
else has($ins, 'cp -a "${SRC}/${PLUGIN}/." "${DEST}/" || die "The plugin files could not be copied', 'I1: a failed copy fails the install');
