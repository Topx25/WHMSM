<?php
/**
 * Manual check for the wp-config edit. Uses a THROWAWAY directory under a lab account — never a real site.
 * The point of these cases is the refusals: this file is what the whole site loads through.
 */
define('SMPRO_BOOT', 1);
$A = '/opt/smpro-testlab/src';
foreach (['defines', 'env', 'mmdb', 'helpers'] as $f) { $p = "$A/includes/$f.php"; if (is_file($p)) require_once $p; }
require_once "$A/includes/croncheck.php";
require_once "$A/includes/wpcron_fix.php";

$user = $argv[1] ?? '';
if ($user === '' || !is_file('/var/cpanel/users/' . $user)) { fwrite(STDERR, "usage: <lab account>\n"); exit(2); }
$root = '/home/' . $user . '/_smpro_wpc_test';
$file = $root . '/wp-config.php';
@mkdir($root, 0755, true);

$fail = 0;
function chk(string $name, bool $pass) { global $fail; printf("  %-46s %s\n", $name, $pass ? 'ok' : 'FAILED'); if (!$pass) $fail++; }

$STD = "<?php\n"
     . "define( 'DB_NAME', 'x' );\n"
     . "define( 'DB_USER', 'y' );\n"
     . "\$table_prefix = 'wp_';\n\n"
     . "/* That's all, stop editing! Happy publishing. */\n\n"
     . "if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }\n"
     . "require_once ABSPATH . 'wp-settings.php';\n";

/* 1 — the ordinary case */
file_put_contents($file, $STD);
echo "case 1 — a normal wp-config with the marker\n";
$dry = smpro_wpc_disable($root, true);
chk('dry run says it would change it', !empty($dry['ok']) && !empty($dry['changed']));
$r = smpro_wpc_disable($root, false);
chk('applied', !empty($r['ok']) && !empty($r['changed']));
chk('the setting is now in effect', smpro_wpc_state($root) === true);
chk('the file still parses', !empty(smpro_wpc_parses((string)file_get_contents($file))['ok']));
chk('everything else survived', strpos((string)file_get_contents($file), "require_once ABSPATH . 'wp-settings.php';") !== false
                                && strpos((string)file_get_contents($file), "\$table_prefix = 'wp_';") !== false);
chk('a copy was kept', !empty($r['backup']) && is_file($r['backup']));

/* 2 — asked again when it is already off */
echo "\ncase 2 — asked again when it is already off\n";
$again = smpro_wpc_disable($root, false);
chk('reports nothing to do rather than editing again', !empty($again['ok']) && empty($again['changed']));

/* 3 — undo */
echo "\ncase 3 — undo\n";
$u = smpro_wpc_undo($root, (string)$r['backup']);
chk('restored', !empty($u['ok']));
chk('the original came back byte for byte', (string)file_get_contents($file) === $STD);

/* 4 — the setting present but switched on */
echo "\ncase 4 — the setting is there but switched on\n";
file_put_contents($file, str_replace("\$table_prefix", "define('DISABLE_WP_CRON', false);\n\$table_prefix", $STD));
chk('read as: visitors can start it', smpro_wpc_state($root) === false);
$r4 = smpro_wpc_disable($root, false);
chk('corrected it', !empty($r4['ok']) && smpro_wpc_state($root) === true);
chk('only one such setting in the file', substr_count((string)file_get_contents($file), 'DISABLE_WP_CRON') === 1);

/* 5 — a file it does not recognise: it must refuse, not guess */
echo "\ncase 5 — no marker and no wp-settings require\n";
file_put_contents($file, "<?php\ndefine( 'DB_NAME', 'x' );\n");
$r5 = smpro_wpc_disable($root, false);
chk('refused instead of guessing a position', empty($r5['ok']));
chk('and said what to do by hand', strpos((string)($r5['error'] ?? ''), "DISABLE_WP_CRON") !== false);
chk('left the file untouched', (string)file_get_contents($file) === "<?php\ndefine( 'DB_NAME', 'x' );\n");

/* 6 — restoring something from outside the account */
echo "\ncase 6 — a copy from somewhere else\n";
$bad = smpro_wpc_undo($root, '/etc/passwd');
chk('refused', empty($bad['ok']));

/* 7 — a saved copy that does not parse must never be installed */
echo "\ncase 7 — a saved copy that does not parse\n";
$dir = smpro_wpc_backup_dir($user);
$broken = $dir . '/20200101_000000_broken.wp-config.php';
@file_put_contents($broken, "<?php\nfunction (((\n");
$r7 = smpro_wpc_undo($root, $broken);
chk('refused to restore it', empty($r7['ok']));
@unlink($broken);

/* tidy up */
smpro_run('rm -rf ' . escapeshellarg($root), 20, ['stderr' => 'discard']);
smpro_run('rm -rf ' . escapeshellarg($dir), 20, ['stderr' => 'discard']);
echo "\ntest directory removed.\n";
echo $fail ? "\n$fail CHECK(S) FAILED\n" : "\nall checks passed\n";
exit($fail ? 1 : 0);
