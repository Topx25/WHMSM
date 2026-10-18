<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/frontlogs.php';
/** t127 - front logs and the Cloudflare setting are discovered from the running configuration; nothing is assumed. */
$dir = sys_get_temp_dir() . '/t127_' . getmypid(); @mkdir($dir);
$conf = "pipelog \"/usr/local/cpanel/bin/splitlogs --dir=$dir --main=x --mainout=/nonexistent\" combinedvhost;\n";
is_eq(smpro_fl_splitlog_dirs($conf), [$dir], 'U1: the per-domain log dir is read from the piped-logger line');
is_eq(smpro_fl_splitlog_dirs('pipelog "/x/splitlogs --dir=/does/not/exist" a;'), [], 'U1: a dir that is not there is not invented');
@file_put_contents("$dir/a.log", "x");
is_eq(smpro_fl_access_logs("access_log off;\n  access_log $dir/a.log main;\n access_log /var/\$x.log;"), ["$dir/a.log"], 'U2: access_log targets: off and variables are skipped');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/frontlogs.php'));
hasnt($src, '/var/log/', 'U3: no log path is written in the discovery code');
hasnt($src, "'/etc/nginx", 'U3: nor an nginx path');
has($src, "if (stripos(\$test, 'test is successful') === false) {\n        @unlink(\$f);", 'U4: the Cloudflare include is kept only after nginx accepts it');
has($src, "smpro_ctl_dry_run())) return true;", 'U4: Dry-Run and Disabled only report');
has($src, "@is_file(SMPRO_VARLIB . '/cf_realip_off')", 'U4: the operator can opt out');
has(str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php')), "smpro_cf_realip_sync()", 'U5: checked after every install and update');
@unlink("$dir/a.log"); @rmdir($dir);
