<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
require_once SMPRO_BASE . '/includes/sitewatch.php';
/**
 * t170 - what the first Site Watch round on a real server (84 sites) showed. 43 sites came out "critical", almost
 * all for files every project carries; and the WordPress core check answered nothing from the scheduled worker,
 * because cron's short PATH finds the web PHP, which refuses to run a script.
 */
$c = fn(string $rel) => smpro_sw_classify_file($rel, true, 500);

// developer-tool settings files are ordinary
foreach (['app/.phpstorm.meta.php', 'site/.php-cs-fixer.dist.php', '.php-cs-fixer.php', 'tools/.rector.php'] as $f) is_eq($c($f), null, 'F: ' . $f . ' is ordinary');
// a dependency tree keeps dot folders of its own: shown, not an alarm
is_eq($c('wp-content/plugins/x/vendor/donatj/phpuseragentparser/.helpers/constants.php')[0] ?? '', 'warning', 'F5: a hidden folder inside vendor/ is a warning');
is_eq($c('node_modules/pkg/.bin/tool.php')[0] ?? '', 'warning', 'F6: ...and inside node_modules/');
// Mac copy leftovers: a warning
is_eq($c('resources/views/._index.blade.php')[0] ?? '', 'warning', 'F7: a "._" file left by a Mac copy is a warning');
// the real thing still alarms
is_eq($c('.cache/x.php')[0] ?? '', 'critical', 'G1: PHP in a hidden folder is still critical');
is_eq($c('wp-content/.tmp/shell.php')[0] ?? '', 'critical', 'G2: ...anywhere outside a dependency tree');
is_eq($c('wp-content/themes/t/.x.php')[0] ?? '', 'critical', 'G3: a hidden PHP file is still critical');
is_eq($c('wp-content/uploads/2026/x.php')[0] ?? '', 'critical', 'G4: PHP in uploads is still critical');
is_eq($c('logo.png.php')[0] ?? '', 'critical', 'G5: a double extension is still a disguised name');
is_eq($c('a3f9c2e1b7d4.php')[0] ?? '', 'critical', 'G6: a random hex name is still a disguised name');
// digits only = a date or serial number
is_eq($c('storage/2022102601.php'), null, 'H1: a name made of digits only is ordinary');
is_eq($c('12345678.php'), null, 'H2: ...whatever its length');
is_eq($c('deadbeef.php'), null, 'H3: letters only is a word, not a random name');

// the second round: compiled-template caches and applications deployed in upload/ or media/
is_eq($c('storage/framework/views/d30401c4f2391d1d940b8452460bb4ef.php'), null, 'J1: a compiled template under its hash name is ordinary');
is_eq($c('bootstrap/cache/a1b2c3d4e5f6.php'), null, 'J2: ...in every framework cache folder');
is_eq($c('app/Http/a3f9c2e1b7d4.php')[0] ?? '', 'critical', 'J3: the same name outside a cache folder is still a disguised name');
is_eq($c('storage/framework/views/logo.png.php')[0] ?? '', 'critical', 'J4: a double extension is a disguise even inside a cache folder');
is_eq($c('upload/system/storage/vendor/symfony/validator/Constraints/Existence.php'), null, 'J5: an application deployed in upload/ is not an uploads folder');
is_eq($c('media/player/index.php'), null, 'J6: ...nor one with its code in media/');
is_eq($c('upload/shell.php')[0] ?? '', 'critical', 'J7: a PHP file dropped straight into upload/ is still critical');
is_eq($c('upload/files/x.php')[0] ?? '', 'critical', 'J8: ...and in its data sub-folders');
is_eq($c('uploads/admin/x.php')[0] ?? '', 'critical', 'J9: "uploads" (plural) is never taken for an application folder');
$sw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sitewatch.php'));
has($sw, "return (smpro_sw_classify_file((string)\$e['data']['path'], true)[0] ?? '') === 'critical';", 'I1: an event stays open only while its file would still be called critical');

foreach (['includes/swdeep.php', 'includes/sdbulk.php'] as $f) {
    $s = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
    has($s, "'cd / && export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin && WP_CLI_CONFIG_PATH=/dev/null WP_CLI_PACKAGES_DIR=/nonexistent '", 'W: ' . $f . ' runs wp-cli with a full PATH (cron has a short one)');
}
$sd = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/swdeep.php'));
has($sd, "'core not verified: wp-cli was started with the web PHP instead of the command-line PHP'", 'W3: the web PHP answering is said as "not verified", in words');
