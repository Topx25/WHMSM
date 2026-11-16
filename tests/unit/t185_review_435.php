<?php
require __DIR__ . '/../support/bootstrap.php';
require __DIR__ . '/../support/plugin_funcs.php';
require_once SMPRO_BASE . '/includes/helpers.php';
smpro_plugin_funcs('modules/database-cleanup.php');
/**
 * t185 - round 435. Bulk database clean removed every script, frame and outside link of a flagged row - a site's
 * embedded video and its links went with the injection - and cut into serialized settings so they no longer read
 * back. Also: tools that only worked under /home, a "safe cache" list that held the account's tmp folder, a
 * Forensics restore that lost what the customer added since.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$own = ['mysite.test'];

/* ---------- what is certain ---------- */
$video  = '<iframe width="560" height="315" src="https://www.youtube.com/embed/abc123" allowfullscreen></iframe>';
$hidden = '<iframe src="http://evil.test/x" width="1" height="1" style="display:none"></iframe>';
$tag    = '<script src="https://analytics.example.test/tag.js"></script>';
$bad    = '<script>eval(atob("ZG9jdW1lbnQud3JpdGUoJ3gnKQ=="))</script>';
$link   = '<a href="https://en.wikipedia.test/wiki/Thing">a reference</a>';
$spam   = '<div style="position:absolute;left:-9999px"><a href="http://pills.test/">cheap</a></div>';
$body   = '<p>Hello</p>' . $video . $tag . $link . $bad . $hidden . $spam . '<p>Bye</p>';
$r = smpro_db_clean_value($body, $own, true);
ok(strpos($r['clean'], 'youtube.com/embed') !== false, 'V1: an embedded video stays');
ok(strpos($r['clean'], 'analytics.example.test') !== false, 'V2: a plain script tag stays');
ok(strpos($r['clean'], 'wikipedia.test') !== false, 'V3: an outside link in plain sight stays');
ok(strpos($r['clean'], 'eval(atob') === false, 'V4: an obfuscated script goes');
ok(strpos($r['clean'], 'evil.test') === false, 'V5: a hidden frame goes');
ok(strpos($r['clean'], 'pills.test') === false, 'V6: a hidden block of links goes');
ok(strpos($r['clean'], '<p>Hello</p>') === 0 && substr($r['clean'], -10) === '<p>Bye</p>', 'V7: the content around them is untouched');
is_eq($r['n'], 3, 'V8: three things were removed');
$r = smpro_db_clean_value('<p>x</p>' . $video . $link, $own, true);
ok($r['n'] === 0 && $r['seen'] > 0 && $r['clean'] === '<p>x</p>' . $video . $link, 'V9: a row with only things that can be legitimate is left whole, and counted as seen');
$r = smpro_db_clean_value('<p>x</p>' . $video . $link, $own, false);
ok($r['n'] >= 1, 'V10: the by-hand path can still remove everything it lists');

/* ---------- a serialized setting still reads back ---------- */
$opt = serialize(['title' => 'Widget', 'text' => '<p>Intro</p>' . $video . $bad . $link, 'n' => 3, 'on' => true, 'deep' => ['x' => 'plain ' . $hidden]]);
$r = smpro_db_clean_value($opt, $own, true);
$u = @unserialize($r['clean'], ['allowed_classes' => false]);
ok(is_array($u), 'S1: the cleaned setting reads back');
ok($u['title'] === 'Widget' && $u['n'] === 3 && $u['on'] === true, 'S2: every other part is as it was');
ok(strpos($u['text'], 'youtube.com/embed') !== false && strpos($u['text'], 'eval(atob') === false, 'S3: the injection is gone from inside it, the video is not');
ok(strpos($u['deep']['x'], 'evil.test') === false && strpos($u['deep']['x'], 'plain ') === 0, 'S4: at any depth');
$cut = str_replace($bad, '', $opt);   // what the old by-position removal produced
ok(@unserialize($cut, ['allowed_classes' => false]) === false, 'S5: (cutting by position really does break it)');
ok(smpro_db_is_ser(smpro_db_ser_relen($cut)), 'S6: the by-hand path repairs the lengths after such a cut');
$obj = 'O:8:"stdClass":1:{s:1:"a";s:' . strlen($bad) . ':"' . $bad . '";}';
$r = smpro_db_clean_value($obj, $own, true);
ok($r['clean'] === $obj && $r['why'] !== '', 'S7: a value that holds stored objects is left alone, with the reason');

/* ---------- stored JSON still reads back ---------- */
$js = json_encode(['elType' => 'widget', 'settings' => ['html' => '<p>a</p>' . $bad, 'url' => 'https://mysite.test/p', 'empty' => new stdClass(), 'list' => []]], JSON_UNESCAPED_SLASHES);
$r = smpro_db_clean_value($js, $own, true);
$d = json_decode($r['clean']);
ok(is_object($d) && strpos($d->settings->html, 'eval(atob') === false && $d->settings->html === '<p>a</p>', 'J1: stored JSON is cleaned inside and reads back');
ok(strpos($r['clean'], '"empty":{}') !== false && strpos($r['clean'], '"list":[]') !== false, 'J2: an empty object stays an object, an empty list a list');
ok(strpos($r['clean'], 'https://mysite.test/p') !== false, 'J3: slashes are written the way the original wrote them');

/* ---------- source checks ---------- */
$db = $src('modules/database-cleanup.php');
has($db, "\$cv = smpro_db_clean_value(\$val, smpro_db_account_domains(\$flag['account']), true);", 'B1: bulk clean removes only what is certain');
has($db, "if (smpro_db_is_ser(\$orig) && !smpro_db_is_ser(\$clean)) {", 'B2: no path may leave a structure that does not read back');
has($db, "return \$c[\$k] = (\$parts === 1 && \$isInt(\$out)) ? \$out : '';", 'B3: a table is changed only through one whole-number key');
has($db, "\$out = smpro_db_exec_big(\$sql, 60);", 'B4: a large row is written through standard input, not a command argument');

$ds = $src('modules/disk-storage.php');
has($ds, "(cache|bootstrap/cache|storage/framework/views)(/.*)?\$#', \$f)", 'C1: only caches are "safe to clear"');
ok(strpos($ds, '|\\.cache|tmp)') === false, 'C2: the account tmp and .cache folders are off that list');
ok(strpos($src('includes/disk_scan.php'), "'.cache','tmp'") === false, 'C3: ...and are no longer offered');
has($ds, "'Nothing was cleared: the account that folder belongs to was not found.'", 'C4: a clear that did not run does not say "cleared"');
foreach (['modules/disk-storage.php', 'modules/spam-phishing.php', 'modules/forensics-audit.php'] as $f) ok(strpos($src($f), "'#^/home/") === false && strpos($src($f), "'#^/home\\d*/") !== false, 'H: ' . basename($f) . ' works for every home (/home2 ...), not only /home');

$fa = $src('modules/forensics-audit.php');
has($fa, "if (!@copy(\$file, \$b)) return '';", 'F1: a copy that could not be made is not reported as made');
has($fa, "\$cur = @is_file(\$file) ? smpro_fa_backup(\$file) : '';", 'F2: a restore keeps the current file first');
has($src('includes/maintenance.php'), "if (\$anyCrit && \$sinceH < \$MIN_GAP_H && \$lastFreed < 52428800) {", 'M1: a critical level a purge did not move is an alert, not another purge');
has($src('includes/tuning.php'), "if (@is_file(\$sg) && @copy(\$sg, \$rp)) \$apacheBack++;", 'T1: web-server files the server refuses are put back');
