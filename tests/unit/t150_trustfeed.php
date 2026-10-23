<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t150_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/license.php';
require_once SMPRO_BASE . '/includes/trustfeed.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
require_once SMPRO_BASE . '/includes/fwallow.php';
/** t150 - beta368: the trusted-bots list from the licence server is verified before it is believed, feeds the
 *  allow-list providers and the Bot Guard catalogue, and never replaces a never-block seed. */
$tf = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/trustfeed.php'));
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fwallow.php'));
$bg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));

// A. nothing unsigned is believed
$good = ['product' => 'smpro', 'feed' => 'trusted-bots', 'version' => 1, 'generated' => time() - 60, 'sources' => []];
for ($i = 0; $i < 5; $i++) $good['sources']['s' . $i] = ['name' => 's' . $i, 'kind' => 'search', 'ranges' => array_map(fn($n) => '10.' . $i . '.' . $n . '.0/24', range(0, 11))];
is_eq(smpro_tf_validate(['payload' => $good, 'signature' => base64_encode('nope')])['why'], 'signature does not verify against the pinned licence key', 'A1: a wrong signature is refused');
is_eq(smpro_tf_validate('garbage')['why'], 'not a feed document', 'A2: not a document');
is_eq(smpro_tf_validate(['payload' => []])['ok'], false, 'A3: an empty payload is refused');
has($tf, "if (\$gen <= 0 || \$gen > \$now + 3600) return ['ok' => false, 'why' => 'generated time is missing or in the future'];", 'A4: a future time is refused');
has($tf, "if (\$now - \$gen > SMPRO_TF_MAXAGE) return ['ok' => false, 'why' => 'older than '", 'A5: an old list is history, not truth');
has($tf, "if (!is_array(\$p['sources'] ?? null) || count(\$p['sources']) < 5) return ['ok' => false, 'why' => 'fewer than five sources'];", 'A6: a thin list is refused');
has($tf, "if (!is_string(\$c) || !preg_match('#^([0-9a-f.:]+)/(\\d{1,3})\$#i', \$c, \$m) || !filter_var(\$m[1], FILTER_VALIDATE_IP))", 'A7: every range must be a range');
has($tf, "if (!preg_match('#^https://[A-Za-z0-9.-]+(:\\d+)?/feeds/trusted-bots\\.json\$#', \$url)) continue;", 'A8: only the fixed path on the licence hosts is ever fetched');
has($tf, "if (defined('SMPRO_TEST_SRC')) return ['ok' => false, 'msg' => 'test: no network'", 'A9: a test never touches the network');
is_eq(smpro_tf_data(), null, 'A10: no kept list -> null, never a guess');
is_eq(smpro_tf_ranges('googlebot'), null, 'A11: ...and a provider reads null, so the allow-list falls back');
is_eq(smpro_tf_families(), [], 'A12: ...and no families are added');
ok(smpro_tf_status()['have'] === false && smpro_tf_status()['why'] === 'not fetched yet', 'A13: the page is told "not fetched yet"');

// B. where the list is read
has($ix, "require __DIR__ . '/includes/trustfeed.php';", 'B1: loaded by the plugin');
has($ix, "require __DIR__ . '/includes/trustfeed.php';      // trusted-bots list from the licence server (verified official ranges)\nrequire __DIR__ . '/includes/fwallow.php';", 'B2: ...before the allow-list that reads it');
has($fa, "if (function_exists('smpro_tf_ranges') && (\$tf = smpro_tf_ranges((string)\$key)) !== null) {", 'B3: a provider\'s ranges come from the verified list first');
has($fa, "if (\$pv && !empty(\$pv['never_block'])) foreach ((array)\$pv['ranges'] as \$seed) if (!in_array(\$seed, \$tf, true)) \$tf[] = \$seed;", 'B4: a never-block provider keeps its seeds underneath');
has($bg, "array_replace(smpro_bg_catalog_builtin(), function_exists('smpro_tf_families') ? smpro_tf_families() : [], smpro_bg_catalog_custom())", 'B5: list families sit between shipped and custom');
has($pg, "elseif (\$act === 'tf_refresh')", 'B6: Pull now action');
has($pg, 'id="bg-trusted"', 'B7: the card');
has($pg, "No verified list is held yet", 'B8: ...says so when there is none');
has($cs, "'trusted bots list'  => 'smpro_tf_cron_sync',", 'B9: cron sync keeps the tick');
has($tf, "\$min = abs(crc32((string)@gethostname())) % 60;", 'B10: each server pulls at a minute of its own');
has($tf, "\"# Safety Monitor Pro - trusted-bots list from the licence server (verified official crawler / mail ranges), every 6 h\\n\$min */6 * * * root timeout 120 \$php \$bin >/dev/null 2>&1\\n\"", 'B11: every six hours, time-bounded');
