<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
require_once SMPRO_BASE . '/includes/sitewatch.php';
/**
 * t174 - Site Watch with no alert rule. On a real server it was switched on for 84 sites and told nobody anything:
 * its findings were on its page only, which is how a planted web shell went unnoticed. Critical findings now go,
 * once each, into one message per check through the server's general alert channels.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$GLOBALS['smpro_sw_default_q'] = [];
is_eq(smpro_sw_cfg()['rules'], [], 'N0: this run has no alert rule');

$ev = fn(string $id, string $sev, string $kind, string $title) => ['id' => $id, 'ts' => time(), 'domain' => 'example.test', 'sev' => $sev, 'kind' => $kind, 'title' => $title, 'data' => []];
smpro_sw_dispatch('example.test', [$ev('a1', 'critical', 'upload_php', 'PHP file in an uploads/images folder: uploads/x.php'), $ev('a2', 'warning', 'htaccess', '.htaccess changed'), $ev('a3', 'critical', 'shell_run', 'Injected file run from the web 3x: uploads/x.php')]);
is_eq(count($GLOBALS['smpro_sw_default_q']), 2, 'N1: the two critical findings are queued, the warning is not');
smpro_sw_dispatch('example.test', [$ev('a1', 'critical', 'upload_php', 'PHP file in an uploads/images folder: uploads/x.php')]);
is_eq(count($GLOBALS['smpro_sw_default_q']), 2, 'N2: the same finding is queued once, whatever the number of checks');
smpro_sw_dispatch('other.test', [$ev('b1', 'critical', 'core_mod', 'WordPress core file changed: wp-includes/load.php')]);
is_eq(array_values(array_unique(array_column($GLOBALS['smpro_sw_default_q'], 0))), ['example.test', 'other.test'], 'N3: findings of several sites share the queue');

$r = smpro_sw_default_alert();
ok(($r['sent'] ?? 0) === 3 || (!function_exists('smpro_notify') && ($r['sent'] ?? -1) === 0), 'N4: one message carries all of them (' . json_encode($r) . ')');
is_eq($GLOBALS['smpro_sw_default_q'], [], 'N5: the queue is empty after the message');
is_eq(smpro_sw_default_alert()['sent'], 0, 'N6: nothing queued = nothing sent');

$sw = $src('includes/sitewatch.php');
has($sw, "    smpro_sw_default_alert();   // one message for the whole check when no alert rule is set", 'W1: the message goes out when the check ends');
has($sw, "if (empty(\$c['rules'])) {", 'W2: only when Site Watch has no rule of its own (a rule decides for itself)');
has($sw, "Add a rule there to choose who is told, and how.", 'W3: the message says why it came this way');
has($src('includes/notify.php'), "'site_watch'       => ['Site Watch (critical findings)',", 'W4: the alert type is registered, so it can be switched per channel');

$iv = $src('includes/investigate.php');
has($iv, "\$c = (string)smpro_acct_get((string)\$user, \$safe, 2097152);", 'U1: un-harden reads the guard file as the account');
has($iv, "if (\$c !== '') { if (trim((string)\$new) === '') smpro_acct_rm((string)\$user, \$safe); else smpro_acct_put((string)\$user, \$safe, rtrim((string)\$new) . \"\\n\"); }", 'U2: ...rewrites or removes it as the account');
ok(strpos($iv, "@chmod(\$safe, 0644); if (\$uid) @chown(\$safe, \$uid);") === false, 'U3: ...and no longer chmods and chowns by path as root');
