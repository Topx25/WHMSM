<?php
/**
 * bin/evidence_tick.php — write down what happened, before the log it happened in rotates away.
 *
 * Installed as /etc/cron.d/smpro-evidence and run every five minutes. It reads the same sources the pages read
 * and appends what it finds to the local evidence journal, hash-chained.
 *
 * Deliberately NOT gated on smpro_ctl_disabled(). A server whose plugin has been switched off is exactly the
 * server whose recent history somebody will want afterwards, and an evidence store that stops recording when
 * the thing it is watching is turned off is not an evidence store.
 *
 * It changes nothing. It blocks nothing, resets nothing, deletes nothing except journals older than the
 * retention window — and never a seal.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'loginfeed', 'geologin', 'geowall', 'evidence'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (!function_exists('smpro_ev_run')) exit(2);

try {
    $r = smpro_ev_run();
} catch (Throwable $e) {
    // A crash in the collector must itself be recorded. Silence here would be the one gap nothing else can show.
    if (function_exists('smpro_ev_append')) @smpro_ev_append('blind', ['why' => 'the collector failed: ' . $e->getMessage()]);
    exit(1);
}

if (PHP_SAPI === 'cli' && in_array('-v', (array)($argv ?? []), true)) {
    printf("logins=%d actions=%d snapshot=%d%s\n", $r['logins'], $r['actions'], $r['snapshot'],
           $r['blind'] ? '  BLIND: ' . implode('; ', $r['blind']) : '');
}
exit(0);
