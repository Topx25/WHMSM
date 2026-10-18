<?php
/**
 * bin/evidence_ship.php — move the evidence journal between a server and its vault.
 *
 * One worker, both directions, because a server can be either end: a Member sends what it has written, a Hub
 * collects what its members sent. A box that is neither does nothing and says so.
 *
 * Like the collector, this is NOT gated on the plugin's global disable switch. A server whose plugin has been
 * switched off is exactly the server whose recent history somebody will want, and a shipper that stops when the
 * thing it protects is turned off protects nothing.
 *
 * It never deletes a local record because a send succeeded — retention does that on its own schedule, so a vault
 * that quietly stopped accepting cannot take the local copy with it.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'hub', 'evidence', 'evship'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (!function_exists('smpro_ev_ship_run') || !function_exists('smpro_ev_vault_collect')) exit(2);

$dry     = in_array('--dry-run', (array)($argv ?? []), true);
$verbose = $dry || in_array('-v', (array)($argv ?? []), true);

try {
    $sent = smpro_ev_ship_run($dry);                    // this server as a Member
    $got  = $dry ? ['ok' => true, 'links' => 0, 'batches' => 0, 'records' => 0, 'errors' => []]
                 : smpro_ev_vault_collect();            // this server as a Hub
} catch (Throwable $e) {
    if (function_exists('smpro_ev_append')) @smpro_ev_append('blind', ['why' => 'the evidence shipper failed: ' . $e->getMessage()]);
    exit(1);
}

if (PHP_SAPI === 'cli' && $verbose) {
    printf("%ssend   : %s — %s\n", $dry ? 'DRY RUN ' : '', $sent['ok'] ? 'ok' : 'PROBLEM', $sent['msg']);
    foreach ((array)$sent['errors'] as $e) printf("          %s\n", $e);
    printf("collect: %s — %d link(s), %d batch(es), %d record(s)\n",
           $got['ok'] ? 'ok' : 'PROBLEM', $got['links'], $got['batches'], $got['records']);
    foreach ((array)$got['errors'] as $e) printf("          %s\n", $e);
}
exit(($sent['ok'] && $got['ok']) ? 0 : 1);
