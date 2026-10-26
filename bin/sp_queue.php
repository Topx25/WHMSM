<?php
/**
 * bin/sp_queue.php - perform the file-lock requests accounts make from cPanel.
 *
 * Runs every two minutes from /etc/cron.d/smpro-siteprotection. The account page cannot set the immutable bit,
 * so it writes a request into its own home and this worker carries it out as root. The rules that make that safe
 * live in includes/spqueue.php; the short version is that a request names a VERB and never a path, and root works
 * out for itself which of that account's files the verb applies to.
 *
 * Two jobs per run: carry out what is waiting, then restore any lock whose one-hour unlock has expired. The
 * second is why the interval is short - an hour that quietly becomes three is a promise broken in the direction
 * that leaves a site unprotected.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);

// phstack must load before spqueue: root decides the targets by detecting the application itself, which is what
// keeps the account from being able to choose the files.
foreach (['defines', 'helpers', 'secret', 'license', 'mmdb', 'phstack', 'phlock', 'ph_ignore', 'fwallow', 'sprules', 'spqueue', 'slmaint', 'compcheck'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}

// Everything this worker needs lives in includes/, so nothing is extracted out of a page module at runtime.
// If that ever stops being true the worker must stop rather than continue: a run that cannot lock anything but
// reports each request as handled is worse than no run at all, because the account is told it is protected.
//
// That guard earned itself. This comment used to say the move had already happened; smpro_ph_chattr() and
// smpro_ph_roots() were still in modules/php-harden.php, which cron can never load, so the guard fired on every
// run and Site Protection performed NOTHING on a live server for 29 hours. The refusal was right and the claim
// above it was wrong - which is why the claim is now checked by a test rather than written down and trusted.
if (!function_exists('smpro_ph_chattr') || !function_exists('smpro_ph_roots') || !function_exists('smpro_ph_inside') || !function_exists('smpro_ph_perm_all')) {
    if (function_exists('smpro_audit')) {
        smpro_audit('siteprotection_worker', ['ok' => 0, 'why' => 'the file-lock helpers are missing from includes/']);
    }
    exit(1);
}

if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
@set_time_limit(120);

try {
    $r = smpro_spq_run();
    $relocked = smpro_spq_relock_due();
    $regranted = function_exists('smpro_spq_retry_pending') ? smpro_spq_retry_pending() : 0;   // rules get another look at what waits
    $kept = function_exists('smpro_spq_keep_free') ? smpro_spq_keep_free() : 0;                 // excluded accounts stay free of anyone's locks
    if (function_exists('smpro_audit') && ((int)($r['handled'] ?? 0) > 0 || $relocked > 0 || $regranted > 0 || $kept > 0)) {
        smpro_audit('siteprotection_worker', ['handled' => (int)($r['handled'] ?? 0), 'relocked' => $relocked, 'auto_granted_on_retry' => $regranted, 'kept_free' => $kept]);
    }
} catch (\Throwable $e) {
    if (function_exists('smpro_audit')) smpro_audit('siteprotection_worker', ['ok' => 0, 'why' => $e->getMessage()]);
}
