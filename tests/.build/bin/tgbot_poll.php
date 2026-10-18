<?php
/**
 * bin/tgbot_poll.php — cron worker (every minute) for the Telegram control bot.
 * Long-polls getUpdates, authorizes the admin chat, runs commands. Installed via /etc/cron.d/smpro-tgbot.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'intrusion', 'notify', 'update', 'reports', 'cooler', 'tgbot'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;   // disabled / license-dormant → do nothing
// graduated degradation: shed this optional worker once the license server has been unreachable for a while (grace phase >= 2)
if (function_exists('smpro_lic_grace_phase') && smpro_lic_grace_phase() >= 2) exit;
if (function_exists('smpro_tg_poll')) { try { smpro_tg_poll(); } catch (\Throwable $e) {} }
