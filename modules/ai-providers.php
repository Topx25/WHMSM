<?php
/**
 * modules/ai-providers.php - AI Providers page.
 * Configure the AI provider used across Safety Monitor Pro for analysis & recommendations.
 * The free-first provider catalog (with usage) renders first; the full engine (live model
 * fetch / testing) is under "Advanced". All config + API keys are stored encrypted inside the
 * plugin's own data directory - nothing is read from or written to any other product's folders.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

require_once __DIR__ . '/ai_providers_engine.php';   // self-contained engine; uses the plugin's own data dir

// Process a settings/test POST first (returns a status message; no redirect/exit).
$GLOBALS['mspro_ai304_message'] = function_exists('mspro_ai304_handle_post') ? mspro_ai304_handle_post() : '';

smpro_layout_header('AI Providers');
?>
<div class="svc-kicker" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800">Configuration</div>
<h1 class="h" style="margin:2px 0 4px">AI Providers</h1>
<p class="sub">Choose the AI provider used across Safety Monitor Pro for analysis &amp; recommendations. Free providers are recommended; your API keys are stored <b>encrypted</b> on this server and never shown.</p>

<?php
// smpro-native catalog: free-first providers with paid/free/limited badges, signup + API-key links,
// live model fetch via the token, multi-select + parallel/series testing, and local usage.
if (function_exists('smpro_ai_catalog_render')) {
    smpro_ai_catalog_render();
} else {
    echo '<div class="card" style="padding:18px">AI Providers catalog is unavailable.</div>';
}
smpro_layout_footer();
