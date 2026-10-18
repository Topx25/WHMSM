<?php
/**
 * Safety Monitor Pro (smpro)
 * defines.php — single source of truth for paths/names.
 * Renaming for production = change values here only.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

// --- Identity ---
define('SMPRO_NAME',        'Safety Monitor Pro');
define('SMPRO_SLUG',        'smpro');
define('SMPRO_VERSION',     '1.0.199');
define('SMPRO_FN_PREFIX',   'smpro_');

// --- Code paths (inside WHM docroot) ---
define('SMPRO_BASE',        __DIR__ . '/..');               // .../cgi/addons/smpro
define('SMPRO_INCLUDES',    SMPRO_BASE . '/includes');
define('SMPRO_MODULES',     SMPRO_BASE . '/modules');
define('SMPRO_ASSETS_URL',  'index.cgi?asset=');            // assets served through router (no direct guess)

// --- Data paths (OUTSIDE web root) ---
define('SMPRO_VARLIB',      '/var/lib/smpro');
define('SMPRO_VARLOG',      '/var/log/smpro');
define('SMPRO_DB',          SMPRO_VARLIB . '/smpro.db');
define('SMPRO_CACHE',       SMPRO_VARLIB . '/cache');
define('SMPRO_LOCKS',       SMPRO_VARLIB . '/locks');

// --- Audit log ---
define('SMPRO_AUDIT_LOG',   SMPRO_VARLOG . '/audit.log');

// --- Resource limits (per plan §20/§28) ---
define('SMPRO_SCAN_NICE',          19);
define('SMPRO_SCAN_IONICE_CLASS',  3);
define('SMPRO_TIMEOUT_QUICK',      5);
define('SMPRO_TIMEOUT_NORMAL',     60);

// --- cPanel session prefix (passed from index.cgi) ---
define('SMPRO_CPSESS', getenv('SM_CPANEL_PREFIX') ?: '');
