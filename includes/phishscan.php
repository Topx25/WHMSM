<?php
/**
 * includes/phishscan.php - phishing-kit scan for one cPanel account, runnable in the BACKGROUND.
 * The scan greps the whole account home and can take a while, so the module starts a DETACHED worker
 * (bin/phish_scan.php) that keeps running even if the admin closes the page; the page then polls the
 * result file and shows the findings when ready (or the last completed result on the next visit).
 * Shared by modules/spam-phishing.php + bin/phish_scan.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_PS_DIR')) define('SMPRO_PS_DIR', SMPRO_VARLIB . '/phishscan');

/** The actual scan (moved out of the module so the headless worker can call it too). */
function smpro_ps_scan($path) {
    if ($path === '') return ['err' => 'Pick a single account.', 'rows' => []];
    $sig = 'paypal|verify[^a-z]{0,3}your[^a-z]{0,3}account|account[^a-z]{0,3}(suspended|locked|limited)|secure[^a-z]{0,3}login|signin[^a-z]{0,3}verify|onedrive|office\\s?365|wells.?fargo|bank.?of.?america|netflix|amazon.*billing|webmail.*upgrade|confirm[^a-z]{0,3}identity|update[^a-z]{0,3}payment';
    $excl = " -not -path '*/vendor/*' -not -ipath '*/node_modules/*' -not -path '*/wp-includes/*' -not -path '*/wp-admin/*'";
    $cmd = 'timeout 280 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 grep -rlIEi ' . escapeshellarg($sig)
        . ' --include=*.php --include=*.html --include=*.htm ' . escapeshellarg($path) . $excl . ' 2>/dev/null | head -200';
    $rows = [];
    foreach (array_filter(array_map('trim', explode("\n", (string)@shell_exec($cmd)))) as $f) {
        if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($f)) continue;   // WP Guard's own file / quarantine -> not a phishing page
        $hasForm = trim((string)@shell_exec('grep -lIEi "<form|password|passwd|action=" ' . escapeshellarg($f) . ' 2>/dev/null')) !== '';
        $hits = trim((string)@shell_exec('grep -oiE ' . escapeshellarg($sig) . ' ' . escapeshellarg($f) . ' 2>/dev/null | tr A-Z a-z | sort -u | head -6'));
        $rows[] = ['file' => $f, 'mtime' => date('Y-m-d H:i', (int)@filemtime($f)), 'form' => $hasForm, 'lures' => array_filter(array_map('trim', explode("\n", $hits)))];
    }
    usort($rows, fn($a, $b) => $b['form'] <=> $a['form']);
    return ['err' => '', 'rows' => $rows];
}

/* keep the old public name working (the module now uses the background job, but anything else that calls it still works) */
if (!function_exists('smpro_sp_phish_scan')) { function smpro_sp_phish_scan($path) { return smpro_ps_scan($path); } }

/* --------------------------- background job management --------------------------- */
function smpro_ps_norm($account) { return preg_replace('/[^a-z0-9._-]/i', '', (string)$account); }
function smpro_ps_job_file($account) { return SMPRO_PS_DIR . '/' . smpro_ps_norm($account) . '.json'; }
function smpro_ps_status($account) {
    $account = smpro_ps_norm($account); if ($account === '') return null;
    $f = smpro_ps_job_file($account); if (!@is_file($f)) return null;
    $d = json_decode((string)@file_get_contents($f), true); return is_array($d) ? $d : null;
}
function smpro_ps_write($account, array $data) {
    $account = smpro_ps_norm($account); if ($account === '') return;
    if (!(@is_dir(SMPRO_PS_DIR) || @mkdir(SMPRO_PS_DIR, 0700, true))) return;
    $f = smpro_ps_job_file($account); $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($data, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
/** True while a scan is actively running (started recently and not yet finished). */
function smpro_ps_is_running($account) {
    $s = smpro_ps_status($account);
    return $s && ($s['state'] ?? '') === 'running' && (time() - (int)($s['started'] ?? 0)) < 900;
}
/** Launch the scan as a DETACHED background worker so it survives the page/request ending. */
function smpro_ps_start($account) {
    $account = smpro_ps_norm($account);
    // The account's real home, not a guessed /home/<user>: this server has /home, /home1 and /home2, and the
    // guess meant every account outside the first partition was reported as scanned-and-clean without ever
    // being opened.
    $home = function_exists('smpro_user_home') ? smpro_user_home($account) : '';
    if ($account === '' || $home === '') return ['ok' => false, 'msg' => 'Unknown or invalid cPanel account.'];
    if (smpro_ps_is_running($account)) return ['ok' => true, 'running' => true, 'msg' => 'A scan is already running for this account — leave it working.'];
    $bin = SMPRO_BASE . '/bin/phish_scan.php';
    if (!@is_file($bin)) return ['ok' => false, 'msg' => 'Scan worker is missing.'];
    smpro_ps_write($account, ['state' => 'running', 'started' => time(), 'finished' => 0, 'account' => $account, 'err' => '', 'rows' => [], 'count' => 0]);
    $php = smpro_php_cli_bin();
    $setsid = is_executable('/usr/bin/setsid') ? '/usr/bin/setsid ' : (trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : '');
    // detach: new session (setsid) + nohup + & -> keeps running after this CGI request (the page) ends
    @shell_exec($setsid . 'nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' ' . escapeshellarg($account) . ' >/dev/null 2>&1 &');
    return ['ok' => true, 'running' => true, 'msg' => 'Phishing scan started in the background — you can safely leave this page; results will be here when you return.'];
}
/** Worker body: run the scan and persist the result. Called by bin/phish_scan.php. */
function smpro_ps_run($account) {
    $account = smpro_ps_norm($account);
    $home = function_exists('smpro_user_home') ? smpro_user_home($account) : '';
    if ($account === '' || $home === '') return;
    $prev = smpro_ps_status($account); $started = (int)($prev['started'] ?? time());
    $r = smpro_ps_scan($home);
    smpro_ps_write($account, [
        'state'    => (!empty($r['err'])) ? 'error' : 'done',
        'started'  => $started, 'finished' => time(), 'account' => $account,
        'err'      => (string)($r['err'] ?? ''), 'rows' => array_values($r['rows'] ?? []), 'count' => count($r['rows'] ?? []),
    ]);
    if (function_exists('smpro_audit')) @smpro_audit('phishing_scan_done', ['account' => $account, 'found' => count($r['rows'] ?? [])]);
}
