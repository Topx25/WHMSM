<?php
/**
 * telemetry_ext.php — Phase A of the Servers/Installations tab.
 * Additive only: stores the latest telemetry snapshot a plugin reports on /api/check,
 * and delivers any pending pull-based command (update/restart/revoke) back to the plugin.
 * Reuses the app's db() (mysqli). Never touches licensing/signing logic.
 *
 * Wire-up in public/index.php:
 *   require_once __DIR__ . '/telemetry_ext.php';   // near the other _ext requires
 * and in api_activate_or_check(), right before the final json_response of the OK path:
 *   if (function_exists('smlic_telemetry_ingest')) smlic_telemetry_ingest($licenseKey, $data, $serverIp, $hostname);
 *   $cmd = function_exists('smlic_command_pop') ? smlic_command_pop($licenseKey) : null;
 *   $resp = ['ok'=>true,'status'=>'active','license'=>$signed]; if ($cmd) $resp['command'] = $cmd;
 *   json_response($resp);
 */

if (!function_exists('db')) return;   // only meaningful inside the app

/** Idempotent schema creation — runs once (guarded by a flag file), reuses the app db(). */
function smlic_telemetry_migrate(): void {
    $flag = __DIR__ . '/../storage/.telemetry_migrated';
    if (is_file($flag)) return;
    try {
        db()->query("CREATE TABLE IF NOT EXISTS license_telemetry (
            license_key VARCHAR(90) NOT NULL PRIMARY KEY, hostname VARCHAR(255) DEFAULT NULL,
            server_ip VARCHAR(45) DEFAULT NULL, mac VARCHAR(64) DEFAULT NULL, os VARCHAR(120) DEFAULT NULL,
            panel VARCHAR(80) DEFAULT NULL, cpu_cores INT DEFAULT NULL, ram_mb INT DEFAULT NULL,
            uptime_sec BIGINT DEFAULT NULL, load1 DECIMAL(7,2) DEFAULT NULL, load15 DECIMAL(7,2) DEFAULT NULL,
            version VARCHAR(20) DEFAULT NULL, accounts INT DEFAULT NULL, reported_at DATETIME DEFAULT NULL, INDEX idx_reported_at (reported_at)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        db()->query("CREATE TABLE IF NOT EXISTS license_commands (
            id BIGINT AUTO_INCREMENT PRIMARY KEY, license_key VARCHAR(90) NOT NULL,
            command VARCHAR(24) NOT NULL, args VARCHAR(190) DEFAULT NULL,
            status ENUM('pending','sent','done','failed') NOT NULL DEFAULT 'pending', result TEXT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, sent_at DATETIME DEFAULT NULL, done_at DATETIME DEFAULT NULL,
            INDEX idx_key_status (license_key, status), INDEX idx_created_at (created_at)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @file_put_contents($flag, date('c'));
    } catch (\Throwable $e) { /* will retry next request until the flag is written */ }
}
smlic_telemetry_migrate();

/** V1 FIX — idempotent: ensure the per-license POLICY columns exist on `licenses`. Without them, /servers,
 *  /servers/view, Reset, and every policy button would throw under mysqli STRICT (the @ operator does NOT suppress
 *  exceptions) → uncaught 500, which also blocks the operator from issuing the `reset` that recovers a flagged box.
 *  Distinct flag file so it runs once even on servers that already passed the telemetry migration. Works on both
 *  MySQL (no ADD COLUMN IF NOT EXISTS) and MariaDB by discovering existing columns first. */
function smlic_licenses_cols_migrate(): void {
    $flag = __DIR__ . '/../storage/.licenses_cols_migrated2';   // bumped (was ...migrated): re-run once to add pair_secret
    if (is_file($flag)) return;
    try {
        $need = [
            'sync_enabled' => "ADD COLUMN sync_enabled TINYINT NOT NULL DEFAULT 0",
            'sync_purge'   => "ADD COLUMN sync_purge TINYINT NOT NULL DEFAULT 0",
            'directive'    => "ADD COLUMN directive VARCHAR(10) NOT NULL DEFAULT 'normal'",
            'pin_version'  => "ADD COLUMN pin_version VARCHAR(20) NULL",
            'pair_secret'  => "ADD COLUMN pair_secret VARCHAR(64) NULL",   // Stage 0: per-license base secret S
        ];
        $have = [];
        if ($rs = db()->query("SHOW COLUMNS FROM licenses")) { while ($row = $rs->fetch_assoc()) $have[strtolower((string)$row['Field'])] = 1; }
        $adds = [];
        foreach ($need as $col => $ddl) if (empty($have[$col])) $adds[] = $ddl;
        if ($adds) db()->query("ALTER TABLE licenses " . implode(', ', $adds));
        @file_put_contents($flag, date('c'));
    } catch (\Throwable $e) { /* retry next request until the flag is written (e.g. licenses table not created yet) */ }
}
smlic_licenses_cols_migrate();

/** UPSERT the latest telemetry snapshot for a license. All fields optional + bounded. */
function smlic_telemetry_ingest(string $key, array $data, string $serverIp, string $hostname): void {
    if ($key === '') return;
    $t = ($data['telemetry'] ?? null);
    if (!is_array($t)) $t = $data;   // accept flat or nested under "telemetry"
    $s   = fn($v, $n) => ($v === null || $v === '') ? null : substr((string)$v, 0, $n);
    $i   = fn($v) => ($v === null || $v === '') ? null : (int)$v;
    $f2  = fn($v) => ($v === null || $v === '') ? null : round((float)$v, 2);
    $mac = $s($t['mac'] ?? null, 64);
    $os  = $s($t['os'] ?? null, 120);
    $pan = $s($t['panel'] ?? null, 80);
    $cor = $i($t['cpu_cores'] ?? null);
    $ram = $i($t['ram_mb'] ?? null);
    $up  = $i($t['uptime_sec'] ?? null);
    $l1  = $f2($t['load1'] ?? null);
    $l15 = $f2($t['load15'] ?? null);
    $ver = $s($t['version'] ?? ($data['plugin_version'] ?? null), 20);
    $acc = $i($t['accounts'] ?? null);
    $host = $s($hostname, 255);
    $ip   = $s($serverIp, 45);
    $sql = "INSERT INTO license_telemetry
              (license_key, hostname, server_ip, mac, os, panel, cpu_cores, ram_mb, uptime_sec, load1, load15, version, accounts, reported_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, NOW())
            ON DUPLICATE KEY UPDATE
              hostname=VALUES(hostname), server_ip=VALUES(server_ip), mac=COALESCE(VALUES(mac),mac),
              os=COALESCE(VALUES(os),os), panel=COALESCE(VALUES(panel),panel),
              cpu_cores=COALESCE(VALUES(cpu_cores),cpu_cores), ram_mb=COALESCE(VALUES(ram_mb),ram_mb),
              uptime_sec=VALUES(uptime_sec), load1=VALUES(load1), load15=VALUES(load15),
              version=COALESCE(VALUES(version),version), accounts=COALESCE(VALUES(accounts),accounts), reported_at=NOW()";
    try {
        $st = db()->prepare($sql);
        if (!$st) return;
        $st->bind_param('ssssssiiiddsi', $key, $host, $ip, $mac, $os, $pan, $cor, $ram, $up, $l1, $l15, $ver, $acc);
        $st->execute();
    } catch (\Throwable $e) { /* telemetry is best-effort — never break a license check */ }
}

/** Duplicate-binding guard: is another license already bound to this exact IP + hostname?
 *  Returns the other license_key (string) if taken, or null. Used to refuse a 2nd serial on the same server. */
function smlic_server_taken($key, $ip, $host, $fp = null) {
    $ip = trim((string)$ip); $host = trim((string)$host); $fp = trim((string)$fp);
    if ($fp === '') return null; // product-aware: dedup by fingerprint
    try {
        $st = db()->prepare("SELECT license_key FROM licenses WHERE license_key <> ? AND bound_fingerprint = ? AND status <> 'expired' LIMIT 1");
        if (!$st) return null;
        $st->bind_param('ss', $key, $fp); $st->execute();
        $r = $st->get_result()->fetch_assoc();
        return $r ? (string)$r['license_key'] : null;
    } catch (\Throwable $e) { return null; }
}

/** Pop the oldest pending command for a license, mark it 'sent', return it (or null). */
function smlic_command_pop(string $key): ?array {
    if ($key === '') return null;
    try {
        $st = db()->prepare("SELECT id, command, args FROM license_commands WHERE license_key=? AND status='pending' ORDER BY id ASC LIMIT 1");
        if (!$st) return null;
        $st->bind_param('s', $key); $st->execute();
        $r = $st->get_result()->fetch_assoc();
        if (!$r) return null;
        $up = db()->prepare("UPDATE license_commands SET status='sent', sent_at=NOW() WHERE id=?");
        $id = (int)$r['id']; $up->bind_param('i', $id); $up->execute();
        return ['id' => (int)$r['id'], 'command' => (string)$r['command'], 'args' => (string)($r['args'] ?? '')];
    } catch (\Throwable $e) { return null; }
}

/** Mark a command done/failed (called from a future /api/command-ack; defined now for completeness). */
function smlic_command_ack(int $id, string $status, string $result = ''): void {
    if (!in_array($status, ['done', 'failed'], true)) return;
    try {
        $st = db()->prepare("UPDATE license_commands SET status=?, result=?, done_at=NOW() WHERE id=?");
        $st->bind_param('ssi', $status, $result, $id); $st->execute();
    } catch (\Throwable $e) {}
}
