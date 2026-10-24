<?php
/**
 * helpers.php - read-only live collectors + small utilities.
 * Every function here READS system state only. No mutation, no restart.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** HTML-escape shortcut. */
function smpro_h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Neutralize spreadsheet formula injection (CWE-1236): prefix a single quote when a cell begins with
 *  = + - @ or a leading control char, so Excel/LibreOffice treat log-derived cells as text, not formulas. */
function smpro_csv_cell($v) {
    $v = (string)$v;
    if ($v !== '' && strpbrk($v[0], "=+-@\t\r\n") !== false) return "'" . $v;
    return $v;
}
/** fputcsv wrapper that runs every field through smpro_csv_cell() - use for any CSV built from log/network data. */
function smpro_fputcsv($fh, array $row) {
    return fputcsv($fh, array_map('smpro_csv_cell', $row));
}

/** Beta build gate - beta-only sections render only when the running build is a beta (version carries "beta").
 *  Same license key works for both stable and beta; the stable build simply hides beta sections. */
function smpro_is_beta() { return defined('SMPRO_VERSION') && stripos(SMPRO_VERSION, 'beta') !== false; }

/** Small inline "🧪 Beta" badge for sections that are in beta test. */
function smpro_beta_badge($label = 'Beta') {
    return '<span style="display:inline-block;font-size:10px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;'
         . 'color:#7c3aed;background:#f3e8ff;border:1px solid #e2d1fb;border-radius:6px;padding:1px 6px;vertical-align:middle;margin-left:6px">'
         . '&#129514; ' . smpro_h($label) . '</span>';
}

/**
 * Brand logo - inline SVG shield with a monitor "pulse" line (Safety + Monitor).
 * Scales to $px; a unique gradient id per call avoids duplicate-id clashes when
 * the logo appears multiple times on one page (header + sidebar + footer).
 */
function smpro_brand_logo($px = 22) {
    static $n = 0; $u = (string)(++$n); $px = (int)$px;
    // Official HostGuard shield mark (from hostguard.org brand asset): shield frame +
    // server rack (units + status LEDs) + padlock badge. Gradient ids suffixed per call
    // so the mark can appear multiple times on one page without id clashes.
    return '<svg class="smpro-logo" width="' . $px . '" height="' . $px . '" viewBox="4 2 92 108" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">'
         . '<defs>'
         . '<linearGradient id="hgF' . $u . '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f9bff"/><stop offset="1" stop-color="#1d62e0"/></linearGradient>'
         . '<linearGradient id="hgB' . $u . '" x1="0" y1="0" x2="0.25" y2="1"><stop offset="0" stop-color="#1f2c4d"/><stop offset="1" stop-color="#0c1426"/></linearGradient>'
         . '<linearGradient id="hgR' . $u . '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2a3a63"/><stop offset="1" stop-color="#16223f"/></linearGradient>'
         . '<linearGradient id="hgU' . $u . '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#33456e"/><stop offset="1" stop-color="#1c2840"/></linearGradient>'
         . '<linearGradient id="hgG' . $u . '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f9bff"/><stop offset="1" stop-color="#1c5fd6"/></linearGradient>'
         . '<radialGradient id="hgL' . $u . '" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#9fe2ff"/><stop offset="1" stop-color="#2bb3f0"/></radialGradient>'
         . '</defs>'
         . '<path d="M50 4 L93 18 V47 C93 80 76 99 50 108 C24 99 7 80 7 47 V18 Z" fill="url(#hgF' . $u . ')"/>'
         . '<path d="M50 9 L88 21.5 V47 C88 77 72 94 50 102 C28 94 12 77 12 47 V21.5 Z" fill="url(#hgB' . $u . ')"/>'
         . '<path d="M50 9 L88 21.5 V47 C88 77 72 94 50 102 Z" fill="url(#hgR' . $u . ')" opacity="0.92"/>'
         . '<g stroke="#0e1730" stroke-width="0.6"><rect x="24" y="30" width="52" height="13" rx="3" fill="url(#hgU' . $u . ')"/><rect x="24" y="46" width="52" height="13" rx="3" fill="url(#hgU' . $u . ')"/><rect x="24" y="62" width="52" height="13" rx="3" fill="url(#hgU' . $u . ')"/></g>'
         . '<g fill="url(#hgL' . $u . ')"><circle cx="31" cy="36.5" r="2.6"/><circle cx="31" cy="52.5" r="2.6"/><circle cx="31" cy="68.5" r="2.6"/></g>'
         . '<g fill="#5b6e96"><rect x="52" y="35.4" width="5" height="2.2" rx="1.1"/><rect x="60" y="35.4" width="5" height="2.2" rx="1.1"/><rect x="68" y="35.4" width="4" height="2.2" rx="1.1"/><rect x="52" y="51.4" width="5" height="2.2" rx="1.1"/><rect x="60" y="51.4" width="5" height="2.2" rx="1.1"/><rect x="68" y="51.4" width="4" height="2.2" rx="1.1"/></g>'
         . '<path d="M50 64 L66 70 V80 C66 90 59 96 50 99 C41 96 34 90 34 80 V70 Z" fill="url(#hgG' . $u . ')" stroke="#0e1730" stroke-width="0.5"/>'
         . '<path d="M45 79 V76 A5 5 0 0 1 55 76 V79" fill="none" stroke="#ffffff" stroke-width="2.4" stroke-linecap="round"/>'
         . '<rect x="43.5" y="79" width="13" height="11" rx="2" fill="#ffffff"/><circle cx="50" cy="84" r="1.7" fill="#1c5fd6"/><rect x="49.2" y="84.5" width="1.6" height="3.6" rx="0.8" fill="#1c5fd6"/>'
         . '</svg>';
}

/** The brand logo as a data:image/svg+xml URI (self-contained, for <link rel=icon>). */
function smpro_brand_favicon_uri() {
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="4 2 92 108">'
         . '<defs>'
         . '<linearGradient id="ff" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f9bff"/><stop offset="1" stop-color="#1d62e0"/></linearGradient>'
         . '<linearGradient id="fb" x1="0" y1="0" x2="0.25" y2="1"><stop offset="0" stop-color="#1f2c4d"/><stop offset="1" stop-color="#0c1426"/></linearGradient>'
         . '<linearGradient id="fu" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#33456e"/><stop offset="1" stop-color="#1c2840"/></linearGradient>'
         . '<linearGradient id="fg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f9bff"/><stop offset="1" stop-color="#1c5fd6"/></linearGradient>'
         . '<radialGradient id="fl" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#9fe2ff"/><stop offset="1" stop-color="#2bb3f0"/></radialGradient>'
         . '</defs>'
         . '<path d="M50 4 L93 18 V47 C93 80 76 99 50 108 C24 99 7 80 7 47 V18 Z" fill="url(#ff)"/>'
         . '<path d="M50 9 L88 21.5 V47 C88 77 72 94 50 102 C28 94 12 77 12 47 V21.5 Z" fill="url(#fb)"/>'
         . '<g stroke="#0e1730" stroke-width="0.6"><rect x="24" y="30" width="52" height="13" rx="3" fill="url(#fu)"/><rect x="24" y="46" width="52" height="13" rx="3" fill="url(#fu)"/><rect x="24" y="62" width="52" height="13" rx="3" fill="url(#fu)"/></g>'
         . '<g fill="url(#fl)"><circle cx="31" cy="36.5" r="2.6"/><circle cx="31" cy="52.5" r="2.6"/><circle cx="31" cy="68.5" r="2.6"/></g>'
         . '<path d="M50 64 L66 70 V80 C66 90 59 96 50 99 C41 96 34 90 34 80 V70 Z" fill="url(#fg)" stroke="#0e1730" stroke-width="0.5"/>'
         . '<path d="M45 79 V76 A5 5 0 0 1 55 76 V79" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>'
         . '<rect x="43.5" y="79" width="13" height="11" rx="2" fill="#fff"/><circle cx="50" cy="84" r="1.7" fill="#1c5fd6"/><rect x="49.2" y="84.5" width="1.6" height="3.6" rx="0.8" fill="#1c5fd6"/>'
         . '</svg>';
    return 'data:image/svg+xml,' . rawurlencode($svg);
}

/** Brand company name as a link to the brand site (used in sidebar + footer). */
function smpro_brand_link($label = null) {
    $name = $label !== null ? $label : (defined('SMPRO_BRAND_COMPANY') ? SMPRO_BRAND_COMPANY : 'HostGuard.org');
    $url  = defined('SMPRO_BRAND_URL') ? SMPRO_BRAND_URL : 'https://hostguard.org';
    return '<a href="' . smpro_h($url) . '" target="_blank" rel="noopener noreferrer" class="smpro-brand-link">' . smpro_h($name) . '</a>';
}

/** Append a JSON line to the audit log. Best-effort, never fatal. */
/**
 * A cron worker that dies must SAY so. Every worker in bin/ wraps its job in try/catch so one bad run cannot
 * leave a stuck process - but an empty catch turned that into silence: a guard that threw on every run looked,
 * from the outside, exactly like a guard that ran and found nothing. This records the failure the same way
 * index.php records a module fatal, so an operator reading the audit trail sees "the login guard has been
 * failing since Tuesday" instead of nothing at all. Falls back to error_log if the audit trail itself is
 * unavailable, so the failure is written SOMEWHERE no matter what broke.
 */
function smpro_worker_fatal($workerFile, \Throwable $e) {
    $d = ['worker' => basename((string)$workerFile), 'err' => $e->getMessage(),
          'file' => basename($e->getFile()), 'line' => $e->getLine()];
    if (function_exists('smpro_audit')) { try { smpro_audit('worker_fatal', $d); return; } catch (\Throwable $x) {} }
    @error_log('smpro worker_fatal ' . json_encode($d));
}

function smpro_audit($action, array $details = []) {
    $line = json_encode([
        'timestamp' => date('c'),
        'level'     => 'INFO',
        'action'    => $action,
        'actor'     => smpro_actor(),
        'ip'        => $_SERVER['REMOTE_ADDR'] ?? 'cli',
        'details'   => $details,
    ], JSON_UNESCAPED_SLASHES);
    // Size-bounded rotation (once per request, best-effort): the log is append-only with no logrotate, and the
    // readers tail/grep it - at ~20MB roll to audit.log.1 and start fresh so it can't grow (or slow reads) forever.
    smpro_log_append(SMPRO_AUDIT_LOG, $line . "\n", 20971520, 3);   // rotated under a lock, three generations
}

/**
 * Lightweight per-actor fixed-window rate limit. Returns TRUE if the call is allowed, FALSE if over budget.
 * File-based (SMPRO_CACHE/rl), best-effort, never fatal - protects paid/upstream endpoints (AI, license server)
 * from a stuck retry loop or a compromised-but-authenticated session burning token/quota.
 */
function smpro_ratelimit($bucket, $max, $window) {
    $dir = SMPRO_CACHE . '/rl';
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $actor = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string)(function_exists('smpro_actor') ? smpro_actor() : 'cli'));
    $f = $dir . '/' . preg_replace('/[^A-Za-z0-9_.-]/', '_', (string)$bucket) . '_' . $actor . '.json';
    $now = time();
    $st = @json_decode((string)@file_get_contents($f), true);
    if (!is_array($st) || ($now - (int)($st['start'] ?? 0)) >= (int)$window) $st = ['start' => $now, 'n' => 0];
    $st['n'] = (int)($st['n'] ?? 0) + 1;
    @file_put_contents($f, json_encode($st), LOCK_EX);
    return $st['n'] <= (int)$max;
}

/** Best-effort actor identity (WHM runs as root). */
function smpro_actor() {
    return $_ENV['REMOTE_USER'] ?? ($_SERVER['REMOTE_USER'] ?? (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'root') : 'root'));
}

/* ----------------------------------------------------------------------
 * LIVE COLLECTORS (read-only)
 * -------------------------------------------------------------------- */

/** CPU core count. */
function smpro_cpu_cores() {
    $n = 0;
    foreach (@file('/proc/cpuinfo') ?: [] as $l) {
        if (strpos($l, 'processor') === 0) $n++;
    }
    return $n ?: 1;
}

/** Load averages from /proc/loadavg -> [1m,5m,15m]. */
function smpro_loadavg() {
    $p = explode(' ', trim(@file_get_contents('/proc/loadavg')));
    return [
        '1m'  => (float)($p[0] ?? 0),
        '5m'  => (float)($p[1] ?? 0),
        '15m' => (float)($p[2] ?? 0),
    ];
}

/** Load-average colour band by ABSOLUTE 1-min value (admin spec, NOT pressure):
 *  <=10 good (green) · >10..25 elev (orange) · >25..30 warn (yellow) · >30 danger (red). */
function smpro_load_cls($v) {
    $v = (float)$v;
    if ($v > 30) return 'danger';
    if ($v > 25) return 'warn';
    if ($v > 10) return 'elev';
    return 'good';
}

/** System uptime in seconds. */
function smpro_uptime() {
    $p = explode(' ', trim(@file_get_contents('/proc/uptime')));
    return (int)($p[0] ?? 0);
}

/** Memory snapshot from /proc/meminfo (values in MB). */
function smpro_memory() {
    $m = [];
    foreach (@file('/proc/meminfo') ?: [] as $l) {
        if (preg_match('/^(\w+):\s+(\d+)/', $l, $x)) $m[$x[1]] = (int)$x[2]; // kB
    }
    $total = $m['MemTotal'] ?? 0;
    $avail = $m['MemAvailable'] ?? ($m['MemFree'] ?? 0);
    $used  = $total - $avail;
    return [
        'total_mb' => round($total / 1024),
        'used_mb'  => round($used / 1024),
        'free_mb'  => round($avail / 1024),
        'percent'  => $total ? round($used / $total * 100, 1) : 0,
        'swap_total_mb' => round(($m['SwapTotal'] ?? 0) / 1024),
        'swap_used_mb'  => round((($m['SwapTotal'] ?? 0) - ($m['SwapFree'] ?? 0)) / 1024),
    ];
}

/** Instant CPU utilization % via two /proc/stat samples (~120ms). */
function smpro_cpu_usage() {
    $a = smpro_cpu_stat_snapshot();
    usleep(120000);
    $b = smpro_cpu_stat_snapshot();
    $dt = $b['total'] - $a['total'];
    $di = $b['idle']  - $a['idle'];
    if ($dt <= 0) return 0.0;
    return round((1 - $di / $dt) * 100, 1);
}
function smpro_cpu_stat_snapshot() {
    foreach (@file('/proc/stat') ?: [] as $l) {
        if (strpos($l, 'cpu ') === 0) {
            $p = preg_split('/\s+/', trim($l));
            array_shift($p);
            $p = array_map('intval', $p);
            $idle  = ($p[3] ?? 0) + ($p[4] ?? 0); // idle + iowait
            $total = array_sum($p);
            return ['idle' => $idle, 'total' => $total];
        }
    }
    return ['idle' => 0, 'total' => 0];
}

/** Root filesystem disk usage. */
function smpro_disk_root() {
    $total = @disk_total_space('/') ?: 0;
    $free  = @disk_free_space('/') ?: 0;
    $used  = $total - $free;
    return [
        'total' => $total,
        'used'  => $used,
        'free'  => $free,
        'percent' => $total ? round($used / $total * 100, 1) : 0,
    ];
}

/** Process count (read-only, counts /proc/<pid> dirs). */
function smpro_process_count() {
    $n = 0;
    foreach (@scandir('/proc') ?: [] as $e) {
        if (ctype_digit($e)) $n++;
    }
    return $n;
}

/** Human-readable bytes. THE canonical byte formatter - new code must call this, not roll its own.
 *  (Several modules still carry their own drifted copies with slightly different output; those are migrated
 *  to this one only when the file is already being edited for another reason, never in a risky mass sweep.) */
function smpro_bytes($b) {
    $u = ['B','KB','MB','GB','TB','PB'];
    $b = (float)$b; $i = 0;
    while ($b >= 1024 && $i < count($u) - 1) { $b /= 1024; $i++; }
    return round($b, $i ? 2 : 0) . ' ' . $u[$i];
}

/**
 * THE canonical timeout-bounded shell runner - new code must call this instead of reinventing a per-file
 * `*_sh`/`*_run` wrapper (there are ~20 drifted copies today; they migrate to this one on touch, not in a
 * mass sweep). Returns captured output as a string.
 *
 *   $timeout  seconds before `timeout(1)` kills the command (min 1).
 *   $opt['stderr']  'merge'  -> 2>&1 (default; you want to see errors)
 *                   'discard'-> 2>/dev/null (a probe whose stderr is noise)
 *                   'keep'   -> leave the caller's own redirection untouched
 *   $opt['path']    true -> prepend a hardened PATH so tools in /usr/local/sbin etc. resolve under the WHM CGI
 *                   environment (that PATH is often missing, which is why bare `sshd`/`csf` sometimes fail).
 *
 * The command is passed through verbatim, exactly like the wrappers it replaces - callers still
 * escapeshellarg() their own arguments. This function adds no quoting and makes nothing safe that wasn't.
 */
function smpro_run(string $cmd, int $timeout = SMPRO_TIMEOUT_NORMAL, array $opt = []): string {
    $redir  = ['merge' => ' 2>&1', 'discard' => ' 2>/dev/null', 'keep' => ''][$opt['stderr'] ?? 'merge'] ?? ' 2>&1';
    $prefix = !empty($opt['path']) ? 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' : '';
    $t      = max(1, (int)$timeout);
    return (string)@shell_exec($prefix . 'timeout ' . $t . ' ' . $cmd . $redir);
}

/**
 * Same runner, but returns [int $exitCode, string $output] for callers that branch on success/failure
 * (the shape the `exec()`-based per-file wrappers use). $output is stdout+stderr combined, trimmed.
 */
/**
 * Stream a command's stdout one line at a time (popen + fgets), so memory stays at one line no matter how long the
 * output is. `shell_exec` + `explode("\n")` holds the WHOLE output twice (the string and the array): a 200k-line
 * cPanel log window is ~60MB raw and ~300MB in PHP, which is over the 128M cap the cPanel CLI ships with - the page
 * died silently at that point. Same contract as smpro_run: the command is passed verbatim, the caller
 * quotes its own arguments; stderr is discarded; a `timeout` bounds the child. Lines come back without their
 * newline. Iterate once - it is a generator, not an array (count()/array_* do not apply).
 */
function smpro_run_lines(string $cmd, int $timeout = SMPRO_TIMEOUT_NORMAL): \Generator {
    $t = max(1, (int)$timeout);
    $h = @popen('timeout ' . $t . ' ' . $cmd . ' 2>/dev/null', 'r');
    if (!$h) return;
    try { while (($l = fgets($h)) !== false) yield rtrim($l, "\r\n"); }
    finally { @pclose($h); }
}

/**
 * Turn a fatal error into a visible, logged failure instead of a blank page. index.cgi runs PHP with
 * display_errors=0 and stderr discarded, so before this a page that ran out of memory or hit a parse/redeclare
 * fatal produced EMPTY output - the operator saw a white page and nothing anywhere said why. Registered once by
 * index.php after helpers load. Writes SMPRO_VARLOG/page_fatal.log, records an audit row, and prints a box (or a
 * JSON error for format=json). Kept lean on purpose: after an out-of-memory bailout there is little headroom.
 */
function smpro_page_fatal_guard(): void {
    static $armed = false; if ($armed) return; $armed = true;
    register_shutdown_function(function () {
        $e = error_get_last();
        if (!$e || !in_array((int)$e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) return;
        $msg   = (string)$e['message'];
        $where = basename((string)$e['file']) . ':' . (int)$e['line'];
        $page  = preg_replace('/[^a-z0-9_-]/i', '', (string)($_GET['page'] ?? ''));
        $oom   = stripos($msg, 'Allowed memory size') !== false;
        $peak  = (int)round(memory_get_peak_usage(true) / 1048576);
        if (defined('SMPRO_VARLOG')) {
            @is_dir(SMPRO_VARLOG) || @mkdir(SMPRO_VARLOG, 0700, true);
            smpro_log_append(SMPRO_VARLOG . '/page_fatal.log', date('c') . " page=$page where=$where peak={$peak}MB limit=" . ini_get('memory_limit') . " msg=" . str_replace("\n", ' ', $msg) . "\n", 2097152, 2);
        }
        if (function_exists('smpro_audit')) { try { smpro_audit('page_fatal', ['page' => $page, 'where' => $where, 'oom' => $oom, 'peak_mb' => $peak, 'msg' => substr($msg, 0, 300)]); } catch (\Throwable $t) {} }
        $human = $oom
            ? 'This page ran out of memory (' . $peak . ' MB used, limit ' . ini_get('memory_limit') . ') while reading its data. Choose a smaller log window or a narrower date range and try again.'
            : 'This page stopped before it finished: ' . $msg;
        if ((string)($_GET['format'] ?? '') === 'json') { echo json_encode(['ok' => false, 'error' => 'page_fatal', 'oom' => $oom, 'where' => $where, 'msg' => $human]); return; }
        echo '<div style="margin:24px;padding:16px 20px;border:1px solid #d33;border-left-width:6px;background:#fff5f5;color:#611;font:14px/1.5 system-ui,sans-serif">'
           . '<b>Page stopped</b> — ' . htmlspecialchars($human, ENT_QUOTES, 'UTF-8')
           . '<div style="margin-top:6px;font-size:12px;color:#844;font-family:monospace">' . htmlspecialchars($where, ENT_QUOTES, 'UTF-8') . ' · recorded in page_fatal.log</div></div>';
    });
}

/**
 * Record a swallowed exception instead of losing it. Optional self-heal steps (installing a cron, refreshing GeoIP,
 * a background posture refresh) must never break a page, so they run inside try/catch - but a `catch {}` that
 * discards the error is how a cron that silently never installs stays invisible for months. Every such site now
 * calls this: one line in SMPRO_VARLOG/soft_fail.log (context, class, message, file:line), capped at 1MB, never throws.
 */
function smpro_soft_fail(string $ctx, \Throwable $e): void {
    try {
        if (!defined('SMPRO_VARLOG')) return;
        $f = SMPRO_VARLOG . '/soft_fail.log';
        @is_dir(SMPRO_VARLOG) || @mkdir(SMPRO_VARLOG, 0700, true);
        $line = date('c') . ' ' . $ctx . ' ' . get_class($e) . ': ' . str_replace("\n", ' ', $e->getMessage()) . ' @ ' . basename($e->getFile()) . ':' . $e->getLine() . "\n";
        @file_put_contents($f, $line, FILE_APPEND | LOCK_EX);
        if (@filesize($f) > 1048576) { $t = (string)@file_get_contents($f); @file_put_contents($f, substr($t, -524288), LOCK_EX); }
    } catch (\Throwable $x) {}
}

/**
 * Worker counterpart of smpro_page_fatal_guard(): a bin/ script that dies of a FATAL (out of memory, redeclare,
 * parse error) never reaches its own try/catch, so before this the worker simply stopped - no audit row, no log
 * line, the cron kept "running". Armed automatically below for every CLI process that is not a web request and
 * not the test lab. Writes the same worker_fatal audit row smpro_worker_fatal() writes, plus SMPRO_VARLOG/worker_fatal.log.
 */
function smpro_worker_fatal_guard(): void {
    static $armed = false; if ($armed) return; $armed = true;
    register_shutdown_function(function () {
        $e = error_get_last();
        if (!$e || !in_array((int)$e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) return;
        $script = basename((string)($_SERVER['SCRIPT_FILENAME'] ?? ($_SERVER['argv'][0] ?? 'cli')));
        $d = ['worker' => $script, 'msg' => substr((string)$e['message'], 0, 400), 'file' => basename((string)$e['file']), 'line' => (int)$e['line'],
              'oom' => stripos((string)$e['message'], 'Allowed memory size') !== false, 'peak_mb' => (int)round(memory_get_peak_usage(true) / 1048576), 'limit' => ini_get('memory_limit')];
        if (defined('SMPRO_VARLOG')) smpro_log_append(SMPRO_VARLOG . '/worker_fatal.log', date('c') . ' ' . json_encode($d, JSON_UNESCAPED_SLASHES) . "\n", 2097152, 2);   // a worker failing every minute wrote without bound
        if (function_exists('smpro_audit')) { try { smpro_audit('worker_fatal', $d); } catch (\Throwable $x) {} }
    });
}
if (PHP_SAPI === 'cli' && getenv('REQUEST_METHOD') === false && !isset($_SERVER['REQUEST_METHOD']) && !defined('SMPRO_TEST_SRC')) smpro_worker_fatal_guard();

function smpro_run_rc(string $cmd, int $timeout = SMPRO_TIMEOUT_NORMAL, array $opt = []): array {
    $prefix = !empty($opt['path']) ? 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' : '';
    $t      = max(1, (int)$timeout);
    $out    = []; $rc = 0;
    @exec($prefix . 'timeout ' . $t . ' ' . $cmd . ' 2>&1', $out, $rc);
    return [(int)$rc, trim(implode("\n", $out))];
}

/** Human-readable uptime. */
function smpro_dur($sec) {
    $d = intdiv($sec, 86400); $sec %= 86400;
    $h = intdiv($sec, 3600);  $sec %= 3600;
    $m = intdiv($sec, 60);
    return ($d ? "{$d}d " : '') . sprintf('%dh %dm', $h, $m);
}

/**
 * Generic read-through file cache (loaded everywhere, unlike smpro_bd_cache in benchdiag).
 * Use to keep expensive probes OFF the render path per the plugin rule: wrap the probe so the
 * result is recomputed at most once per $ttl instead of on every page load / post-action reload.
 *   $data = smpro_cache_through('netbw', 300, fn() => smpro_net_bandwidth());
 * With $compute=false it returns the cached value even if stale (never recomputes) - the render-only
 * mode; a format=json poll then calls it with $compute=true to refresh. Cache under SMPRO_CACHE, 0600.
 */
function smpro_cache_through($key, $ttl, callable $producer, $compute = true) {
    $dir = defined('SMPRO_CACHE') ? SMPRO_CACHE : (SMPRO_VARLIB . '/cache');
    $f = $dir . '/ct_' . preg_replace('/[^a-z0-9_]/i', '', (string)$key) . '.json';
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    $has = is_array($d) && array_key_exists('v', $d);
    if ($has && (time() - (int)($d['ts'] ?? 0)) < $ttl) return $d['v'];
    if (!$compute) return $has ? $d['v'] : null;                 // stale beats blocking on the render path
    $v = $producer();
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode(['ts' => time(), 'v' => $v], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    return $v;
}
/** Invalidate a smpro_cache_through() entry - call after an action that changes what the probe would report. */
function smpro_cache_bust($key) {
    $dir = defined('SMPRO_CACHE') ? SMPRO_CACHE : (SMPRO_VARLIB . '/cache');
    @unlink($dir . '/ct_' . preg_replace('/[^a-z0-9_]/i', '', (string)$key) . '.json');
}

/** Status color from a percentage (green<80, warn<90, danger). */
function smpro_status($pct) {
    if ($pct >= 90) return 'danger';
    if ($pct >= 80) return 'warn';
    return 'good';
}
/* LOAD pressure (load ÷ cores, %) verdict - the SINGLE source of truth for load colour, used everywhere
 * (dashboard, Server Health page, top bar, health score): warn ≥70%, danger ≥100%. Keep these thresholds
 * identical to smpro_sv_snapshot()/load-monitor verdict so the same load never shows two different colours. */
function smpro_load_status($pressure) {
    if ($pressure >= 100) return 'danger';
    if ($pressure >= 70)  return 'warn';
    return 'good';
}

/**
 * Centralized redaction (plan §11). Strips session tokens, auth tokens,
 * passwords and signed URLs from any text before display/export.
 */
function smpro_redact_sensitive($text) {
    $text = (string)$text;
    $text = preg_replace('#/cpsess\d+#', '/cpsess[REDACTED]', $text);
    $text = preg_replace('/\b(cpsess|access_token|refresh_token|auth_token|security_token|token|signature_v2|sign|api[_-]?key|apikey|secret)=([^&\s"\']+)/i', '$1=[REDACTED]', $text);
    $text = preg_replace('/\b(pass|passwd|password|pwd)=([^&\s"\']+)/i', '$1=[REDACTED]', $text);
    return $text;
}

/* ---- Server Health snapshot (matches the legacy dashboard score logic exactly) ---- */
if (!defined('SMPRO_SV_ABS_WARN')) define('SMPRO_SV_ABS_WARN', 15.0);   // legacy fallback only
/** Absolute load thresholds SCALED to core count - so a big server (e.g. 96 cores) is not
 *  flagged warning/danger at light load. Warn ≈ coresx0.5 (~50% pressure), danger ≈ coresx0.85. */
function smpro_sv_abs_warn($cores)   { $cores = max(1, (int)$cores); return max(6.0,  round($cores * 0.5,  1)); }
function smpro_sv_abs_danger($cores) { $cores = max(1, (int)$cores); return max(10.0, round($cores * 0.85, 1)); }
/** Color class for a 0-100 percentage: good(green) / attn(blue) / danger(red). */
function smpro_sv_col($pct) { if ($pct >= 90) return 'danger'; if ($pct >= 70) return 'attn'; return 'good'; }
/**
 * Full server-health snapshot. Health is driven by Load Averages PEAK pressure
 * across cores - identical formula to the legacy Safety Monitor dashboard.
 */
function smpro_sv_snapshot() {
    $m = smpro_collect_metrics();
    $cores = max(1, (int)$m['cores']); $load = $m['load'];
    $l1 = round((float)$load['1m'], 2); $l5 = round((float)$load['5m'], 2); $l15 = round((float)$load['15m'], 2);
    $peak = max($l1, $l5, $l15);
    $pressure = round(($peak / $cores) * 100, 1);
    $absWarn = smpro_sv_abs_warn($cores); $absDanger = smpro_sv_abs_danger($cores);

    if ($pressure >= 100 || $peak >= $absDanger) $level = 'danger';
    elseif ($pressure >= 70 || $peak >= $absWarn) $level = 'warning';
    else $level = 'good';

    if ($level === 'danger') { $score = max(0, min(59, 59 - (int)round(max(0, $pressure - 100) * 0.5))); $cause = 'Critical Load Averages detected.'; }
    elseif ($level === 'warning') {
        if ($pressure >= 70) { $score = max(60, 79 - (int)round(($pressure - 70) * 0.65)); $cause = 'Elevated Load Averages pressure.'; }
        else { $score = 78; $cause = 'High absolute Load Average detected.'; }
    } else { $score = max(80, 100 - (int)round($pressure * 0.25)); $cause = 'No critical Load Averages detected.'; }

    $title = $level === 'good' ? 'Optimal status' : ($level === 'warning' ? 'Warning status' : 'Danger status');
    $cls = $level === 'good' ? 'good' : ($level === 'warning' ? 'warn' : 'danger');

    $tp = smpro_top_processes(60);
    $tu = $tp['groups'][0] ?? null;
    $tup = $tu ? round($tu['cpu'] / $cores * 100, 1) : 0;
    $lp = [];
    foreach (['1m' => $l1, '5m' => $l5, '15m' => $l15] as $k => $v) $lp[$k] = ['v' => $v, 'p' => round($v / $cores * 100, 1)];

    return [
        'ts' => $m['ts'], 'host' => $m['host'], 'cores' => $cores,
        'score' => $score, 'status' => strtoupper($level), 'status_title' => $title, 'cause' => $cause, 'cls' => $cls,
        'eff' => $pressure, 'peak' => $peak, 'abs_warn' => (int)$absWarn, 'load' => $lp,
        'cpu' => ['p' => $m['cpu']['pct'], 'cls' => smpro_sv_col($m['cpu']['pct'])],
        'ram' => ['p' => $m['ram']['pct'], 'cls' => smpro_sv_col($m['ram']['pct']), 'used' => $m['ram']['used'], 'total' => $m['ram']['total']],
        'disk' => ['p' => $m['disk']['pct'], 'cls' => smpro_sv_col($m['disk']['pct']), 'used' => $m['disk']['used'], 'total' => $m['disk']['total'], 'free' => $m['disk']['free']],
        'swap' => ['p' => $m['swap']['pct'], 'cls' => smpro_sv_col($m['swap']['pct']), 'used_mb' => $m['swap']['used_mb'], 'total_mb' => $m['swap']['total_mb']],
        'procs' => $m['procs'],
        'top_user' => $tu ? ['user' => $tu['user'], 'cpu' => $tu['cpu'], 'pressure' => $tup, 'cls' => smpro_sv_col(min(100, $tup))] : null,
    ];
}

/* ----------------------------------------------------------------------
 * IP INTELLIGENCE (shared) - country / provider / ASN via Team Cymru whois,
 * cached on disk, with a per-request new-lookup cap. Plus datacenter/bot
 * detection (logins from cloud/hosting ranges are almost always automated).
 * -------------------------------------------------------------------- */
if (!defined('SMPRO_IPCACHE')) define('SMPRO_IPCACHE', SMPRO_VARLIB . '/cache/ipintel.json');
if (!defined('SMPRO_IPTTL'))   define('SMPRO_IPTTL', 30 * 86400);
if (!defined('SMPRO_IPMAXNEW')) define('SMPRO_IPMAXNEW', 40);

function &smpro_ip_cache() {
    static $c = null;
    if ($c === null) {
        $d = is_file(SMPRO_IPCACHE) ? json_decode((string)@file_get_contents(SMPRO_IPCACHE), true) : null;
        $c = is_array($d) ? $d : [];
    }
    return $c;
}
function smpro_ip_is_external($ip) {
    return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function smpro_ip_parse_cymru($lines) {
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l === '' || stripos($l, 'AS Name') !== false || stripos($l, 'Bulk mode') !== false || strpos($l, '|') === false) continue;
        $p = array_map('trim', explode('|', $l));
        if (count($p) >= 7) return ['asn' => 'AS' . $p[0], 'country' => $p[3], 'provider' => $p[6], 'source' => 'Team Cymru whois'];
    }
    return [];
}
/** Is this IP's network a datacenter / cloud / hosting provider (=> likely bot)? */
function smpro_ip_is_datacenter($intel) {
    $hay = strtoupper(($intel['provider'] ?? '') . ' ' . ($intel['asn'] ?? ''));
    if ($hay === ' ') return false;
    static $kw = ['GOOGLE','AMAZON','AWS','AZURE','MICROSOFT','DIGITALOCEAN','OVH','HETZNER','LINODE',
        'VULTR','ALIBABA','TENCENT','CONTABO','LEASEWEB','SCALEWAY','ORACLE','M247','CHOOPA','RACKSPACE',
        'GODADDY','IONOS','SELECTEL','CLOUD','HOSTING','SERVER','DATACENTER','DATA CENTER','COLO','VPS',
        'DIGITAL OCEAN','CLOUDFLARE','FASTLY','LIMESTONE','PSYCHZ','QUADRANET','HOSTWINDS','NAMECHEAP'];
    // word-boundary match: a bare substring made short tokens (SERVER/COLO/VPS/CLOUD) false-match inside
    // residential org names (OBSERVER, COLOMBIA, ...), wrongly stripping home-region auto-block protection.
    foreach ($kw as $k) if (preg_match('/\b' . preg_quote($k, '/') . '\b/', $hay)) return true;
    return false;
}

/**
 * SECURITY guard for any root-run delete / backup / rewrite target. Returns the resolved real path ONLY if
 * it is NOT a symlink AND (after resolving every component) still lives under one of $allowedPrefixes; else ''.
 * Defeats a customer planting a symlink under their own /home/<acct>/ (e.g. -> /root/.ssh/id_rsa or /etc/shadow)
 * to make a root-executed copy()/unlink()/rename() leak or destroy a file outside their account.
 */
function smpro_path_safe($file, array $allowedPrefixes) {
    $file = (string) $file;
    if ($file === '' || is_link($file)) return '';            // a symlink target is refused outright
    $rp = @realpath($file);                                    // resolves symlink components + /.. + normalizes
    if ($rp === false) return '';
    foreach ($allowedPrefixes as $pre) {
        $pre = rtrim((string) $pre, '/');
        if ($pre === '') continue;
        // Also match the prefix's REAL path, so a server-level symlink (e.g. /home -> /home2, or accounts
        // on /home2/home3) doesn't wrongly reject an in-account file. $rp is fully resolved, so an attacker
        // symlink escaping the account still fails (it won't be under any allowed root).
        $preR = @realpath($pre);
        foreach (($preR !== false && $preR !== $pre) ? [$pre, $preR] : [$pre] as $p) {
            if ($rp === $p || strpos($rp, $p . '/') === 0) return $rp;
        }
    }
    return '';
}
/** Resolve country/provider/ASN for an IP (cached). $cap=false skips new whois. */
/* ---- offline GeoIP (local MaxMind DB) - resolves COUNTRY with no network, so it works even when outbound
 *      whois/port-43 is blocked by the firewall (the usual reason Country shows "n/a" on a locked-down box). ---- */
function smpro_geoip_bin() {
    static $b = null;
    if ($b === null) $b = is_executable('/usr/bin/mmdblookup') ? '/usr/bin/mmdblookup' : (trim((string)@shell_exec('command -v mmdblookup 2>/dev/null')) ?: '');
    return $b;
}
function smpro_geoip_db($kind = 'Country', $fresh = false) {
    static $p = [];
    if (!$fresh && isset($p[$kind])) return $p[$kind];
    // OUR own downloaded copy (SMPRO_VARLIB/geoip) is searched FIRST so a fresh DB always beats a stale/absent
    // system DB - this is what makes country resolve on a box with no system GeoIP DB.
    foreach ([SMPRO_VARLIB . '/geoip', '/usr/share/GeoIP', '/var/lib/csf/Geo', '/usr/local/share/GeoIP', '/var/lib/GeoIP', '/usr/share/GeoIP2'] as $d)
        foreach (["GeoLite2-$kind.mmdb", "GeoIP2-$kind.mmdb", "dbip-$kind.mmdb"] as $f)
            if (is_file("$d/$f")) return $p[$kind] = "$d/$f";
    return $p[$kind] = '';
}
/** Offline 2-letter country code for an IP via the local MaxMind DB. '' if unavailable.
 *  Prefers the fast `mmdblookup` binary; falls back to the pure-PHP reader (includes/mmdb.php) when the binary
 *  is absent - so country still resolves on a box without libmaxminddb installed. */
function smpro_geoip_cc($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $db = smpro_geoip_db('Country') ?: smpro_geoip_db('City');
    if ($db === '') return '';
    $bin = smpro_geoip_bin();
    if ($bin !== '') {
        $out = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' country iso_code 2>/dev/null');
        if (preg_match('/"([A-Za-z]{2})"/', $out, $m)) return strtoupper($m[1]);
    }
    return function_exists('smpro_mmdb_country') ? smpro_mmdb_country($db, $ip) : '';   // pure-PHP fallback
}
/** Offline ASN org/number via the local MaxMind ASN DB (if present). Returns ['asn'=>,'provider'=>] or [].
 *  Same mmdblookup-then-pure-PHP fallback as smpro_geoip_cc(). */
function smpro_geoip_asn($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return [];
    $db = smpro_geoip_db('ASN');
    if ($db === '') return [];
    $bin = smpro_geoip_bin();
    if ($bin !== '') {
        $r = [];
        $n = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' autonomous_system_number 2>/dev/null');
        if (preg_match('/(\d+)/', $n, $m)) $r['asn'] = 'AS' . $m[1];
        $o = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' autonomous_system_organization 2>/dev/null');
        if (preg_match('/"([^"]+)"/', $o, $m)) $r['provider'] = trim($m[1]);
        if ($r) return $r;
    }
    return function_exists('smpro_mmdb_asn') ? smpro_mmdb_asn($db, $ip) : [];           // pure-PHP fallback
}
/** Candidate download URLs for a GeoIP DB kind, in fallback order. All no-key / https / curl-able (verified).
 *  date('Y-m') is built at runtime here (the DB-IP file is month-stamped). */
function smpro_geoip_sources($kind) {
    $mo = date('Y-m'); $pm = date('Y-m', strtotime('first day of last month'));
    if (strtolower($kind) === 'asn') return [
        'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-asn-mmdb@latest/geolite2-asn.mmdb',      // combined v4+v6, no gzip
        'https://github.com/sapics/ip-location-db/releases/download/latest/geolite2-asn-ipv4.mmdb',     // 30x -> needs follow
        "https://download.db-ip.com/free/dbip-asn-lite-$mo.mmdb.gz",
        "https://download.db-ip.com/free/dbip-asn-lite-$pm.mmdb.gz",
    ];
    return [
        "https://download.db-ip.com/free/dbip-country-lite-$mo.mmdb.gz",                                 // gzip, v4+v6, current month
        "https://download.db-ip.com/free/dbip-country-lite-$pm.mmdb.gz",                                 // prev-month fallback
        'https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country-mmdb/dbip-country-ipv4.mmdb',
        'https://github.com/sapics/ip-location-db/releases/download/latest/dbip-country-ipv4.mmdb',      // 30x -> needs follow
        'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country-mmdb/geolite2-country-ipv4.mmdb',
    ];
}
/** Download a FRESH GeoIP DB from multiple free sources, validate it (pure-PHP reader, no mmdblookup needed),
 *  and atomically install it to SMPRO_VARLIB/geoip so it takes precedence over a stale/absent system DB.
 *  Returns ['ok'=>bool,'kind'=>,'source'=>,'bytes'=>,'msg'=>]. */
function smpro_geoip_update($kind = 'Country') {
    $kind = (strtolower($kind) === 'asn') ? 'ASN' : 'Country';
    $dir = SMPRO_VARLIB . '/geoip'; @is_dir($dir) || @mkdir($dir, 0755, true);
    $dest = "$dir/GeoLite2-$kind.mmdb";
    $marker = "\xab\xcd\xefMaxMind.com";
    // PRIMARY source = our LICENSED central delivery (we curate + keep it fresh from many mirrors,
    // gated by the license so it's a paid feature). Public mirrors stay as fallback so a server is
    // never left without a DB if our endpoint is unreachable or the license lapses.
    $lk   = (defined('SMPRO_LIC_BASE') && function_exists('smpro_lic_key')) ? trim((string) smpro_lic_key()) : '';
    $ours = ($lk !== '') ? [SMPRO_LIC_BASE . '/api/geoip?kind=' . strtolower($kind)] : [];
    foreach (array_merge($ours, smpro_geoip_sources($kind)) as $url) {
        $opts = ['timeout' => 90, 'follow' => true, 'maxbytes' => 80 * 1024 * 1024];   // cap download (anti-bomb)
        if ($lk !== '' && strpos($url, SMPRO_LIC_BASE . '/api/geoip') === 0) $opts['headers'] = ['X-License-Key: ' . $lk];   // authenticate to OUR endpoint (key stays in-process)
        $res = smpro_http($url, $opts);
        if (($res['code'] ?? 0) !== 200 || strlen($res['body']) < 50000) continue;
        $body = $res['body'];
        // gzip-bomb guard: cap the decompressed size (real DBs are ~30MB; reject anything wildly larger)
        if (substr($url, -3) === '.gz') { $d = @gzdecode($body, 96 * 1024 * 1024); if ($d === false || $d === '') continue; $body = $d; }
        if (strlen($body) < 100000 || strrpos($body, $marker) === false) continue;     // not a real mmdb
        // write to temp + validate WITH THE PURE-PHP READER (independent of mmdblookup)
        $tmp = $dest . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, $body) === false) continue;
        @chmod($tmp, 0644);
        $valid = false;
        if (function_exists('smpro_mmdb_open')) {
            if ($kind === 'Country') $valid = (smpro_mmdb_country($tmp, '8.8.8.8') === 'US');
            else                     $valid = (bool)(smpro_mmdb_asn($tmp, '8.8.8.8'));
        } else { $valid = true; }                                                       // reader absent -> trust marker check
        if (!$valid) { @unlink($tmp); continue; }
        if (!@rename($tmp, $dest)) { @unlink($tmp); continue; }                          // atomic install
        smpro_geoip_db($kind, true);                                                     // bust the path cache
        if (function_exists('smpro_in_cfg_save')) smpro_in_cfg_save(['geoip_last_update' => time()]);
        if (function_exists('smpro_audit')) smpro_audit('geoip_update', ['kind' => $kind, 'source' => $url, 'bytes' => strlen($body)]);
        return ['ok' => true, 'kind' => $kind, 'source' => $url, 'bytes' => strlen($body), 'msg' => "$kind DB updated (" . round(strlen($body)/1048576, 1) . " MB)"];
    }
    if (function_exists('smpro_audit')) smpro_audit('geoip_update', ['kind' => $kind, 'ok' => false]);
    return ['ok' => false, 'kind' => $kind, 'source' => '', 'bytes' => 0, 'msg' => "Could not download a $kind GeoIP database from any source."];
}
/** Throttled background refresh: pull Country+ASN when missing OR older than ~7 days. Cheap to call every cron tick. */
function smpro_geoip_auto_update() {
    $cfg = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    if (isset($cfg['geoip_auto_update']) && !$cfg['geoip_auto_update']) return;
    $missing = (smpro_geoip_db('Country') === '' || smpro_geoip_db('ASN') === '');
    $stale   = (time() - (int)($cfg['geoip_last_update'] ?? 0)) > 7 * 86400;
    if (!$missing && !$stale) return;
    foreach (['Country', 'ASN'] as $k) { try { smpro_geoip_update($k); } catch (\Throwable $e) { smpro_soft_fail('geoip_update:' . $k, $e); } }
}
/** HTTP request via the native curl extension so auth tokens/keys stay in this process's memory and never
 *  appear in the command line (shelling out to the `curl` binary leaks secrets via /proc/<pid>/cmdline,
 *  readable by other local users). TLS verification is ON. Returns ['code'=>int,'body'=>string,'error'=>string].
 *  $opts: method, headers[], body(string), timeout(int). Falls back to escaped shell curl only if the
 *  extension is missing (degraded - argv exposure - but functional). */
/** True when a request header carries a credential (then redirects are never followed). */
function smpro_http_has_secret_header(array $headers): bool {
    foreach ($headers as $h) if (preg_match('/^\s*(authorization|x-api-key|key|access-token|x-auth-token|api-key|x-token|cf-api-key|x-auth-key|x-auth-email)\s*:/i', (string)$h)) return true;
    return false;
}
function smpro_http($url, array $opts = []) {
    $method  = strtoupper((string)($opts['method'] ?? 'GET'));
    $timeout = (int)($opts['timeout'] ?? 15);
    $headers = (array)($opts['headers'] ?? []);
    $body    = $opts['body'] ?? null;
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $set = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => max(3, min(10, $timeout)),
            // Follow redirects BY DEFAULT (pass follow=>false to opt out). It used to be opt-in and no caller
            // ever opted in, so every JSON API here - Cloudflare, AbuseIPDB, Telegram, Pushbullet - would have
            // silently received an HTML redirect page the day its vendor moved a path, and json_decode would
            // just return null with no error. That exact failure hit the bot-ranges feed (see fwallow.php).
            // Capped at 5 hops, and TLS verification stays on across every hop.
            // A redirect may not leave https (so a hostile upstream cannot bounce a root-context request to
            // http://127.0.0.1:2087 or a metadata address), and a call that carries a secret header never follows
            // one at all: libcurl drops only Authorization/Cookie across hosts, custom API-key headers would travel.
            CURLOPT_FOLLOWLOCATION => (!array_key_exists('follow', $opts) || !empty($opts['follow'])) && !smpro_http_has_secret_header($headers),
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_USERAGENT      => 'SafetyMonitorPro',
        ];
        if (!empty($opts['maxbytes'])) {                      // refuse oversized downloads (anti decompression/transfer bomb)
            $max = (int)$opts['maxbytes'];
            $set[CURLOPT_MAXFILESIZE] = $max;                                   // rejects when Content-Length exceeds the cap
            $set[CURLOPT_NOPROGRESS]  = false;
            $set[CURLOPT_PROGRESSFUNCTION] = function ($ch, $dlTotal, $dlNow) use ($max) { return ($dlNow > $max || $dlTotal > $max) ? 1 : 0; }; // abort if it grows past the cap mid-stream
        }
        if ($method === 'POST')      { $set[CURLOPT_POST] = true; if ($body !== null) $set[CURLOPT_POSTFIELDS] = $body; }
        elseif ($method !== 'GET')   { $set[CURLOPT_CUSTOMREQUEST] = $method; if ($body !== null) $set[CURLOPT_POSTFIELDS] = $body; }
        $hdr = '';
        if (!empty($opts['want_headers'])) $set[CURLOPT_HEADERFUNCTION] = function ($ch, $line) use (&$hdr) { $hdr .= $line; return strlen($line); };
        curl_setopt_array($ch, $set);
        $out = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = (string)curl_error($ch); curl_close($ch);
        return ['code' => $code, 'body' => ($out === false ? '' : (string)$out), 'error' => $err, 'hdr' => $hdr];
    }
    // degraded fallback: extension absent -> shell curl (args fully escaped; only used if curl_init is missing)
    $cmd = 'curl -s -m ' . $timeout . ((!array_key_exists('follow', $opts) || !empty($opts['follow'])) ? ' -L --max-redirs 5' : '') . ' -X ' . escapeshellarg($method) . ' ' . escapeshellarg($url) . " -w '\\n%{http_code}'";
    // headers (tokens, keys) and the body never ride in argv, where every local user can read them in ps: they go
    // through a 0600 curl config file that is removed right after the call
    $cfgLines = [];
    foreach ($headers as $hh) $cfgLines[] = 'header = ' . json_encode((string)$hh);
    if ($body !== null) $cfgLines[] = 'data-binary = ' . json_encode((string)$body);
    $cf = '';
    if ($cfgLines) {
        $dir = defined('SMPRO_VARLIB') ? SMPRO_VARLIB . '/locks' : sys_get_temp_dir(); @is_dir($dir) || @mkdir($dir, 0700, true);
        $cf = $dir . '/curl.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.cfg';
        if (@file_put_contents($cf, implode("\n", $cfgLines) . "\n", LOCK_EX) === false) $cf = ''; else { @chmod($cf, 0600); $cmd .= ' --config ' . escapeshellarg($cf); }
    }
    $raw = (string)@shell_exec($cmd . ' 2>/dev/null');
    if ($cf !== '') @unlink($cf);
    $nl = strrpos($raw, "\n"); $code = $nl !== false ? (int)substr($raw, $nl + 1) : 0;
    return ['code' => $code, 'body' => $nl !== false ? substr($raw, 0, $nl) : $raw, 'error' => ''];
}
/** Mark the in-memory IP cache as changed; it is flushed to disk once, when the process ends. */
/**
 * Run $fn once per $ttl seconds per $key and hand back its result from disk in between. For page renders that
 * shell out to something slow (an API that takes seconds inside a WHM CGI, gunzip of rotated archives): the
 * first visitor pays, everyone in the next $ttl gets the page at once. `$fresh` bypasses and refills.
 * Only JSON-serialisable results; a null/false result is not cached (so a failed collection is retried).
 */
/**
 * smpro_memo for a SHELL COMMAND, with stale-while-refresh: a fresh value is returned from the cache; an expired one
 * (up to $maxStale old) is returned AS IS and the command is re-run in the background by bin/memo_refresh.php, so
 * the page never pays for the slow command itself after the first time. Only when nothing is cached is the
 * command run inline. The command text is stored in the root-only cache dir (0600) for the refresher to read.
 */
function smpro_memo_cmd(string $key, int $ttl, string $cmd, int $timeout = 60, int $maxStale = 604800, bool $bgOnMiss = false): string {
    $key = preg_replace('/[^a-zA-Z0-9_.-]/', '_', $key);
    $f = SMPRO_CACHE . '/memo_' . $key . '.json';
    clearstatcache(true, $f);
    $age = @is_file($f) ? time() - (int)@filemtime($f) : null;
    if ($age !== null && $age <= $maxStale) {
        $j = json_decode((string)@file_get_contents($f), true);
        if (is_array($j) && array_key_exists('v', $j)) {
            if ($age > $ttl) smpro_memo_refresh_bg($key, $cmd, $timeout);
            return (string)$j['v'];
        }
    }
    if ($bgOnMiss && !defined('SMPRO_TEST_SRC')) { smpro_memo_refresh_bg($key, $cmd, $timeout); return ''; }   // nothing yet: say so now, compute behind the page
    $v = (string)@shell_exec('timeout ' . max(1, $timeout) . ' sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null');
    @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true);
    if (@file_put_contents($f . '.tmp', json_encode(['v' => $v], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
    return $v;
}
/** Hand a memo command to the background refresher (at most one refresh per key at a time; none inside the test lab). */
function smpro_memo_refresh_bg(string $key, string $cmd, int $timeout): void {
    if (defined('SMPRO_TEST_SRC')) return;
    $cf = SMPRO_CACHE . '/memo_' . $key . '.cmd';
    clearstatcache(true, $cf);
    if (@is_file($cf) && time() - (int)@filemtime($cf) < $timeout + 30) return;   // a refresh is already under way
    @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true);
    if (@file_put_contents($cf, json_encode(['cmd' => $cmd, 't' => $timeout]), LOCK_EX) === false) return;
    @chmod($cf, 0600);
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    $bin = SMPRO_BASE . '/bin/memo_refresh.php';
    if (!is_file($bin)) return;
    @shell_exec('nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' ' . escapeshellarg($key) . ' >/dev/null 2>&1 &');
}
function smpro_memo(string $key, int $ttl, callable $fn, bool $fresh = false) {
    $key = preg_replace('/[^a-zA-Z0-9_.-]/', '_', $key);
    $f = SMPRO_CACHE . '/memo_' . $key . '.json';
    clearstatcache(true, $f);
    if (!$fresh && @is_file($f) && time() - (int)@filemtime($f) <= $ttl) {
        $j = json_decode((string)@file_get_contents($f), true);
        if (is_array($j) && array_key_exists('v', $j)) return $j['v'];
    }
    $v = $fn();
    if ($v !== null && $v !== false) {
        @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true);
        if (@file_put_contents($f . '.tmp', json_encode(['v' => $v], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
    }
    return $v;
}

/**
 * Is cPHulk enabled? Read from cPanel's own switch file, not the API. `whmapi1 cphulk_status` answers in 20 ms
 * from a shell and took 12 SECONDS from inside a WHM CGI on a production server (the API client detects the
 * cpsrvd context and takes a slower path); the file is what that API reads. null = could not tell.
 */
function smpro_cphulk_enabled(): ?bool {
    $f = '/var/cpanel/hulkd/enabled';
    if (@file_exists($f)) return true;                       // present = on (cPanel writes a timestamp in it)
    if (@is_dir('/var/cpanel/hulkd')) return false;          // the daemon's dir exists but the switch is absent = off
    if (!is_executable('/usr/local/cpanel/bin/whmapi1')) return null;
    $j = json_decode(trim((string)@shell_exec('timeout 15 /usr/local/cpanel/bin/whmapi1 --output=json cphulk_status 2>/dev/null')), true);
    return is_array($j) && isset($j['data']['is_enabled']) ? (bool)$j['data']['is_enabled'] : null;
}

function smpro_ip_cache_dirty(): void {
    static $armed = false;
    if ($armed) return;
    $armed = true;
    register_shutdown_function(function () {
        $cache = &smpro_ip_cache();
        // evict on save: entries past their TTL go, and the book is capped at 20,000 (oldest first) - it was
        // rewritten whole by every process and never shrank
        $cut = time() - SMPRO_IPTTL;
        foreach ($cache as $k => $v) if ((int)($v['cached_at'] ?? 0) < $cut) unset($cache[$k]);
        if (count($cache) > 20000) { uasort($cache, fn($a, $b) => (int)($a['cached_at'] ?? 0) <=> (int)($b['cached_at'] ?? 0)); $cache = array_slice($cache, -20000, null, true); }
        $t = SMPRO_IPCACHE . '.tmp';
        @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
        if (@file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600); }
    });
}
function smpro_ip_intel($ip, $cap = true) {
    static $new = 0;
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ip' => $ip, 'country' => '', 'provider' => '', 'asn' => '', 'scope' => 'invalid'];
    if (!smpro_ip_is_external($ip)) return ['ip' => $ip, 'country' => 'LOCAL', 'provider' => 'Private/Reserved', 'asn' => '', 'scope' => 'local'];
    $cache = &smpro_ip_cache();
    $now = time();
    // The cache is written ONCE per process, at shutdown, not after every address. It used to be re-serialised
    // and rewritten for every new entry: forty new attacker addresses on one page meant forty rewrites of a file
    // that holds every address the server has ever looked up.
    $save = function () { smpro_ip_cache_dirty(); };
    if (isset($cache[$ip]) && ($now - (int)($cache[$ip]['cached_at'] ?? 0)) < SMPRO_IPTTL) {
        $r = $cache[$ip]; $r['scope'] = 'external';
        if ((($r['country'] ?? '') === '' || strtolower($r['country']) === 'n/a')) {     // backfill country offline for old network-only entries
            $cc = smpro_geoip_cc($ip); if ($cc !== '') { $cache[$ip]['country'] = $r['country'] = $cc; $save(); }
        }
        return $r;
    }
    // OFFLINE country FIRST - no network, no cap. This is what makes Country resolve behind egress firewalls.
    $cc = smpro_geoip_cc($ip);
    $intel = ['ip' => $ip, 'country' => ($cc !== '' ? $cc : 'n/a'), 'provider' => 'n/a', 'asn' => '', 'cached_at' => $now];
    $intel['source'] = ($cc !== '') ? 'local GeoIP database' : 'unavailable';
    if ($asn = smpro_geoip_asn($ip)) { $intel = array_merge($intel, $asn); $intel['source'] = 'local GeoIP database'; }
    // network whois (Team Cymru) enriches provider/ASN - only within the per-request cap
    if ($cap && $new < SMPRO_IPMAXNEW) {
        $new++;
        $raw = @shell_exec('timeout 4 whois -h whois.cymru.com ' . escapeshellarg(' -v ' . $ip) . ' 2>/dev/null');
        if ($raw) { $p = smpro_ip_parse_cymru(explode("\n", $raw)); if ($p) {
            if ((($p['country'] ?? '') === '' || strtolower((string)($p['country'] ?? '')) === 'n/a') && $cc !== '') $p['country'] = $cc;   // keep the offline country if whois lacks it
            $intel = array_merge($intel, $p);
            $intel['source'] = 'Team Cymru whois';
        }}
    }
    $intel['scope'] = 'external';
    if ($cc !== '' || ($intel['provider'] !== 'n/a' && $intel['provider'] !== '')) {       // cache only when we learned something
        $store = $intel; unset($store['scope']); $cache[$ip] = $store; $save();
    }
    return $intel;
}

/** Is this country one of the operator's CONFIGURED trusted regions (home ∪ caution)? Formerly a fixed 22-country
 *  Arab list; now delegates to the same region config the auto-block tiers use, so "foreign" is defined by the
 *  operator's market - not a baked-in region. Empty config (or config layer not loaded) ⇒ false ⇒ the country is
 *  treated as foreign/outside. The name is kept for its many callers; semantics are "is a trusted home region". */
function smpro_cc_is_arab($cc) {
    $cc = strtoupper((string)$cc);
    if ($cc === '' || !function_exists('smpro_im_trusted_regions')) return false;
    return in_array($cc, smpro_im_trusted_regions(), true);
}

/** Is an IP "foreign" = external + resolved to a NON-Arab country. Shared rule for
 *  login/spam/brute-force/intrusion. Returns ['foreign'=>bool,'cc'=>CC,'arab'=>bool,'local'=>bool,'known'=>bool]. */
function smpro_geo_foreign($ip) {
    $in  = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
    $cc  = strtoupper((string)($in['country'] ?? ''));
    $loc = (($in['scope'] ?? '') === 'local') || $cc === 'LOCAL' || (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip));
    if ($loc) return ['foreign'=>false,'cc'=>'LOCAL','arab'=>false,'local'=>true,'known'=>true];
    $known = ($cc !== '' && $cc !== 'N/A' && $cc !== 'NA');
    $arab  = smpro_cc_is_arab($cc);
    return ['foreign'=>($known && !$arab), 'cc'=>$cc, 'arab'=>$arab, 'local'=>false, 'known'=>$known];
}

/**
 * Warm the IP cache for many IPs in ONE Team Cymru bulk whois call (fast).
 * Falls back to a few individual lookups if netcat is unavailable.
 */
function smpro_ip_intel_bulk($ips, bool $async = false) {
    $cache = &smpro_ip_cache();
    $now = time();
    $need = [];
    foreach (array_unique($ips) as $ip) {
        if ($ip === '' || !smpro_ip_is_external($ip)) continue;
        if (isset($cache[$ip]) && ($now - (int)($cache[$ip]['cached_at'] ?? 0)) < SMPRO_IPTTL) continue;
        $need[] = $ip;
    }
    if (!$need) return;
    $need = array_slice($need, 0, 200);
    if ($async && !defined('SMPRO_TEST_SRC')) {
        // A page never waits for whois. The addresses get their COUNTRY from the local GeoIP now (what the home-region
        // rules need), marked to expire in ten minutes, and a detached worker fetches ASN + provider meanwhile.
        foreach ($need as $ip) if (!isset($cache[$ip])) { $cc = smpro_geoip_cc($ip); $cache[$ip] = ['ip'=>$ip,'country'=>$cc,'provider'=>'(resolving)','asn'=>'','source'=>'GeoIP (whois pending)','cached_at'=>$now - SMPRO_IPTTL + 600]; }
        $want = SMPRO_CACHE . '/ipintel_want.json'; @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true);
        $prev = @is_file($want) ? json_decode((string)@file_get_contents($want), true) : []; $list = array_values(array_unique(array_merge(is_array($prev) ? $prev : [], $need)));
        @file_put_contents($want . '.tmp', json_encode(array_slice($list, -400)), LOCK_EX); @chmod($want . '.tmp', 0600); @rename($want . '.tmp', $want);
        $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php'; $bin = SMPRO_BASE . '/bin/ipintel_warm.php';
        if (is_file($bin)) @shell_exec('nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' >/dev/null 2>&1 &');
        return;
    }
    // Team Cymru bulk whois over a raw TCP socket via bash /dev/tcp (one round-trip
    // for all IPs). ncat's bulk mode is unreliable here, so we avoid it.
    $query = "begin\nverbose\n" . implode("\n", $need) . "\nend\n";
    $script = 'exec 3<>/dev/tcp/whois.cymru.com/43 || exit 1; printf %s ' . escapeshellarg($query) . ' >&3; cat <&3';
    $raw = (string)@shell_exec('timeout 14 bash -c ' . escapeshellarg($script) . ' 2>/dev/null');
    if (trim($raw) === '') {
        // whois/Team Cymru unreachable (e.g. outbound port 43 blocked) -> warm COUNTRY offline from the local
        // MaxMind DB so the table + the home-region protection still work. Country-only here for speed.
        foreach (array_slice($need, 0, 80) as $ip) {
            if (isset($cache[$ip])) continue;
            $cc = smpro_geoip_cc($ip);
            if ($cc !== '') $cache[$ip] = ['ip'=>$ip,'country'=>$cc,'provider'=>'n/a','asn'=>'','source'=>'GeoIP (offline)','cached_at'=>$now];
        }
        $t = SMPRO_IPCACHE . '.tmp'; @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
        @file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600);
        return;
    }
    foreach (explode("\n", $raw) as $l) {
        $l = trim($l);
        if ($l === '' || stripos($l, 'Bulk mode') !== false || stripos($l, 'AS Name') !== false || strpos($l, '|') === false) continue;
        $p = array_map('trim', explode('|', $l)); // AS | IP | Prefix | CC | Registry | Allocated | AS Name
        if (count($p) >= 7 && filter_var($p[1], FILTER_VALIDATE_IP)) {
            $cache[$p[1]] = ['ip' => $p[1], 'asn' => 'AS' . $p[0], 'country' => $p[3], 'provider' => $p[6], 'source' => 'Team Cymru bulk', 'cached_at' => $now];
        }
    }
    $t = SMPRO_IPCACHE . '.tmp';
    @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
    @file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600);
}

/** Path to the csf binary, or '' if not installed. */
function smpro_csf_bin() {
    foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b;
    return '';
}
/** Run a CSF action (block=-d / allow=-a / unblock=-dr). Immediate, no restart. Block/allow go through the
 *  VERIFIED helpers (never trust csf stdout); unblock removes from csf.deny robustly. */
function smpro_csf_do($action, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'invalid IP'];   // parity with the deny/allow helpers
    if ($action === 'block' && function_exists('smpro_csf_deny_add')) { $r = smpro_csf_deny_add($ip, 'smpro'); return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']), 'recorded'=>!empty($r['recorded']), 'msg'=>(string)$r['msg']]; }
    if ($action === 'allow' && function_exists('smpro_csf_allow_add')) { $r = smpro_csf_allow_add($ip, 'smpro'); return ['ok'=>!empty($r['ok']), 'msg'=>(string)$r['msg']]; }
    $csf = smpro_csf_bin();
    if ($csf === '') return ['ok' => false, 'msg' => 'csf not found'];
    if ($action === 'unblock') {
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip) . ' 2>&1');
        // also strip any direct csf.deny line we may have written when CSF was a no-op
        $f = '/etc/csf/csf.deny';
        if (is_file($f) && is_writable($f) && smpro_csf_denied($ip)) {
            $keep = array_filter(file($f, FILE_IGNORE_NEW_LINES) ?: [], fn($l) => !preg_match('/^' . preg_quote($ip, '/') . '(\s|$|\/|#)/', trim($l)));
            @file_put_contents($f, implode("\n", $keep) . "\n", LOCK_EX);
            if (!smpro_csf_testing()) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
        }
        clearstatcache();
        return ['ok' => !smpro_csf_denied($ip), 'msg' => smpro_csf_denied($ip) ? ('could not remove ' . $ip) : ($ip . ' unblocked')];
    }
    $flag = $action === 'allow' ? '-a' : '-d';
    $out = (string)@shell_exec('timeout 25 ' . escapeshellarg($csf) . ' ' . $flag . ' ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro ' . date('Y-m-d H:i')) . ' 2>&1');
    return ['ok' => $out !== '' && stripos($out, 'error') === false, 'msg' => trim(mb_substr($out, 0, 160))];
}
/** Set of IPs already blocked by CSF (permanent csf.deny + temporary deny). */
function smpro_csf_blocked_set() {
    $set = [];
    if (is_readable('/etc/csf/csf.deny')) foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^([0-9a-fA-F:.]+)/', $l, $m)) $set[$m[1]] = 'perm';
    }
    $csf = smpro_csf_bin();
    if ($csf !== '') foreach (explode("\n", (string)@shell_exec('timeout 5 ' . escapeshellarg($csf) . ' -t 2>/dev/null')) as $l)
        if (stripos($l, 'DENY') !== false && preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $l, $m) && !isset($set[$m[1]])) $set[$m[1]] = 'temp';
    return $set;
}
/* ---- shared "hidden IPs" ignore-list (persisted, applies across modules) ---- */
if (!defined('SMPRO_HIDDEN_IPS')) define('SMPRO_HIDDEN_IPS', SMPRO_VARLIB . '/state/hidden_ips.json');
function smpro_hidden_ips() {
    static $s = null;
    // reload on first use OR after a same-request toggle set the dirty flag (otherwise the flag was dead)
    if ($s === null || !empty($GLOBALS['__smpro_hidden_dirty'])) {
        $d = is_file(SMPRO_HIDDEN_IPS) ? json_decode((string)@file_get_contents(SMPRO_HIDDEN_IPS), true) : null;
        $s = is_array($d) ? $d : [];
        unset($GLOBALS['__smpro_hidden_dirty']);
    }
    return $s;
}
function smpro_hidden_ip_toggle($ip, $hide) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $s = smpro_hidden_ips();
    if ($hide) $s[$ip] = ['at' => date('c'), 'by' => smpro_current_actor()];
    else unset($s[$ip]);
    @is_dir(dirname(SMPRO_HIDDEN_IPS)) || @mkdir(dirname(SMPRO_HIDDEN_IPS), 0700, true);
    $t = SMPRO_HIDDEN_IPS . '.tmp';
    @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_HIDDEN_IPS); @chmod(SMPRO_HIDDEN_IPS, 0600);
    // refresh the static cache
    $GLOBALS['__smpro_hidden_dirty'] = true;
    return true;
}

/** True for the 22 Arab-League country codes. */
function smpro_is_arab_cc($cc) {
    // single source of truth - delegate to smpro_cc_is_arab() so the Arab-CC list can never drift in two places
    return smpro_cc_is_arab($cc);
}

/** Redact secrets from a command line before display/export. */
function smpro_redact_cmd($s) {
    // key=value or "key value" secrets
    $s = preg_replace('/(--?(?:password|passwd|pass|pwd|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key))(=|\s+)\S+/i', '$1=***', $s);
    // mysql-style -p<password> (only when followed by non-space right after -p)
    $s = preg_replace('/(\s-p)(?=\S)\S+/', '$1***', $s);
    return $s;
}

/** Friendly service name guessed from a process/command name. */
function smpro_service_guess($comm) {
    static $map = [
        'mysqld' => 'MySQL/MariaDB', 'mariadbd' => 'MySQL/MariaDB', 'mysql' => 'MySQL client',
        'httpd' => 'Apache', 'apache2' => 'Apache', 'nginx' => 'Nginx', 'lsphp' => 'LiteSpeed PHP',
        'php-fpm' => 'PHP-FPM', 'php' => 'PHP', 'php-cgi' => 'PHP-CGI',
        'exim' => 'Exim (mail)', 'dovecot' => 'Dovecot (mail)', 'pure-ftpd' => 'FTP', 'proftpd' => 'FTP',
        'named' => 'DNS (BIND)', 'pdns_server' => 'PowerDNS', 'sshd' => 'SSH',
        'cpsrvd' => 'cPanel', 'cphulkd' => 'cPHulk', 'queueprocd' => 'cPanel queue', 'tailwatchd' => 'cPanel tailwatch',
        'imunify360' => 'Imunify360', 'ai-bolit' => 'Imunify scan', 'lfd' => 'CSF/LFD', 'csf' => 'CSF',
        'redis-server' => 'Redis', 'memcached' => 'Memcached', 'crond' => 'Cron', 'systemd' => 'systemd',
        'clamd' => 'ClamAV', 'spamd' => 'SpamAssassin',
    ];
    $c = strtolower(trim($comm));
    return $map[$c] ?? '';
}

/** Is this a real cPanel account? */
function smpro_is_cpanel_user($user) {
    return $user !== '' && preg_match('/^[a-zA-Z0-9._-]+$/', $user) && is_file('/var/cpanel/users/' . $user);
}

/** Per-user CPU risk based on pressure across cores. */
function smpro_proc_risk($cpu, $cores) {
    $pressure = $cores > 0 ? ($cpu / $cores) : $cpu;
    if ($cpu >= 300 || $pressure >= 8) return 'DANGER';
    if ($cpu >= 100 || $pressure >= 4) return 'WARNING';
    return 'GOOD';
}

/**
 * Is this a KNOWN-GOOD security / hosting-platform daemon? Prevents the plugin from flagging or acting on
 * legitimate infrastructure as suspicious. (Real-world lesson: Imunify's Rust scanner "rustbolit" - an
 * unknown-looking root process consuming CPU/RAM - is a legitimate Imunify component, not malware.)
 * Matches the process comm (basename) case-insensitively against exact names and prefixes.
 */
function smpro_is_trusted_system_proc($comm) {
    $c = strtolower(trim((string)$comm)); if ($c === '') return false;
    static $exact = null, $prefix = null;
    if ($exact === null) {
        $exact = array_flip([
            // Imunify360 / AI-Bolit family (incl. the Rust rewrite)
            'rustbolit', 'ai-bolit', 'aibolit', 'imunify360', 'imunify360-agent', 'imunify-resident',
            'defence360agent', 'imunify-antivirus', 'imunify-notify', 'i360watchdog',
            // CloudLinux: LVE / CageFS / DB governor / selectors
            'lvestats', 'lvestats-server', 'lve_stats2', 'cagefsctl', 'cldetect', 'db_governor', 'dbgovernor',
            'lvewrapper', 'cl-quota', 'cldiag', 'lvemanager', 'wmt', 'lveps',
            // cPanel core daemons
            'cpsrvd', 'cpaneld', 'cphulkd', 'queueprocd', 'tailwatchd', 'cpanellogd', 'dnsadmin', 'cpdavd',
            // firewall / AV
            'lfd', 'csf', 'clamd', 'freshclam', 'kcarectl',
        ]);
        $prefix = ['imunify', 'defence360', 'lve', 'cagefs', 'cloudlinux', 'cl-', 'cpanel', 'cphulk', 'db_governor', 'rustbolit', 'ai-bolit', 'aibolit'];
    }
    if (isset($exact[$c])) return true;
    foreach ($prefix as $p) if (strpos($c, $p) === 0) return true;
    return false;
}

/** Hide Safety Monitor's own scan noise from the listing. */
function smpro_proc_self_noise($comm, $args) {
    $c = strtolower($comm);
    if (in_array($c, ['ps', 'head', 'awk', 'sort', 'nice', 'timeout'], true)) return true;
    $a = strtolower($args);
    if (strpos($a, '/cgi/addons/smpro/') !== false) return true;
    if (strpos($a, 'smpro/index') !== false) return true;
    return false;
}

/**
 * Live process list (read-only via ps), with the same depth as the legacy page:
 * full usernames, PPID/STAT/ETIME/args, per-user groups, per-command rollup,
 * cPanel detection, risk scoring. No kill/renice/env exposure (plan §38).
 * Args are redacted before display/export.
 */
function smpro_top_processes($limit = 100) {
    $limit    = max(20, min(300, (int)$limit));
    $hideSelf = true;

    // user:48 keeps full usernames; comm:32 readable; COLUMNS=4096 avoids arg truncation.
    // Shell ordering is strict: the env assignment MUST come first, before timeout
    // and nice - neither of those can parse a leading VAR=val token.
    $ps = 'ps -eo user:48=,pid=,ppid=,comm:32=,pcpu=,pmem=,stat=,etime=,args= --sort=-pcpu';
    $build = function ($t) use ($ps) {
        $w = 'timeout ' . (int)$t . ' ';
        if (is_executable('/usr/bin/nice')) $w .= 'nice -n ' . SMPRO_SCAN_NICE . ' ';
        return 'COLUMNS=4096 ' . $w . $ps . ' 2>/dev/null | head -n 800';
    };
    $raw = @shell_exec($build(SMPRO_TIMEOUT_QUICK));
    // Busy/IO-saturated server: ps can take >5s to walk /proc for hundreds of PIDs and get killed by
    // the quick timeout, leaving the panel empty ("broke"). Retry once, patiently, before giving up.
    if (strlen(trim((string)$raw)) < 40) $raw = @shell_exec($build(15));

    $cores = smpro_cpu_cores();
    $load  = smpro_loadavg();

    $rows = [];
    $hiddenSelf = 0;
    foreach (explode("\n", (string)$raw) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        $p = preg_split('/\s+/', $line, 9);
        if (!$p || count($p) < 8) continue;

        $user = rtrim((string)$p[0]);
        $comm = (string)$p[3];
        $args = smpro_redact_cmd((string)($p[8] ?? ''));
        if ($user === '') continue;
        if ($hideSelf && smpro_proc_self_noise($comm, $args)) { $hiddenSelf++; continue; }

        $rows[] = [
            'user'      => $user,
            'pid'       => (int)$p[1],
            'ppid'      => (int)$p[2],
            'process'   => $comm,
            'cpu'       => round((float)$p[4], 1),
            'mem'       => round((float)$p[5], 1),
            'stat'      => (string)$p[6],
            'etime'     => (string)$p[7],
            'args'      => $args,
            'is_cpanel' => smpro_is_cpanel_user($user),
        ];
        if (count($rows) >= $limit) break;
    }

    // Group by user + roll up commands.
    $groups = [];
    $commands = [];
    foreach ($rows as $r) {
        $u = $r['user']; $cmdName = $r['process'];
        if (!isset($groups[$u])) {
            $groups[$u] = ['user' => $u, 'is_cpanel' => $r['is_cpanel'], 'cpu' => 0.0, 'mem' => 0.0,
                           'processes' => 0, 'top_process' => '', 'top_pid' => 0, 'top_cpu' => 0.0, '_cmds' => []];
        }
        $groups[$u]['cpu'] += $r['cpu'];
        $groups[$u]['mem'] += $r['mem'];
        $groups[$u]['processes']++;
        if ($r['cpu'] > $groups[$u]['top_cpu']) {
            $groups[$u]['top_cpu'] = $r['cpu']; $groups[$u]['top_process'] = $cmdName; $groups[$u]['top_pid'] = $r['pid'];
        }
        $groups[$u]['_cmds'][$cmdName] = ($groups[$u]['_cmds'][$cmdName] ?? 0) + 1;
        if (!isset($commands[$cmdName])) $commands[$cmdName] = ['command' => $cmdName, 'count' => 0, 'cpu' => 0.0];
        $commands[$cmdName]['count']++; $commands[$cmdName]['cpu'] += $r['cpu'];
    }
    foreach ($groups as &$g) {
        $g['cpu'] = round($g['cpu'], 1);
        $g['mem'] = round($g['mem'], 1);
        $g['pressure'] = round($cores > 0 ? $g['cpu'] / $cores : 0, 1);
        $g['risk'] = smpro_proc_risk($g['cpu'], $cores);
        arsort($g['_cmds']);
        $topName = array_key_first($g['_cmds']);
        $g['top_command_group'] = $topName !== null ? $topName . ' ×' . $g['_cmds'][$topName] : '';
        unset($g['_cmds'], $g['top_cpu']);
    }
    unset($g);
    $groups = array_values($groups);
    usort($groups, fn($a, $b) => $b['cpu'] <=> $a['cpu']);

    foreach ($commands as &$c) $c['cpu'] = round($c['cpu'], 1);
    unset($c);
    $commands = array_values($commands);
    usort($commands, fn($a, $b) => $b['cpu'] <=> $a['cpu']);

    return [
        'ts'          => date('H:i:s'),
        'time'        => date('Y-m-d H:i:s'),
        'cores'       => $cores,
        'load'        => $load,
        'load_disp'   => sprintf('%.2f / %.2f / %.2f', $load['1m'], $load['5m'], $load['15m']),
        'limit'       => $limit,
        'hidden_self' => $hiddenSelf,
        'total'       => count($rows),
        'users_count' => count($groups),
        'top_user'    => $groups[0] ?? null,
        'groups'      => $groups,
        'commands'    => array_slice($commands, 0, 16),
        'rows'        => $rows,
    ];
}

/**
 * Collect ALL live metrics in one shot. Shared by the HTML render and the
 * JSON polling endpoint so both always show identical, real-time values.
 */
/** Highest CPU/package temperature in °C (thermal zones -> sensors), or null if no sensor. */
function smpro_cpu_temp() {
    $max = null;
    foreach (glob('/sys/class/thermal/thermal_zone*/temp') ?: [] as $f) {
        $v = (int)trim((string)@file_get_contents($f));
        if ($v > 0 && $v < 200000) { $c = $v / 1000; if ($max === null || $c > $max) $max = $c; }
    }
    if ($max !== null) return round($max, 1);
    $out = (string)@shell_exec('sensors 2>/dev/null');
    if ($out !== '') {
        // take the FIRST temperature after each label's colon (the live reading) - ignore (high=/crit=) thresholds
        foreach (explode("\n", $out) as $line) {
            if (preg_match('/:\s*[+]?(\d{2,3}(?:\.\d)?)\s*°C/u', $line, $m)) {
                $c = (float)$m[1];
                if ($c > 0 && $c < 150 && ($max === null || $c > $max)) $max = $c;
            }
        }
        if ($max !== null) return round($max, 1);
    }
    return null;
}
function smpro_collect_metrics() {
    $cores = smpro_cpu_cores();
    $load  = smpro_loadavg();
    $cpu   = smpro_cpu_usage();
    $mem   = smpro_memory();
    $disk  = smpro_disk_root();
    $procs = smpro_process_count();
    $up    = smpro_uptime();

    $pressure = $cores ? round($load['1m'] / $cores * 100, 1) : 0;
    $swap_pct = $mem['swap_total_mb'] ? round($mem['swap_used_mb'] / $mem['swap_total_mb'] * 100, 1) : 0;
    $health   = smpro_load_status($pressure);   // load uses the 70/100 rule (consistent w/ Server Health page)

    return [
        'ts'        => date('H:i:s'),
        'host'      => gethostname(),
        'cores'     => $cores,
        'load'      => $load,
        'pressure'  => $pressure,
        'health'    => $health,
        'health_label' => $health === 'good' ? 'GOOD' : ($health === 'warn' ? 'WARNING' : 'CRITICAL'),
        'cpu'       => ['pct' => $cpu, 'status' => smpro_status($cpu)],
        'ram'       => ['pct' => $mem['percent'], 'status' => smpro_status($mem['percent']),
                        'used' => smpro_bytes($mem['used_mb'] * 1048576), 'total' => smpro_bytes($mem['total_mb'] * 1048576)],
        'disk'      => ['pct' => $disk['percent'], 'status' => smpro_status($disk['percent']),
                        'used' => smpro_bytes($disk['used']), 'total' => smpro_bytes($disk['total']), 'free' => smpro_bytes($disk['free'])],
        'swap'      => ['pct' => $swap_pct, 'status' => smpro_status($swap_pct),
                        'used_mb' => $mem['swap_used_mb'], 'total_mb' => $mem['swap_total_mb']],
        'procs'     => $procs,
        'uptime'    => smpro_dur($up),
        'temp'      => smpro_cpu_temp(),
    ];
}

/** Set of THIS server's own IP addresses (bound IPs + cPanel main/additional). Cached. */
function smpro_server_ips() {
    static $set = null;
    if ($set !== null) return $set;
    $set = [];
    foreach (explode("\n", (string)@shell_exec("ip -o addr show 2>/dev/null | awk '{print \$4}'")) as $l) {
        $ip = explode('/', trim($l))[0];
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) $set[$ip] = 1;
    }
    $mi = is_readable('/var/cpanel/mainip') ? trim((string)@file_get_contents('/var/cpanel/mainip')) : '';
    if (filter_var($mi, FILTER_VALIDATE_IP)) $set[$mi] = 1;
    if (is_readable('/etc/ips')) foreach (file('/etc/ips', FILE_IGNORE_NEW_LINES) ?: [] as $l)
        if (preg_match('/^([0-9a-fA-F:.]+):/', trim($l), $m) && filter_var($m[1], FILTER_VALIDATE_IP)) $set[$m[1]] = 1;
    return $set;
}
/** True if $ip is loopback/localhost or one of this server's own IPs (never block these). */
function smpro_is_server_ip($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') return false;
    if ($ip === '::1' || $ip === '::' || strpos($ip, '127.') === 0) return true;
    return isset(smpro_server_ips()[$ip]);
}

/* ---- plugin master control: Enabled / Dry-Run / Disabled (+ auto re-enable date) ---- */
function smpro_ctl_file() { return SMPRO_VARLIB . '/control.json'; }
/**
 * The one way state is written: temp file in the same directory, mode 0600, rename over the target. A reader
 * never sees a half-written file and a crash never leaves an empty one. Returns false when nothing was written.
 */
function smpro_json_save(string $file, $data, int $flags = JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE, int $mode = 0600): bool {
    $dir = dirname($file);
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $tmp = $file . '.tmp.' . getmypid();
    $json = json_encode($data, $flags);
    if ($json === false || @file_put_contents($tmp, $json, LOCK_EX) === false) { @unlink($tmp); return false; }
    @chmod($tmp, $mode);
    if (!@rename($tmp, $file)) { @unlink($tmp); return false; }
    return true;
}
function smpro_json_load(string $file, $default = []) {
    $j = @is_file($file) ? json_decode((string)@file_get_contents($file), true) : null;
    return is_array($j) ? $j : $default;
}
function smpro_ctl_save($c) { smpro_json_save(smpro_ctl_file(), $c, JSON_UNESCAPED_SLASHES); }
/** Read control state, auto re-enabling if a scheduled re-enable time has passed. */
function smpro_ctl_get() {
    $f = smpro_ctl_file();
    $c = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (!is_array($c)) $c = [];
    $c += ['mode' => 'enabled', 'reenable_at' => 0, 'updated_at' => 0, 'actor' => ''];
    if (!in_array($c['mode'], ['enabled', 'dryrun', 'disabled'], true)) $c['mode'] = 'enabled';
    // auto re-enable: a scheduled restart time has arrived -> flip back to enabled
    if ($c['mode'] === 'disabled' && (int)$c['reenable_at'] > 0 && time() >= (int)$c['reenable_at']) {
        $c['mode'] = 'enabled'; $c['reenable_at'] = 0; $c['updated_at'] = time(); $c['actor'] = 'auto-reenable';
        smpro_ctl_save($c);
        if (function_exists('smpro_audit')) smpro_audit('plugin_control', ['mode' => 'enabled', 'by' => 'auto-reenable']);
    }
    return $c;
}
function smpro_ctl_mode()     { return smpro_ctl_get()['mode']; }
function smpro_ctl_disabled() {
    if (smpro_ctl_get()['mode'] === 'disabled') return true;                 // admin manually disabled
    // flagged diagnostics marker (confirmed endpoint redirect) -> IMMEDIATE full stop; cleared only by a server reset
    if (function_exists('smpro_lic_tlm_at') && smpro_lic_tlm_at() > 0) return true;
    // connection-loss SOFT stop (opted-in licenses only, reversible) -> full stop; resumes the instant a fresh
    // signed exchange returns. NOT a tamper - must stay OUT of $smTamperLock so License/Plugin-Control stay reachable.
    if (function_exists('smpro_lic_sync_disabled') && smpro_lic_sync_disabled()) return true;
    // pairing REVERSIBLE stop (opt-in; signed pair_stop=true) - same soft, non-tamper, self-healing posture as sync.
    if (function_exists('smpro_lic_pair_stopped') && smpro_lic_pair_stopped()) return true;
    // license stopped (expired/suspended/revoked) for >48h -> whole plugin dormant (all functions off; resumes on renewal)
    if (function_exists('smpro_lic_dormant') && smpro_lic_dormant()) return true;
    return false;
}
/** True when the plugin should MONITOR but NOT take automatic actions (auto-block, auto-fix, throttle, auto-update). */
function smpro_ctl_dry_run()  { return smpro_ctl_get()['mode'] === 'dryrun'; }

/* ---- admin self-IP firewall allow-list (offer to whitelist the operator's own IP) ---- */
/** The admin's connecting IP (X-Forwarded-For / X-Real-IP / REMOTE_ADDR; skips loopback). */
function smpro_admin_ip() {
    // WHM/cpsrvd is the direct peer (NOT behind a proxy/CDN), so REMOTE_ADDR is the real, unforgeable client IP.
    // Trust it first; only fall back to the forgeable X-Forwarded-For/X-Real-IP if REMOTE_ADDR is somehow absent.
    foreach (['REMOTE_ADDR','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP'] as $k) {
        $v = trim((string)($_SERVER[$k] ?? '')); if ($v === '') continue;
        $v = trim(explode(',', $v)[0]);
        if (filter_var($v, FILTER_VALIDATE_IP) && $v !== '127.0.0.1' && $v !== '::1') return $v;
    }
    return '';
}
/** Is the IP already in csf.allow (full allow / never block)? */
function smpro_csf_allowlisted($ip) {
    if ($ip === '' || !is_readable('/etc/csf/csf.allow')) return false;
    return isset(smpro_csf_allow_index()[(string)$ip]);
}
/** The leading token of every csf.allow line, indexed once per process (re-read when the file changes). A line
 *  "NET/24 # x" is found by "NET/24" and by "NET" alone, exactly as the old per-call scan matched. */
function smpro_csf_allow_index(): array {
    static $idx = null, $sig = '';
    clearstatcache(true, '/etc/csf/csf.allow');
    $now = @filemtime('/etc/csf/csf.allow') . ':' . @filesize('/etc/csf/csf.allow');
    if ($idx !== null && $sig === $now) return $idx;
    $idx = []; $sig = $now;
    foreach (file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        $tok = preg_split('/[\s#]/', $l, 2)[0]; if ($tok === '') continue;
        $idx[$tok] = 1;
        $slash = strpos($tok, '/'); if ($slash !== false) $idx[substr($tok, 0, $slash)] = 1;
    }
    return $idx;
}
/**
 * Robustly add an IP to csf.allow (full allow / never block). Works whether CSF is enabled
 * or disabled (TESTING): tries `csf -a`, then VERIFIES against csf.allow, and if it didn't land
 * (e.g. CSF disabled = csf -a is a no-op) it appends to /etc/csf/csf.allow directly so the allow
 * applies as soon as CSF runs. Returns ['ok'=>bool,'already'=>bool,'msg'=>string]. Never trusts
 * csf's stdout for success - only the actual presence in csf.allow.
 */
/* ================================ WP Guard allowlist ================================
 * WP Guard is HostGuard's WordPress security plugin. SM Pro must TRUST its OWN files and defensive
 * artifacts - never flag / quarantine / "possible compromise" them - while still scanning everything
 * else. VERIFY, don't trust the name: a wp-guard.php is only trusted when its header carries BOTH
 * "Plugin Name: WP Guard" AND "Author: HostGuard" (an attacker could drop a fake same-named file).
 */
function smpro_wpguard_verify($file) {
    $h = (string)@file_get_contents($file, false, null, 0, 8192);   // plugin headers live in the first ~8KB
    return $h !== '' && preg_match('/Plugin Name:\s*WP\s*Guard/i', $h) && preg_match('/Author:\s*HostGuard/i', $h);
}
/* ============================ IPv6 address handling ============================
 * ONE rule, because getting it wrong fails silently rather than loudly: a bare IPv6 literal already
 * contains colons, so anything that joins it to a port with ":" produces an address that parses wrong and
 * the connection just never succeeds - the peer/host reads as "down" or "unreachable" and nothing says why.
 *
 *   Building host:port (sockets, URLs, curl --resolve, Host: headers)  -> smpro_host_port()
 *   Need only the bracketed host                                       -> smpro_ip_bracket()
 *   Comparing/storing/logging an address, or matching it against a list -> use it BARE, never bracketed
 *
 * Hostnames and IPv4 pass through untouched, so these are always safe to call - never hand-roll the join.
 */

/** Bracket a bare IPv6 literal for use in a host:port context. Hostname/IPv4/already-bracketed: unchanged. */
function smpro_ip_bracket(string $host): string {
    $h = trim($host);
    if ($h === '' || $h[0] === '[') return $h;                 // already bracketed
    // A bare IPv6 literal is the only form with 2+ colons and no brackets; "host:port" has exactly one.
    // Strip a link-local zone (fe80::1%eth0) before validating - FILTER_VALIDATE_IP rejects the %zone form,
    // so validating the raw string would leave a link-local address unbracketed and silently unreachable.
    $bare = (($pc = strpos($h, '%')) !== false) ? substr($h, 0, $pc) : $h;
    return (substr_count($bare, ':') >= 2 && filter_var($bare, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false)
        ? '[' . $h . ']' : $h;                                 // keep the zone INSIDE the brackets
}

/** Join a host and port correctly for any family: "1.2.3.4:80", "example.com:80", "[2001:db8::1]:80". */
function smpro_host_port(string $host, int $port): string {
    return smpro_ip_bracket($host) . ':' . $port;
}

/**
 * Install (or refresh) an /etc/cron.d entry and VERIFY it landed. Returns true only when the file exists
 * afterwards with the intended content.
 *
 * Why verify: a cron file is how most background features actually run. Writing it with `@file_put_contents`
 * and ignoring the result means a read-only /etc, a full disk, or an immutable flag leaves the UI reporting
 * the feature as enabled while nothing is ever scheduled - the same "silent nothing looks like success" class
 * of bug as an empty parse rendering green. Callers should surface a false return rather than assume.
 *
 * Also normalises the two things that make a cron.d file silently ignored by cron: mode 0644 and a trailing
 * newline (cron skips a final line with no newline).
 */
function smpro_cron_install(string $path, string $content): bool {
    if ($path === '' || strpos($path, '/etc/cron.d/') !== 0) return false;
    // A TEST must never write a real cron. /etc/cron.d is an absolute path with no sandbox equivalent, so any
    // test that saves a feature's settings installed a live scheduled job on the machine running the suite -
    // the lab caught it, restored the file and went red at random. Reported as success so the calling code is
    // still exercised; what is skipped is the write, not the logic.
    if (defined('SMPRO_TEST_SRC')) return true;
    if (substr($content, -1) !== "\n") $content .= "\n";
    if (@is_file($path) && (string)@file_get_contents($path) === $content) { @chmod($path, 0644); return true; }
    if (@file_put_contents($path, $content, LOCK_EX) === false) return false;
    @chmod($path, 0644);
    return @is_file($path) && (string)@file_get_contents($path) === $content;
}

/**
 * Every file that holds log lines for the last $days of $path - the live file plus its rotated siblings,
 * newest first. Returned paths may be gzipped; pair with smpro_log_read_cmd().
 *
 * Why this exists: log rotation is a per-server policy, not a constant. Measured on a stock cPanel box -
 * weekly rotation keeping 4 generations - the LIVE exim/maillog/secure files held only ~5 days. A reader that
 * looks at the live file alone therefore answers "nothing found" for any window longer than that, and every
 * page above it renders that emptiness as a clean result. On a host that rotates daily the live file can hold
 * a few hours. Rotated names differ by tool (logrotate `x.1`/`x.1.gz`, cPanel `x-<date>`, syslog `x.gz`), so
 * match broadly and let mtime decide what is in range.
 */
function smpro_log_files(string $path, int $days = 7, int $maxRotatedBytes = 0): array {
    if ($path === '' || !@is_readable($path)) return [];
    $cutoff = time() - max(1, $days) * 86400;
    $cand   = array_merge(glob($path . '.*') ?: [], glob($path . '-*') ?: []);
    $rot    = [];
    foreach ($cand as $f) {
        if (!@is_file($f) || !@is_readable($f)) continue;
        $mt = @filemtime($f);
        // A rotated file is in range when it was CLOSED after the cutoff: its last line is its mtime.
        if ($mt === false || $mt < $cutoff) continue;
        $rot[$f] = $mt;
    }
    arsort($rot);                                   // newest rotation first - for budget selection (keep newest)
    // Optional on-disk size budget for the ROTATED portion. This is what makes rotation-aware reading safe on
    // high-volume logs: on a busy mail/auth server the rotated exim/secure files are enormous, so with a budget
    // set they are skipped and the caller effectively reads the live file only - the cheap, pre-existing path.
    // On a quiet server the rotated files are small, fit the budget, and the extra history is recovered. The
    // property that creates the performance risk (log size) is exactly the one that switches the behaviour off.
    // 0 = unbudgeted (callers reading low-volume logs, e.g. login events).
    $budget = max(0, $maxRotatedBytes);
    $used   = 0;
    $sel    = [];                                   // selected rotated, NEWEST first
    foreach (array_keys($rot) as $f) {
        if ($budget > 0) {
            $sz = (int)@filesize($f);
            // Strict budget: if even the newest rotated file alone exceeds it, include nothing and read the live
            // file only. On a high-volume log that is the safe direction - better a shorter window than a scan
            // that decompresses gigabytes into the caller's timeout.
            if ($used + $sz > $budget) break;
            $used += $sz;
        }
        $sel[] = $f;
    }
    // ORDER MATTERS: callers stream these files in list order and pipe into `tail -n N`, which keeps the END of
    // the stream. So emit OLDEST->NEWEST with the LIVE file LAST - then `tail -n N` keeps the newest N lines
    // (live + most-recent rotated). Emitting live-first (the previous bug) made tail return the OLDEST rotated
    // data and silently discard the live file whenever the total exceeded N.
    $out = array_reverse($sel);                     // rotated: oldest -> newest
    $out[] = $path;                                 // live file last (newest)
    return $out;
}

/**
 * Shell fragment that streams those files OLDEST-first (live last), transparently decompressing gzipped ones, so
 * an existing `... | grep x | tail -n N` pipeline keeps working unchanged - just swap the plain path for this,
 * and `tail -n N` still yields the NEWEST N lines.
 * Returns '' when nothing is readable, which callers must treat as "no data", never as "nothing happened".
 * $maxRotatedBytes caps the on-disk size of the rotated portion (0 = uncapped) - pass a budget for high-volume
 * system logs (exim, secure, maillog) so a busy server does not decompress gigabytes into a timeout.
 */
function smpro_log_read_cmd(string $path, int $days = 7, int $maxFiles = 6, int $maxRotatedBytes = 0): string {
    $files = smpro_log_files($path, $days, $maxRotatedBytes);
    if (!$files) return '';
    // Keep the NEWEST $maxFiles (they are at the END of the oldest->newest+live-last list) - never the oldest.
    $files = array_slice($files, -max(1, $maxFiles));
    $parts = [];
    foreach ($files as $f) {
        $parts[] = (substr($f, -3) === '.gz')
            ? 'zcat -f ' . escapeshellarg($f) . ' 2>/dev/null'
            : 'cat ' . escapeshellarg($f) . ' 2>/dev/null';
    }
    return '{ ' . implode('; ', $parts) . '; }';
}

/** Convenience wrapper for HIGH-VOLUME system logs (exim_mainlog, /var/log/secure, maillog): rotation-aware
 *  reading with a sane on-disk budget so busy servers fall back to the live file automatically. Drop-in for a
 *  bare log path inside a `... | grep | tail` pipeline; returns '' if nothing is readable. */
function smpro_syslog_read_cmd(string $path, int $days = 7): string {
    return smpro_log_read_cmd($path, $days, 5, 200 * 1024 * 1024);   // ≤200 MB of rotated data
}

/**
 * Canonical PHP-CLI interpreter for detached workers - the ONE place that answers "which php do we exec?".
 *
 * Portability rule: never name a specific EA-PHP branch. A server built on ea-php83 only has no ea-php82, and a
 * resolver that falls through to a bare 'php' depends on root's PATH, which under cron/setsid is often just
 * /usr/bin:/bin - the worker then never starts and the job dies with "no heartbeat" and no explanation.
 * Order: cPanel's own bundled PHP (always present, version-stable) -> newest installed EA-PHP -> PATH -> system dirs.
 */
function smpro_php_cli_bin(): string {
    static $b = null;
    if ($b !== null) return $b;
    if (@is_executable('/usr/local/cpanel/3rdparty/bin/php')) return ($b = '/usr/local/cpanel/3rdparty/bin/php');
    $ea = glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [];
    natsort($ea);                                                   // ea-php74 < ea-php80 < ... < ea-php85
    foreach (array_reverse($ea) as $p) if (@is_executable($p)) return ($b = $p);
    $which = trim((string)@shell_exec('command -v php 2>/dev/null'));
    if ($which !== '' && @is_executable($which)) return ($b = $which);
    foreach (['/usr/local/bin/php', '/usr/bin/php', '/bin/php'] as $p) if (@is_executable($p)) return ($b = $p);
    return ($b = 'php');                                            // last resort - let exec fail loudly, not silently
}

/**
 * Is $path a TRUSTED WP Guard file / behavior that scanners must leave alone?
 *   - wp-content/mu-plugins/wp-guard.php  and  wp-content/plugins/wp-guard/wp-guard.php   (header-verified)
 *   - wp-content/plugins/wp-guard/readme.txt
 *   - wp-content/hostguard-security.log
 *   - anything under wp-content/hostguard-quarantine/          (malware WP Guard already neutralized - leave it)
 *   - a .htaccess whose body contains "php_flag engine off"    (WP Guard's PHP-execution lockdown)
 * Returns FALSE for uploads/*.php, Protector.php and injected index.php - those stay real threats.
 */
/** The WP Guard WHM plugin, when installed: found through its WHM app registration and its own cron line, never a
 *  fixed path. ['installed'=>bool,'version'=>'','data_dir'=>'','db'=>'','url'=>'']. Read-only; memoized. */
function smpro_wpguard_whm(): array {
    static $w = null; if ($w !== null) return $w;
    $w = ['installed' => false, 'version' => '', 'data_dir' => '', 'db' => '', 'url' => ''];
    $conf = '';
    foreach (glob('/var/cpanel/apps/*.conf') ?: [] as $f) { $c = (string)@file_get_contents($f, false, null, 0, 4096); if (preg_match('/^name=wpguard\s*$/m', $c)) { $conf = $c; break; } }
    if ($conf === '' || !preg_match('#^url=(/cgi/addons/[A-Za-z0-9_-]+/)#m', $conf, $m)) return $w;
    $w['url'] = $m[1] . 'index.cgi';
    $idx = '/usr/local/cpanel/whostmgr/docroot' . $m[1] . 'index.php';
    if (preg_match("/define\('WPG_VERSION',\s*'([0-9.]+)'/", (string)@file_get_contents($idx, false, null, 0, 65536), $v)) $w['version'] = $v[1];
    foreach (glob('/etc/cron.d/*') ?: [] as $f) {
        if (preg_match('#\s(/\S+)/auto_update\.sh\b#', (string)@file_get_contents($f, false, null, 0, 4096), $d) && strpos($f, 'wpguard') !== false) { $w['data_dir'] = $d[1]; break; }
    }
    if ($w['data_dir'] !== '' && is_file($w['data_dir'] . '/wpguard.db')) $w['db'] = $w['data_dir'] . '/wpguard.db';
    $w['installed'] = $w['version'] !== '';
    return $w;
}
/** True when $path sits in a WP Guard WHM quarantine - <home-parent>/.wpguard-quarantine/... or <home>/.wpguard/quarantine/... -
 *  and every folder from that quarantine root down is root-owned and closed to the account. An account cannot make a
 *  root-owned folder, so naming a folder this way buys an attacker nothing. Those files are the originals WP Guard keeps
 *  for its own Undo: alerting on them is noise and deleting or cleaning them would break WP Guard's rollback. */
function smpro_wpguard_whm_quarantined(string $path): bool {
    static $ok = [];
    if (!preg_match('#^(.*?/(?:\.wpguard-quarantine|\.wpguard/quarantine))/(.+)$#', str_replace('\\', '/', $path), $m)) return false;
    if (!smpro_wpguard_whm()['installed']) return false;
    $dir = $m[1]; $rest = explode('/', $m[2]); array_pop($rest);
    foreach (array_merge([''], $rest) as $part) {
        $dir = $part === '' ? $dir : $dir . '/' . $part;
        if (!isset($ok[$dir])) { $st = @lstat($dir); $ok[$dir] = $st && !is_link($dir) && is_dir($dir) && (int)$st['uid'] === 0 && ((int)$st['mode'] & 0022) === 0; }
        if (!$ok[$dir]) return false;
    }
    return true;
}
/** WP Guard WHM keeps the site plugin it deploys at <home>/.wpguard/<16 hex>/wp-guard.php, owned by root in root-owned
 *  folders the account cannot write. Imunify flags it as an admin "file lock" tool; on a production server 250 of 262
 *  "currently malicious" files were these copies. Trusted only when WP Guard WHM is installed, the file and both
 *  folders are root-owned and closed to group/other, it is a regular file, and its header is WP Guard's own. */
function smpro_wpguard_whm_sitecopy(string $path): bool {
    if (!preg_match('#^(/home[0-9]*/[^/]+/\.wpguard)/[0-9a-f]{16}/wp-guard\.php$#', str_replace('\\', '/', $path), $m)) return false;
    if (!smpro_wpguard_whm()['installed']) return false;
    foreach ([$m[1], dirname($path), $path] as $x) {
        $st = @lstat($x);
        if (!$st || is_link($x) || (int)$st['uid'] !== 0 || ((int)$st['mode'] & 0022) !== 0) return false;
    }
    return is_file($path) && smpro_wpguard_verify($path);
}
function smpro_wpguard_trusted($path) {
    $p = (string)$path; if ($p === '') return false;
    if (smpro_wpguard_whm_quarantined($p)) return true;   // WP Guard WHM's kept originals (its Undo depends on them)
    if (smpro_wpguard_whm_sitecopy($p)) return true;      // WP Guard WHM's per-site plugin copy (Imunify calls it a "file lock tool")
    $n = str_replace('\\', '/', $p);
    // Quarantine trust: require the dir to be ACTUALLY locked down (Deny from all / Require all denied) -
    // an unconditional substring match let an account hide an executable webshell by just naming a dir this
    // way. Deny-from-all blocks web access under every SAPI (unlike php_flag), so an attacker adding it to
    // pass this check only neutralizes their own file.
    if (($qp = strpos($n, '/wp-content/hostguard-quarantine/')) !== false) {
        $qht = (string)@file_get_contents(substr($n, 0, $qp) . '/wp-content/hostguard-quarantine/.htaccess', false, null, 0, 4096);
        return (bool)preg_match('/(?:Deny\s+from\s+all|Require\s+all\s+denied)/i', $qht);
    }
    if (substr($n, -34) === '/wp-content/hostguard-security.log') return true;                  // WP Guard's log
    if (substr($n, -28) === '/plugins/wp-guard/readme.txt') return true;                        // plugin readme
    if (preg_match('#/wp-content/(mu-plugins/wp-guard\.php|plugins/wp-guard/wp-guard\.php)$#', $n))
        return is_file($p) ? (bool)smpro_wpguard_verify($p) : false;                            // header-verified plugin file
    if (substr($n, -10) === '/.htaccess' && is_file($p)) {                                      // WP Guard's "engine off" lockdown
        $h = (string)@file_get_contents($p, false, null, 0, 8192);
        // Trust ONLY a PURE PHP-lockdown .htaccess: it must disable the PHP engine AND carry no
        // PHP-execution-HIJACK directive. Otherwise an attacker could append "php_flag engine off"
        // (which is silently ignored under PHP-FPM/suPHP) to a .htaccess that also smuggles an
        // auto_prepend / AddHandler backdoor, and ride this allowlist to evade the scan.
        if (preg_match('/php_flag\s+engine\s+off/i', $h)
            && !preg_match('/auto_prepend_file|auto_append_file|php_value\s+auto_(prepend|append)/i', $h)
            && !preg_match('/(?:Add|Set)Handler[^\n]*\bphp/i', $h)) return true;
    }
    return false;
}

function smpro_csf_allow_add($ip, $reason = '') {
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'already'=>false,'msg'=>'invalid IP'];
    if (smpro_csf_allowlisted($ip)) return ['ok'=>true,'already'=>true,'msg'=>$ip . ' is already allow-listed (csf.allow).'];
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';
    $csf = function_exists('smpro_im_csf_bin') ? smpro_im_csf_bin() : '';
    if ($csf !== '') @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($ip) . ' ' . escapeshellarg($reason) . ' 2>&1');
    clearstatcache();
    if (!smpro_csf_allowlisted($ip)) {                              // csf disabled / no-op -> write the file directly
        $f = '/etc/csf/csf.allow';
        if (is_file($f) && is_writable($f)) @file_put_contents($f, $ip . ' # ' . $reason . ' - ' . date('D M j H:i:s Y') . "\n", FILE_APPEND | LOCK_EX);
        clearstatcache();
        if ($csf !== '' && smpro_csf_allowlisted($ip)) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');  // reload if CSF is enabled
    }
    $ok = smpro_csf_allowlisted($ip);
    // ALSO make the allow take effect on the LIVE firewall right now - works even if CSF is disabled/TESTING/desynced
    // (stale rules loaded, INPUT policy DROP). A top-of-INPUT ACCEPT short-circuits every downstream drop sub-chain
    // (INPUT_imunify360, LOCALINPUT, CSF's own chains). This is what prevents a lock-out when csf.allow alone can't apply.
    $live = function_exists('smpro_fw_iptables_allow') ? smpro_fw_iptables_allow($ip) : '';
    $eff  = $ok || $live !== '';
    return ['ok'=>$eff, 'already'=>false,
            'msg'=>($ok ? ($ip . ' added to csf.allow (never block)') : ('csf.allow not writable for ' . $ip)) . ($live !== '' ? ' + applied live to ' . $live . '.' : ($ok ? '.' : ' — and no live iptables to apply to.'))];
}
/**
 * Make an allow take effect on the LIVE firewall immediately, regardless of CSF state (enabled / disabled / TESTING /
 * desynced with stale rules still loaded). Inserts a top-of-INPUT ACCEPT for $ip into the live iptables (v4) or
 * ip6tables (v6). Because it sits at position 1 of the filter INPUT chain it is evaluated BEFORE the jumps to every
 * drop sub-chain (INPUT_imunify360, LOCALINPUT, CSF's chains), so the traffic is accepted even while those chains
 * would otherwise drop it. Idempotent (skips if an identical ACCEPT already exists). Accepts a bare IP or CIDR.
 * Returns a short label (e.g. "iptables INPUT ACCEPT 1.2.3.4") or '' if nothing was applied. A live rule is not
 * persistent on its own - callers also record the IP in csf.allow for durability across a firewall rebuild/reboot.
 */
function smpro_fw_iptables_allow($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') return '';
    $bare = explode('/', $ip)[0];
    if (!filter_var($bare, FILTER_VALIDATE_IP)) return '';
    $v6   = strpos($bare, ':') !== false;
    $name = $v6 ? 'ip6tables' : 'iptables';
    $bin  = trim((string)@shell_exec('command -v ' . $name . ' 2>/dev/null'));
    if ($bin === '') foreach (['/usr/sbin/', '/sbin/', '/usr/bin/'] as $d) if (@is_executable($d . $name)) { $bin = $d . $name; break; }
    if ($bin === '') return '';
    $b = escapeshellarg($bin); $a = escapeshellarg($ip);
    // insert at the TOP only if an identical ACCEPT is not already present (idempotent); -C exits 0 when it exists
    @shell_exec('timeout 8 ' . $b . ' -C INPUT -s ' . $a . ' -j ACCEPT 2>/dev/null || timeout 8 ' . $b . ' -I INPUT 1 -s ' . $a . ' -j ACCEPT 2>/dev/null');
    $present = trim((string)@shell_exec('timeout 8 ' . $b . ' -C INPUT -s ' . $a . ' -j ACCEPT 2>/dev/null; echo $?')) === '0';
    if (function_exists('smpro_audit')) @smpro_audit('fw_live_allow', ['ip'=>$ip, 'chain'=>$name . ':INPUT', 'ok'=>$present ? 1 : 0]);
    return $present ? ($name . ' INPUT ACCEPT ' . $ip) : '';
}
/**
 * Live firewall vs CSF-management state - used to warn about and recover from the dangerous desync where CSF shows
 * DISABLED (or TESTING, or lfd not running) but its old rules are still loaded, INPUT policy is DROP, and (often)
 * Imunify360 chains keep dropping - so a csf.allow edit never reaches the live chains and you can be locked out.
 * Read-only. Returns keys: csf_installed, csf_disabled, csf_testing, lfd_active, input_policy, rule_count, chains[],
 * imunify, iptables, desync (bool).
 */
function smpro_fw_sync_state() {
    $csfInstalled = @is_file('/etc/csf/csf.conf') || (function_exists('smpro_csf_bin') && smpro_csf_bin() !== '');
    $csfDisabled  = $csfInstalled && @is_file('/etc/csf/csf.disable');
    $testing      = function_exists('smpro_csf_testing') && smpro_csf_testing();
    $lfdActive    = trim((string)@shell_exec('timeout 6 systemctl is-active lfd 2>/dev/null')) === 'active';
    $bin = trim((string)@shell_exec('command -v iptables 2>/dev/null'));
    if ($bin === '') foreach (['/usr/sbin/iptables', '/sbin/iptables'] as $p) if (@is_executable($p)) { $bin = $p; break; }
    $policy = ''; $ruleCount = 0; $chains = [];
    if ($bin !== '') {
        $S = (string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -S 2>/dev/null');
        if (preg_match('/^-P INPUT (\w+)/m', $S, $m)) $policy = strtoupper($m[1]);
        $ruleCount = max(0, substr_count($S, "\n") - 3);                                   // minus the 3 "-P chain policy" lines
        foreach (['imunify360', 'LOCALINPUT', 'DENYIN', 'ALLOWIN', 'LOGDROPIN'] as $c) if (stripos($S, $c) !== false) $chains[] = $c;
    }
    $imunify = function_exists('smpro_has_bin') && smpro_has_bin('imunify360-agent');
    $csfNotManaging = $csfInstalled && ($csfDisabled || $testing || !$lfdActive);
    // rules are actively dropping, but CSF is not the thing managing them -> a csf.allow edit won't touch the live chains
    $desync = ($policy === 'DROP' && $ruleCount > 8 && $csfNotManaging);
    return ['csf_installed'=>$csfInstalled, 'csf_disabled'=>$csfDisabled, 'csf_testing'=>$testing, 'lfd_active'=>$lfdActive,
            'input_policy'=>$policy, 'rule_count'=>$ruleCount, 'chains'=>$chains, 'imunify'=>$imunify, 'iptables'=>($bin !== ''), 'desync'=>$desync];
}
/** Is CSF in TESTING mode? Then `csf -d` writes csf.deny but does NOT load rules into iptables -> NOT enforced. */
function smpro_csf_testing() {
    $f = '/etc/csf/csf.conf';
    return is_readable($f) && (bool)preg_match('/^\s*TESTING\s*=\s*"?1"?/m', (string)@file_get_contents($f));
}
/** Is the IP currently in csf.deny (permanent or temp)? Direct end-state read - the source of truth for "blocked". */
function smpro_csf_denied($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') return false;
    clearstatcache();
    $set = function_exists('smpro_csf_blocked_set') ? smpro_csf_blocked_set() : [];
    return isset($set[$ip]);
}
/**
 * Robustly block an IP in CSF - the deny twin of smpro_csf_allow_add(). Tries `csf -d`, VERIFIES the IP
 * actually landed in csf.deny, falls back to a direct csf.deny write if csf was a no-op, and reloads CSF
 * when it is enforcing. NEVER trusts csf's stdout. Detects TESTING mode (recorded but NOT enforced).
 * Returns ['ok'=>bool ENFORCED, 'recorded'=>bool, 'testing'=>bool, 'already'=>bool, 'msg'=>string].
 */
/** Is CSF actually ENFORCING? Having the binary is not enough: `csf -x` leaves /etc/csf/csf.disable behind and
 *  csf then owns no iptables rules at all, so a deny is recorded and never applied. */
function smpro_csf_enabled() {
    if (smpro_csf_bin() === '') return false;
    return !@is_file('/etc/csf/csf.disable');
}
/** Is Imunify360's firewall the one actually in charge?
 *  Its worker processes are named im360:/imunify360-*, so `pgrep -x imunify360` finds nothing even when it is
 *  running. Use authoritative evidence instead: the agent answers AND its iptables chain is live (or systemd
 *  reports the unit active). Cached per request - `iptables -S` is not free. */
function smpro_imunify_fw_available() {
    static $c = null;
    if ($c !== null) return $c;
    if (!@is_executable('/usr/bin/imunify360-agent')) return $c = false;
    $chain = trim((string)@shell_exec('timeout 10 iptables -S 2>/dev/null | grep -c imunify360'));
    if ($chain !== '' && (int)$chain > 0) return $c = true;
    return $c = (trim((string)@shell_exec('systemctl is-active imunify360 2>/dev/null')) === 'active');
}
function smpro_imunify_block_ip($ip, $reason = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'invalid IP'];
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip)) return ['ok' => false, 'msg' => 'refused: Cloudflare edge IP'];
    if (!function_exists('smpro_fw_never_block')) { $fwf = __DIR__ . '/fwallow.php'; if (is_file($fwf)) require_once $fwf; }
    if (function_exists('smpro_fw_never_block') && ($nb = smpro_fw_never_block($ip)) !== '') return ['ok' => false, 'msg' => 'refused: ' . $ip . ' belongs to ' . $nb . ' - blocking it would bounce your customers\' mail'];
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';
    $out = (string)@shell_exec('timeout 40 /usr/bin/imunify360-agent blacklist ip add ' . escapeshellarg($ip)
        . ' --comment ' . escapeshellarg($reason) . ' 2>&1');
    $ok = stripos($out, 'error') === false && stripos($out, 'traceback') === false;
    return ['ok' => $ok, 'msg' => $ok ? ($ip . ' blocked in Imunify360.') : ('Imunify360 refused the block: ' . trim(mb_substr($out, 0, 140)))];
}
/**
 * Which firewall is ACTUALLY enforcing on this server?
 * Returns ['id','label','how'] for the first engine that genuinely owns the packet filter. A managed firewall
 * is preferred over raw tables so we never fight the tool that is in charge. Cached per request.
 */
function smpro_fw_engine() {
    static $e = null;
    if ($e !== null) return $e;
    $act = function ($u) { return trim((string)@shell_exec('systemctl is-active ' . escapeshellarg($u) . ' 2>/dev/null')) === 'active'; };
    if (smpro_csf_enabled())            return $e = ['id'=>'csf',      'label'=>'CSF',        'how'=>'csf -d'];
    if (smpro_imunify_fw_available())   return $e = ['id'=>'imunify',  'label'=>'Imunify360', 'how'=>'imunify360-agent blacklist'];
    if (trim((string)@shell_exec('command -v bitninjacli 2>/dev/null')) !== '' && $act('bitninja'))
                                        return $e = ['id'=>'bitninja', 'label'=>'BitNinja',   'how'=>'bitninjacli --blacklist'];
    if ($act('firewalld'))              return $e = ['id'=>'firewalld','label'=>'firewalld',  'how'=>'firewall-cmd rich-rule'];
    if (trim((string)@shell_exec('command -v ufw 2>/dev/null')) !== ''
        && stripos((string)@shell_exec('ufw status 2>/dev/null'), 'Status: active') !== false)
                                        return $e = ['id'=>'ufw',      'label'=>'ufw',        'how'=>'ufw deny from'];
    // A managed firewall we recognise but cannot drive - say so rather than guess a CLI and silently fail.
    foreach (['pyxsoft' => 'PyxSoft', 'pyxsoft-antimalware' => 'PyxSoft AntiMalware'] as $bin => $lbl)
        if (trim((string)@shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null')) !== '')
            return $e = ['id'=>'unsupported', 'label'=>$lbl, 'how'=>''];
    if (trim((string)@shell_exec('command -v iptables 2>/dev/null')) !== '')
                                        return $e = ['id'=>'iptables', 'label'=>'iptables',   'how'=>'iptables -I INPUT DROP'];
    if (trim((string)@shell_exec('command -v nft 2>/dev/null')) !== '')
                                        return $e = ['id'=>'nftables', 'label'=>'nftables',   'how'=>'nft add rule'];
    return $e = ['id'=>'none', 'label'=>'none', 'how'=>''];
}
/** Persist a raw iptables rule so it survives a reboot. Returns '' when it could be persisted. */
function smpro_fw_iptables_persist() {
    if (trim((string)@shell_exec('command -v netfilter-persistent 2>/dev/null')) !== '') { @shell_exec('timeout 30 netfilter-persistent save >/dev/null 2>&1'); return ''; }
    if (@is_dir('/etc/sysconfig') && trim((string)@shell_exec('command -v iptables-save 2>/dev/null')) !== '') { @shell_exec('timeout 30 sh -c "iptables-save > /etc/sysconfig/iptables" 2>/dev/null'); return ''; }
    return ' The rule is active now but is NOT saved across a reboot on this server.';
}
/**
 * Block an IP with whichever firewall is ACTUALLY enforcing.
 * A server can have CSF installed but disabled while something else owns every rule - writing to csf.deny
 * there records the block and enforces nothing, which is the worst outcome: the admin believes the attacker
 * is blocked. Pick the live engine; if none can enforce, say so instead of reporting success.
 */
/**
 * $force skips the verified-crawler shield. It is for a deliberate, informed decision made about a bot the
 * operator is looking at (Bot Guard's own Block button) - never for an automatic response.
 */
function smpro_fw_block_ip($ip, $reason = '', $force = false) {
    // Accepts a single address OR a CIDR range - every engine below takes both, and the subnet blockers need it.
    $ip = trim((string)$ip);
    $isCidr = (bool)preg_match('#^([0-9a-fA-F:.]+)/(\d{1,3})$#', $ip, $cm) && filter_var($cm[1], FILTER_VALIDATE_IP);
    if (!$isCidr && !filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'engine'=>'','recorded'=>false,'msg'=>'invalid IP or CIDR'];
    $cfIp = $isCidr ? $cm[1] : $ip;                                    // Cloudflare check uses the network address
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($cfIp))
        return ['ok'=>false,'engine'=>'','recorded'=>false,'msg'=>'refused: Cloudflare edge IP — blocking it would cut ALL inbound traffic.'];
    // MAIL-PROVIDER SHIELD. Google's and Microsoft's sending ranges (as they publish them in SPF) are never blocked,
    // not even with force: a block there has no symptom on this server and every Gmail / Microsoft 365 message to
    // the customers bounces until somebody notices. Refused here, at the one point every block passes through.
    if (!function_exists('smpro_fw_never_block')) { $fwf = __DIR__ . '/fwallow.php'; if (@is_file($fwf)) require_once $fwf; }
    if (function_exists('smpro_fw_never_block') && ($nb = smpro_fw_never_block($cfIp)) !== '') {
        if (function_exists('smpro_audit')) smpro_audit('firewall_block_refused_mail', ['ip'=>$ip,'provider'=>$nb,'reason'=>(string)$reason]);
        return ['ok'=>false,'engine'=>'','recorded'=>false,'msg'=>'refused: ' . $ip . ' belongs to ' . $nb . ' - blocking it would bounce your customers\' mail. If this address really attacks, report it to the provider; it must not be blocked here.'];
    }

    // VERIFIED CRAWLER SHIELD. Blocking Googlebot or Bingbot has no error and no symptom: the site simply falls
    // out of the index over the following days, and nothing on this server ever connects the two events. So a
    // block aimed at a forward-confirmed crawler is refused here, at the one point every block passes through -
    // panel buttons, the break-in report, the automatic response in the notify worker, the hub, all of them.
    // A single address only: a range cannot be resolved, and a crawler's own ranges are in the allow-list, which
    // the engines below already honour. A DNS failure reads as "not a crawler", so this can never stand between
    // an operator and an attacker.
    if (!$isCidr && !$force) {
        if (!function_exists('smpro_bg_crawler_shield')) { $bg = __DIR__ . '/botguard.php'; if (@is_file($bg)) require_once $bg; }
        if (function_exists('smpro_bg_crawler_shield')) {
            $cs = smpro_bg_crawler_shield($ip);
            if (!empty($cs['crawler'])) {
                if (function_exists('smpro_audit')) smpro_audit('firewall_block_refused_crawler', ['ip'=>$ip,'bot'=>$cs['name'],'host'=>$cs['host'],'reason'=>(string)$reason]);
                return ['ok'=>false,'engine'=>'','recorded'=>false,'crawler'=>$cs['name'],
                        'msg'=>'refused: this is really ' . $cs['name'] . ' (' . $cs['host'] . ', confirmed both ways in DNS). '
                             . 'Blocking it removes the site from ' . ($cs['kind'] === 'search' ? 'search results' : ($cs['kind'] === 'archive' ? 'the archive' : 'that service'))
                             . ' with no warning anywhere. Decide it deliberately in Bot Guard if you really want it gone.'];
            }
        }
    }
    $eng = smpro_fw_engine();
    $why = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';

    if ($eng['id'] === 'csf') {
        if ($isCidr) {                                                  // smpro_csf_deny_add validates a single IP
            $csfb = smpro_csf_bin();
            @shell_exec('timeout 25 ' . escapeshellarg($csfb) . ' -d ' . escapeshellarg($ip) . ' ' . escapeshellarg($why . ' - ' . date('Y-m-d H:i')) . ' 2>&1');
            $inDeny = @is_file('/etc/csf/csf.deny') && strpos((string)@file_get_contents('/etc/csf/csf.deny'), $ip) !== false;
            return ['ok'=>$inDeny, 'engine'=>'csf', 'recorded'=>$inDeny,
                    'msg'=>$inDeny ? ($ip . ' blocked in CSF.') : ('CSF did not record ' . $ip . '.')];
        }
        $r = smpro_csf_deny_add($ip, $reason); $r['engine'] = 'csf';
        if (!empty($r['ok'])) return $r;
        // CSF is enabled but not enforcing this (TESTING) - use the next live engine if there is one
        if (smpro_imunify_fw_available()) {
            $i = smpro_imunify_block_ip($ip, $reason);
            if (!empty($i['ok'])) return ['ok'=>true,'engine'=>'imunify','recorded'=>true,'testing'=>!empty($r['testing']),
                'msg'=>$i['msg'] . ' (CSF is not enforcing, so Imunify360 was used.)'];
        }
        return $r;
    }
    if ($eng['id'] === 'imunify')  { $i = smpro_imunify_block_ip($ip, $reason); $i['engine']='imunify';  $i['recorded']=!empty($i['ok']); return $i; }
    if ($eng['id'] === 'bitninja') {
        $o = (string)@shell_exec('timeout 40 bitninjacli --blacklist --add=' . escapeshellarg($ip) . ' 2>&1');
        $ok = stripos($o,'error') === false && stripos($o,'usage') === false;
        return ['ok'=>$ok,'engine'=>'bitninja','recorded'=>$ok,'msg'=>$ok ? ($ip.' blocked in BitNinja.') : ('BitNinja refused the block: '.trim(mb_substr($o,0,140)))];
    }
    if ($eng['id'] === 'firewalld') {
        $fam = strpos($ip, ':') !== false ? 'ipv6' : 'ipv4';
        $rule = 'rule family="' . $fam . '" source address="' . $ip . '" drop';
        $o  = (string)@shell_exec('timeout 30 firewall-cmd --permanent --add-rich-rule=' . escapeshellarg($rule) . ' 2>&1');
        @shell_exec('timeout 30 firewall-cmd --reload >/dev/null 2>&1');
        $ok = stripos($o,'success') !== false || stripos($o,'already') !== false;
        return ['ok'=>$ok,'engine'=>'firewalld','recorded'=>$ok,'msg'=>$ok ? ($ip.' blocked in firewalld (permanent rich rule).') : ('firewalld refused the block: '.trim(mb_substr($o,0,140)))];
    }
    if ($eng['id'] === 'ufw') {
        $o = (string)@shell_exec('timeout 30 ufw deny from ' . escapeshellarg($ip) . ' 2>&1');
        $ok = stripos($o,'added') !== false || stripos($o,'existing') !== false || stripos($o,'updated') !== false;
        return ['ok'=>$ok,'engine'=>'ufw','recorded'=>$ok,'msg'=>$ok ? ($ip.' blocked in ufw.') : ('ufw refused the block: '.trim(mb_substr($o,0,140)))];
    }
    if ($eng['id'] === 'iptables') {
        $bin = strpos($ip, ':') !== false ? 'ip6tables' : 'iptables';
        if (trim((string)@shell_exec('command -v ' . $bin . ' 2>/dev/null')) === '')
            return ['ok'=>false,'engine'=>'iptables','recorded'=>false,'msg'=>'No ' . $bin . ' on this server for that address family.'];
        $have = (int)trim((string)@shell_exec('timeout 15 ' . $bin . ' -C INPUT -s ' . escapeshellarg($ip) . ' -j DROP >/dev/null 2>&1 && echo 1 || echo 0'));
        if (!$have) @shell_exec('timeout 20 ' . $bin . ' -I INPUT 1 -s ' . escapeshellarg($ip) . ' -j DROP 2>&1');
        $ok = (int)trim((string)@shell_exec('timeout 15 ' . $bin . ' -C INPUT -s ' . escapeshellarg($ip) . ' -j DROP >/dev/null 2>&1 && echo 1 || echo 0')) === 1;
        $note = $ok ? smpro_fw_iptables_persist() : '';
        return ['ok'=>$ok,'engine'=>'iptables','recorded'=>$ok,'msg'=>$ok ? ($ip.' blocked with a direct '.$bin.' DROP rule.'.$note) : ('Could not add the '.$bin.' rule for '.$ip.'.')];
    }
    if ($eng['id'] === 'nftables') {
        $o = (string)@shell_exec('timeout 20 nft add rule inet filter input ip saddr ' . escapeshellarg($ip) . ' drop 2>&1');
        $ok = trim($o) === '';
        return ['ok'=>$ok,'engine'=>'nftables','recorded'=>$ok,'msg'=>$ok ? ($ip.' blocked with an nftables drop rule.') : ('nftables refused the rule: '.trim(mb_substr($o,0,140)))];
    }
    if ($eng['id'] === 'unsupported') {
        $r = smpro_csf_deny_add($ip, $reason);
        return ['ok'=>false,'engine'=>'unsupported','recorded'=>!empty($r['recorded']),
            'msg'=>$eng['label'] . ' appears to be the firewall on this server, and SM Pro cannot drive it directly. '
                 . ($r['recorded'] ? $ip . ' was recorded in csf.deny, but it will NOT take effect. ' : '')
                 . 'Block ' . $ip . ' from ' . $eng['label'] . '\'s own interface.'];
    }
    // Nothing is enforcing - record it so it applies if CSF is switched back on, but never claim success.
    $r = smpro_csf_deny_add($ip, $reason);
    return ['ok'=>false,'engine'=>'none','recorded'=>!empty($r['recorded']),
        'msg'=>(!empty($r['recorded']) ? $ip . ' was written to csf.deny, but ' : 'Could not block ' . $ip . ': ')
             . 'no firewall on this server is currently enforcing. CSF is disabled (run "csf -e" to re-enable) and no other active firewall was found, so the block will NOT take effect yet.'];
}
function smpro_csf_deny_add($ip, $reason = '') {
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'recorded'=>false,'testing'=>false,'already'=>false,'msg'=>'invalid IP'];
    // Ultimate backstop: NEVER write a Cloudflare edge IP into csf.deny - it fronts inbound traffic for EVERY site
    // on the box, so a deny would black-hole all of them. Blocks any direct caller, not just smpro_im_block_ip.
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip)) return ['ok'=>false,'recorded'=>false,'testing'=>false,'already'=>false,'msg'=>'refused: Cloudflare edge IP — blocking it would cut ALL inbound traffic. Block the real client at Cloudflare, not CSF.'];
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';   // parity w/ allow_add: no newlines into csf.deny
    $testing = smpro_csf_testing();
    $csf = smpro_csf_bin();
    $already = smpro_csf_denied($ip);
    if (!$already && $csf !== '')
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -d ' . escapeshellarg($ip) . ' ' . escapeshellarg(($reason !== '' ? $reason : 'smpro') . ' - ' . date('Y-m-d H:i')) . ' 2>&1');
    if (!smpro_csf_denied($ip)) {                                    // csf absent / no-op (e.g. disabled) -> write csf.deny directly
        $f = '/etc/csf/csf.deny';
        if (is_file($f) && is_writable($f)) @file_put_contents($f, $ip . ' # ' . ($reason !== '' ? $reason : 'smpro') . ' - ' . date('D M j H:i:s Y') . "\n", FILE_APPEND | LOCK_EX);
        if ($csf !== '' && !$testing && smpro_csf_denied($ip)) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');   // reload only if enforcing
    }
    $recorded = smpro_csf_denied($ip);
    // "Enforced" also requires CSF to be ENABLED. It can be installed, not in TESTING mode, and still disabled
    // (`csf -x` -> /etc/csf/csf.disable), in which case it owns no iptables rules and the deny does nothing.
    $csfOn    = smpro_csf_enabled();
    $enforced = $recorded && !$testing && $csf !== '' && $csfOn;
    if (!$recorded) $msg = ($csf === '' ? 'No firewall (CSF) installed — cannot block ' . $ip . '.' : 'Could not write csf.deny for ' . $ip . '.');
    elseif (!$csfOn) $msg = $ip . ' added to csf.deny, but CSF is DISABLED on this server — it is enforcing nothing. Run "csf -e" to enable it, or block through the firewall that is actually active.';
    elseif ($testing) $msg = $ip . ' added to csf.deny, but CSF is in TESTING mode — NOT enforced. Set TESTING=0 (Server Tune-up) to actually block.';
    elseif ($csf === '') $msg = $ip . ' written to csf.deny — will apply once CSF is installed/running.';
    else $msg = ($already ? $ip . ' is already blocked in CSF.' : $ip . ' blocked in CSF (csf.deny).');
    return ['ok'=>$enforced, 'recorded'=>$recorded, 'testing'=>$testing, 'already'=>$already && $recorded, 'msg'=>$msg];
}
function smpro_fw_self_state() { $f = SMPRO_VARLIB . '/fw_self_allow.json'; $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($d) ? $d : []; }
function smpro_fw_self_state_save($s) { smpro_json_save(SMPRO_VARLIB . '/fw_self_allow.json', $s, JSON_UNESCAPED_SLASHES); }
/** Offer to allow-list the admin's own IP? true when CSF is present, an IP is detected,
 *  it's not already in csf.allow, and it hasn't already been added. (Re-asks each session until added.) */
function smpro_fw_self_should_prompt() {
    if (!function_exists('smpro_im_csf_bin') || smpro_im_csf_bin() === '') return false;
    $ip = smpro_admin_ip(); if ($ip === '') return false;
    if (smpro_csf_allowlisted($ip)) return false;
    $st = smpro_fw_self_state();
    return (($st[$ip]['d'] ?? '') !== 'added');
}

/** All cPanel account usernames on this server (cached). Empty on a non-cPanel host. */
function smpro_cpanel_users() {
    static $u = null;
    if ($u !== null) return $u;
    $u = [];
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) {
        $b = basename($f);
        if ($b !== '' && $b !== 'system' && preg_match('/^[a-zA-Z0-9._-]+$/', $b)) $u[] = $b;
    }
    sort($u);
    return $u;
}
/**
 * Emit the shared account autocomplete: a JS list of all cPanel users + a small
 * reliable typeahead widget (filters as you type, styled dropdown, keyboard nav).
 * Attaches to any input carrying  data-ac="accounts". Also keeps a native
 * <datalist id="smAccounts"> as a no-JS fallback.
 */
function smpro_account_datalist() {
    $users = smpro_cpanel_users();
    if (!$users) return;
    echo '<datalist id="smAccounts">';
    foreach ($users as $u) echo '<option value="' . smpro_h($u) . '">';
    echo '</datalist>';
    echo '<script>window.SM_ACCOUNTS=' . json_encode(array_values($users), JSON_UNESCAPED_SLASHES) . ';</script>';
    ?>
<style>
.sm-ac{position:absolute;z-index:9999;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 14px 34px rgba(15,23,42,.16);max-height:300px;overflow:auto;padding:4px}
.sm-aci{padding:8px 11px;font-size:13px;cursor:pointer;font-family:ui-monospace,Consolas,monospace;border-radius:7px}
.sm-aci.on,.sm-aci:hover{background:var(--brand-bg);color:var(--brand)}
.sm-aci b{color:var(--brand);font-weight:800}
.sm-ac-empty{padding:9px 11px;font-size:12px;color:var(--muted)}
</style>
<script>
(function(){
  var ACC=window.SM_ACCOUNTS||[]; if(!ACC.length)return;
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  document.querySelectorAll('input[data-ac="accounts"]').forEach(function(inp){
    inp.setAttribute('autocomplete','off'); inp.removeAttribute('list');
    var box=document.createElement('div');box.className='sm-ac';box.style.display='none';document.body.appendChild(box);
    var idx=-1,items=[];
    function place(){var r=inp.getBoundingClientRect();box.style.left=(r.left+window.scrollX)+'px';box.style.top=(r.bottom+window.scrollY+3)+'px';box.style.minWidth=Math.max(220,r.width)+'px';}
    function render(){
      var q=(inp.value||'').toLowerCase().trim();
      items=ACC.filter(function(a){return q===''||a.toLowerCase().indexOf(q)>=0;});
      items.sort(function(a,b){var pa=a.toLowerCase().indexOf(q)===0?0:1,pb=b.toLowerCase().indexOf(q)===0?0:1;return pa-pb||a.localeCompare(b);});
      items=items.slice(0,14);
      if(!items.length){box.innerHTML='<div class="sm-ac-empty">No matching account</div>';place();box.style.display='block';return;}
      var re=q?new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','ig'):null;
      box.innerHTML=items.map(function(a,i){var lbl=re?esc(a).replace(re,'<b>$1</b>'):esc(a);return '<div class="sm-aci'+(i===idx?' on':'')+'" data-v="'+esc(a)+'">'+lbl+'</div>';}).join('');
      place();box.style.display='block';
    }
    function close(){box.style.display='none';idx=-1;}
    function choose(v){inp.value=v;close();inp.dispatchEvent(new Event('change',{bubbles:true}));inp.focus();}
    inp.addEventListener('input',function(){idx=-1;render();});
    inp.addEventListener('focus',render);
    inp.addEventListener('keydown',function(e){
      if(box.style.display==='none'){if(e.key==='ArrowDown')render();return;}
      if(e.key==='ArrowDown'){idx=Math.min(items.length-1,idx+1);render();e.preventDefault();}
      else if(e.key==='ArrowUp'){idx=Math.max(0,idx-1);render();e.preventDefault();}
      else if(e.key==='Enter'){if(idx>=0&&items[idx]){choose(items[idx]);e.preventDefault();}else close();}
      else if(e.key==='Escape'){close();}
    });
    box.addEventListener('mousedown',function(e){var it=e.target.closest('.sm-aci');if(it){choose(it.getAttribute('data-v'));e.preventDefault();}});
    inp.addEventListener('blur',function(){setTimeout(close,160);});
    window.addEventListener('scroll',function(){if(box.style.display!=='none')place();},true);
    window.addEventListener('resize',function(){if(box.style.display!=='none')place();});
  });
})();
</script>
    <?php
}

/**
 * Where an account's files actually are, from /etc/passwd.
 *
 * NOT "/home/$user". A cPanel server spreads accounts across /home, /home1, /home2 ... as partitions fill, and this
 * very box has three. Every feature that guessed the path silently did nothing for every account outside the first
 * one - and reported that as "nothing found", which is the failure this codebase exists to avoid. The scanner that
 * hunts phishing was one of them.
 *
 * Returns '' when the account does not exist, which callers must treat as "cannot look", never as "clean".
 */
function smpro_user_home($user) {
    // Cached per process: this is now called wherever a path used to be built by hand, which on a page that walks
    // many accounts is thousands of times. One passwd lookup per account per request is the budget.
    static $memo = [];
    $u = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$user);
    if ($u === '') return '';
    if (isset($memo[$u])) return $memo[$u];
    if (function_exists('posix_getpwnam')) {
        $pw = @posix_getpwnam($u);
        if (is_array($pw) && !empty($pw['dir']) && @is_dir($pw['dir'])) return $memo[$u] = rtrim((string)$pw['dir'], '/');
    }
    foreach ((array)@file('/etc/passwd', FILE_IGNORE_NEW_LINES) as $line) {
        $p = explode(':', (string)$line);
        if (count($p) >= 6 && $p[0] === $u && $p[5] !== '' && @is_dir($p[5])) return $memo[$u] = rtrim($p[5], '/');
    }
    return $memo[$u] = '';
}

/** A year-less syslog stamp ("Dec 31 23:50:00") with the CURRENT year lands a year in the future for the first days of
 *  January (and fails on Feb 29 of a non-leap year): a stamp ahead of now belongs to last year. */
function smpro_syslog_ts(string $monDayTime, int $yr = 0): int {
    $yr = $yr ?: (int)date('Y');
    $ts = (int)(@strtotime(trim($monDayTime) . ' ' . $yr) ?: 0);
    if ($ts === 0 || $ts > time() + 86400) $ts = (int)(@strtotime(trim($monDayTime) . ' ' . ($yr - 1)) ?: 0);
    return $ts;
}
/** A cPanel login_log bracket stamp: ISO "YYYY-MM-DD HH:MM:SS +0000" (whostmgrd/cpaneld) or Apache-style
 *  "DD/Mon/YYYY:HH:MM:SS +0000" (webmail), which strtotime cannot read. 0 means unreadable - never "now". */
function smpro_login_ts($t): int {
    $t = trim((string)$t);
    if ($t === '') return 0;
    if (preg_match('#^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+\-]\d{4})?#', $t, $m))
        return (int)(@strtotime($m[1] . ' ' . $m[2] . ' ' . $m[3] . ' ' . $m[4] . ':' . $m[5] . ':' . $m[6] . ' ' . ($m[7] ?? '')) ?: 0);
    if (preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $t)) $t = preg_replace('/:/', ' ', $t, 1);
    return (int)(@strtotime($t) ?: 0);
}

/** One advisory lock for every read-modify-write of csf.deny by this plugin (CSF itself appends; a block appended
 *  between a read and a full rewrite disappeared). Blocking; released by the caller or at exit. */
function smpro_csf_deny_lock() {
    $d = (defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks')); @is_dir($d) || @mkdir($d, 0700, true);
    $h = @fopen($d . '/csf_deny.lock', 'c'); if (!$h) return null;
    if (!@flock($h, LOCK_EX)) { @fclose($h); return null; }
    return $h;
}
function smpro_csf_deny_unlock($h): void { if ($h) { @flock($h, LOCK_UN); @fclose($h); } }

/** Append one line to a product log, rotating by size under a lock: file -> .1 -> .2 -> .3. Two processes crossing
 *  the size line used to both rename, and the fresh log overwrote .1; seven logs never rotated at all. */
function smpro_log_append(string $file, string $line, int $maxBytes = 20971520, int $gens = 3): bool {
    @is_dir(dirname($file)) || @mkdir(dirname($file), 0700, true);
    $lk = @fopen($file . '.lock', 'c'); if ($lk) @flock($lk, LOCK_EX);
    clearstatcache(true, $file);
    if (@filesize($file) > $maxBytes) {
        for ($i = $gens; $i >= 2; $i--) if (@is_file($file . '.' . ($i - 1))) @rename($file . '.' . ($i - 1), $file . '.' . $i);
        @rename($file, $file . '.1');
    }
    $ok = @file_put_contents($file, $line, FILE_APPEND | LOCK_EX) !== false;
    @chmod($file, 0600);
    if ($lk) { @flock($lk, LOCK_UN); @fclose($lk); }
    return $ok;
}
