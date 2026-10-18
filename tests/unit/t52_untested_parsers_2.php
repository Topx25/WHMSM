<?php
/**
 * t52_untested_parsers_2.php — second batch of includes with NO test references (audit 2026-09-06):
 * domains, disk_tmp, maintenance (auto-purge model), uinvestigate, digest, diskio. Same rule as t51: every
 * function here turns a measurement into a decision an operator sees, and a wrong decision is indistinguishable
 * from a right one on the page. Fixtures are literal; nothing shells out.
 *
 *   U80 domains        — parking_ns / ip_in_cidr / cdn_label / whois_server
 *   U81 disk_tmp       — scaled_timeout bounds; plan() refusals (plain, unknown, zero, cap, non-ext, no space) + tmpfs RAM guard
 *   U82 maintenance    — swap_hmib / velocity (window, span, NTP-step) / decide (no samples, critical, stable→daily floor, hold) / sched_expr / cron_line
 *   U83 uinvestigate   — parse_apachetime / login_ts (3 formats) / outcome / is_wpadmin_legit (admin-ajax NOT legit) / verdict_copy never says "safe"
 *   U84 digest         — always_immediate; hold() short-circuits for critical + when disabled
 *   U85 diskio         — dev_is_whole / temp_tier
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/domains.php');
smpro_plugin_funcs('includes/disk_tmp.php');
smpro_plugin_funcs('includes/maintenance.php');
smpro_plugin_funcs('includes/uinvestigate.php');
smpro_plugin_funcs('includes/notify.php');
smpro_plugin_funcs('includes/digest.php');
smpro_plugin_funcs('includes/diskio.php');

/* ---------- U80 domains ---------- */
ok(function_exists('smpro_dom_parking_ns'), 'U80: domains functions loaded router-free');
is_eq(smpro_dom_parking_ns(['NS1.DNS-PARKING.COM', 'ns2.dns-parking.com']), 'dns-parking', 'U80: parking NS detected case-insensitively');
is_eq(smpro_dom_parking_ns(['ns1.sedoparking.com']), 'Sedo', 'U80: Sedo parking');
is_eq(smpro_dom_parking_ns(['ns1.example.net', 'ns2.example.net']), '', 'U80: ordinary NS is not parking');
is_eq(smpro_dom_parking_ns([]), '', 'U80: no NS → empty (not a parking verdict)');
ok(smpro_dom_ip_in_cidr('104.16.1.1', '104.16.0.0/13'), 'U80: ip_in_cidr inside');
ok(!smpro_dom_ip_in_cidr('104.32.0.1', '104.16.0.0/13'), 'U80: ip_in_cidr just outside a /13');
ok(smpro_dom_ip_in_cidr('203.0.113.9', '203.0.113.9'), 'U80: bare address == /32');
ok(smpro_dom_ip_in_cidr('203.0.113.9', '0.0.0.0/0'), 'U80: /0 matches everything');
ok(!smpro_dom_ip_in_cidr('not-an-ip', '203.0.113.0/24'), 'U80: garbage ip is false, not a warning');
is_eq(smpro_dom_cdn_label('104.16.1.1'), 'Cloudflare', 'U80: a Cloudflare edge address is labelled so it is not read as a hijack');
is_eq(smpro_dom_cdn_label('203.0.113.9'), '', 'U80: non-CDN address has no label');
is_eq(smpro_dom_cdn_label('2606:4700::1'), '', 'U80: v6 is out of scope for the v4 table (empty, no error)');
is_eq(smpro_dom_whois_server('com'), 'whois.verisign-grs.com', 'U80: whois server for com');
is_eq(smpro_dom_whois_server('com.sa'), 'whois.nic.net.sa', 'U80: two-label TLD resolves');
is_eq(smpro_dom_whois_server('zz'), '', 'U80: unknown TLD → empty (caller must not query "")');

/* ---------- U81 disk_tmp ---------- */
ok(function_exists('smpro_ds_tmp_plan'), 'U81: disk_tmp functions loaded router-free');
is_eq(smpro_ds_tmp_scaled_timeout(0), 300, 'U81: timeout floor 300s');
is_eq(smpro_ds_tmp_scaled_timeout(1024 * 1073741824), 7200, 'U81: timeout ceiling 7200s');
is_eq(smpro_ds_tmp_scaled_timeout(8 * 1048576 * 600), 600, 'U81: timeout scales at 8MB/s');
$G = 1073741824;
$det = function (array $o = []) use ($G) {
    return array_replace([
        'backing' => 'loop', 'size_bytes' => 4 * $G, 'backfs_avail_bytes' => 100 * $G, 'backfs_avail_inodes' => 1000000,
        'backfs_mount' => '/usr', 'fstype' => 'ext4', 'container' => false, 'loop_ok' => true,
        'securetmp_running' => false, 'cagefs' => false,
    ], $o);
};
$p = smpro_ds_tmp_plan($det(['backing' => 'plain']));
ok($p['refuse'] && !$p['safe'], 'U81: plain-dir /tmp is refused'); has($p['reason'], 'not a separate mount', 'U81: plain reason explains why');
ok(smpro_ds_tmp_plan($det(['backing' => 'unknown']))['refuse'], 'U81: unknown backing refused');
ok(smpro_ds_tmp_plan($det(['size_bytes' => 0]))['refuse'], 'U81: zero current size refused');
$p = smpro_ds_tmp_plan($det(['size_bytes' => 32 * $G]));
ok($p['refuse'], 'U81: at the 32GiB cap → refused'); has($p['reason'], 'cap', 'U81: cap reason names the cap');
$p = smpro_ds_tmp_plan($det(['fstype' => 'xfs']));
ok($p['refuse'], 'U81: xfs loopback refused (mkfs flags are ext-specific)'); has($p['reason'], 'xfs', 'U81: reason names the fs');
ok(smpro_ds_tmp_plan($det(['container' => true, 'loop_ok' => false]))['refuse'], 'U81: container without loop refused');
ok(smpro_ds_tmp_plan($det(['securetmp_running' => true]))['refuse'], 'U81: securetmp running → refused');
$p = smpro_ds_tmp_plan($det(['backfs_avail_bytes' => 8 * $G]));
ok($p['refuse'], 'U81: 8GiB free cannot hold 8GiB new + headroom'); has($p['reason'], 'headroom', 'U81: space reason shows the headroom arithmetic');
ok(smpro_ds_tmp_plan($det(['backfs_avail_inodes' => 500]))['refuse'], 'U81: inode-starved backing fs refused');
$p = smpro_ds_tmp_plan($det(['size_bytes' => 20 * $G]));
if (!$p['refuse']) is_eq($p['new_bytes'], 32 * $G, 'U81: doubling 20GiB is capped at 32GiB');
else has($p['reason'], 'binary', 'U81: on a box without the loop toolchain the only refusal left is a missing binary');
$p = smpro_ds_tmp_plan($det(['backing' => 'tmpfs', 'size_bytes' => 64 * $G]));
if (function_exists('smpro_mnt_mem') && (int)(smpro_mnt_mem()['mem_total'] ?? 0) > 0) { ok($p['refuse'], 'U81: doubling a 64GiB tmpfs beyond half of RAM is refused'); has($p['reason'], 'RAM safety', 'U81: tmpfs refusal names RAM safety'); }
else ok(true, 'U81: (no /proc/meminfo here — tmpfs RAM guard exercised on the gate host)');

/* ---------- U82 maintenance ---------- */
ok(function_exists('smpro_mnt_decide'), 'U82: maintenance functions loaded router-free');
is_eq(smpro_swap_hmib(512), '512 MiB', 'U82: hmib MiB');
is_eq(smpro_swap_hmib(2048), '2 GiB', 'U82: hmib whole GiB');
is_eq(smpro_swap_hmib(1536), '1.5 GiB', 'U82: hmib fractional GiB');
$t0 = 1_700_000_000;
$rows = [['t' => $t0, 'tmp' => 10.0], ['t' => $t0 + 3600, 'tmp' => 20.0], ['t' => $t0 + 7200, 'tmp' => 30.0]];
is_eq(smpro_mnt_velocity($rows, 'tmp'), 10.0, 'U82: velocity = 10 %/h over a 2h span');
is_eq(smpro_mnt_velocity([['t' => $t0, 'tmp' => 10.0]], 'tmp'), 0.0, 'U82: one sample → 0 (not a guess)');
is_eq(smpro_mnt_velocity([['t' => $t0, 'tmp' => 10.0], ['t' => $t0 + 600, 'tmp' => 90.0]], 'tmp'), 0.0, 'U82: 10-minute span is too short → 0');
is_eq(smpro_mnt_velocity([['t' => $t0 + 7200, 'tmp' => 10.0], ['t' => $t0, 'tmp' => 90.0]], 'tmp'), 0.0, 'U82: NTP step (newest sample older than reference) → 0, never negative-inflated');
is_eq(smpro_mnt_velocity([['t' => $t0, 'tmp' => null], ['t' => $t0 + 3600, 'tmp' => null]], 'tmp'), 0.0, 'U82: null datapoints (non-separate mount) are skipped');
$long = []; for ($i = 0; $i <= 12; $i++) $long[] = ['t' => $t0 + $i * 3600, 'root' => 50.0 + $i];
is_eq(smpro_mnt_velocity($long, 'root'), 1.0, 'U82: velocity uses the 6h window, not the whole history');
$d = smpro_mnt_decide([]);
ok(!$d['purge'], 'U82: no samples → no purge'); is_eq($d['reason'], 'no samples yet', 'U82: no-sample reason is honest');
$d = smpro_mnt_decide([['t' => time(), 'tmp' => 90.0, 'root' => 50.0, 'home' => null, 'swap' => 0.0, 'ino' => 10.0]]);
ok($d['purge'] && !$d['light'], 'U82: tmp at 90% is critical → full purge now'); has($d['reason'], 'tmp:crit', 'U82: signal named');
$d = smpro_mnt_decide([['t' => time(), 'tmp' => 20.0, 'root' => 50.0, 'home' => 40.0, 'swap' => 0.0, 'ino' => 10.0]]);
ok($d['purge'] && $d['light'] === true, 'U82: stable metrics but never purged → daily-floor LIGHT purge');
has($d['reason'], 'daily floor', 'U82: daily floor reason');
smpro_mnt_state_save(['last_purge_at' => time() - 3600, 'last_freed' => 10 * 1048576]);
$d = smpro_mnt_decide([['t' => time(), 'tmp' => 75.0, 'root' => 50.0, 'home' => 40.0, 'swap' => 0.0, 'ino' => 10.0]]);
ok(!$d['purge'], 'U82: high tmp 1h after a purge → HOLD (anti-thrash)');
ok($d['alert'] === true, 'U82: hold + last run freed <50MB → alert: the fill is data, not junk');
smpro_mnt_state_save(['last_purge_at' => time() - 4 * 3600, 'last_freed' => 0]);
$d = smpro_mnt_decide([['t' => time(), 'tmp' => 75.0, 'root' => 50.0, 'home' => 40.0, 'swap' => 0.0, 'ino' => 10.0]]);
ok($d['purge'] && $d['light'] === null, 'U82: high tmp 4h after a purge → purge (gap passed)');
$d = smpro_mnt_decide([['t' => time(), 'tmp' => 20.0, 'root' => 50.0, 'home' => 40.0, 'swap' => 0.0, 'ino' => 10.0]]);
ok(!$d['purge'] && $d['reason'] === 'stable', 'U82: stable + purged 4h ago → stable');
smpro_mnt_state_save(['last_purge_at' => 0, 'last_freed' => 0]);
is_eq(smpro_mnt_sched_expr(['mode' => 'smart']), '7 * * * *', 'U82: smart mode is hourly at :07');
is_eq(smpro_mnt_sched_expr(['interval' => '24h']), '9 3 * * *', 'U82: 24h is a daily line (*/24 would be invalid cron)');
is_eq(smpro_mnt_sched_expr([]), '9 */6 * * *', 'U82: default 6h');
is_eq(smpro_mnt_sched_expr(['interval' => 'weird']), '9 */6 * * *', 'U82: unknown interval falls back to 6h');
$cl = smpro_mnt_cron_line(['mode' => 'fixed', 'interval' => '3h']);
has($cl, '9 */3 * * * root ', 'U82: cron line carries expr + user'); has($cl, 'flock -n', 'U82: cron line is single-flight'); has($cl, 'timeout 1200', 'U82: cron line is time-bounded'); has($cl, 'bin/autopurge.php', 'U82: cron line runs the worker');
ok(substr($cl, -1) === "\n", 'U82: cron line ends with newline (a missing one breaks cron.d)');

/* ---------- U83 uinvestigate ---------- */
ok(function_exists('smpro_ui_login_ts'), 'U83: uinvestigate functions loaded router-free');
is_eq(smpro_ui_parse_apachetime('09/06/2026:14:05:07 -0000'), gmmktime(14, 5, 7, 9, 6, 2026), 'U83: cPanel access_log time is MM/DD/YYYY (US order)');
is_eq(smpro_ui_login_ts('2026-09-06 14:05:07 +0000'), gmmktime(14, 5, 7, 9, 6, 2026), 'U83: ISO login_log timestamp');
is_eq(smpro_ui_login_ts('06/Sep/2026:14:05:07 +0000'), gmmktime(14, 5, 7, 9, 6, 2026), 'U83: Apache DD/Mon/YYYY with colon separator');
is_eq(smpro_ui_login_ts('09/06/2026:14:05:07 +0000'), gmmktime(14, 5, 7, 9, 6, 2026), 'U83: numeric MM/DD/YYYY with colon separator');
is_eq(smpro_ui_login_ts(''), 0, 'U83: empty → 0');
is_eq(smpro_ui_login_ts('garbage'), 0, 'U83: garbage → 0, not a warning');
foreach ([400, 401, 403, 406, 429] as $c) is_eq(smpro_ui_outcome($c), 'blocked', "U83: $c is blocked");
is_eq(smpro_ui_outcome(200), 'reached', 'U83: 200 reached'); is_eq(smpro_ui_outcome(302), 'reached', 'U83: 302 reached'); is_eq(smpro_ui_outcome(500), 'other', 'U83: 500 other'); is_eq(smpro_ui_outcome(404), 'other', 'U83: 404 is other, not blocked');
ok(smpro_ui_is_wpadmin_legit('/wp-admin/update.php?action=upload-plugin'), 'U83: authenticated plugin upload is the owner');
ok(smpro_ui_is_wpadmin_legit('/blog/wp-admin/theme-install.php'), 'U83: sub-path install is legit');
ok(!smpro_ui_is_wpadmin_legit('/wp-admin/admin-ajax.php?action=upload'), 'U83: admin-ajax is NOT excused (nopriv handlers)');
ok(!smpro_ui_is_wpadmin_legit('/wp-admin/async-upload.php'), 'U83: async-upload is NOT excused');
ok(!smpro_ui_is_wpadmin_legit('/wp-admin/update.php.bak'), 'U83: regex is anchored at the path end');
ok(!smpro_ui_is_wpadmin_legit('/uploads/update.php'), 'U83: same file name outside wp-admin is not legit');
foreach (['compromise_confirmed', 'compromise_suspected', 'suspicious_file', 'attacks_reached', 'attacks_blocked', 'reconnaissance', 'anything_else'] as $v) {
    [$txt, $cls] = smpro_ui_verdict_copy($v, 3, false);
    ok($txt !== '' && in_array($cls, ['red', 'amber', 'green', 'neutral'], true), "U83: verdict '$v' has copy + known colour");
    ok(!preg_match('/\bsafe\b(?! is)/i', $txt) || stripos($txt, 'not proof of safety') !== false, "U83: verdict '$v' never says the account is safe");
}
is_eq(smpro_ui_verdict_copy('compromise_confirmed')[1], 'red', 'U83: confirmed is red');
has(smpro_ui_verdict_copy('attacks_blocked', 7)[0], 'All 7 attack', 'U83: blocked count is phrased');
has(smpro_ui_verdict_copy('attacks_reached', 0, false)[0], 'unavailable', 'U83: unscanned account says inspection was unavailable, not "found nothing"');

/* ---------- U84 digest ---------- */
ok(function_exists('smpro_dg_hold'), 'U84: digest functions loaded router-free');
is_eq(smpro_dg_always_immediate(), ['load_high', 'license_expiry'], 'U84: load + license are never digested');
smpro_dg_cfg_save(array_replace(smpro_dg_cfg(), ['enabled' => false]));
ok(!smpro_dg_hold('disk_full'), 'U84: digest disabled → nothing is held');
smpro_dg_cfg_save(array_replace(smpro_dg_cfg(), ['enabled' => true, 'ai_critical' => null]));
ok(smpro_dg_hold('disk_full') === true || in_array('disk_full', smpro_dg_critical_types(), true), 'U84: routine type is held when digest enabled (unless the catalogue marks it critical)');
ok(!smpro_dg_hold('load_high'), 'U84: load_high bypasses the digest');
ok(!smpro_dg_hold('disk_full', ['severity' => 'critical']), 'U84: critical severity bypasses the digest');
foreach (['fm_foreign_write', 'honeytoken_login'] as $t) ok(!smpro_dg_hold($t), "U84: $t (critical in the catalogue) bypasses the digest");
smpro_dg_cfg_save(array_replace(smpro_dg_cfg(), ['ai_critical' => ['disk_full']]));
ok(!smpro_dg_hold('disk_full'), 'U84: AI-classified critical set overrides the built-in list');
smpro_dg_cfg_save(array_replace(smpro_dg_cfg(), ['enabled' => false, 'ai_critical' => null]));

/* ---------- U85 diskio ---------- */
ok(function_exists('smpro_ds_dev_is_whole'), 'U85: diskio functions loaded router-free');
foreach (['sda', 'vdb', 'xvda', 'nvme0n1', 'md0', 'dm-0'] as $n) ok(smpro_ds_dev_is_whole($n), "U85: $n is a whole device");
foreach (['sda1', 'nvme0n1p2', 'loop0', 'ram0', 'sr0', 'fd0', 'dm-name-x'] as $n) ok(!smpro_ds_dev_is_whole($n), "U85: $n is not a whole device");
is_eq(smpro_ds_temp_tier(null), null, 'U85: no temperature → null (not "ok")');
is_eq(smpro_ds_temp_tier(49), 'ok', 'U85: 49°C ok'); is_eq(smpro_ds_temp_tier(50), 'warn', 'U85: 50°C warn'); is_eq(smpro_ds_temp_tier(60), 'danger', 'U85: 60°C danger');
