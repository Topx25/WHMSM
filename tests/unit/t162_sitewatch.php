<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
require_once SMPRO_BASE . '/includes/sitewatch.php';
/** t162 - Site Watch: file classification, database diff, report rules, safety of the fix steps. */
is_eq(smpro_sw_classify_file('wp-content/uploads/2026/11/x.php', true)[0] ?? '', 'critical', 'F1: PHP in uploads is critical');
is_eq(smpro_sw_classify_file('wp-content/plugins/a/.cache/x.php', true)[0] ?? '', 'critical', 'F2: PHP in a hidden folder is critical');
is_eq(smpro_sw_classify_file('img/logo.png.php', true)[0] ?? '', 'critical', 'F3: disguised name is critical');
is_eq(smpro_sw_classify_file('.htaccess', false)[0] ?? '', 'warning', 'F4: .htaccess change is a warning');
ok(smpro_sw_classify_file('wp-content/plugins/woo/inc/a.php', true) === null, 'F5: an ordinary new plugin file is not flagged');
$old = ['admins' => ['admin' => ['id' => 1, 'email' => 'a@x', 'registered' => '']], 'options' => ['siteurl' => 'https://a', 'home' => 'https://a', 'active_plugins' => 'x'], 'inj_posts' => [], 'inj_options' => []];
$new = $old; $new['admins']['wp_support'] = ['id' => 9, 'email' => 'e@x', 'registered' => '2026']; $new['inj_posts'] = [5, 6]; $new['options']['siteurl'] = 'https://evil';
$k = array_column(smpro_sw_db_diff($old, $new), 1);
ok(in_array('new_admin', $k, true) && in_array('db_inject', $k, true) && in_array('db_url', $k, true), 'D1: new admin, injected posts and a changed siteurl are found');
is_eq(smpro_sw_db_diff($old, $old), [], 'D2: nothing changed, nothing reported');
ok(smpro_sw_rule_match(['sites' => '*'], 'a.com') && smpro_sw_rule_match(['sites' => ['a.com', 'b.com']], 'b.com') && !smpro_sw_rule_match(['sites' => ['a.com']], 'c.com'), 'R1: rules match all sites, a list, and not others');
ok(smpro_sw_rank('critical') > smpro_sw_rank('warning') && smpro_sw_rank('warning') > smpro_sw_rank('info'), 'R2: levels are ordered');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sitewatch.php'));
has($src, "if (in_array(\$dom, smpro_sw_cfg()['protect'], true) && array_filter(\$batch, fn(\$e) => \$e['sev'] === 'critical')) smpro_sw_fix_safe(\$dom, 'auto');", 'P1: automatic protection only on the selected sites');
has($src, "'safe' => false, 'event' => \$e['id']]; }", 'P2: removing an administrator is never a safe (automatic) step');
has($src, "if (\$real === false || strpos(\$real, rtrim((string)@realpath(\$doc), '/') . '/') !== 0 || is_link(\$abs) || !is_file(\$real))", 'P3: quarantine only moves a real file inside the site');
has($src, "could not back up the user - nothing changed", 'P4: the user row is backed up before it is removed');
has($src, "\$k = \$e['id'] . '|' . \$ch . '|' . \$to; if (isset(\$sent[\$k])) continue;", 'P5: an event is never sent twice to the same recipient');
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/site-watch.php'));
has($m, "smpro_require_valid_csrf('sw_action'); smpro_require_root();", 'S1: actions need CSRF + root');
has($m, "smpro_require_root(); header('Content-Type: application/json');", 'S2: read endpoints are root only');
