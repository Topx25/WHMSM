<?php
/**
 * includes/insight.php — "Daily insight": one useful item per day on the Dashboard, plus any REAL warnings
 * detected on this server right now (pinned above the tip). Content is a mix of:
 *   - a curated library of tips / tricks / options / security best-practices (rotates daily, stable within a day),
 *   - live server-derived warnings (pending update not pulled, CSF disabled, a service down, monitoring/alerts off,
 *     disk/swap pressure, end-of-life PHP) that surface only when they actually apply.
 * Read-only. Cheap: reuses the metrics the Dashboard already collected + the cached service scan.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Curated library. cat: tip|trick|security|feature. Each may carry a page route + CTA label. */
function smpro_insight_library() {
    return [
        // ---- using SM Pro (features/tricks) ----
        ['cat'=>'feature','t'=>'Auto-restart your services','b'=>'Turn on the Service Monitor and pick which services to watch — SM Pro checks them every few minutes and restarts a stopped service automatically, so a crash at 3am fixes itself.','page'=>'cpanel-services','cta'=>'Open Service Manager'],
        ['cat'=>'trick','t'=>'Never let Cloudflare or your uptime monitor get blocked','b'=>'On the Firewall page, add the Cloudflare / UptimeRobot / Googlebot allow-lists and enable Auto-update. LFD will never block your proxy or monitoring probes — a common cause of "the site is down" false alarms.','page'=>'firewall-status','cta'=>'Open Firewall'],
        ['cat'=>'feature','t'=>'Hear about incidents instantly','b'=>'Wire up Telegram or WhatsApp in Notifications. You get a message the moment a service goes down, an account starts spamming, or an attack is auto-blocked — no need to watch the dashboard.','page'=>'notifications','cta'=>'Set up alerts'],
        ['cat'=>'trick','t'=>'Stop a hacked account without taking its site offline','b'=>'When an account is compromised and spamming, use "Block ALL sending" in Spam & Phishing. It stops every mailbox and PHP mail() script for that account while the website keeps serving visitors.','page'=>'spam-phishing','cta'=>'Open Spam & Phishing'],
        ['cat'=>'feature','t'=>'Diagnose a slow or broken site in one click','b'=>'Site Doctor pinpoints why a site is slow or erroring and offers a safe one-click optimize (image compression, caching, WebP) that is fully reversible.','page'=>'site-doctor','cta'=>'Open Site Doctor'],
        ['cat'=>'feature','t'=>'A forensic timeline for any account or IP','b'=>'User Investigation correlates web-attack logins, auth logs and recently-changed files into a single timeline and tells you whether an account was actually breached — not just that it was scanned.','page'=>'user-investigation','cta'=>'Investigate'],
        ['cat'=>'feature','t'=>'Keep the disk from filling up on its own','b'=>'The Auto-purge scheduler clears caches, old logs and temp files on a cadence you choose (or a smart, log-driven mode) so /tmp and logs never quietly fill the disk.','page'=>'disk-storage','cta'=>'Open Disk / Storage'],
        ['cat'=>'trick','t'=>'Pull a new release the moment it ships','b'=>'On the Updates page, the Force-update button applies the latest version immediately instead of waiting for the daily check.','page'=>'updates','cta'=>'Open Updates'],
        ['cat'=>'feature','t'=>'A weekly 10-minute security review','b'=>'The Security Health page gives you a prioritized, fix-it-now checklist. Skim it once a week and clear the red items — it is the fastest way to stay ahead of problems.','page'=>'security-health','cta'=>'Open Security Health'],
        ['cat'=>'trick','t'=>'Add cPanel license servers to the allow-list','b'=>'A blocked cPanel license check can suspend WHM. Allow-list cPanel\'s license servers from the Firewall page so that can never happen.','page'=>'firewall-status','cta'=>'Open Firewall'],
        // ---- security best-practice advisories ----
        ['cat'=>'security','t'=>'Password SSH is the #1 brute-force target','b'=>'Switch SSH to key-only authentication and disable root password login. It removes the single most-attacked door on any server.'],
        ['cat'=>'security','t'=>'Most site hacks exploit a KNOWN plugin bug','b'=>'The majority of WordPress/Joomla compromises use a plugin or theme vulnerability that already had a patch. Keeping core + plugins + themes updated closes most of the attack surface for free.'],
        ['cat'=>'security','t'=>'End-of-life PHP gets no security fixes','b'=>'PHP 7.4 and earlier are end-of-life. Move sites to PHP 8.1+ so they keep receiving security patches — old PHP is a standing liability even behind a WAF.'],
        ['cat'=>'security','t'=>'Turn on 2FA for WHM/cPanel logins','b'=>'Two-factor authentication on WHM and cPanel stops a stolen or phished password from becoming a full compromise.'],
        ['cat'=>'security','t'=>'Never leave .git, .env or backup archives in a webroot','b'=>'Attackers scan every site for /.git/, /.env and stray backup .zip/.sql files. One exposed secret or database dump is game over — keep them out of public_html.'],
        ['cat'=>'security','t'=>'Contain spam before it lists your server','b'=>'Set sensible per-account outbound mail limits. If one account is compromised, tight limits keep it from sending enough spam to get your server IP blacklisted.'],
        ['cat'=>'security','t'=>'A disabled firewall is the #1 post-breach finding','b'=>'Keep CSF/LFD enabled at all times. "We turned CSF off to debug and forgot" is how a huge share of incidents start.'],
        ['cat'=>'security','t'=>'Watch for symlink attacks on shared hosting','b'=>'On shared servers, one hacked account can symlink to a neighbour\'s wp-config.php and read its database password. Keep accounts patched and consider symlink protection.'],
        ['cat'=>'security','t'=>'Enable ModSecurity if it is off','b'=>'A web application firewall (ModSecurity + OWASP CRS) blocks whole classes of injection and exploit traffic before it reaches the app. Turning it on is one of the highest-value hardening steps.'],
        ['cat'=>'security','t'=>'Back up — and verify the backup restores','b'=>'A backup you have never restored is a hope, not a plan. Confirm your JetBackup/cPanel backups actually complete and can be restored before you need them.'],
        ['cat'=>'trick','t'=>'Allow-list search-engine crawlers','b'=>'Add the Googlebot and Bingbot ranges to your allow-list so an over-eager LFD rule never blocks a crawler and hurts your SEO.','page'=>'firewall-status','cta'=>'Open Firewall'],
        ['cat'=>'security','t'=>'Restrict WHM to known IPs or Cloudflare','b'=>'Limiting WHM/cPanel access to your office/VPN IPs (or putting it behind Cloudflare Access) removes it from the open internet where it is constantly probed.'],
    ];
}

/** Live, server-specific findings. Returns items with sev: critical|high|warn|tip. Cheap (reuses $m + cached scan). */
function smpro_insight_dynamic($m = null) {
    $out = [];
    // 1) a published update the admin has not pulled
    if (function_exists('smpro_upd_cfg')) {
        $uc = smpro_upd_cfg(); $latest = (string)($uc['latest'] ?? ''); $cur = defined('SMPRO_VERSION') ? SMPRO_VERSION : '';
        if ($latest !== '' && $cur !== '' && version_compare($latest, $cur, '>'))
            $out[] = ['sev'=>'high','cat'=>'update','t'=>'Update available — v'.$latest,'b'=>'A newer SM Pro release ('.$latest.') is out and this server is still on '.$cur.'. Pull it to get the latest fixes and features.','page'=>'updates','cta'=>'Update now'];
    }
    // 2) CSF disabled / firewall off
    if (@is_file('/etc/csf/csf.disable'))
        $out[] = ['sev'=>'critical','cat'=>'warning','t'=>'Your firewall (CSF) is DISABLED','b'=>'CSF/LFD is turned off, so brute-force protection and blocking are not running. Re-enable it as soon as possible.','page'=>'firewall-status','cta'=>'Fix firewall'];
    // 3) a watched/critical service is down
    if (function_exists('smpro_svc_scan_cached')) {
        [$rows] = smpro_svc_scan_cached(120); $down = [];
        foreach ((array)$rows as $r) if (!empty($r['down']) && !empty($r['critical'])) $down[] = $r['label'];
        if ($down) $out[] = ['sev'=>'critical','cat'=>'warning','t'=>count($down).' critical service(s) down','b'=>'These are not running: '.implode(', ', array_slice($down,0,5)).'. Start them and consider turning on the Service Monitor so this self-heals.','page'=>'cpanel-services','cta'=>'Fix services'];
    }
    // 4) monitoring available but off
    if (function_exists('smpro_svcmon_cfg')) { $c = smpro_svcmon_cfg();
        if (empty($c['enabled'])) $out[] = ['sev'=>'tip','cat'=>'suggestion','t'=>'Service auto-monitoring is off','b'=>'Turn on the Service Monitor and SM Pro will restart a stopped service automatically and alert you — downtime recovers on its own.','page'=>'cpanel-services','cta'=>'Turn it on'];
    }
    // 5) no notification channel configured
    if (function_exists('smpro_ntf_load')) { $nc = smpro_ntf_load();
        $anyCh = !empty($nc['email']['enabled']) || !empty($nc['telegram']['enabled']) || !empty($nc['whatsapp']['enabled']) || !empty($nc['pushbullet']['enabled']);
        if (!$anyCh) $out[] = ['sev'=>'tip','cat'=>'suggestion','t'=>'No alert channel is set up','b'=>'Connect Email, Telegram or WhatsApp so you actually hear about incidents instead of finding out later.','page'=>'notifications','cta'=>'Set up alerts'];
    }
    // 6) disk / swap pressure (from the metrics the dashboard already has)
    if (is_array($m)) {
        $dpct = (float)($m['disk']['pct'] ?? 0);
        if ($dpct >= 90) $out[] = ['sev'=>'high','cat'=>'warning','t'=>'Disk is '.round($dpct).'% full','b'=>'You are close to a full disk — sites and mail start failing at 100%. Clear space or enable Auto-purge.','page'=>'disk-storage','cta'=>'Free up space'];
        $spct = (float)($m['swap']['pct'] ?? 0);
        if ($spct >= 80) $out[] = ['sev'=>'warn','cat'=>'warning','t'=>'Swap is '.round($spct).'% used','b'=>'Heavy swap use means the server is short on RAM and will feel slow. Investigate the top processes or expand swap.','page'=>'top-processes','cta'=>'See processes'];
    }
    // 7) end-of-life PHP (the panel's own runtime — a cheap, always-available signal)
    if (defined('PHP_VERSION') && version_compare(PHP_VERSION, '8.0.0', '<'))
        $out[] = ['sev'=>'warn','cat'=>'security','t'=>'End-of-life PHP detected ('.PHP_VERSION.')','b'=>'PHP '.PHP_VERSION.' no longer receives security fixes. Move sites to PHP 8.1+ so they keep getting patched.'];
    return $out;
}

/** The pick for today: pinned real warnings (most severe first) + one rotating library tip (stable per day). */
function smpro_insight_today($m = null) {
    $dyn = smpro_insight_dynamic($m);
    $rank = ['critical'=>0,'high'=>1,'warn'=>2,'tip'=>3];
    usort($dyn, fn($a,$b) => ($rank[$a['sev']] ?? 9) <=> ($rank[$b['sev']] ?? 9));
    $pinned = array_slice(array_filter($dyn, fn($x)=>in_array($x['sev'],['critical','high'],true)), 0, 3);
    $suggest = array_values(array_filter($dyn, fn($x)=>in_array($x['sev'],['warn','tip'],true)));
    // daily rotation seed — changes each day, identical all day (no Date.now equivalent needed; plugin runs under normal PHP)
    $lib = smpro_insight_library();
    $seed = (int)date('Y') * 366 + (int)date('z');
    // most days show a curated tip; if there are gentle suggestions, fold them into the rotation pool too
    $pool = $lib; foreach ($suggest as $s) $pool[] = ['cat'=>$s['cat'] ?? 'suggestion','t'=>$s['t'],'b'=>$s['b'],'page'=>$s['page'] ?? '','cta'=>$s['cta'] ?? ''];
    $tip = $pool ? $pool[$seed % count($pool)] : null;
    return ['pinned'=>$pinned, 'tip'=>$tip];
}

/** Render the Daily Insight card. Pass the Dashboard's already-collected metrics array to avoid recomputing. */
function smpro_insight_render($m = null) {
    $d = smpro_insight_today($m);
    $h = function_exists('smpro_h') ? 'smpro_h' : fn($s)=>htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $catMeta = [
        'security'  => ['&#128737;', 'Security tip'],
        'tip'       => ['&#128161;', 'Tip'],
        'trick'     => ['&#10024;', 'Did you know'],
        'feature'   => ['&#127775;', 'Feature'],
        'suggestion'=> ['&#128161;', 'Suggestion'],
        'update'    => ['&#8635;', 'Update'],
        'warning'   => ['&#9888;', 'Warning'],
    ];
    $sevColor = ['critical'=>'dang','high'=>'dang','warn'=>'warn','tip'=>'brand'];
    ob_start(); ?>
    <div class="ins-wrap">
      <?php foreach ($d['pinned'] as $p): $c = $sevColor[$p['sev']] ?? 'warn'; ?>
        <a class="ins-pin ins-<?= $c ?>"<?= !empty($p['page']) ? ' href="index.cgi?page='.$h($p['page']).'"' : '' ?>>
          <span class="ins-pin-ic">&#9888;</span>
          <span class="ins-pin-tx"><b><?= $h($p['t']) ?></b><span><?= $h($p['b']) ?></span></span>
          <?php if (!empty($p['cta'])): ?><span class="ins-pin-cta"><?= $h($p['cta']) ?> &rarr;</span><?php endif; ?>
        </a>
      <?php endforeach; ?>
      <?php if ($d['tip']): $t = $d['tip']; [$ic,$lbl] = $catMeta[$t['cat']] ?? ['&#128161;','Tip']; ?>
        <div class="ins-card">
          <div class="ins-ic"><?= $ic ?></div>
          <div class="ins-body">
            <div class="ins-kicker"><?= $h($lbl) ?> <span class="ins-day">&middot; today</span></div>
            <div class="ins-title"><?= $h($t['t']) ?></div>
            <div class="ins-text"><?= $h($t['b']) ?></div>
            <?php if (!empty($t['page'])): ?><a class="ins-cta" href="index.cgi?page=<?= $h($t['page']) ?>"><?= $h($t['cta'] ?: 'Open') ?> &rarr;</a><?php endif; ?>
          </div>
        </div>
      <?php endif; ?>
    </div>
    <style>
    .ins-wrap{margin:0 0 14px;display:flex;flex-direction:column;gap:10px}
    .ins-pin{display:flex;align-items:center;gap:12px;text-decoration:none;color:var(--ink);border-radius:12px;padding:11px 14px;border:1px solid var(--line);border-left:5px solid var(--warn);background:var(--card)}
    .ins-pin.ins-dang{border-left-color:var(--dang);background:var(--dang-bg)}
    .ins-pin.ins-warn{border-left-color:var(--warn);background:var(--warn-bg)}
    .ins-pin.ins-brand{border-left-color:var(--brand);background:var(--brand-bg)}
    .ins-pin[href]{cursor:pointer;transition:.15s}.ins-pin[href]:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(0,0,0,.10)}
    .ins-pin-ic{font-size:18px;flex:none}
    .ins-pin-tx{display:flex;flex-direction:column;line-height:1.4;flex:1;min-width:0}
    .ins-pin-tx b{font-size:13px}.ins-pin-tx span{font-size:12px;color:var(--muted)}
    .ins-pin.ins-dang .ins-pin-tx b{color:var(--dang)}
    .ins-pin-cta{font-size:12px;font-weight:700;color:var(--brand);white-space:nowrap;flex:none}
    .ins-card{display:flex;gap:14px;align-items:flex-start;border:1px solid var(--line);border-left:5px solid var(--brand);border-radius:14px;padding:14px 16px;background:linear-gradient(180deg,var(--brand-bg),var(--card) 70%)}
    .ins-ic{font-size:26px;flex:none;width:46px;height:46px;display:flex;align-items:center;justify-content:center;background:var(--card);border:1px solid var(--line);border-radius:12px}
    .ins-body{flex:1;min-width:0}
    .ins-kicker{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--brand);font-weight:800}
    .ins-day{color:var(--muted);font-weight:600}
    .ins-title{font-size:15px;font-weight:800;margin:3px 0 4px;line-height:1.25}
    .ins-text{font-size:12.5px;color:var(--muted);line-height:1.55}
    .ins-cta{display:inline-block;margin-top:8px;font-size:12.5px;font-weight:700;color:var(--brand);text-decoration:none}
    .ins-cta:hover{text-decoration:underline}
    </style>
    <?php
    return ob_get_clean();
}
