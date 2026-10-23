<?php
/**
 * menu.php — single source of truth for the sidebar menu + routing.
 * Register a module once here; it appears in the shared sidebar on every page
 * and becomes routable. Aliases activate the same item.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/**
 * Menu registry.
 * Each item: id (canonical route + module file name), label, icon,
 *            aliases[], built(bool) = has a real module yet.
 */
function smpro_menu() {
    // Ordered by importance. Reports first (overview), then threat detection, then
    // server monitoring, then settings. Within each group, most-important first.
    $m = [
        'Reports' => [
            ['id' => 'dashboard',        'label' => 'Dashboard',          'icon' => '&#9632;', 'built' => true,  'feature' => 'dashboard', 'aliases' => []],
            ['id' => 'reports-center',   'label' => 'Reports Center',     'icon' => '&#128203;', 'built' => true,  'aliases' => ['reports-hub','ip-report','ip-lookup','all-reports']],
            ['id' => 'analytics-reports','label' => 'Analytics Reports',  'icon' => '&#9650;', 'built' => true,  'feature' => 'analytics_reports', 'aliases' => ['reports-analytics','report-dashboard','reports']],
        ],
        'Security &amp; Access' => [
            ['id' => 'intrusion-monitor',   'label' => 'Intrusion Monitor',   'icon' => '&#128680;', 'built' => true,  'feature' => 'web_attack_monitor', 'aliases' => ['intrusion','intrusion_monitor','attack-monitor','attack_monitor','attacks','ids','web-attacks','web_attacks']],
            ['id' => 'bot-guard',           'label' => 'Bot Guard',           'icon' => '&#129302;','built' => true,  'feature' => 'web_attack_monitor', 'aliases' => ['bot_guard','bots','crawlers','bot-control','bot_control','botguard']],
            ['id' => 'forensics-audit',     'label' => 'Forensics / Audit',  'icon' => '&#9670;', 'built' => true,  'feature' => 'suspicious_files', 'aliases' => ['forensics_audit','forensics']],
            ['id' => 'site-doctor',         'label' => 'Site Doctor',        'icon' => '&#129658;', 'built' => true,  'feature' => 'suspicious_files', 'aliases' => ['site_doctor','sitedoctor','site-rescue','diagnose','doctor']],
            ['id' => 'security-health',     'label' => 'Security Health',     'icon' => '&#10003;', 'built' => true,  'feature' => 'security_health', 'aliases' => ['security_checks','security-checks']],
            ['id' => 'compromise-check',    'label' => 'Compromise Check',    'icon' => '&#128273;', 'built' => true,  'feature' => 'security_health', 'aliases' => ['compromise','compromised','doors','persistence']],
            ['id' => 'learned-defense',     'label' => 'Learned Defense',     'icon' => '&#129504;', 'built' => true,  'feature' => 'security_health', 'aliases' => ['learn','learned','lessons','hunt','hidden-processes']],
            ['id' => 'system-updates',      'label' => 'System updates',      'icon' => '&#8635;',   'built' => true,  'feature' => 'security_health', 'aliases' => ['updates','update','dnf','yum','upcp','patch','patches','kernel']],
            ['id' => 'server-tuning',       'label' => 'Server Tune-up',      'icon' => '&#128295;', 'built' => true,  'aliases' => ['tuning','perf','performance','optimize','hardening-tuning','server_tuning']],
            ['id' => 'imunify360-reports',  'label' => 'Imunify360 Reports',  'icon' => '&#9888;',  'built' => true,  'feature' => 'web_attack_monitor', 'aliases' => ['imunify-reports','imunify360']],
            ['id' => 'spam-phishing',       'label' => 'Spam & Phishing',     'icon' => '&#128231;','built' => true,  'feature' => 'email_queue_monitor', 'aliases' => ['spam_phishing','spam','phishing']],
            ['id' => 'database-cleanup',    'label' => 'DB Cleanup',          'icon' => '&#128190;','built' => true,  'feature' => 'database_cleanup', 'aliases' => ['db-cleanup','database_cleanup','db','sql-cleanup']],
            ['id' => 'account-audit',       'label' => 'Account Audit',       'icon' => '&#9679;',  'built' => true,  'feature' => 'login_monitor', 'aliases' => ['account_audit','login-monitor','login_monitor','login-correlation','login_correlation','password-reset-audit','password_reset_audit','login-access','login_access']],
            ['id' => 'firewall-status',     'label' => 'Firewall Status',     'icon' => '&#9873;',  'built' => true,  'feature' => 'firewall_status', 'aliases' => ['firewall_status']],
            ['id' => 'domain-checker',      'label' => 'Domain Checker',      'icon' => '&#127760;','built' => true,  'aliases' => ['domain_checker','domains','domain-check','domain_check','domain-audit','dns-check']],
            ['id' => 'php-harden',          'label' => 'PHP Harden',          'icon' => '&#128274;','built' => true,  'feature' => 'htaccess_watcher', 'aliases' => ['php_harden','safety-lock','safety_lock','safety-lock-requests','hardening']],
        ],
        'Server Monitoring' => [
            ['id' => 'load-monitor',   'label' => 'Server Health & System', 'icon' => '&#128737;', 'built' => true, 'feature' => 'service_health', 'aliases' => ['load_monitor','load','server-health','server_health','health','hardware','hardware_details','hardware-details','platform','system-info','system-load','system_load','load-monitor']],
            ['id' => 'top-processes',  'label' => 'Top Processes',  'icon' => '&#9881;', 'built' => true,  'feature' => 'top_processes', 'aliases' => ['top_processes','processes']],
            ['id' => 'resource-limits','label' => 'Resource Limit Reached', 'icon' => '&#9201;', 'built' => true, 'feature' => 'top_processes', 'aliases' => ['resource_limits','lve','508','resource-limit','limits','lve-limits','cloudlinux-limits','entry-processes']],
            ['id' => 'disk-storage',   'label' => 'Disk / Storage', 'icon' => '&#128202;', 'built' => true,  'feature' => 'disk_monitor', 'aliases' => ['disk_storage','disk','storage']],
            ['id' => 'network',        'label' => 'Network Traffic', 'icon' => '&#128225;', 'built' => true, 'feature' => 'network_traffic', 'aliases' => ['network-traffic','net','bandwidth','traffic']],
            ['id' => 'backup-monitor', 'label' => 'Backup Monitor', 'icon' => '&#128190;', 'built' => true,  'feature' => 'backup_monitor', 'aliases' => ['backup_monitor','jetbackup','backups']],
            ['id' => 'restore-migrate','label' => 'Restore & Migrate', 'icon' => '&#128228;', 'built' => true,  'feature' => 'backup_monitor', 'aliases' => ['restore_migrate','migrate','migration','transfer','restore','import','directadmin','plesk']],
            ['id' => 'cpanel-services','label' => 'Service Manager', 'icon' => '&#9881;', 'built' => true,  'feature' => 'cpanel_services', 'aliases' => ['cpanel_services','services','service-manager','service_manager','svc-monitor','service-monitor','svcmon']],
            ['id' => 'database-health','label' => 'Database Health', 'icon' => '&#128044;', 'built' => true,  'feature' => 'service_health', 'aliases' => ['database_health','db-health','db_health','mysql','mysql-health','mysql_health','database-performance','db-performance','sql','dbhealth','mariadb']],
            ['id' => 'benchmark',      'label' => 'Benchmark & Diagnostics', 'icon' => '&#127937;', 'built' => true,  'feature' => 'service_health', 'aliases' => ['benchmarks','bench','hardware-benchmark','hardware_benchmark','diagnostics','benchdiag','troubleshooting','kernel','stress-test','perf-test']],
        ],
        'Settings' => [
            ['id' => 'plugin-control',      'label' => 'Plugin Control',      'icon' => '&#9211;',  'built' => true,  'aliases' => ['plugin_control','enable-disable','power','master-switch','onoff']],
            ['id' => 'multi-server',        'label' => 'Multi-Server Hub',    'icon' => '&#127760;','built' => true,  'feature' => 'multi_server', 'aliases' => ['multi_server','hub','fleet','servers-hub']],
            ['id' => 'profiles',            'label' => 'Protection Profiles', 'icon' => '&#128737;','built' => true,  'aliases' => ['profile','protection-profiles','auto-setup','autosetup','security-profiles']],
            ['id' => 'notifications',       'label' => 'Notifications',       'icon' => '&#128276;','built' => true,  'feature' => 'telegram_alerts', 'aliases' => ['notify','notification','alerts','notifications-center']],
            ['id' => 'whatsapp',            'label' => 'WhatsApp Gateway',    'icon' => '&#128241;','built' => true,  'feature' => 'telegram_alerts', 'aliases' => ['whatsapp-gateway','wa','whats']],
            ['id' => 'telegram-bot',        'label' => 'Telegram Bot',        'icon' => '&#129302;','built' => true,  'feature' => 'telegram_alerts', 'aliases' => ['telegram_bot','tgbot','telegram-control','bot']],
            ['id' => 'ai-providers',        'label' => 'AI Providers',        'icon' => '&#9881;',  'built' => true,  'feature' => 'ai_providers', 'aliases' => ['ai_providers','aiproviders']],
            ['id' => 'license',             'label' => 'License',             'icon' => '&#128273;','built' => true,  'aliases' => ['licence','licensing','activation']],
            ['id' => 'auto-reports',        'label' => 'Automatic Reports',   'icon' => '&#128202;','built' => true,  'aliases' => ['auto_reports','autoreports','scheduled-reports','periodic-reports']],
            ['id' => 'updates',             'label' => 'Updates',             'icon' => '&#8635;',  'built' => true,  'aliases' => ['update','auto-update','check-update','upgrade']],
            ['id' => 'legal',               'label' => 'Terms & Legal',       'icon' => '&#128220;','built' => true,  'aliases' => ['terms','terms-and-conditions','terms-conditions','privacy','privacy-policy','eula','refund','legal-terms']],
        ],
    ];
    // User Investigation — a BETA-labeled feature (badge on the page), shipped in all builds.
    $m['Security &amp; Access'][] = ['id' => 'user-investigation', 'label' => 'User Investigation', 'icon' => '&#128373;', 'built' => true, 'feature' => 'suspicious_files', 'aliases' => ['user_investigation', 'user-invest', 'investigate-user', 'account-investigation']];
    return $m;
}

/**
 * Sections that are NEW / updated in a recent release — drives the "NEW" nav badge.
 * item id => the release tag it was last changed in. BUMP the tag whenever a section gets a real update;
 * the badge then re-appears for that section, and disappears again for each admin once they open it
 * (localStorage-tracked, so it shows "once per update"). Remove stale entries after a few releases.
 */
function smpro_new_features() {
    // RULE: whenever a section gets a real update, BUMP its tag here to the shipping version so the NEW badge
    // re-appears next to it (shown once per admin per update, cleared when they open the section).
    return [
        'bot-guard'          => '1.1.10-beta368', // beta348: Site Shield - one domain closed to hosting/VPN networks, scanner tools and secret-file probes; Bot Guard's patterns are its source
        'intrusion-monitor'  => '1.1.8', // 1.1.8: the product no longer assumes a home market: protect_regions ships EMPTY and the plugin SUGGESTS the country this server is in instead of defaulting to any region. Until a home region is set, location checks say so instead of flagging every login as foreign. NEW decoy accounts (honeytoken_users): any login to one is a confirmed leaked-credential list. 1.1.7: FIX false positive - the "Attack from the server's own / local IP" alert fired on a security plugin's OWN self-test. Really Simple SSL requests /wp-content/uploads/code-execution.php from the box to prove uploads can't run PHP (it WANTS a 404), and the filename tripped the Malicious-Upload heuristic. Those self-tests are now excluded, but ONLY from the server's own IP - the identical request from an external address still flags, and any other upload from the box still flags, so real detection is unchanged. 1.1.6: successful cPanel/webmail logins from outside the home region are now detected (Notifications) via a shared login_log reader that also flags one account signing in from several countries in a week. 1.1.3: emergency response now OBEYS the PHP Harden ignore list and names skipped accounts.
        'forensics-audit'    => '1.1.1-beta34', // beta34: the top summary counters (Critical / High / Needs-review / Active-malware / Persistence / Accounts-affected) are now modern icon stat-cards with health colour + context sub-lines, and the findings tables got zebra rows + hover. beta29: the "Affected accounts" list (was an unbounded wall of hundreds of chips filling the page) is now a clean, contained card — a bounded scrollable grid, sorted most-findings-first, with an instant filter box and tidier per-account chips. beta22 Comprehensive Account Forensics — one-click "Deep-analyze (real vs false positive)" on any flagged file: reproduces why it flagged, deep-scans (entropy/tokens/nested-chain/owner/timestomp/baseline), correlates web-attack + auth logs, reaches a verdict (LIKELY FALSE POSITIVE for a legit large single-file app), + a shared Whitelist Manager that stops re-alerts AND blocks auto-quarantine while genuine tamper still fires. Read-only.
        'imunify360-reports' => '1.1.8', // 1.1.8: FIX - the page was crashing on open: a helper it defines (smpro_im_campaigns) was ALSO defined by the always-loaded intrusion engine with a different meaning, so PHP refused to load the page at all. The module's copy is now smpro_imu_malware_families - the malware-family grouping it always was - and the page opens again. WP Guard allowlist: trusted WP Guard files no longer shown as "active threats" and the one-click delete refuses them
        'network'            => '1.1.8', // 1.1.8: the 'Top talkers' table no longer shows an empty, reassuring list when the socket table simply could not be read (ss missing or timed out) - it now says the read failed, because a live server with zero connections is not a state that happens.
        'whatsapp'           => '1.1.0-beta19', // removed the real example IP from the Gateway URL field; saving the gateway now auto-allowlists its IP(s) so our auto-block/CSF never blocks it
        'notifications'      => '1.1.9', // 1.1.9: FIX - the detection worker (foreign logins, File Manager writes from abroad, decoy logins, breaches, service/disk/backup checks) now runs every 15 min on EVERY enabled install. It used to be scheduled only after the admin toggled Auto-checks or enabled intrusion auto-block, so on an untouched server no detector had ever run and a takeover through File Manager went unseen. Also 1.1.9: readable foreign-login alerts. // 1.1.9: the foreign cPanel/webmail login alert is readable now: grouped by ACCOUNT with per-account totals, country NAMES, the network behind the address, which door (panel / webmail as mailbox), when it last happened, every account listed (says how many more when capped), and a what-to-do section (legitimate travel vs leaked password). Same for the multi-country anomaly. // 1.1.8: three new alerts - 'File Manager write from outside your region' (with the write-then-delete takeover-tool signature at critical), 'Decoy account login', and 'Home region not set' (a setup gap reported as a finding, because silence there would read as 'no foreign logins'). 1.1.6: NEW alert - a successful cPanel/webmail login from OUTSIDE your home region (EG/SA + the Arab set). The foreign-login alert previously read only /var/log/secure (SSH), so account takeovers through the cPanel panel and webmail - the door attackers actually use with a stolen password - raised nothing. A companion alert fires when ONE account is signed into from several different countries in a week (the shape of a shared/stolen password even from an in-region VPN). Both aggregate and dedupe - one line per source, never a flood. 1.1.0-beta19: WhatsApp Gateway URL example IP removed; saving auto-allowlists the gateway IP
        'account-audit'      => '1.1.10', // 1.1.10: NEW Break-in Report tab — every network carries a VERDICT (Attack — block / Look first / Probably not an attack) with the reasons: accounts targeted (password spraying), addresses per network (proxy pool), attempts per address (hammering), rate and time span (scripted), cloud vs residential, the door used; a single address with a few attempts on one account is called what it usually is — a wrong saved password. the brute-force networks moved off the results page into a one-line alert that opens a full report: every network with its addresses and attempts, split residential/business vs cloud/hosting, with a decision per network (Block all / Allow-list / Ignore, reversible), allow-listed addresses left out and named. Also: searching an address or an account now also lists its PANEL ACTIONS (API and File Manager calls inside a cPanel session), with a new event type. A takeover that arrives with a stolen password, an API token or a reseller 'log in as' leaves no login line at all — the File Manager calls are the only trace, and the page used to drop them (a real case: 0 matched for the attacker's address). // 1.1.8: FIX - large log windows (100k+ lines) made the page come back BLANK: cPanel's PHP caps memory at 128M and the window was held in memory twice. Logs are now streamed line by line, the search text filters the raw lines first, the cap was raised, and if a page ever stops it shows why instead of a white screen. // beta16: IP report scans ALL auth services (SSH/mail/FTP/cPanel/webmail), web parse hardened + time-bounded. beta17: BLANK date box = full available range (oldest→newest detected), no more forced last-7-days default; period line shows the real detected span
        'site-doctor'        => '1.1.0-beta15', // Optimize EXECUTION layer: one-click "Auto-optimize (safe)", auto-INSTALL image tools (jpegoptim/optipng/gifsicle/cwebp), server-wide OPcache/HTTP2/Keep-Alive/slow-log one-click via Tune-up, Brotli; optimizers run as the account user; run-scoped "Undo everything"
        'user-investigation' => '1.1.1-beta20', // beta20: broadened the timeline with two research-driven sources — Exim outbound-mail attribution (which script sent mail + compromised-app vs stolen-mailbox-password vector, and a burst signal) and an access-log web-shell hunt (POST-heavy, single-client, referer-less .php served 2xx). Older: NEW forensic enrichment — every web-attack row now shows its real OUTCOME (blocked at WAF vs reached the app), and when an exploit-class request reaches the app the timeline deep-scans recently-changed webroot files near it, correlates a real malicious file change back to the attack, and shows an honest account verdict banner (blocked / reached / suspected / confirmed). Bounded + read-only.
        'updates'            => '1.0.251',        // Stable/Beta update channel choice
        'disk-storage'       => '1.1.1-beta53', // beta53: the Hardware Benchmark section MOVED out of this page into its own "Benchmark & Diagnostics" section (where it now also covers PHP + MySQL benchmarks, kernel/software troubleshooting and a saved report history) — a link here points to it. beta50: FIX — the Hardware Benchmark section could be missing on a heavily-loaded server. The page render used to run dmidecode/lscpu/lsblk on every load, which under extreme IO saturation made the page slow and the browser/cpsrvd cut it off before the benchmark card (at the bottom) rendered. The static hardware inventory is now cached (~24h) and computed off the page render (via the same lightweight format=json poll as the live meters), so the page loads fast and the benchmark card always appears; the inventory fills in on the first poll. beta48: NEW "Hardware Benchmark" section — an instant hardware inventory (CPU model/threads/GHz, RAM total + type/speed via dmidecode, disks model/size/SSD-HDD, bare-metal vs virtualized) PLUS a one-click bounded benchmark of CPU (AES-256 single + all-core throughput + scaling), RAM bandwidth (read/write via /dev/shm) and Disk (sequential read/write + random 4K IOPS via fio) — laid out in clean result cards. Runs as a DETACHED background worker so it survives closing the page; results appear on return. beta47: FIX — Disk I/O live update + temperature column now work The live poll was going through a page-internal endpoint; it now uses the SAME mechanism as the dashboard load meter (index.php format=json&metric=diskio → clean JSON before any page render), so it updates every 5s in place with no refresh; and the per-disk Temperature column always shows (values fill in on the first poll, smartctl runs in the background so it never slows the page). beta46: the "Disk I/O — read/write speed & load" card made LIVE + a temperature column (pauses when the tab is hidden), and adds a per-disk TEMPERATURE column (°C via SMART/smartctl, cached ~60s; green <50 / orange 50-60 / red ≥60; "—" for RAID arrays or if smartmontools isn't installed). beta44: NEW Disk I/O card — per-disk read/write MB/s + IOPS + a BUSY% bar that is the real performance signal (green <60% / orange 60-85% / red ≥85%); a disk can be 99% busy at low MB/s and still be the bottleneck. From /proc/diskstats (no sysstat), covers whole disks + RAID/LVM. Also: Auto-Purge + Auto Swap-Cycle grouped in ONE "Automation & Schedulers" section. beta34: Disk/Storage top redesigned as stat-cards + table polish — the top summary is now modern icon stat-cards (root disk / /home / accounts / near-full) with live health colour + context sub-lines, and the Filesystems and Top-accounts tables got summary chips, zebra rows and hover. beta33: NEW Auto Swap-Cycle scheduler — like the Auto-Purge scheduler but for swap: pick a threshold and SM Pro drains swap back to RAM in the background (swapoff+swapon) every time usage crosses it, but ONLY when RAM can safely absorb the pages (else it skips — never an OOM). beta30: Add/resize-swap dialog fixed + reworked — clearly separates System RAM from the Recommended swap (was showing "125 GiB RAM" as if it were the swap recommendation); size input is now in GiB with the max shown and a live preview + clamp warning (typing 125000 no longer silently became 12 GiB); the swap ceiling was raised from 16 GiB to 64 GiB; and the whole Interactive Admin Disk Tools panel got a design polish
        // 1.0.256 — security + reliability review (2026-07-05):
        'reports-center'     => '1.1.1-beta66', // beta66: the Incidents list is now a folded accordion — every incident (and every grouped/recurring one) starts COLLAPSED and opens with an arrow that rotates, instead of a long flat table. Each folded row still shows severity (with a severity-coloured left edge so a critical item stands out while closed), title, ×count and the time/range at a glance; expanding reveals the plain-language detail, the recurring-offenders table and the individual events. Added Expand-all / Collapse-all controls. beta65: NEW recurring-load-pressure finding; beta64: grouping + humanising + reclassify. beta18: NEW "Recurring load pressure" finding. When an automated action keeps firing (the load guard throttling a process every ~11 minutes for days), the plugin now works out WHY: it tallies which process IDs recur across all the firings, resolves the ones still running to their process name and owning (cPanel) account, and raises one actionable warn/performance incident naming the top offenders (with a throttled-count each and a cPanel-account flag) so you fix the root cause instead of watching the guard fire forever. Builds on beta64's grouping/humanising of the Incidents list. beta64: the Incidents list is readable again — routine automation is grouped into one row with a x-count + time range + plain summary + expandable events, the raw JSON detail is replaced with a human sentence, and routine automation is reclassified from security/warn to maintenance/info so real incidents are not drowned out. beta18: the Incidents list is readable again. A routine automated action that fires constantly (the load cooler throttling a runaway process every ~11 minutes) used to appear as hundreds of separate "warn / security" rows, each showing raw JSON like {"pids":[…],"percent":20,"minutes":10}, burying the real incidents. Now: repeated identical events are GROUPED into a single row with a ×count, the time shown as a first→last range, a plain-language summary ("Fired 400 times over 3d — about once every 11m"), and an expandable list of the individual events; the raw JSON is replaced everywhere with a human sentence ("Throttled 2 processes to 20% CPU for 10 min"); and routine automation is reclassified from security/warn to maintenance/info so it no longer looks like a threat. A genuinely important event (e.g. CSF disabled) is no longer drowned out. beta18: //
        'dashboard'          => '1.1.1-beta50', // beta50: RESILIENCE — the Top Processes panel no longer comes back empty ("broke") on a severely IO-saturated server. Enumerating hundreds of PIDs via ps could exceed the 5s quick-timeout and get killed, leaving no rows; it now retries once patiently (15s) before giving up, so the panel stays populated under heavy load. beta39: PERFORMANCE — the panel is much lighter to load and navigate. The 8 boot self-heal cron re-asserts no longer run on every single request: they are skipped on the dashboard's live-poll and other lightweight JSON endpoints, and throttled to ~once every 3 minutes on full loads (self-heal coverage unchanged). The dashboard live-poll interval went from 2s to 5s (still real-time, ~60% fewer full PHP-CLI requests). beta37: the Security & Health Score is now HONEST — it also factors in open Server Tune-up hardening findings (SSH/Apache/MySQL/CSF/symlink/Jail-Apache/jailshell…), not just acute issues + firewall/AV presence, so it no longer shows 100 while Tune-up has pending items. Uses a cached posture summary refreshed by a throttled background scan (dashboard stays light, no inline heavy scan); a clickable chip links straight to Server Tune-up. beta18: NEW Daily insight card, reordered home layout, dark-mode button colors
        'cpanel-services'    => '1.1.1-beta49', // beta49: the Reboot-readiness checks that CAN be fixed now show a one-click "🔧 Fix" — e.g. the "fstab declares /tmp as ext4 but the image is ext3" warning: SM Pro backs up /etc/fstab, aligns the /tmp entry's type to the actual image type (safe, non-disruptive, no remount), and verifies. beta46: NEW "Reboot readiness & scheduled reboot" — a pre-reboot safety check (does the NEXT-boot kernel have its CloudLinux LVE module kmodlve? boot images + NIC driver present for it? RAID healthy? /boot room? a fallback kernel? fstab/tmp sane?) with a ready/caution/blocked verdict, PLUS schedule an automatic reboot at a chosen date+time that RE-VERIFIES at fire time and ABORTS (with an alert) if anything critical fails — and can pin the current known-good kernel instead of the new one. beta43: FIX — CSF sometimes reported "partially present" after uninstall because the check used systemctl (a removed unit still says "inactive") and the purge left CSF's /usr/sbin/csf symlinks + chkservd entry. Now the purge also removes the csf/lfd symlinks, init scripts and chkserv.d/lfd + reset-failed, and the "is it gone?" check looks at real residue (binaries + key dirs), so a clean removal reports UNINSTALLED. beta42: the Uninstall button truly REMOVES the add-on itself (no more "run this in a shell"). It runs an escalating engine — vendor uninstaller → package manager → official network uninstaller — stops once the add-on is gone, then PURGES leftovers (files, systemd units, and its iptables chains; for CSF it also re-opens the INPUT policy so you're not left locked out), and verifies + shows a per-step log. Works for CSF, Imunify, ClamAV, KernelCare, ModSecurity, CageFS/LVE/Governor; CloudLinux runs too (flagged high-risk: the kernel needs a reboot). beta41: first Uninstall button; beta34: state-matched Fix/Enable/Start + Ignore
        'resource-limits'    => '1.1.10-beta362', // beta352: NEW page - who hit a CloudLinux LVE limit (508), what runs this second, and three ways out (end hung PHP, lift x2 for a while with automatic put-back, reset to package)
        'firewall-status'    => '1.1.10-beta367', // beta348: Country Login Lock sees VPN exits and hosting networks (report or block), kernel-set backend
        'spam-phishing'      => '1.1.10-beta354', // beta354: Remove all frozen works on big queues (exiqgrep, no 500 cap) and reports the count read back from the queue. beta348: beta348: MailGuard panel (holds, throttles, verdicts) and the truth about the shared sender-block list
        'benchmark'          => '1.1.2', // 1.1.2: FIX — the same defect as Database Health, here in two places: the "Does the hardware match the load?" rows and the hardware-health findings (disks, SMART, RAID) were assembled with compact(), which the release build breaks silently, so they rendered with no text in them. Both are now written out field by field. beta63: NEW "Drive lifetime & wear" — per disk: hours powered on since manufacture, total data written and read, a HEALTH % and a PERFORMANCE % measured against what a healthy drive of that class should do. beta62: the Hardware score now carries its COVERAGE instead of renormalising over the parts it could measure and presenting that as a confident grade. beta61: storage changes are stack-aware — every blocked case explains the real risk and the exact manual command instead of being silently skipped. beta60: NEW overall Hardware score + a 7-day sampler behind "Does the hardware match the load?". beta58: per-device READ-ONLY testing + full storage layout.
        'database-health'    => '1.1.2', // 1.1.2: FIX — Findings said "5 issue(s)" and showed five EMPTY boxes: a severity badge, a "Fix" label, and no title, evidence, explanation or recommendation. The checks had genuinely found the problems and lost every word describing them on the way to the screen. The cause was in how a release is built: the results were assembled with compact(), which names its values in strings, and the build renames variables without rewriting those strings — so compact() returned nothing, silently. Every finding is now written out field by field, and the build refuses to produce a release containing compact(). beta54: the page is now fully LIVE/dynamic — KPIs, the utilization table, findings, the score and the verdict all refresh in place (refresh-interval selector + Pause), no page reload. NEW "Ways to improve" computes the right value for THIS server from its own RAM, cores and actual InnoDB data size, shows current vs recommended with an impact rating and the reason, applies the dynamic ones LIVE in one click (including an ONLINE InnoDB buffer-pool resize that refuses if free RAM is too low) — each with Undo — and prints a copy-ready my.cnf block. beta52: "Utilization & configuration" table. beta51: NEW Database Health — a general MySQL/MariaDB slowness diagnostic with a live "queries running now" panel and safe reversible one-click fixes.
        'load-monitor'       => '1.1.10-beta363', // Overload Investigator + "Cool this user" now handle cPanel usernames longer than 8 chars
        'ai-providers'       => '1.0.256', // AI failover now skips a decommissioned model (HTTP 404) instead of aborting the whole chain
        'server-tuning'      => '1.1.1-beta38', // beta38: REAL FIX for Apply doing nothing — the plugin was calling a whmapi1 function that does not exist, `set_tweaks`; cPanel's actual function is `set_tweaksetting` (key=/value=, one per call). Every tweak-based fix (Jail Apache / symlink protection, and the cPanel-Advisor passthrough: email rate-limit, quota, referrer, cookie-IP) now uses the correct function, so Apply actually applies. beta36: symlink used an invalid tweak key (now Jail Apache); Jail-Apache detection reads the real `jailapache` tweak. beta35: NEW "Access Isolation & Jailing" advisor group — symlink protection, mod_ruid2 + Jail Apache, jailshell, CageFS; reversible + backed up. beta32: hide server info from customer cPanel
        'database-cleanup'   => '1.1.1-beta40', // beta40: the Restore panel now has a "👁 View" button on every entry that shows EXACTLY what was removed from that row — the injected snippets that were stripped (type, host, byte size, the actual code) plus the backed-up original value, read from the pre-clean backup, read-only. Also shows a "Removed (bytes)" column. So you can review precisely what a bulk clean deleted. beta28: redesigned the per-account group header in the findings list (avatar, prominent name, injection-count pill, DB chips, aligned actions) — was cramped/ugly. beta27: NEW "Restore (undo a clean/trash)" panel — every clean/trash is backed up first, and now you can one-click restore any of them if it was a mistake (cleaned row → original value back; trashed post → status back), verified against the DB. beta26 Location clarity + native Analyze-file jump. beta25 verified-write fixes

        'security-health'     => '1.1.10-beta348', // beta348: new cards - CSF CC_ALLOW (voids every block), MailGuard, PHP session.upload_progress (Apply/Undo)
        'compromise-check'    => '1.1.10-beta348', // beta348: every API token shows what it can do, who made it, when it expires, when it was last used; Revoke AND Disable whatever its age; FTP delete keeps the files; every door kind explained
        'learned-defense'    => '1.1.10-beta371', // beta369: the store checks every kept file before Restore (lessons, code, ClamAV) and refuses a malicious one; sections behind a navigator // beta348: redesigned - severity strip, findings grouped by account (worst first) with filters, Quarantine-all exact matches, file-name lessons, .htaccess-CGI and ELF checks, MailGuard script origins
        'system-updates'     => '1.1.10-beta348', // beta348: NEW page - packages, cPanel and the kernel: what is pending, told when it appears, applied by itself or by the button; broken downloads diagnosed and repaired; every domain's PHP version photographed before/after with Put back
        'php-harden'         => '1.1.10', // 1.1.10: locking and unlocking files is about 80x faster. Every file used to cost four separate processes (probe chattr, run chattr, probe lsattr, run lsattr) — measured at 12ms per file, so 200 files took 2.4 seconds of almost pure process spawning. It is now done in batched calls (29ms for the same 200), files already in the wanted state cost nothing at all, and Force Unprotect — whose sweep used to run out of its time budget and stop part-way while reporting the account released — now completes. Success is still decided by reading the attribute back, never by an exit code. 1.1.5: the ignore state is now stated where you are looking. The "ignored" pill sat at the top of the page while the list explaining it was halfway down, past two large tables, so an operator who had just excluded an account saw the top of the page and reasonably concluded nothing had happened. A banner directly under the account header now names the exclusion, its scope, who added it, when, and why, with a Remove button in place. And the page no longer offers what it will refuse: on an account excluded from all protection the Apply buttons are disabled with the reason beside them, and the Fast Protection preview says it is showing what protection WOULD lock rather than presenting it as pending work. 1.1.3: NEW "Force unprotect & ignore" - some accounts cannot take file hardening (a site that updates itself, a deploy pipeline that rewrites its own configuration, an owner who edits core files); for those, locking files is an outage rather than protection. Force unprotect removes EVERY lock the plugin holds over the account - the union of what the manifest recorded and what a live scan still sees locked, not just what is selected in the browser - and reports anything it could NOT clear as still protected instead of counting it done. The account then goes on an ignore list shown on the same page, and the reason is required because an entry outlives the session that created it. Two scopes: exclude from all protection, or from automatic passes only (an admin can still apply by hand while emergency response and auto re-lock leave it alone). Cleaning a compromised site is never skipped under either scope. 1.0.256: Drupal stack detection precedence fix
        // 1.1.0-beta1.8 (beta channel):
        'plugin-control'     => '1.1.0-beta1.8', // NEW Diagnostics self-test — see which optional integrations are active/missing + one-click install
    ];
}

/**
 * One-time "what's new" callout shown INSIDE a section the first time an admin opens it after an update.
 * Shares the exact seen-state of the NEW nav badge (localStorage "<id>|<version>"), so it appears once then clears.
 * Only sections with a noteworthy user-facing change need an entry; the version is taken from smpro_new_features().
 */
function smpro_new_feature_note($id) {
    static $notes = [
        'cpanel-services' => ['title' => 'New: Reboot readiness & scheduled reboot', 'text' => 'There is a new “🔄 Reboot readiness & scheduled reboot” panel. Before any reboot, SM Pro runs the same safety checks a careful admin would: does the kernel that will boot NEXT have its CloudLinux LVE module (kmodlve) — so resource limits still work? Are its boot images (vmlinuz + initramfs) and your network card driver present for it — so the box comes back online? Is the RAID healthy, is there room in /boot, and is there a fallback kernel to boot if the new one fails? It shows a clear READY / CAUTION / BLOCKED verdict with every check. You can also schedule an automatic reboot for a date & time you pick — and crucially it RE-RUNS all those checks at that exact moment and ABORTS the reboot (alerting you) if anything critical fails, so it can never boot the server into a broken kernel. You can also choose to pin the current, known-good kernel instead of the new one. Everything is double-confirmed, logged, and you get a notification when it runs or aborts. — Also: the “🗑 Uninstall” button on an installed add-on now actually REMOVES it — SM Pro runs the whole removal itself instead of telling you to open a shell. It escalates through methods until the add-on is gone: the vendor’s own uninstaller first, then the package manager, then (for Imunify) the official network uninstaller — and then it PURGES what’s left behind: leftover files, systemd units, and the add-on’s iptables chains. For CSF it also re-opens the INPUT policy so removing the firewall can’t leave you locked out. It then verifies and shows a per-step log. Works for CSF/LFD, Imunify, ClamAV, KernelCare and ModSecurity; CloudLinux components (CageFS/LVE/Governor) run too but are flagged HIGH RISK with an extra confirmation, since fully removing the CloudLinux kernel needs a reboot into a stock kernel. Double-confirmed and logged. (Also recent: state-matched Fix/Enable/Start actions on stopped services, and a 🔕 Ignore button to mute a service you turned off on purpose.)'],
        'firewall-status' => ['title' => 'New: allows apply LIVE — anti-lockout', 'text' => 'When you allow an IP in the firewall it is now ALSO applied to the running iptables immediately (a top-of-INPUT ACCEPT), not just written to csf.allow. That matters because a whitelist in csf.allow does NOT take effect while CSF is disabled or de-synced — and if old CSF/Imunify360 drop rules are still loaded, incoming connections get dropped (inside INPUT_imunify360 / LOCALINPUT) before they ever reach the “allow port 22” rule, which is how you get locked out. The live ACCEPT sits at the very top of INPUT, so it beats every one of those drop chains right away. New tools on this page: “🛡️ Allow my IP LIVE (now)” to instantly protect your current session, and — when SM Pro detects the dangerous “CSF disabled but stale DROP rules still loaded” state — a red warning with a one-click “Re-sync firewall” that re-enables CSF and rebuilds the live rules from your allow/deny lists.'],
        'spam-phishing'  => ['title' => 'Fixed: the 400k/600k mail windows could blank the page', 'text' => 'The larger mail-log windows could exceed cPanel&#39;s 128 MB PHP limit and the page came back empty. The Exim log is now streamed line by line, so the window size no longer decides whether the page opens. Also (from before): Mail queue: the new “View all queued messages” button lists every message in the Exim queue — sender, cPanel owner, recipients, size, and frozen/queued state — so you can see exactly what is there and delete only the messages you select, instead of blind-purging. The phishing “Scan now” now runs as a real BACKGROUND job on the server: start it and you can close the page and come back — the scan keeps running and the result is waiting for you (the page polls and shows it automatically). Also (from before): the “Outgoing mail by account” table has a Block ALL sending button that stops a whole compromised account from sending while its website stays online, and the blocked-sender tool warns that blocking *@your-server-hostname stops almost nothing.'],
        'site-doctor'    => ['title' => 'New: Auto-optimize — the system does the work', 'text' => 'Optimize now goes beyond suggestions and actually FIXES things. The new “⚡ Auto-optimize” button installs the image tools if they are missing, enables browser caching + Gzip, recompresses your large images (run as the account user), and generates + serves WebP — all in one click, fully reversible with a single “Undo everything from this run”. Where a tool is missing, an “Install & enable” button installs it for you; and server-wide wins (OPcache, HTTP/2, Keep-Alive, slow-query log) are now one-click through the reversible Server Tune-up engine, clearly marked as affecting all sites. Every file change is backed up first and stays owned by the account.'],
        'whatsapp'       => ['title' => 'New: gateway is auto-allowlisted', 'text' => 'The example IP was removed from the Gateway URL box, and when you save the gateway its IP address is now automatically added to the firewall allowlist — so Safety Monitor’s own auto-block and CSF can never block your WhatsApp gateway and silently stop alerts.'],
        'notifications'  => ['title' => 'New: WhatsApp gateway auto-allowlisted', 'text' => 'Saving the WhatsApp gateway now adds its IP to the firewall allowlist so it is never auto-blocked, and the example IP was removed from the Gateway URL field.'],
        'bot-guard'      => ['title' => 'New section: Bot Guard', 'text' => 'One place to see every automated client hitting your sites and decide what happens to it. Official crawlers (Googlebot, Bingbot, Applebot, DuckDuckBot, Yandex, Baidu, AI crawlers, uptime monitors…) are VERIFIED the way their publishers document — forward-confirmed reverse DNS or published IP ranges — because a User-Agent string proves nothing; verified ones are allowed automatically. Bots that cannot be verified wait in a queue for your decision: allow, block, ignore, or mark not legitimate. Any bot that sends attack-signature requests (secret-file probes, injection, web-shell parameters, login brute force, scanner tools) goes to a GRAY list with a counter, and past the threshold it is blocked automatically through the same guarded path the Intrusion Monitor uses — never the server&#39;s own IP, a Cloudflare edge, or an allow-listed address, and Dry-Run turns blocks into records. Ships OFF: turn it on in Security &amp; Access → Bot Guard.'],
        'account-audit'  => ['title' => 'Fixed: large log windows no longer return a blank page', 'text' => 'Auditing an IP with a 100k or 200k-line window used to come back as an empty white page: cPanel&#39;s PHP limits a page to 128 MB and the whole window was held in memory twice. The logs are now read line by line, the search text is applied while reading so only matching events are kept, and the memory cap was raised. If any page ever stops before finishing, it now shows a message saying why (and records it in page_fatal.log) instead of a blank screen. Also (from before): Searching an IP now shows every login &amp; access attempt it made across ALL services — SSH, mail (IMAP/POP/SMTP), FTP and cPanel/WHM/webmail — not just the cPanel logs. So an IP that is brute-forcing mail or SSH (and used to show “no activity”) now lists every failed login, which usernames it targeted, and the outcome, alongside its web requests. Also: leaving a date box BLANK now scans the full available range — from the oldest to the newest entry in the logs — instead of defaulting to the last 7 days, and a Period line shows the exact span detected. The web-log parsing was hardened for non-standard formats and time-bounded so it stays fast on busy servers.'],
        'forensics-audit' => ['title' => 'New: Deep-analyze a flagged file (real vs false positive)', 'text' => 'When a file is flagged as a possible web-shell, click “🔍 Deep-analyze” on the finding to get a full read-only forensics report: it reproduces exactly why the file was flagged, deep-scans it (entropy, dangerous-token families, nested decode→eval chains, owner, timestamps, and a diff against an accepted baseline), and correlates the write time against your web-access and login logs. It reaches a clear verdict — for example a legitimate large single-file application is correctly called LIKELY FALSE POSITIVE with the exact reasons. You can then Whitelist the file so it stops re-alerting on every edit and is never auto-quarantined, while genuine tampering (a newly-injected obfuscated payload or a 10× size jump) still fires. Manage all entries in the new Whitelist Manager. No account file is ever modified. (Also from beta21: Safety Monitor trusts HostGuard’s WP Guard plugin’s own files.)'],
        'reports-center' => ['title' => 'New: IP report sees every login attempt', 'text' => 'The per-IP report’s “Login Attempts” section now scans ALL authentication services — SSH, mail (IMAP/POP/SMTP), FTP and cPanel/WHM/webmail — instead of only SSH and cPanel. So an IP that is brute-forcing mail or SSH (and used to show “no login attempts”) now lists every failed login, which usernames it targeted, and per-service counts. The quick IP-profile popup was also made more reliable and now shows the same login attempts.'],
        'plugin-control' => ['title' => 'New: Diagnostics self-test', 'text' => 'Plugin Control now shows which optional integrations are active or missing — with a one-click install for each.'],
        'load-monitor'   => ['title' => 'Overload Investigator fix', 'text' => 'The Overload Investigator and “Cool this user” now correctly handle cPanel usernames longer than 8 characters.'],
        'benchmark'      => ['title' => 'Fixed: blank rows in workload fit and hardware health', 'text' => 'Two parts of this page — the “Does the hardware match the load?” rows and the hardware-health findings for disks, SMART and RAID — were rendering with no text in them, for the same build-time reason as Database Health. Both are fixed, and the release build now refuses to produce a package that can fail this way. Everything below describes what the page does. The Hardware Benchmark has moved out of Disk / Storage into its own “🏁 Benchmark & Diagnostics” section, and it now covers far more than hardware. One click runs a full benchmark of the machine — CPU (AES-256 single + all-core), RAM bandwidth, disk sequential read/write and random 4K IOPS, PHP throughput (integer, hash and array/sort), and MySQL (connect latency, query throughput, and InnoDB insert rate measured on a TEMPORARY table that is auto-dropped). It runs as a background job so you can close the page, and every finished run is SAVED into a new Reports table so you can compare this run against previous ones and see whether the server got faster or slower. Below the benchmark is a troubleshooting section for the parts that usually cause trouble: the KERNEL — the key sysctl values checked against recommended ones (swappiness, socket/SYN backlog, max open files, TCP FIN timeout), plus a scan of the kernel log for the things that really hurt (OOM killer kills, tasks hung on I/O, disk I/O errors, filesystem corruption, segfaults, conntrack/TCP memory exhaustion) — and the SOFTWARE stack (end-of-life PHP versions still installed, OPcache turned off or too small). Each kernel tunable that is safe to change gets a one-click fix: it applies instantly, is written to our own /etc/sysctl.d drop-in so it survives a reboot, touches no data (so there is nothing to back up), and has a one-click Undo that restores the exact previous value. Findings that need a human decision are explained instead, with what to look at.'],
        'database-health' => ['title' => 'Fixed: findings that showed no text', 'text' => 'This page was reporting “5 issue(s)” and then showing five empty boxes — a severity badge, a “Fix” label, and no title, no evidence, no explanation and no recommendation. The page was not wrong about there being problems: it had genuinely found them and lost every word describing them on the way to the screen. The cause was in how a release is built rather than in the checks, and it is fixed, with a check added to the build so it cannot recur silently. Everything below describes what the page does. The Database Health page spells everything out. A new “Utilization & configuration” table shows, for every important MySQL resource: what it is currently set to, how much of it you are actually USING (with a bar), the IDEAL value to aim for, a plain Good / Could-improve / Needs-attention status, and a one-line explanation of what it does — so you can see at a glance what is used, what is spare, and which number is better. Every headline metric also shows its ideal target next to it. And the one-click fixes are now explicit: each one tells you exactly what it changes (from → to), and reassures you that it only changes a live MySQL TUNING NUMBER via SET GLOBAL — it touches no data and deletes nothing, so there is nothing to back up. Every fix is fully reversible: it reverts on the next MySQL restart, and you get a one-click UNDO that restores the previous value instantly. (Original: a general MySQL/MariaDB slowness diagnostic that reads THIS server’s own counters — temp-tables-to-disk, unindexed joins, slow-query-log off, connection pileups, buffer-pool miss rate, lock waits — plus a live “queries running now” panel where you can kill a stuck statement.) It is a GENERAL MySQL/MariaDB slowness diagnostic that works on any server — it reads THIS machine’s own database counters (SHOW GLOBAL STATUS / VARIABLES and the live process list) and turns them into plain-language findings, each ranked by impact and normalized to your server’s uptime so nothing is hard-coded to one box. It catches the usual real causes of a slow database: internal temp tables spilling to disk, joins running with no index, the slow-query log being off (so slowness is invisible), connection saturation and query pileups (more queries running at once than you have CPU cores), a small InnoDB buffer pool re-reading hot data from disk, table-cache overflow, and MyISAM/InnoDB lock contention. A LIVE “Queries running now” panel shows exactly what is executing this second — and lets you kill a single stuck statement with KILL QUERY (which aborts the query but keeps the connection). It also offers a few SAFE, reversible one-click fixes applied live with SET GLOBAL (no restart): enable the slow-query log, raise the temp-table size, and raise the table-open cache — each also tells you the my.cnf line to make it permanent. The whole scan is read-only and every query is time-bounded, so it stays fast even on an overloaded server.'],
        'user-investigation' => ['title' => 'New: outbound-mail attribution + web-shell hunt', 'text' => 'The timeline now pulls in two more high-signal sources. Outbound mail: from Exim it attributes spam back to the exact script that sent it (cwd=) and tells you the VECTOR - a compromised web app (P=local/pipe) versus a stolen mailbox password (P=esmtpa) - and flags an outbound BURST as a strong compromise signal. Web-shell hunt: it scans the account access logs for the classic web-shell fingerprint - a .php URL that was served (2xx), hit by only one or two client IPs, and POST-heavy or with no Referer - catching shells the WAF never saw. Both appear as normal, source-tagged timeline rows with their own stat cards. It is still strictly read-only and never changes a file.'],
        'disk-storage'   => ['title' => 'New: Auto Swap-Cycle — keep swap from filling up on its own', 'text' => 'Just like the Auto-Purge scheduler reclaims disk junk on a schedule, the new Auto Swap-Cycle keeps swap under control automatically. Turn it on and set a threshold — for example 80% — and every 5 minutes SM Pro checks swap usage in the background; when it crosses your threshold it cycles swap (swapoff + swapon) to move idle pages back into RAM and free the swap, exactly like the manual “Cycle swap” button but done for you. Crucially it only ever runs when it is SAFE: if free RAM cannot absorb the swapped-out pages (it needs free RAM ≥ 1.5× swap-in-use and ≥ 25% RAM free), the run is skipped rather than forced — so it can never trigger an out-of-memory kill. It runs on the server even if you close the page, and every action is logged and audited. Find it in the Interactive Admin Disk Tools, right under the Auto-Purge Scheduler.'],
        'system-updates' => ['title' => 'New: System updates', 'text' => 'Packages, cPanel and the kernel in one place. The server looks every few hours, shows what is pending and what it is, tells you when something new appears, and applies it at the hour you choose or when you press the button - never a reboot. A broken download is diagnosed from the tool\'s own words and repaired when the kind is safe (cache, stale lock, rpm database, one dead repository). Every domain\'s PHP version is photographed before and after, and a domain that changed can be put back in one press.'],
        'resource-limits' => ['title' => 'New: the way out of "Resource Limit Is Reached"', 'text' => 'Every account that hit a CloudLinux limit in the last hour / day / week, which limit (entry processes, memory, processes, CPU, I/O) and why in plain words, what is running in its LVE this second, and three actions: end the PHP/cron processes hung for 2+ minutes (the 508 clears at once), lift the limits x2 for 15 min / 1 h / 4 h with automatic put-back, or reset the account to its package limits. ve.cfg is backed up before every change and every action is audited.'],
        'learned-defense' => ['title' => 'The store checks a file before it goes back', 'text' => 'Every quarantined file now carries a verdict - the lessons, a reader of the code itself, and ClamAV when the server has it - shown on its row with the reasons. Restore refuses a file that looks malicious unless you tick that you understand the risk, and such a restore is never remembered as safe. "Check all" judges the whole store at once, "View" shows the first lines, and every row says why the file was taken. The page is one set of folding sections behind a navigator.'],
        'compromise-check' => ['title' => 'API tokens, explained and closable', 'text' => 'Every token now says what it can do, who made it and from where, when it expires (or NEVER) and when it was last used. Revoke and Disable are offered whatever the token\'s age - an account token too. The FTP button deletes the login and keeps the files, and says so. Every kind of door has a sentence saying what it is.'],
        'security-health' => ['title' => 'New cards', 'text' => 'CSF CC_ALLOW (a country exemption that voids every block), MailGuard (shared list, holds, throttles), and PHP session.upload_progress (a file-inclusion bug must not become code execution) - each with Apply and Undo.'],
        'bot-guard' => ['title' => 'New: Site Shield', 'text' => 'Close one domain to hosting/VPN networks, scanner tools and secret-file probes while people on home and mobile networks pass. A cPanel per-vhost include, tested before the reload, removed if the test refuses; the account\'s nginx page cache is turned off while shielded.'],
        'spam-phishing' => ['title' => 'MailGuard on this server', 'text' => 'When MailGuard is installed the page shows its holds, throttles and verdicts, and says the truth about the sender-block list: one list, two products - disabling enforcement here alone does not unblock an address.'],
        'firewall-status' => ['title' => 'VPN exits and hosting networks', 'text' => 'The Country Login Lock now knows the kind of network a sign-in comes from (published prefix lists, refreshed daily): a correct password through a VPN or from a rented server is reported, or blocked when you say so.'],
        'php-harden'     => ['title' => 'The ignore state is now shown where you are looking', 'text' => 'If you excluded an account from protection, the page said so only in a small pill at the top and kept the explanation halfway down, past two large tables - so it was easy to exclude an account and conclude that nothing had happened. There is now a banner directly under the account header naming the exclusion, its scope, who added it, when, and why, with a Remove button right there. The page also no longer offers what it will refuse: on an account excluded from all protection the Apply buttons are disabled with the reason beside them, and the Fast Protection preview says it is showing what protection WOULD lock rather than presenting it as work about to happen. About the feature itself: some accounts cannot take file hardening. A site that updates itself, a deploy pipeline that rewrites its own configuration, an owner who edits core files by hand — for these, locking files is not protection, it is an outage. There is now a “Force unprotect” control at the bottom of this page for exactly that case. It removes EVERY lock the plugin holds over the account, not only what is ticked in the browser: it takes the union of what the manifest recorded locking and what a live scan can still see locked, so a lock applied by an older build is not left behind with nothing pointing at it. Anything it cannot clear — an immutable file on a filesystem that has since been remounted read-only, for instance — is reported as STILL PROTECTED rather than counted as done. The account is then added to an ignore list, shown as a table on this page with the reason, who added it, when, and a Remove button. The reason is required: the entry outlives the session that created it, and an unexplained exclusion cannot be reviewed later. There are two scopes. “Exclude from all protection” also refuses protection applied by hand from this page, and the refusal names the rule so you can lift it instead of working around it. “Exclude from automatic passes only” still lets an administrator protect the account deliberately, while emergency response and the automatic re-lock that follows a temporary unlock leave it alone. Cleaning a compromised site is never skipped under either scope — removing a web shell is not the same promise as locking files the owner writes to. Removing an entry from the list does not re-protect the account by itself; it only makes it eligible again.'],
        'intrusion-monitor' => ['title' => 'Emergency response now respects force-unprotected accounts', 'text' => 'If you have used PHP Harden’s new “Force unprotect” on an account, emergency response no longer hardens it behind your back — which previously would have happened unattended, at the moment the site was already under attack, which is the worst possible time to break it. The account is skipped and NAMED in the run summary, so a deliberate exclusion never looks like coverage you did not get. Cleaning still runs on those accounts: quarantining a web shell is not the same promise as locking files the owner writes to. (Also recent: the “Attack from the server’s own / local IP” alert answers the question instead of asking you to go hunting — a “Connection sources” panel resolves every connection involving that IP down to the process, the binary, the redacted command line and the owning cPanel account.)'],
        'server-tuning'  => ['title' => 'New: Access Isolation & Jailing — the account-isolation gaps WHM warns about, fixable in one click', 'text' => 'Server Tune-up now scans for the account-isolation weaknesses that WHM’s own Security Advisor flags — the ones that were missing here — and fixes them for you: (1) Symlink race-condition protection, so one account cannot win a symlink race to read another account’s files; (2) Apache vhost segmentation via mod_ruid2 + Jail Apache, so every site runs as its own user instead of a shared web user (installs the module for you if it is missing); (3) accounts running outside the jail — it lists every cPanel account still on a full /bin/bash shell and switches them to jailshell; and (4) CloudLinux CageFS — enable it for all users so each account gets its own isolated filesystem. Each fix backs up first, records an undo-able profile, and is reversible. Heads-up: enabling Jail Apache can affect accessing Mailman through Apache, and you should not jail a user who legitimately needs a full shell.'],
    ];
    return $notes[$id] ?? null;
}

/** Flat lookup: route or alias → canonical id (+ built flag + label). */
function smpro_menu_lookup() {
    static $map = null;
    if ($map !== null) return $map;
    $map = [];
    foreach (smpro_menu() as $items) {
        foreach ($items as $it) {
            $map[$it['id']] = $it;
            foreach ($it['aliases'] as $a) $map[$a] = $it;
        }
    }
    return $map;
}

/** Resolve a requested page (incl. aliases) to its canonical item, or null. */
function smpro_menu_resolve($page) {
    $map = smpro_menu_lookup();
    return $map[$page] ?? null;
}

/** Render the shared sidebar. $activeId = canonical id of current page. Sections are collapsible. */
/**
 * What the search can find, built from the very menu the sidebar draws.
 *
 * Deriving it rather than keeping a second list is the whole point: a search that is maintained separately goes
 * stale the first time somebody adds a page and forgets, and a search that cannot find a feature is worse than
 * no search — it answers "we don't have that" about something we do have.
 *
 * It is built AFTER the licence filter, so a plan that does not include a feature cannot find it here either.
 */
function smpro_menu_search_index(array $visible): array {
    $blurb = smpro_menu_blurbs();
    $out = [];
    foreach ($visible as $section => $items) {
        foreach ($items as $it) {
            $id = (string)$it['id'];
            $out[] = [
                'id'      => $id,
                'label'   => strip_tags((string)$it['label']),
                'section' => strip_tags((string)$section),
                'icon'    => (string)($it['icon'] ?? ''),
                'about'   => (string)($blurb[$id] ?? ''),
                // Aliases are what somebody actually types: the old name, the thing they call it, the job it does.
                'alias'   => implode(' ', array_map('strval', (array)($it['aliases'] ?? []))),
            ];
        }
    }
    return $out;
}

/**
 * One line per page saying what it is FOR — the answer to "which page do I want?".
 *
 * Written as the job, not the feature list: somebody searching is looking for a task they need done, and matching
 * on that is why typing "who deleted" finds User Investigation and "brute force" finds the audit.
 */
function smpro_menu_blurbs(): array {
    return [
        'dashboard'           => 'Everything at a glance: load, attacks, alerts, what changed today.',
        'reports-center'      => 'Every report in one place, plus a full lookup on any IP address.',
        'analytics-reports'   => 'Trends over time — traffic, attacks, resource use.',
        'intrusion-monitor'   => 'Live attacks, attacker IPs, blocking, and the emergency response.',
        'bot-guard'           => 'Crawlers and bots: which are genuine, which are pretending, what blocking one would cost.',
        'forensics-audit'     => 'After a break-in: what happened, when, and which files it touched.',
        'site-doctor'         => 'A site is down, slow or white-screening — diagnose and fix it.',
        'security-health'     => 'Is this server actually hardened? Scored, with the gaps listed.',
        'compromise-check'    => 'The doors a break-in leaves: FTP sub-accounts, forwarders, cron, keys, tokens - and whether the build is past the auth bypass.',
        'learned-defense'     => 'The server learns from every incident you confirm, hunts for the same thing everywhere, and shows processes a file scan cannot see.',
        'system-updates'      => 'Packages, cPanel and the kernel: what is pending, told to you when it appears, applied by itself or by your button - and a broken download diagnosed and repaired.',
        'server-tuning'       => 'Make the server faster: PHP, cache, database, web server.',
        'imunify360-reports'  => 'What Imunify360 found and cleaned.',
        'spam-phishing'       => 'Outbound spam, phishing pages, and which account is sending it.',
        'database-cleanup'    => 'Reclaim database space; find bloated and abandoned tables.',
        'account-audit'       => 'Per-account activity: logins, failed logins, break-in attempts, panel actions.',
        'firewall-status'     => 'Blocked and allowed addresses, country rules, and the firewall\'s real state.',
        'domain-checker'      => 'DNS, SSL, expiry and blacklists for a domain.',
        'php-harden'          => 'Lock an account\'s files so nothing can overwrite them, and restrict where it may be signed into.',
        'user-investigation'  => 'Everything one account did — and who deleted files or emails, from where and when.',
        'load-monitor'        => 'Server health: CPU, memory, disk, and what is eating them.',
        'top-processes'       => 'What is running right now, and which account owns it.',
        'resource-limits'     => 'Who hit a CloudLinux limit (508), and the way out.',
        'disk-storage'        => 'Where the disk went, and moving accounts between drives.',
        'network'             => 'Traffic, connections and bandwidth by account.',
        'backup-monitor'      => 'Are backups actually running, and can they be restored?',
        'restore-migrate'     => 'Restore an account, or move one in from another server.',
        'cpanel-services'     => 'Start, stop and repair the server\'s services.',
        'database-health'     => 'MySQL health, slow queries, crashed tables.',
        'benchmark'           => 'Measure this server and compare it against others.',
        'plugin-control'      => 'Turn parts of the plugin on and off; dry-run mode.',
        'multi-server'        => 'All your servers in one view.',
        'profiles'            => 'Protection presets you can apply to accounts in bulk.',
        'notifications'       => 'Where alerts go: email, Telegram, WhatsApp, push.',
        'whatsapp'            => 'Send alerts to WhatsApp.',
        'telegram-bot'        => 'Send alerts to Telegram, and control the server from a chat.',
        'ai-providers'        => 'Connect an AI provider so the panel can explain and advise.',
        'license'             => 'Your licence, plan and renewal.',
        'auto-reports'        => 'Scheduled reports, sent to you automatically.',
        'updates'             => 'Update the plugin and see what changed.',
        'legal'               => 'Terms and legal notices.',
    ];
}

/**
 * The search box, its results panel, and the behaviour that makes it usable with the keyboard alone.
 *
 * Everything is rendered and matched in the browser from an index that is already on the page, so a keystroke
 * costs nothing — no request, no spinner, and it works on a panel that is slow to reach. The index is small
 * (one line per page) and is the same list the sidebar draws, so the two cannot disagree.
 */
function smpro_menu_search_box(array $index): void {
    ?>
<div class="smx" id="smx">
  <div class="smx-inp">
    <span class="smx-ic">&#128269;</span>
    <input type="text" id="smxQ" autocomplete="off" spellcheck="false" placeholder="Search features…"
           aria-label="Search features" aria-expanded="false" aria-controls="smxList" role="combobox" aria-autocomplete="list">
    <kbd class="smx-kbd" id="smxKbd">/</kbd>
  </div>
  <div class="smx-res" id="smxList" role="listbox" hidden></div>
</div>
<style>
.smx{padding:10px 12px 4px;position:relative}
.smx-inp{display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:9px;padding:6px 9px}
.smx-inp:focus-within{border-color:rgba(120,160,255,.65);background:rgba(255,255,255,.09)}
.smx-ic{font-size:12px;opacity:.75;flex:none}
.smx input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:#e8eefc;font-size:13px;padding:2px 0}
.smx input::placeholder{color:#8fa0c0}
.smx-kbd{flex:none;font:600 10.5px ui-monospace,Menlo,Consolas,monospace;color:#8fa0c0;border:1px solid rgba(255,255,255,.18);border-radius:5px;padding:1px 5px}
.smx-res{position:absolute;left:12px;right:12px;top:calc(100% - 2px);z-index:60;max-height:min(62vh,460px);overflow:auto;
  background:#121a2c;border:1px solid rgba(255,255,255,.14);border-radius:10px;box-shadow:0 16px 40px rgba(0,0,0,.5);padding:5px}
.smx-item{display:block;padding:7px 9px;border-radius:7px;text-decoration:none;color:#dfe8fa;cursor:pointer}
.smx-item:hover,.smx-item[aria-selected=true]{background:rgba(120,160,255,.16)}
.smx-t{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:700}
.smx-sec{margin-left:auto;font-size:10.5px;font-weight:600;color:#8fa0c0;white-space:nowrap}
.smx-a{font-size:11.5px;line-height:1.5;color:#9db0d0;margin-top:2px}
.smx-item mark{background:rgba(255,214,102,.30);color:inherit;border-radius:2px;padding:0 1px}
.smx-none{padding:10px;font-size:12.5px;color:#9db0d0}
html[dir=rtl] .smx-sec{margin-left:0;margin-right:auto}
</style>
<script>
(function(){
  var IDX = <?= json_encode($index, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>;
  var q = document.getElementById('smxQ'), box = document.getElementById('smxList');
  if (!q || !box) return;
  var cur = -1, shown = [];

  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}

  /* Highlight the part that matched, so the reason a result is there is visible rather than guessed at. */
  function mark(text, needle){
    var t = esc(text); if(!needle) return t;
    var i = t.toLowerCase().indexOf(needle.toLowerCase());
    if (i < 0) return t;
    return t.slice(0,i) + '<mark>' + t.slice(i, i+needle.length) + '</mark>' + t.slice(i+needle.length);
  }

  /* Rank: the name beats the alias beats the description, and a word-start beats a match in the middle.
     Somebody typing "fire" wants Firewall Status first, not a page whose description happens to say "fire". */
  function score(it, n){
    var L = it.label.toLowerCase(), A = (it.alias||'').toLowerCase(), B = (it.about||'').toLowerCase(), S = it.section.toLowerCase();
    if (L === n) return 0;
    if (L.indexOf(n) === 0) return 1;
    if ((' '+L).indexOf(' '+n) > -1) return 2;
    if (L.indexOf(n) > -1) return 3;
    if (A.indexOf(n) > -1) return 4;
    if ((' '+B).indexOf(' '+n) > -1) return 5;
    if (B.indexOf(n) > -1) return 6;
    if (S.indexOf(n) > -1) return 7;
    return -1;
  }

  function render(){
    var n = q.value.trim().toLowerCase();
    if (!n){ close(); return; }
    var hits = [];
    for (var i=0;i<IDX.length;i++){ var sc = score(IDX[i], n); if (sc >= 0) hits.push([sc, i, IDX[i]]); }
    hits.sort(function(a,b){ return a[0]-b[0] || a[2].label.localeCompare(b[2].label); });
    shown = hits.slice(0, 12).map(function(h){ return h[2]; });

    if (!shown.length){
      box.innerHTML = '<div class="smx-none">Nothing matches &ldquo;' + esc(q.value.trim()) + '&rdquo;.</div>';
      box.hidden = false; q.setAttribute('aria-expanded','true'); cur = -1; return;
    }
    box.innerHTML = shown.map(function(it, k){
      return '<a class="smx-item" role="option" id="smx-o'+k+'" aria-selected="'+(k===0?'true':'false')+'"'
           + ' href="index.cgi?page='+encodeURIComponent(it.id)+'">'
           + '<span class="smx-t">'+(it.icon||'')+' <span>'+mark(it.label,n)+'</span>'
           + '<span class="smx-sec">'+esc(it.section)+'</span></span>'
           + (it.about ? '<span class="smx-a">'+mark(it.about,n)+'</span>' : '')
           + '</a>';
    }).join('');
    box.hidden = false; q.setAttribute('aria-expanded','true');
    cur = 0; sync();
  }

  function sync(){
    var items = box.querySelectorAll('.smx-item');
    for (var i=0;i<items.length;i++) items[i].setAttribute('aria-selected', i===cur ? 'true':'false');
    if (cur >= 0 && items[cur]) { items[cur].scrollIntoView({block:'nearest'}); q.setAttribute('aria-activedescendant','smx-o'+cur); }
  }
  function close(){ box.hidden = true; box.innerHTML=''; cur=-1; shown=[]; q.setAttribute('aria-expanded','false'); q.removeAttribute('aria-activedescendant'); }
  function go(){ var items = box.querySelectorAll('.smx-item'); if (cur>=0 && items[cur]) window.location.href = items[cur].getAttribute('href'); }

  q.addEventListener('input', render);
  q.addEventListener('focus', function(){ if (q.value.trim()) render(); });
  q.addEventListener('keydown', function(e){
    if (e.key === 'ArrowDown'){ e.preventDefault(); if(!shown.length){render();return;} cur = (cur+1) % shown.length; sync(); }
    else if (e.key === 'ArrowUp'){ e.preventDefault(); if(!shown.length) return; cur = (cur-1+shown.length) % shown.length; sync(); }
    else if (e.key === 'Enter'){ if (cur>=0){ e.preventDefault(); go(); } }
    else if (e.key === 'Escape'){ if (!box.hidden){ e.preventDefault(); close(); } else { q.value=''; q.blur(); } }
  });
  document.addEventListener('click', function(e){ if (!e.target.closest || !e.target.closest('#smx')) close(); });

  /* "/" focuses the search from anywhere — but never while something is being typed into, which would swallow
     a slash somebody meant to put in a path. */
  document.addEventListener('keydown', function(e){
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target, tag = (t && t.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || (t && t.isContentEditable)) return;
    e.preventDefault(); q.focus(); q.select();
  });
})();
</script>
    <?php
}

function smpro_menu_render($activeId) {
    echo '<nav class="smpro-side" id="smproSide">';
    $brandPlan = function_exists('smpro_lic_state') ? trim((string)(smpro_lic_state()['plan'] ?? '')) : '';
    $brandPlanHtml = $brandPlan !== '' ? ' <em style="font-style:normal;font-weight:700;background:rgba(59,91,219,.18);color:#cfe0ff;padding:1px 7px;border-radius:7px;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em">' . smpro_h(ucfirst($brandPlan)) . '</em>' : '';
    $brandBy = defined('SMPRO_BRAND_COMPANY') && SMPRO_BRAND_COMPANY !== ''
             ? '<span class="smpro-brand-by">by ' . (function_exists('smpro_brand_link') ? smpro_brand_link() : smpro_h(SMPRO_BRAND_COMPANY)) . '</span>' : '';
    echo '<div class="smpro-brand">'
       . (function_exists('smpro_brand_logo') ? smpro_brand_logo(30) : '')
       . '<div class="smpro-brand-tx"><b>' . smpro_h(SMPRO_NAME) . '</b>'
       . '<span>v' . smpro_h(SMPRO_VERSION) . $brandPlanHtml . '</span>'
       . $brandBy
       . '</div></div>';
    $enforce = defined('SMPRO_LIC_ENFORCE') && SMPRO_LIC_ENFORCE && function_exists('smpro_lic_section_allowed');
    $new = function_exists('smpro_new_features') ? smpro_new_features() : [];   // NEW-badge registry (id => release tag)

    // Work out what this licence can actually see FIRST, so the search box below and the links underneath it are
    // built from one and the same list. Two passes over the same filter is how they would drift apart.
    $visible = [];
    foreach (smpro_menu() as $section => $items) {
        $keep = [];
        foreach ($items as $it) {
            if ($enforce && $it['id'] !== 'license' && !smpro_lic_section_allowed($it['feature'] ?? '')) continue;
            $keep[] = $it;
        }
        if ($keep) $visible[$section] = $keep;
    }
    smpro_menu_search_box(smpro_menu_search_index($visible));

    foreach ($visible as $section => $items) {
        // Already filtered by the licence above — $items here is exactly what this plan may see.
        $vis = $items;
        $sid = substr(md5($section), 0, 8);
        $hasActive = false;
        foreach ($vis as $it) if ($it['id'] === $activeId) { $hasActive = true; break; }
        echo '<div class="smpro-secwrap" data-sec="' . $sid . '"' . ($hasActive ? ' data-active="1"' : '') . '>';
        echo '<div class="smpro-sec" data-sectoggle="' . $sid . '" role="button" tabindex="0">'
           . '<span data-i18n>' . $section . '</span><span class="smpro-secchev" aria-hidden="true">&#9656;</span></div>';
        echo '<div class="smpro-secitems">';
        foreach ($vis as $it) {
            $cls = $it['id'] === $activeId ? ' active' : '';
            $soon = $it['built'] ? '' : '<em class="soon">soon</em>';
            $nb = isset($new[$it['id']]) ? '<em class="smpro-newbadge" data-nk="' . smpro_h($it['id'] . '|' . $new[$it['id']]) . '">NEW</em>' : '';
            echo '<a class="smpro-link' . $cls . '" href="index.cgi?page=' . smpro_h($it['id']) . '">'
               . '<i>' . $it['icon'] . '</i><span data-i18n>' . smpro_h($it['label']) . '</span>' . $soon . $nb . '</a>';
        }
        echo '</div></div>';
    }
    echo '</nav>';
    smpro_menu_collapse_assets();
}

/** Collapse CSS + JS for the sidebar sections (emitted once). State persists in localStorage;
 *  the section containing the current page is never auto-collapsed. */
function smpro_menu_collapse_assets() {
    static $done = false; if ($done) return; $done = true;
    ?>
<style>
.smpro-sec{display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.smpro-sec:hover{color:#aab7d8}
.smpro-secchev{margin-left:auto;font-size:9px;opacity:.6;transition:transform .15s ease;transform:rotate(90deg)}
.smpro-secwrap.col .smpro-secchev{transform:rotate(0deg)}
.smpro-secwrap.col .smpro-secitems{display:none}
.smpro-newbadge{margin-left:auto;font-size:8.5px;font-weight:800;letter-spacing:.05em;color:#fff;background:#e8590c;border-radius:6px;padding:1px 5px;line-height:1.5;flex:none}
.smpro-link.active .smpro-newbadge{background:#fff;color:#e8590c}
.smpro-newnote{display:flex;gap:12px;align-items:flex-start;margin:0 0 16px;padding:13px 15px;border-radius:12px;background:linear-gradient(90deg,#fff7ed,#fffbeb);border:1px solid #fed7aa;border-left:4px solid #e8590c;box-shadow:0 4px 14px rgba(232,89,12,.09)}
.smpro-newnote .nn-ic{font-size:20px;line-height:1.15;flex:none}
.smpro-newnote .nn-tx{flex:1;min-width:0;font-size:13px;line-height:1.55;color:#7c2d12}
.smpro-newnote .nn-tx b{display:block;font-size:14px;color:#9a3412;margin-bottom:2px}
.smpro-newnote .nn-x{border:none;background:transparent;color:#c2410c;font-size:20px;line-height:1;cursor:pointer;padding:0 2px;flex:none;opacity:.65}
.smpro-newnote .nn-x:hover{opacity:1}
html[data-theme=dark] .smpro-newnote{background:#2a1a0e;border-color:#7c3a12;box-shadow:none}
html[data-theme=dark] .smpro-newnote .nn-tx{color:#fdba74}html[data-theme=dark] .smpro-newnote .nn-tx b{color:#fdba74}
</style>
<script>
(function(){
  var KEY='smpro_seccol_v1';
  function load(){try{return JSON.parse(localStorage.getItem(KEY))||{};}catch(e){return {};}}
  function save(o){try{localStorage.setItem(KEY,JSON.stringify(o));}catch(e){}}
  var state=load();
  document.querySelectorAll('.smpro-secwrap').forEach(function(w){
    var id=w.getAttribute('data-sec');
    if(state[id]==='1' && w.getAttribute('data-active')!=='1') w.classList.add('col');  // keep active section open
  });
  function toggle(h){var w=h.closest('.smpro-secwrap');if(!w)return;var id=w.getAttribute('data-sec');
    var col=w.classList.toggle('col');state[id]=col?'1':'0';save(state);}
  document.addEventListener('click',function(e){var h=e.target.closest('.smpro-sec[data-sectoggle]');if(h)toggle(h);});
  document.addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('smpro-sec')){e.preventDefault();toggle(e.target);}});
  // "NEW" nav badge — shown once per update: hide any (section|release) the admin has already opened.
  (function(){
    var NK='smpro_new_seen_v1', seen; try{seen=JSON.parse(localStorage.getItem(NK))||{};}catch(e){seen={};}
    function save(){try{localStorage.setItem(NK,JSON.stringify(seen));}catch(e){}}
    // one-time colored "what's new" callout for the CURRENT section — shown the first time it's opened (shares the
    // badge's seen-state), then remembered. Runs BEFORE the active-badge is marked seen below, so its key is fresh.
    var nn=document.getElementById('smproNewNote');
    if(nn){ var nk=nn.getAttribute('data-nk');
      if(nk && !seen[nk]){ nn.style.display=''; seen[nk]=1; save(); }
      var nx=document.getElementById('smproNewNoteX'); if(nx)nx.addEventListener('click',function(){ nn.style.display='none'; });
    }
    document.querySelectorAll('.smpro-newbadge').forEach(function(b){ if(seen[b.getAttribute('data-nk')]) b.style.display='none'; });
    var act=document.querySelector('.smpro-link.active .smpro-newbadge');   // viewing the section counts as seen
    if(act){ seen[act.getAttribute('data-nk')]=1; save(); act.style.display='none'; }
    document.querySelectorAll('.smpro-link').forEach(function(a){
      var b=a.querySelector('.smpro-newbadge'); if(!b)return;
      a.addEventListener('click',function(){ var k=b.getAttribute('data-nk'); if(k){seen[k]=1;save();} });
    });
  })();
})();
</script>
<?php
}
