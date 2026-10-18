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
    return [
        'Reports' => [
            ['id' => 'dashboard',        'label' => 'Dashboard',          'icon' => '&#9632;', 'built' => true,  'feature' => 'dashboard', 'aliases' => []],
            ['id' => 'reports-center',   'label' => 'Reports Center',     'icon' => '&#128203;', 'built' => true,  'aliases' => ['reports-hub','ip-report','ip-lookup','all-reports']],
            ['id' => 'analytics-reports','label' => 'Analytics Reports',  'icon' => '&#9650;', 'built' => true,  'feature' => 'analytics_reports', 'aliases' => ['reports-analytics','report-dashboard','reports']],
        ],
        'Security &amp; Access' => [
            ['id' => 'intrusion-monitor',   'label' => 'Intrusion Monitor',   'icon' => '&#128680;', 'built' => true,  'feature' => 'web_attack_monitor', 'aliases' => ['intrusion','intrusion_monitor','attack-monitor','attack_monitor','attacks','ids','web-attacks','web_attacks']],
            ['id' => 'forensics-audit',     'label' => 'Forensics / Audit',  'icon' => '&#9670;', 'built' => true,  'feature' => 'suspicious_files', 'aliases' => ['forensics_audit','forensics']],
            ['id' => 'site-doctor',         'label' => 'Site Doctor',        'icon' => '&#129658;', 'built' => true,  'feature' => 'suspicious_files', 'aliases' => ['site_doctor','sitedoctor','site-rescue','diagnose','doctor']],
            ['id' => 'security-health',     'label' => 'Security Health',     'icon' => '&#10003;', 'built' => true,  'feature' => 'security_health', 'aliases' => ['security_checks','security-checks']],
            ['id' => 'server-tuning',       'label' => 'Server Tune-up',      'icon' => '&#128295;', 'built' => true,  'aliases' => ['tuning','perf','performance','optimize','hardening-tuning','server_tuning']],
            ['id' => 'imunify360-reports',  'label' => 'Imunify360 Reports',  'icon' => '&#9888;',  'built' => true,  'feature' => 'web_attack_monitor', 'aliases' => ['imunify-reports','imunify360']],
            ['id' => 'spam-phishing',       'label' => 'Spam & Phishing',     'icon' => '&#128231;','built' => true,  'feature' => 'email_queue_monitor', 'aliases' => ['spam_phishing','spam','phishing']],
            ['id' => 'database-cleanup',    'label' => 'DB Cleanup',          'icon' => '&#128190;','built' => true,  'feature' => 'database_cleanup', 'aliases' => ['db-cleanup','database_cleanup','db','sql-cleanup']],
            ['id' => 'account-audit',       'label' => 'Account Audit',       'icon' => '&#9679;',  'built' => true,  'feature' => 'login_monitor', 'aliases' => ['account_audit','login-monitor','login_monitor','login-correlation','login_correlation','password-reset-audit','password_reset_audit','login-access','login_access']],
            ['id' => 'firewall-status',     'label' => 'Firewall Status',     'icon' => '&#9873;',  'built' => true,  'feature' => 'firewall_status', 'aliases' => ['firewall_status']],
            ['id' => 'php-harden',          'label' => 'PHP Harden',          'icon' => '&#128274;','built' => true,  'feature' => 'htaccess_watcher', 'aliases' => ['php_harden','safety-lock','safety_lock','safety-lock-requests','hardening']],
        ],
        'Core Monitoring' => [
            ['id' => 'load-monitor',   'label' => 'Server Health & System', 'icon' => '&#128737;', 'built' => true, 'feature' => 'service_health', 'aliases' => ['load_monitor','load','server-health','server_health','health','hardware','hardware_details','hardware-details','platform','system-info','system-load','system_load','load-monitor']],
            ['id' => 'top-processes',  'label' => 'Top Processes',  'icon' => '&#9881;', 'built' => true,  'feature' => 'top_processes', 'aliases' => ['top_processes','processes']],
            ['id' => 'disk-storage',   'label' => 'Disk / Storage', 'icon' => '&#128202;', 'built' => true,  'feature' => 'disk_monitor', 'aliases' => ['disk_storage','disk','storage']],
            ['id' => 'network',        'label' => 'Network Traffic', 'icon' => '&#128225;', 'built' => true, 'feature' => 'network_traffic', 'aliases' => ['network-traffic','net','bandwidth','traffic']],
            ['id' => 'backup-monitor', 'label' => 'Backup Monitor', 'icon' => '&#128190;', 'built' => true,  'feature' => 'backup_monitor', 'aliases' => ['backup_monitor','jetbackup','backups']],
            ['id' => 'cpanel-services','label' => 'cPanel Services', 'icon' => '&#9881;', 'built' => true,  'feature' => 'cpanel_services', 'aliases' => ['cpanel_services','services']],
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
            ['id' => 'legal',               'label' => 'Terms &amp; Legal',   'icon' => '&#128220;','built' => true,  'aliases' => ['terms','terms-and-conditions','terms-conditions','privacy','privacy-policy','eula','refund','legal-terms']],
        ],
    ];
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
function smpro_menu_render($activeId) {
    echo '<nav class="smpro-side" id="smproSide">';
    $brandPlan = function_exists('smpro_lic_state') ? trim((string)(smpro_lic_state()['plan'] ?? '')) : '';
    $brandPlanHtml = $brandPlan !== '' ? ' <em style="font-style:normal;font-weight:700;background:rgba(59,91,219,.18);color:#cfe0ff;padding:1px 7px;border-radius:7px;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em">' . smpro_h(ucfirst($brandPlan)) . '</em>' : '';
    echo '<div class="smpro-brand"><b>' . smpro_h(SMPRO_NAME) . '</b><span>v' . smpro_h(SMPRO_VERSION) . $brandPlanHtml . '</span></div>';
    $enforce = defined('SMPRO_LIC_ENFORCE') && SMPRO_LIC_ENFORCE && function_exists('smpro_lic_section_allowed');
    foreach (smpro_menu() as $section => $items) {
        // HIDE any feature that is not in this server's license plan (each tier shows only its own functions).
        $vis = [];
        foreach ($items as $it) {
            if ($enforce && $it['id'] !== 'license' && !smpro_lic_section_allowed($it['feature'] ?? '')) continue;
            $vis[] = $it;
        }
        if (!$vis) continue;                                    // skip a section with nothing visible
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
            echo '<a class="smpro-link' . $cls . '" href="index.cgi?page=' . smpro_h($it['id']) . '">'
               . '<i>' . $it['icon'] . '</i><span data-i18n>' . smpro_h($it['label']) . '</span>' . $soon . '</a>';
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
})();
</script>
<?php
}
