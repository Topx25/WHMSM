<?php
/**
 * plans_ext.php — MULTI-PRODUCT pricing plans + license creation from a plan.
 * Products: Safety Monitor Pro (safety_monitor) and MailShield OSM (mailshield).
 * Each plan belongs to a product and carries price + cycle + max_servers + a feature
 * set (codes from that product's catalog) + a "most popular" flag. The Plans page
 * shows per-product tabs, clear pricing cards, a feature comparison, and edit forms.
 * Reuses panel helpers: db() (mysqli), h(), csrf_token(), require_admin(), require_csrf(), redirect(), layout_start/end().
 */
if (!function_exists('db')) return;

/** Known products (code => display name). */
function splan_products(): array {
    return ['safety_monitor' => 'Safety Monitor Pro', 'mailshield' => 'MailShield OSM'];
}

/** Safety Monitor feature catalog (code => label). */
function splan_catalog_sm(): array {
    if (function_exists('pext_section_catalog')) return pext_section_catalog();
    return ['dashboard'=>'Dashboard','service_health'=>'Server Health','load_monitor'=>'Load Monitor','top_processes'=>'Top Processes',
        'firewall_status'=>'Firewall Status','login_monitor'=>'Account Audit','disk_monitor'=>'Disk / Storage','suspicious_files'=>'Forensics / Audit',
        'htaccess_watcher'=>'PHP Harden','email_queue_monitor'=>'Spam & Phishing','web_attack_monitor'=>'Imunify360 Reports','telegram_alerts'=>'Notifications / WhatsApp',
        'analytics_reports'=>'Analytics Reports','security_health'=>'Security Health','database_cleanup'=>'DB Cleanup','network_traffic'=>'Network Traffic',
        'hardware_platform'=>'Hardware & Platform','cpanel_services'=>'cPanel Services','backup_monitor'=>'Backup Monitor','ai_providers'=>'AI Providers',
        'site_doctor'=>'Site Doctor','multi_server'=>'Multi-Server Management'];
}

/** MailShield feature catalog (code => label). */
function splan_catalog_ms(): array {
    return ['dashboard'=>'Dashboard','incoming'=>'Incoming Spam','outgoing'=>'Outgoing Spam','campaigns'=>'Campaigns',
        'queue'=>'Mail Queue','reports'=>'osm Reports','account_status'=>'Account Status','event_config'=>'Event Configuration',
        'load_monitor'=>'Load Monitor','enforcement'=>'Enforcement (hold/suspend/firewall)','per_user_limits'=>'Per-user Limits',
        'multi_server'=>'Multi-Server Management'];
}

function splan_catalog(string $product = 'safety_monitor'): array {
    return $product === 'mailshield' ? splan_catalog_ms() : splan_catalog_sm();
}

/** Active product from the request, defaulting to safety_monitor. */
function splan_cur_product(): string {
    $p = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_GET['product'] ?? $_POST['product'] ?? 'safety_monitor')));
    return array_key_exists($p, splan_products()) ? $p : 'safety_monitor';
}

function splan_migrate(): void {
    // Runs ONCE (flag-guarded) — never ALTERs on every request.
    $flag = __DIR__ . '/../storage/.plans_mp2';
    if (is_file($flag)) return;
    try {
        @db()->query("ALTER TABLE licenses MODIFY plan VARCHAR(40) NOT NULL DEFAULT 'pro'");
        db()->query("CREATE TABLE IF NOT EXISTS plans (
            id INT AUTO_INCREMENT PRIMARY KEY, code VARCHAR(40) NOT NULL, name VARCHAR(80) NOT NULL,
            tier INT NOT NULL DEFAULT 0, price DECIMAL(10,2) NOT NULL DEFAULT 0, currency VARCHAR(8) NOT NULL DEFAULT 'USD',
            cycle ENUM('trial','monthly','yearly','once') NOT NULL DEFAULT 'monthly', trial_days INT NOT NULL DEFAULT 0,
            max_servers INT NOT NULL DEFAULT 1, features JSON NULL, active TINYINT NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Multi-product columns (idempotent — ignore "duplicate column" errors)
        @db()->query("ALTER TABLE plans ADD COLUMN product VARCHAR(40) NOT NULL DEFAULT 'safety_monitor'");
        @db()->query("ALTER TABLE plans ADD COLUMN most_popular TINYINT NOT NULL DEFAULT 0");
        // Drop any single-column UNIQUE on `code` (so both products can reuse free_trial/basic/pro/ultra)
        if ($ix = @db()->query("SHOW INDEX FROM plans WHERE Column_name='code'")) {
            while ($row = $ix->fetch_assoc()) {
                if ((int)$row['Non_unique'] === 0 && $row['Key_name'] !== 'uq_product_code' && $row['Key_name'] !== 'PRIMARY') {
                    @db()->query("ALTER TABLE plans DROP INDEX `" . $row['Key_name'] . "`");
                }
            }
        }
        @db()->query("ALTER TABLE plans ADD UNIQUE KEY uq_product_code (product, code)");
        // Existing rows defaulted to product='safety_monitor' via the column default.
        $cnt = 0; if ($r = db()->query("SELECT COUNT(*) c FROM plans WHERE product='safety_monitor'")) $cnt = (int)($r->fetch_assoc()['c'] ?? 0);
        if ($cnt === 0) splan_seed('safety_monitor');
        $cnt = 0; if ($r = db()->query("SELECT COUNT(*) c FROM plans WHERE product='mailshield'")) $cnt = (int)($r->fetch_assoc()['c'] ?? 0);
        if ($cnt === 0) splan_seed('mailshield');
        @file_put_contents($flag, date('c'));
    } catch (\Throwable $e) { /* retry next request */ }
}

/** Seed the four default tiers for a product. */
function splan_seed(string $product): void {
    if ($product === 'mailshield') {
        $core  = ['dashboard','incoming','outgoing','queue','reports'];
        $basic = array_merge($core, ['campaigns','account_status','event_config','load_monitor']);
        $pro   = array_merge($basic, ['enforcement','per_user_limits']);
        $ultra = array_keys(splan_catalog_ms());
    } else {
        $coreSm = ['dashboard','service_health','load_monitor','top_processes','firewall_status','login_monitor'];
        $basic  = array_merge($coreSm, ['disk_monitor','network_traffic','cpanel_services','backup_monitor','hardware_platform','analytics_reports','security_health']);
        $pro    = array_merge($basic, ['suspicious_files','web_attack_monitor','email_queue_monitor','htaccess_watcher','database_cleanup','site_doctor','ai_providers','telegram_alerts']);
        $ultra  = array_keys(splan_catalog_sm());
        $core   = $coreSm;
    }
    // [code, name, tier, price, cycle, trial_days, max_servers, features, most_popular]
    $seed = [
        ['free_trial','Free Trial',0,0.00,'trial',14,1,$core,0],
        ['basic','Basic',1,9.00,'monthly',0,1,$basic,0],
        ['pro','Pro',2,19.00,'monthly',0,3,$pro,1],
        ['ultra','Ultra',3,39.00,'monthly',0,10,$ultra,0],
    ];
    foreach ($seed as $p) {
        $st = db()->prepare("INSERT INTO plans (product,code,name,tier,price,currency,cycle,trial_days,max_servers,features,most_popular)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)");
        $fj = json_encode(array_values($p[7])); $cur = 'USD';
        $st->bind_param('sssidssiisi', $product, $p[0], $p[1], $p[2], $p[3], $cur, $p[4], $p[5], $p[6], $fj, $p[8]);
        $st->execute();
    }
}

/** Plan-aware serial prefix per product+plan. */
function splan_keygen(string $product, string $plan): string {
    $base = $product === 'mailshield' ? 'MS' : 'SM';
    $suffix = ['free_trial'=>'TRIAL','trial'=>'TRIAL','basic'=>'BS','pro'=>'PRO','ultra'=>'UA'][$plan] ?? '';
    $pfx = $suffix ? ($base . '-' . $suffix) : $base;
    $r = []; for ($i = 0; $i < 3; $i++) $r[] = strtoupper(bin2hex(random_bytes(2)));
    return $pfx . '-' . date('Y') . '-' . implode('-', $r);
}

function splan_all(string $product = ''): array {
    $out = [];
    if ($product !== '') {
        $st = db()->prepare("SELECT * FROM plans WHERE product=? ORDER BY tier ASC");
        $st->bind_param('s', $product); $st->execute();
        $r = $st->get_result();
    } else {
        $r = @db()->query("SELECT * FROM plans ORDER BY product, tier ASC");
    }
    if ($r) while ($p = $r->fetch_assoc()) { $p['features'] = json_decode((string)$p['features'], true) ?: []; $out[] = $p; }
    return $out;
}

function splan_route(string $path): bool {
    $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($path === '/plans' && $m === 'GET')          { splan_page(); return true; }
    if ($path === '/plans/save' && $m === 'POST')    { splan_save(); return true; }
    if ($path === '/plans/delete' && $m === 'POST')  { splan_delete(); return true; }
    if ($path === '/licenses/new' && $m === 'GET')   { splan_new_form(); return true; }
    if ($path === '/licenses/new' && $m === 'POST')  { splan_new_save(); return true; }
    return false;
}

function splan_save(): void {
    require_admin(); require_csrf();
    $product = splan_cur_product();
    $code = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['code'] ?? '')));
    if ($code === '') redirect('/plans?product=' . $product);
    $name = trim((string)($_POST['name'] ?? $code)); $price = (float)($_POST['price'] ?? 0);
    $cur = substr(trim((string)($_POST['currency'] ?? 'USD')), 0, 8);
    $cycle = in_array($_POST['cycle'] ?? 'monthly', ['trial','monthly','yearly','once'], true) ? $_POST['cycle'] : 'monthly';
    $trial = max(0, (int)($_POST['trial_days'] ?? 0)); $maxs = max(1, (int)($_POST['max_servers'] ?? 1)); $tier = (int)($_POST['tier'] ?? 0);
    $pop = !empty($_POST['most_popular']) ? 1 : 0; $active = isset($_POST['active']) ? (int)!!$_POST['active'] : 1;
    $feats = array_values(array_intersect(array_map('strval', (array)($_POST['features'] ?? [])), array_keys(splan_catalog($product))));
    $fj = json_encode($feats);
    $st = db()->prepare("INSERT INTO plans (product,code,name,tier,price,currency,cycle,trial_days,max_servers,features,most_popular,active)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE name=VALUES(name),tier=VALUES(tier),price=VALUES(price),currency=VALUES(currency),cycle=VALUES(cycle),
        trial_days=VALUES(trial_days),max_servers=VALUES(max_servers),features=VALUES(features),most_popular=VALUES(most_popular),active=VALUES(active)");
    $st->bind_param('sssidssiisii', $product, $code, $name, $tier, $price, $cur, $cycle, $trial, $maxs, $fj, $pop, $active);
    $st->execute();
    // PROPAGATE (mandatory): push the edited feature set to every license on this product+plan, so each
    // customer's plugin shows/hides exactly these features after its next sync from the license server.
    if ($up = db()->prepare("UPDATE licenses SET features=?, updated_at=NOW() WHERE product_code=? AND plan=?")) {
        $up->bind_param('sss', $fj, $product, $code); $up->execute();
        $n = db()->affected_rows;
        if (function_exists('log_event')) log_event(null, 'plan_features_propagate', 'ok', $product . '/' . $code . ' → ' . (int)$n . ' license(s): ' . $fj, []);
    }
    redirect('/plans?product=' . $product);
}

function splan_delete(): void {
    require_admin(); require_csrf();
    $product = splan_cur_product();
    $code = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['code'] ?? '')));
    if ($code !== '') { $st = db()->prepare("DELETE FROM plans WHERE product=? AND code=?"); $st->bind_param('ss', $product, $code); $st->execute(); }
    redirect('/plans?product=' . $product);
}

function splan_money($p): string {
    return $p['price'] > 0 ? h($p['currency']) . ' ' . rtrim(rtrim(number_format($p['price'], 2), '0'), '.') : 'Free';
}

/** Short, human feature preview for a pricing card (the full tick/cross grid lives in the matrix). */
function splan_feat_preview(array $p, array $cat): string {
    $codes = (array)$p['features'];
    if (!$codes) return 'Core monitoring only';
    if (count($codes) >= count($cat)) return 'Every feature included';
    $labels = [];
    foreach ($cat as $fcode => $flabel) if (in_array($fcode, $codes, true)) $labels[] = $flabel;
    $shown = array_slice($labels, 0, 3);
    $more = count($labels) - count($shown);
    return implode(', ', $shown) . ($more > 0 ? ' +' . $more . ' more' : '');
}

function splan_page(): void {
    require_admin(); layout_start('Plans');
    $product = splan_cur_product();
    $products = splan_products();
    $plans = splan_all($product);
    $cat = splan_catalog($product);
    $pname = $products[$product];

    echo '<section class="hero"><div><h1>Pricing Plans</h1><p>Manage the tiers a customer can be licensed on — price, billing, server limit, and the exact features each plan unlocks.</p></div><a class="btn" href="/licenses/new?product=' . h($product) . '">&#10133; Create license</a></section>';

    // product tabs
    echo '<div class="ptabs">';
    foreach ($products as $code => $label) {
        $on = $code === $product ? ' ptab-on' : '';
        $n = count(splan_all($code));
        echo '<a class="ptab' . $on . '" href="/plans?product=' . h($code) . '">' . h($label) . ' <span class="ptab-n">' . $n . '</span></a>';
    }
    echo '</div>';

    // ===== pricing cards (clean summary — chips + a one-line feature preview; the full tick/cross grid is the matrix below) =====
    echo '<div class="plan-cards">';
    foreach ($plans as $p) {
        $pop = !empty($p['most_popular']);
        $inactive = isset($p['active']) && !$p['active'];
        $fc = count((array)$p['features']);
        $allf = $fc >= count($cat);
        echo '<div class="plan-card' . ($pop ? ' plan-pop' : '') . ($inactive ? ' plan-soon' : '') . '">';
        echo '<div class="plan-top">' . ($pop ? '<span class="plan-pop-tag">&#9733; Most popular</span>' : '') . ($inactive ? '<span class="plan-soon-tag">Coming soon</span>' : '') . '</div>';
        echo '<div class="plan-name">' . h($p['name']) . '</div>';
        echo '<div class="plan-price">' . splan_money($p) . '<span class="plan-cyc">/' . h($p['cycle']) . '</span></div>';
        echo '<div class="plan-meta">'
           . '<span class="chip">' . (int)$p['max_servers'] . ' server' . ($p['max_servers'] > 1 ? 's' : '') . '</span>'
           . ($p['trial_days'] ? '<span class="chip">' . (int)$p['trial_days'] . '-day trial</span>' : '')
           . '<span class="chip' . ($allf ? ' chip-pri' : '') . '">' . ($allf ? 'All features' : $fc . ' feature' . ($fc === 1 ? '' : 's')) . '</span>'
           . '</div>';
        echo '<div class="plan-desc">' . h(splan_feat_preview($p, $cat)) . '</div>';
        echo '<div class="plan-cta">';
        if ($inactive) {
            echo '<a class="btn btn-ghost" href="#pf_' . h($p['code']) . '">&#9998; Edit / publish</a>';
        } else {
            echo '<a class="btn' . ($pop ? '' : ' btn-light') . '" href="/licenses/new?product=' . h($product) . '&plan=' . h($p['code']) . '">Create license</a>'
               . '<a class="btn btn-ghost" href="#pf_' . h($p['code']) . '">&#9998; Edit</a>';
        }
        echo '</div>';
        echo '</div>';
    }
    if (!$plans) echo '<div class="card">No plans yet for ' . h($pname) . ' — add one below.</div>';
    echo '</div>';

    // ===== comparison matrix (collapsible — available but not dominating the page) =====
    if ($plans) {
        echo '<details class="cmp-wrap"><summary>&#128202; Compare all ' . h($pname) . ' plans side-by-side</summary>';
        echo '<div class="card cmp-card"><div style="overflow-x:auto"><table class="cmp"><thead><tr><th>Feature</th>';
        foreach ($plans as $p) echo '<th>' . h($p['name']) . '</th>';
        echo '</tr></thead><tbody>';
        echo '<tr class="cmp-hl"><td>Price</td>'; foreach ($plans as $p) echo '<td>' . splan_money($p) . '<span class="cyc">/' . h($p['cycle']) . '</span></td>'; echo '</tr>';
        echo '<tr><td>Max servers</td>'; foreach ($plans as $p) echo '<td>' . (int)$p['max_servers'] . '</td>'; echo '</tr>';
        echo '<tr><td>Trial</td>'; foreach ($plans as $p) echo '<td>' . ($p['trial_days'] ? (int)$p['trial_days'] . ' days' : '&mdash;') . '</td>'; echo '</tr>';
        foreach ($cat as $fcode => $flabel) {
            echo '<tr><td>' . h($flabel) . '</td>';
            foreach ($plans as $p) { $has = in_array($fcode, (array)$p['features'], true); echo '<td>' . ($has ? '<span class="tick"></span>' : '<span class="cross-d">&mdash;</span>') . '</td>'; }
            echo '</tr>';
        }
        echo '</tbody></table></div></div></details>';
    }

    // ===== manage plans (each plan opens its own editor on click — no more wall of forms) =====
    echo '<div class="card mng"><h2>Manage ' . h($pname) . ' plans</h2><p class="muted">Click a plan to edit it, or add a new one. Editing a plan\'s features propagates to every license already on that plan.</p>';
    foreach ($plans as $p) {
        echo '<details class="pedit" id="pf_' . h($p['code']) . '"><summary>'
           . '<span class="pe-name">' . h($p['name']) . '</span>'
           . '<span class="pe-tag">' . h($p['code']) . '</span>'
           . '<span class="pe-price">' . splan_money($p) . '/' . h($p['cycle']) . '</span>'
           . (!empty($p['most_popular']) ? '<span class="pe-pop">&#9733; popular</span>' : '')
           . ((isset($p['active']) && !$p['active']) ? '<span class="pe-off">hidden</span>' : '')
           . '<span class="pe-srv">' . (int)$p['max_servers'] . ' srv &middot; ' . count((array)$p['features']) . ' features</span>'
           . '<span class="pe-edit">&#9998; Edit</span></summary>';
        splan_edit_form($product, $p, $cat, false);
        echo '</details>';
    }
    $blank = ['code'=>'','name'=>'','tier'=>count($plans),'price'=>0,'currency'=>'USD','cycle'=>'monthly','trial_days'=>0,'max_servers'=>1,'features'=>[],'most_popular'=>0,'active'=>1];
    echo '<details class="pedit pnew"' . (!$plans ? ' open' : '') . ' id="newplan"><summary><span class="pe-name">&#10133; Add a new plan</span></summary>';
    splan_edit_form($product, $blank, $cat, true);
    echo '</details>';
    echo '</div>';

    echo '<style>'
       . '.ptabs{display:flex;gap:6px;margin-bottom:18px;border-bottom:1px solid #e6eaf1}'
       . '.ptab{padding:10px 18px;font-size:14px;font-weight:700;color:#6b7686;border-bottom:3px solid transparent;display:flex;align-items:center;gap:7px}'
       . '.ptab:hover{color:#3b5bdb}.ptab-on{color:#3b5bdb;border-bottom-color:#3b5bdb}'
       . '.ptab-n{background:#eef2ff;color:#3b5bdb;border-radius:999px;font-size:11px;padding:1px 8px;font-weight:800}'
       . '.plan-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-bottom:18px}'
       . '.plan-card{position:relative;background:#fff;border:1px solid #e6eaf1;border-radius:16px;padding:20px;display:flex;flex-direction:column;box-shadow:0 1px 2px rgba(16,24,51,.04)}'
       . '.plan-pop{border:2px solid #3b5bdb;box-shadow:0 8px 24px rgba(59,91,219,.12)}.plan-off{opacity:.6}'
       . '.plan-soon{border:1px dashed #c7b3e6;opacity:.94}.plan-soon .plan-price{color:#94a3b8}'
       . '.plan-soon-tag{background:#f1ecfe;color:#7c5cff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px}'
       . '.plan-top{min-height:22px;display:flex;gap:6px}'
       . '.plan-pop-tag{background:#3b5bdb;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px}'
       . '.plan-hid{background:#fee2e2;color:#b91c1c;font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px}'
       . '.plan-name{font-size:16px;font-weight:800;color:#0f1b33;margin-top:6px}'
       . '.plan-price{font-size:30px;font-weight:800;color:#0f1b33;margin:4px 0}.plan-cyc{font-size:14px;color:#6b7686;font-weight:600}'
       . '.plan-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px}'
       . '.chip{background:#f1f5f9;color:#475569;font-size:11.5px;font-weight:600;padding:3px 9px;border-radius:999px}'
       . '.chip-pri{background:#eef2ff;color:#3b5bdb}'
       . '.plan-desc{font-size:12.5px;color:#475569;line-height:1.6;flex:1;border-top:1px solid #f1f5f9;padding-top:12px;margin-top:12px}'
       . '.plan-feats{display:flex;flex-direction:column;gap:6px;font-size:12.5px;flex:1;border-top:1px solid #f1f5f9;padding-top:12px}'
       . '.pf{color:#1f2733;display:flex;align-items:center}.pf-off{color:#b6bdc9}'
       . '.tick,.cross{display:inline-block;width:16px;margin-right:8px;font-weight:800}'
       . '.tick::before{content:"\\2713";color:#16a34a}.cross::before{content:"\\2715";color:#cbd5e1}'
       . '.cross-d{color:#cbd5e1}'
       . '.plan-cta{display:flex;gap:8px;margin-top:16px}.plan-cta .btn{flex:1;text-align:center}'
       . '.btn-light{background:#eef2ff;color:#3b5bdb}.btn-ghost{background:transparent;border:1px solid #d6dcea;color:#475569}'
       // collapsible comparison
       . '.cmp-wrap{margin-bottom:18px}.cmp-wrap>summary{cursor:pointer;font-weight:700;font-size:14px;color:#3b5bdb;padding:12px 16px;background:#fff;border:1px solid #e6eaf1;border-radius:12px;list-style:none}'
       . '.cmp-wrap>summary::-webkit-details-marker{display:none}.cmp-wrap>summary:before{content:"\\25B8 ";color:#94a3b8}.cmp-wrap[open]>summary:before{content:"\\25BE "}'
       . '.cmp-card{margin-top:10px}.cmp{width:100%;border-collapse:collapse;font-size:13px}'
       . '.cmp th,.cmp td{padding:9px 12px;border-bottom:1px solid #eef1f6;text-align:center}'
       . '.cmp th:first-child,.cmp td:first-child{text-align:left;font-weight:600;color:#334155}'
       . '.cmp thead th{background:#f8fafc;font-weight:800;color:#0f1b33}.cmp tr.cmp-hl td{font-weight:800;color:#0f1b33}.cmp .cyc{font-size:11px;color:#94a3b8;font-weight:600}'
       . '.cmp .tick{width:auto;margin:0}'
       // manage section
       . '.mng h2{margin:0 0 4px}.muted{color:#6b7686;font-size:13px;margin:0 0 14px}'
       . '.pedit{border:1px solid #e6eaf1;border-radius:12px;margin-bottom:10px;overflow:hidden}'
       . '.pedit[open]{border-color:#3b5bdb;box-shadow:0 4px 14px rgba(59,91,219,.08)}'
       . '.pedit>summary{cursor:pointer;display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:13px 16px;list-style:none;background:#fff}'
       . '.pedit>summary::-webkit-details-marker{display:none}.pedit[open]>summary{background:#f7f9ff;border-bottom:1px solid #eef1f6}'
       . '.pe-name{font-weight:800;color:#0f1b33;font-size:14px}.pe-tag{font-family:monospace;font-size:11px;background:#f1f5f9;color:#64748b;padding:2px 8px;border-radius:6px}'
       . '.pe-price{font-weight:700;color:#3b5bdb;font-size:13px}.pe-pop{font-size:11px;color:#b45309;background:#fef3c7;padding:2px 8px;border-radius:999px;font-weight:700}'
       . '.pe-off{font-size:11px;color:#b91c1c;background:#fee2e2;padding:2px 8px;border-radius:999px;font-weight:700}'
       . '.pe-srv{font-size:12px;color:#94a3b8;margin-left:auto}.pe-edit{font-size:12px;color:#3b5bdb;font-weight:700}'
       . '.pform{padding:16px}.pform-flags{display:flex;gap:20px;margin:12px 0}.flagchk{display:flex;align-items:center;gap:7px;font-weight:600;font-size:13px}.flagchk input{width:auto}'
       . '.pform-sub{font-weight:800;font-size:13px;color:#0f2657;margin:6px 0 8px}'
       . '.pform-feats{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px 18px}'
       . '.sw-row{display:flex;align-items:center;gap:10px;font-size:13px;cursor:pointer}.sw-row .sw-l{flex:1;color:#334155}'
       . '.sw2{position:relative;display:inline-block;width:42px;height:22px;flex:0 0 auto}.sw2 input{opacity:0;width:0;height:0;position:absolute;margin:0}'
       . '.sw2 .sl{position:absolute;inset:0;background:#cbd5e1;border-radius:999px;transition:.18s}'
       . '.sw2 .sl:before{content:"";position:absolute;height:16px;width:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.18s;box-shadow:0 1px 2px rgba(0,0,0,.25)}'
       . '.sw2 input:checked+.sl{background:#16a34a}.sw2 input:checked+.sl:before{transform:translateX(20px)}'
       . '.pform-act{margin-top:14px;display:flex;gap:8px}'
       . '</style>';
    // open + scroll to the editor when a card "Edit" link is clicked (<details> doesn\'t auto-open on hash)
    echo '<script>function smOpenHash(){var h=location.hash.slice(1);if(!h)return;var d=document.getElementById(h);if(d&&d.tagName==="DETAILS"){d.open=true;d.scrollIntoView({behavior:"smooth",block:"start"});}}window.addEventListener("hashchange",smOpenHash);smOpenHash();</script>';
    layout_end();
}

/** Shared add/edit plan form (used inside each collapsible editor on the Plans page). */
function splan_edit_form(string $product, array $p, array $cat, bool $isNew): void {
    echo '<form method="post" action="/plans/save?product=' . h($product) . '" class="pform">';
    echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '"><input type="hidden" name="product" value="' . h($product) . '">';
    echo '<div class="form-grid">';
    echo '<label>Code' . ($isNew ? '' : ' (locked)') . '<input name="code" value="' . h($p['code']) . '"' . ($isNew ? '' : ' readonly') . ' placeholder="e.g. agency"></label>';
    echo '<label>Name<input name="name" value="' . h($p['name']) . '" placeholder="Display name"></label>';
    echo '<label>Price<input name="price" type="number" step="0.01" value="' . h($p['price']) . '"></label>';
    echo '<label>Currency<input name="currency" value="' . h($p['currency']) . '"></label>';
    echo '<label>Billing cycle<select name="cycle">'; foreach (['trial','monthly','yearly','once'] as $c) echo '<option' . ($p['cycle'] === $c ? ' selected' : '') . '>' . $c . '</option>'; echo '</select></label>';
    echo '<label>Trial days<input name="trial_days" type="number" value="' . (int)$p['trial_days'] . '"></label>';
    echo '<label>Max servers<input name="max_servers" type="number" min="1" value="' . (int)$p['max_servers'] . '"></label>';
    echo '<label>Sort order (tier)<input name="tier" type="number" value="' . (int)$p['tier'] . '"></label>';
    echo '</div>';
    echo '<div class="pform-flags"><label class="flagchk"><input type="checkbox" name="most_popular" value="1"' . (!empty($p['most_popular']) ? ' checked' : '') . '> &#9733; Most popular</label>'
       . '<label class="flagchk"><input type="checkbox" name="active" value="1"' . (!isset($p['active']) || $p['active'] ? ' checked' : '') . '> Active (visible to customers)</label></div>';
    echo '<div class="pform-sub">Features unlocked by this plan</div><div class="pform-feats">';
    foreach ($cat as $code => $label) {
        $on = in_array($code, (array)$p['features'], true) ? ' checked' : '';
        echo '<label class="sw-row"><span class="sw-l">' . h($label) . '</span><span class="sw2"><input type="checkbox" name="features[]" value="' . h($code) . '"' . $on . '><span class="sl"></span></span></label>';
    }
    echo '</div>';
    echo '<div class="pform-act"><button class="ok" type="submit">' . ($isNew ? '&#10133; Add plan' : '&#128190; Save changes') . '</button>';
    if (!$isNew) echo '<button class="danger" type="submit" formaction="/plans/delete?product=' . h($product) . '" onclick="return confirm(\'Delete plan ' . h($p['code']) . '? Licenses already created keep their features.\')">Delete</button>';
    echo '</div></form>';
}

function splan_new_form(): void {
    require_admin(); layout_start('Create License');
    $product = splan_cur_product();
    $products = splan_products();
    $plans = splan_all($product);
    $sel = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_GET['plan'] ?? '')));
    // feature CODE map for THIS product + a per-plan map (RAW codes) for the live preview & customize sync
    $catalog = splan_catalog($product);
    $planJs = [];
    foreach ($plans as $p) {
        $planJs[$p['code']] = ['name' => $p['name'], 'price' => (float)$p['price'], 'currency' => $p['currency'],
            'cycle' => $p['cycle'], 'max_servers' => (int)$p['max_servers'], 'trial_days' => (int)$p['trial_days'],
            'features' => array_values((array)$p['features'])];
    }
    if ($sel === '' && $plans) $sel = $plans[0]['code'];   // default the preview to the first plan
    echo '<section class="hero"><div><h1>Create License</h1><p>Pick a plan — its features, servers &amp; duration apply automatically. The summary on the right updates live; tick <b>Customize</b> to override them for this one license.</p></div></section>';
    echo '<form method="post" action="/licenses/new"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    echo '<div class="cl-grid"><div class="cl-main">';

    // --- Customer ---
    echo '<div class="card cl-sect"><div class="cl-h">Customer</div><div class="cl-fg">';
    echo '<label>Client name<input name="client_name" placeholder="Customer / company"></label>';
    echo '<label>Client email<input name="client_email" type="email" placeholder="client@example.com"></label>';
    echo '<label class="cl-wide">Phone / WhatsApp <span class="cl-opt">(optional — intl format, for WhatsApp delivery)</span><input name="client_phone" id="clPhone" placeholder="+201234567890" oninput="smDeliver()"></label>';
    echo '</div></div>';

    // --- Plan & licensing ---
    echo '<div class="card cl-sect"><div class="cl-h">Plan &amp; licensing</div><div class="cl-fg">';
    echo '<label>Product<select name="product" onchange="location.href=\'/licenses/new?product=\'+this.value">';
    foreach ($products as $code => $label) echo '<option value="' . h($code) . '"' . ($code === $product ? ' selected' : '') . '>' . h($label) . '</option>';
    echo '</select></label>';
    echo '<label>Plan<select name="plan" id="planSel" onchange="smPlanView()">'; foreach ($plans as $p) echo '<option value="' . h($p['code']) . '"' . ($p['code'] === $sel ? ' selected' : '') . '>' . h($p['name']) . ' — ' . ($p['price'] > 0 ? h($p['currency']) . ' ' . h((string)$p['price']) . '/' . h($p['cycle']) : 'Free') . '</option>'; echo '</select></label>';
    echo '<label class="cl-wide">Expiry <span class="cl-opt">(blank = auto from plan)</span><input name="expires_at" placeholder="YYYY-MM-DD"></label>';
    echo '</div>';
    // CUSTOMIZE: override this license\'s features + max-servers on top of the plan template
    echo '<label class="cust-tog"><input type="checkbox" name="customize" id="custTog" value="1" onchange="smCust()"> &#9881; Customize features &amp; servers for THIS license (overrides the plan)</label>';
    echo '<div id="custBox" class="cust-box" style="display:none">';
    echo '<label class="cust-ms">Max servers <input type="number" name="max_servers" id="custMs" min="1" value="1" disabled></label>';
    echo '<div class="cust-sub">Features for this license:</div><div class="cust-feats">';
    foreach ($catalog as $fcode => $flabel) echo '<label class="cust-f"><span class="fn">' . h($flabel) . '</span><span class="sw2"><input type="checkbox" name="features[]" value="' . h($fcode) . '" data-fc="' . h($fcode) . '" disabled onchange="smSwTxt(this)"><span class="sl"></span></span><span class="swtxt off">OFF</span></label>';
    echo '</div></div>';
    echo '</div>';

    // --- Delivery ---
    echo '<div class="card cl-sect"><div class="cl-h">Delivery</div>';
    echo '<label class="cl-chk"><input type="checkbox" name="notify_customer" id="notifyCust" value="1" checked onchange="smDeliver()"> &#9993;&#65039; Email / WhatsApp the license key + install command to the customer on creation</label>';
    echo '</div>';

    echo '</div>'; // .cl-main

    // --- RIGHT: live order summary (sticky) ---
    echo '<aside class="cl-side"><div class="card cl-summary"><div class="cl-h">Summary</div>';
    echo '<div id="planView" class="plan-view"></div>';
    echo '<div id="deliveryLine" class="cl-deliver"></div>';
    echo '<button class="ok cl-go" type="submit">&#128273; Generate license</button>';
    echo '<a class="cl-back" href="/plans?product=' . h($product) . '">Back to plans</a>';
    echo '</div></aside>';

    echo '</div></form>';
    echo '<style>'
       . '.cl-grid{display:grid;grid-template-columns:1.6fr 1fr;gap:16px;align-items:start}'
       . '.cl-main{display:flex;flex-direction:column;gap:14px}'
       . '.cl-sect{padding:18px 20px}'
       . '.cl-h{font-size:12px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;color:#94a3b8;margin-bottom:13px}'
       . '.cl-fg{display:grid;grid-template-columns:1fr 1fr;gap:13px 14px}'
       . '.cl-fg label{display:block;font-size:13.5px;font-weight:600;color:#334155}'
       . '.cl-fg .cl-wide{grid-column:1/-1}'
       . '.cl-fg input,.cl-fg select{display:block;width:100%;box-sizing:border-box;margin-top:6px;padding:10px 12px;border:1px solid #d6dcea;border-radius:9px;font-size:14.5px;background:#fff;color:#1f2733}'
       . '.cl-fg input:focus,.cl-fg select:focus{outline:none;border-color:#3b5bdb;box-shadow:0 0 0 3px rgba(59,91,219,.12)}'
       . '.cl-opt{color:#94a3b8;font-weight:400;font-size:12px}'
       . '.cl-chk{display:flex;align-items:flex-start;gap:9px;font-size:13.5px;color:#334155;cursor:pointer;line-height:1.45}.cl-chk input{width:auto;margin-top:2px}'
       . '.cl-side{position:sticky;top:16px}'
       . '.cl-summary{padding:20px;box-shadow:0 6px 18px rgba(16,24,51,.06)}'
       . '.cl-go{width:100%;margin-top:16px;font-size:14.5px;font-weight:700;padding:12px}'
       . '.cl-back{display:block;text-align:center;margin-top:9px;font-size:13px;color:#3b5bdb;text-decoration:none}'
       . '.cl-deliver{border-top:1px solid #f1f5f9;margin-top:14px;padding-top:12px;font-size:13px;color:#475569;line-height:1.5}.cl-deliver .ok{color:#16a34a;font-weight:800}.cl-deliver.off{color:#94a3b8}'
       // live preview lives inside the summary card → borderless, larger type
       . '.cl-summary .plan-view{margin:0;border:0;padding:0;background:transparent}'
       . '.plan-view .pv-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.plan-view .pv-head b{font-size:19px;color:#0f1b33}'
       . '.plan-view .pill{background:#3b5bdb;color:#fff;border-radius:999px;padding:3px 11px;font-size:13px;font-weight:700}'
       . '.plan-view .pv-meta{color:#64748b;font-size:13px;margin:7px 0 12px}'
       . '.plan-view .pv-sub{font-weight:800;font-size:11.5px;letter-spacing:.03em;text-transform:uppercase;color:#475569;border-top:1px solid #f1f5f9;padding-top:11px;margin-bottom:8px}'
       . '.plan-view ul.pv-feats{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:5px;max-height:260px;overflow:auto}'
       . '.plan-view ul.pv-feats li{font-size:13px;color:#1f2733}.plan-view ul.pv-feats li.muted{color:#94a3b8}'
       // customize panel
       . '.cust-tog{display:flex;align-items:center;gap:8px;margin-top:14px;font-size:14px;cursor:pointer}'
       . '.cust-box{margin-top:10px;border:1px dashed var(--line,#cbd5e1);border-radius:12px;padding:14px 16px}'
       . '.cust-box .cust-ms{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;margin-bottom:10px}.cust-box .cust-ms input{width:90px;padding:7px 10px;border:1px solid #d6dcea;border-radius:8px;font-size:14px}'
       . '.cust-sub{font-weight:700;font-size:13.5px;margin-bottom:8px;color:#334155}'
       . '.cust-feats{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px 16px}'
       . '.cust-f{display:flex;align-items:center;gap:10px;font-size:13.5px;cursor:pointer}.cust-f .fn{flex:1}'
       . '.sw2{position:relative;display:inline-block;width:42px;height:22px;flex:0 0 auto}'
       . '.sw2 input{opacity:0;width:0;height:0;position:absolute;margin:0}'
       . '.sw2 .sl{position:absolute;inset:0;background:#cbd5e1;border-radius:999px;transition:.18s}'
       . '.sw2 .sl:before{content:"";position:absolute;height:16px;width:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.18s;box-shadow:0 1px 2px rgba(0,0,0,.25)}'
       . '.sw2 input:checked+.sl{background:#16a34a}.sw2 input:checked+.sl:before{transform:translateX(20px)}'
       . '.sw2 input:disabled+.sl{opacity:.5}'
       . '.swtxt{font-size:11px;font-weight:700;width:26px;text-align:left}.swtxt.on{color:#16a34a}.swtxt.off{color:#94a3b8}'
       . '@media(max-width:960px){.cl-grid{grid-template-columns:1fr}.cl-side{position:static}}'
       . '</style>';
    echo '<script>var SM_PLANS=' . json_encode($planJs, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ';'
       . 'var SM_CATALOG=' . json_encode($catalog, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ';'
       . 'function smEsc(s){return String(s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}[c];});}'
       . 'function smCustOn(){var t=document.getElementById("custTog");return t&&t.checked;}'
       . 'function smSwTxt(cb){var l=cb.closest(".cust-f");if(!l)return;var t=l.querySelector(".swtxt");if(t){t.textContent=cb.checked?"ON":"OFF";t.className="swtxt "+(cb.checked?"on":"off");}}'
       . 'function smSync(){var sel=document.getElementById("planSel");if(!sel)return;var p=SM_PLANS[sel.value];if(!p)return;var set={};(p.features||[]).forEach(function(c){set[c]=1;});'
       . 'document.querySelectorAll("#custBox input[data-fc]").forEach(function(cb){cb.checked=!!set[cb.getAttribute("data-fc")];smSwTxt(cb);});var ms=document.getElementById("custMs");if(ms)ms.value=p.max_servers;}'
       . 'function smPlanView(){var sel=document.getElementById("planSel");if(!sel)return;var p=SM_PLANS[sel.value],b=document.getElementById("planView");if(!p||!b){if(b)b.innerHTML="";return;}'
       . 'var dur=p.trial_days>0?(p.trial_days+"-day trial"):(p.cycle==="yearly"?"1 year":(p.cycle==="monthly"?"1 month":"lifetime / no expiry"));'
       . 'var price=p.price>0?(smEsc(p.currency)+" "+p.price+"/"+smEsc(p.cycle)):"Free";'
       . 'var head="<div class=\\"pv-head\\"><b>"+smEsc(p.name)+"</b><span class=\\"pill\\">"+price+"</span></div>"+"<div class=\\"pv-meta\\">"+p.max_servers+" server(s) &middot; "+dur+" (when expiry is left blank)</div>";'
       . 'if(smCustOn()){b.innerHTML=head+"<div class=\\"pv-sub\\">Customizing below &#8595; (plan template pre-loaded)</div>";}'
       . 'else{var labels=(p.features||[]).map(function(c){return SM_CATALOG[c]||c;});var feats=labels.length?labels.map(function(f){return "<li>&#10003; "+smEsc(f)+"</li>";}).join(""):"<li class=\\"muted\\">core monitoring only</li>";'
       . 'b.innerHTML=head+"<div class=\\"pv-sub\\">Included features ("+labels.length+"):</div><ul class=\\"pv-feats\\">"+feats+"</ul>";}'
       . 'smSync();}'
       . 'function smCust(){var on=smCustOn();var box=document.getElementById("custBox");if(box){box.style.display=on?"":"none";box.querySelectorAll("input").forEach(function(i){i.disabled=!on;});}smPlanView();}'
       . 'function smDeliver(){var n=document.getElementById("notifyCust"),ph=document.getElementById("clPhone"),d=document.getElementById("deliveryLine");if(!d)return;if(n&&!n.checked){d.className="cl-deliver off";d.innerHTML="Customer will not be notified automatically.";return;}var wa=(ph&&ph.value.trim()!=="")?" &amp; WhatsApp":"";d.className="cl-deliver";d.innerHTML="<span class=\\"ok\\">\\u2713</span> Key + install command will be emailed"+wa+" on creation.";}'
       . 'smCust();smDeliver();</script>';
    layout_end();
}

function splan_new_save(): void {
    require_admin(); require_csrf();
    $product = splan_cur_product();
    $code = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['plan'] ?? '')));
    $plan = null; foreach (splan_all($product) as $p) if ($p['code'] === $code) { $plan = $p; break; }
    if (!$plan) redirect('/plans?product=' . $product);
    $key = splan_keygen($product, $code);
    $name = trim((string)($_POST['client_name'] ?? '')); $email = trim((string)($_POST['client_email'] ?? ''));
    $phone = trim((string)($_POST['client_phone'] ?? ''));
    $exp = trim((string)($_POST['expires_at'] ?? ''));
    if ($exp === '') { if ((int)$plan['trial_days'] > 0) $exp = date('Y-m-d H:i:s', time() + (int)$plan['trial_days'] * 86400); elseif ($plan['cycle'] === 'yearly') $exp = date('Y-m-d H:i:s', time() + 365 * 86400); elseif ($plan['cycle'] === 'monthly') $exp = date('Y-m-d H:i:s', time() + 31 * 86400); else $exp = null; }
    else $exp = date('Y-m-d H:i:s', strtotime($exp) ?: time());
    // CUSTOMIZE: when ticked, this license overrides the plan template with the admin-chosen features + max-servers
    // (features validated against THIS product's catalog so nothing outside it can be granted); else use the plan as-is.
    if (!empty($_POST['customize'])) {
        $feats = array_values(array_intersect(array_map('strval', (array)($_POST['features'] ?? [])), array_keys(splan_catalog($product))));
        $fj = json_encode($feats);
        $maxs = max(1, min(10000, (int)($_POST['max_servers'] ?? $plan['max_servers'])));
    } else {
        $fj = json_encode(array_values((array)$plan['features']));
        $maxs = (int)$plan['max_servers'];
    }
    $st = db()->prepare("INSERT INTO licenses (license_key,client_name,client_email,client_phone,status,plan,product_code,features,max_servers,expires_at) VALUES (?,?,?,?, 'new', ?, ?, ?, ?, ?)");
    if (!$st) { redirect('/plans?product=' . $product); }
    $st->bind_param('sssssssis', $key, $name, $email, $phone, $code, $product, $fj, $maxs, $exp);
    if (!$st->execute()) { if (function_exists('log_event')) log_event($key, 'create_from_plan', 'fail', db()->error, []); redirect('/licenses/new?product=' . $product . '&plan=' . $code); }
    $id = (int)db()->insert_id;
    if (function_exists('log_event')) log_event($key, 'create_from_plan', 'ok', $product . '/' . $code, []);
    // DELIVERY: email (+WhatsApp) the license key + install command to the customer (default-on checkbox).
    if (!empty($_POST['notify_customer']) && function_exists('smlic_deliver_license')) {
        $licRow = db()->query("SELECT * FROM licenses WHERE id=" . $id)->fetch_assoc();
        if (is_array($licRow)) { $sum = ''; smlic_deliver_license($licRow, $sum); }
    }
    redirect('/licenses/edit?id=' . $id);
}
