<?php
/**
 * legal.php — Terms & Conditions + Privacy Policy (GDPR) + Refund/Withdrawal.
 *   - Shown as a one-time ACCEPTANCE gate the first time the plugin is opened.
 *   - Always available as the "Terms & Legal" page (last item under Settings).
 * Acceptance is recorded at SMPRO_VARLIB/legal_accepted.json {version, ts, actor, ip}.
 * Bump smpro_legal_version() whenever the text materially changes to re-prompt acceptance.
 *
 * NOTE: this is a practical, EU-aware template — not legal advice. The Provider should have
 * the company details below filled in and the final text reviewed by qualified counsel.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ----- editable company / product identity (change here only) ----- */
function smpro_legal_company() {
    return [
        'product' => defined('SMPRO_NAME') ? SMPRO_NAME : 'Safety Monitor Pro',
        'name'    => 'AiTech',                                   // TODO: registered legal entity name
        'address' => '',                                         // TODO: registered business address
        'contact' => 'support@iptvpro.org',                     // TODO: legal/privacy contact email
        'site'    => 'https://iptvpro.org',
        'law'     => 'the laws applicable at the Provider’s principal place of business',  // TODO: governing law (e.g. "England & Wales")
        'effective' => '2026-06-24',
    ];
}
/** Document version — change to re-trigger first-run acceptance for everyone. */
function smpro_legal_version() { return '2026-06-24'; }

/* ----- acceptance state ----- */
function smpro_legal_file()  { return SMPRO_VARLIB . '/legal_accepted.json'; }
function smpro_legal_state() { $f = smpro_legal_file(); return is_file($f) ? (json_decode((string)@file_get_contents($f), true) ?: []) : []; }
function smpro_legal_accepted() { $s = smpro_legal_state(); return !empty($s['version']) && (string)$s['version'] === smpro_legal_version(); }
function smpro_legal_accept() {
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $rec = ['version' => smpro_legal_version(), 'ts' => time(),
            'actor' => function_exists('smpro_current_actor') ? (string)smpro_current_actor() : 'root',
            'ip' => function_exists('smpro_current_remote_ip') ? (string)smpro_current_remote_ip() : (string)($_SERVER['REMOTE_ADDR'] ?? '')];
    $ok = (bool)@file_put_contents(smpro_legal_file(), json_encode($rec, JSON_UNESCAPED_SLASHES));
    @chmod(smpro_legal_file(), 0600);
    if (function_exists('smpro_audit')) smpro_audit('legal_accept', ['version' => $rec['version']]);
    return $ok;
}

/* ----- the document: array of [title, html-body] sections ----- */
function smpro_legal_sections() {
    $c = smpro_legal_company();
    $P = smpro_h($c['product']); $N = smpro_h($c['name']); $E = smpro_h($c['contact']); $S = smpro_h($c['site']); $L = smpro_h($c['law']);
    return [
        ['Agreement to terms',
         "<p>These Terms &amp; Conditions, together with the Privacy Policy and the Refund &amp; Right-of-Withdrawal Policy below (collectively, the “<b>Terms</b>”), are a binding agreement between you (the “<b>Customer</b>”, “you”) and {$N} (the “<b>Provider</b>”, “we”, “us”) governing your access to and use of the {$P} software and related services (the “<b>Software</b>”). By installing, activating, or using the Software you confirm that you have read, understood, and agree to be bound by the Terms. If you do not agree, do not install or use the Software. If you accept on behalf of an organisation, you confirm you are authorised to bind that organisation.</p>"],

        ['1. Definitions',
         "<ul><li><b>Software</b> — the {$P} plugin, its updates, and the licensing/telemetry services it connects to.</li>"
        . "<li><b>Licence</b> — the right to use the Software granted under these Terms for the plan you purchased.</li>"
        . "<li><b>Server</b> — a single physical or virtual machine on which the Software is installed and activated.</li>"
        . "<li><b>Consumer</b> — a natural person acting outside their trade, business, craft or profession.</li></ul>"],

        ['2. Licence grant &amp; scope',
         "<p>Subject to your compliance with the Terms and payment of applicable fees, the Provider grants you a non-exclusive, non-transferable, revocable licence to install and use one (1) instance of the Software on each licensed Server, for the features included in your plan, for the duration of your subscription or licence term. A licence is bound to the Server’s primary IP address and hardware fingerprint and may not be shared across Servers.</p>"],

        ['3. Restrictions',
         "<p>Except to the extent expressly permitted by these Terms or by mandatory applicable law, you must not: (a) copy, resell, sublicense, rent, lease, or distribute the Software, except as an authorised reseller under a separate written agreement; (b) remove, alter, or obscure any proprietary notices; (c) circumvent, disable, or interfere with the licensing, integrity, or security mechanisms; or (d) use the Software to develop a competing product. Nothing in this section limits any right you have under applicable law that cannot be excluded, including, where applicable, the right to decompile for interoperability under Directive 2009/24/EC.</p>"],

        ['3A. Licence security, anti-tamper &amp; automated enforcement',
         "<p>The Software contains licensing, cryptographic integrity, anti-tamper, anti-cloning, and anti-forgery mechanisms that protect the Provider’s rights and verify that each installation is genuine and validly licensed. You acknowledge and agree that:</p>"
        . "<ul>"
        . "<li><b>No tampering or circumvention.</b> You must not (and must not attempt to, or permit any third party to) modify, patch, hook, repackage, reverse-engineer, decompile, or disassemble the Software; tamper with or disable its licensing, integrity, update-signature, telemetry, or security mechanisms; or otherwise bypass, defeat, or interfere with licence validation or enforcement — save only to the limited extent such a restriction cannot be excluded under mandatory applicable law (e.g. decompilation for interoperability under Directive 2009/24/EC).</li>"
        . "<li><b>No forgery or key abuse.</b> You must not forge, spoof, replay, or fabricate any licence key, activation, signed response, integrity manifest, hardware fingerprint, or server identity; operate a counterfeit or proxy licensing server; or share, resell, sublicense, reuse, clone, image, or duplicate a licence or an activated installation across more than the licensed Server(s) or to evade per-Server licensing.</li>"
        . "<li><b>Genuine signed builds only.</b> You must run only unmodified, Provider-signed builds obtained through the official update channel.</li>"
        . "</ul>"
        . "<p><b>Detection &amp; automated enforcement.</b> The Software and the licensing service may automatically detect tampering, forgery, cloning, integrity failure, or licence expiry/suspension and, as a graduated and proportionate response, may <b>warn, degrade, suspend, disable, or terminate</b> the Software and the associated services on the affected Server — in whole or in part, automatically and without prior notice — and a confirmed tamper, suspected piracy, or operator-ordered termination may cause the Software to disable itself or remove itself from the Server. The Provider may also suspend or terminate the Licence. <b>These measures are a contractual remedy for breach and an essential part of the product’s security model, and you expressly consent to them.</b> Legitimate, reversible conditions (such as a temporary loss of connectivity, or a normal expiry pending renewal) are handled with grace periods and are restored automatically once the condition is resolved or the Licence is renewed.</p>"
        . "<p><b>Consequence.</b> Any breach of this section is a <b>material breach</b> of these Terms that immediately voids the Licence, entitles the Provider to terminate the Licence and stop the service <b>without refund</b>, and is without prejudice to the Provider’s other rights and remedies, including in respect of infringement of its intellectual-property rights.</p>"],

        ['4. Ownership',
         "<p>The Software is licensed, not sold. The Provider and its licensors retain all right, title, and interest in and to the Software, including all intellectual property rights. You receive only the limited licence expressly set out in these Terms. Any feedback you provide may be used by the Provider without obligation to you.</p>"],

        ['5. Fees, billing &amp; renewal',
         "<p>Paid plans are charged in advance for the subscription period stated at purchase. Unless you cancel before renewal, subscriptions renew automatically for successive periods at the then-current price; we will give reasonable prior notice of any price change. Fees are exclusive of taxes unless stated otherwise; you are responsible for applicable taxes. Failure to pay may result in suspension or termination of the Licence.</p>"],

        ['6. Term, suspension &amp; termination',
         "<p>These Terms apply for as long as you use the Software or hold a Licence. Either party may terminate for material breach not cured within 14 days of notice. We may suspend or terminate the Licence for non-payment, unlawful use, or breach of these Terms. On termination your right to use the Software ends and you must stop using it; activated licences may be deactivated. Sections that by their nature should survive (e.g. ownership, disclaimers, liability, governing law) survive termination.</p>"],

        ['7. Updates &amp; support',
         "<p>We may provide updates, which are governed by these Terms. We may add, change, or remove features over time. Support is provided for supported versions through the channels we make available. We do not guarantee uninterrupted availability of the licensing/telemetry services.</p>"],

        ['8. Acceptable use &amp; your responsibilities',
         "<p>The Software runs with administrative (root) privileges on your Server and can change firewall, service, and security settings. You are solely responsible for your Server, your data and backups, your configuration choices, and for using the Software lawfully and only on systems you are authorised to administer. You must not use the Software to attack, disrupt, or gain unauthorised access to any system, or in violation of any applicable law.</p>"],

        ['9. Third-party services',
         "<p>The Software can integrate with third-party tools and services (for example Imunify360, ConfigServer/CSF, cPanel/WHM, and messaging or AI providers such as Telegram, WhatsApp, Pushbullet, and AI model providers). You are responsible for your own accounts, API keys, and compliance with those third parties’ terms. The Provider is not responsible for third-party services.</p>"],

        ['10. Disclaimers',
         "<p>To the maximum extent permitted by law, the Software is provided “<b>as is</b>” and “<b>as available</b>”, without warranties of any kind, whether express, implied, or statutory, including any implied warranties of merchantability, fitness for a particular purpose, and non-infringement. Security tools reduce risk but cannot guarantee detection or prevention of all threats, downtime, data loss, or compromise. This section does not affect statutory rights that cannot be excluded, including the statutory guarantees that apply to Consumers.</p>"],

        ['11. Limitation of liability',
         "<p>To the maximum extent permitted by law, the Provider will not be liable for any indirect, incidental, special, consequential, or punitive damages, or for loss of profits, revenue, data, or goodwill. The Provider’s total aggregate liability arising out of or related to the Software will not exceed the amount you paid for the Software in the twelve (12) months before the event giving rise to the claim. <b>Nothing in these Terms excludes or limits liability that cannot be excluded or limited under applicable law</b>, including liability for death or personal injury caused by negligence, for fraud, or for any other liability that may not be limited by law; and where you are a Consumer, your mandatory statutory rights are not affected.</p>"],

        ['12. Indemnification',
         "<p>If you are using the Software for business purposes, you agree to indemnify and hold the Provider harmless from claims, losses, and expenses arising from your unlawful use of the Software, your breach of these Terms, or your violation of any third-party rights.</p>"],

        ['13. Governing law &amp; disputes',
         "<p>These Terms are governed by {$L}, without regard to conflict-of-law rules. If you are a Consumer resident in the European Union (or the UK), you benefit from any mandatory consumer-protection provisions of the law of your country of residence, and you may bring proceedings in your local courts; the EU Online Dispute Resolution platform is available at <span class=\"lg-mono\">https://ec.europa.eu/consumers/odr</span>.</p>"],

        ['14. Changes to these Terms',
         "<p>We may update these Terms from time to time. When we make material changes we will update the version and effective date and, where appropriate, ask you to accept the new Terms in the plugin. Your continued use after the changes take effect constitutes acceptance.</p>"],

        ['15. Privacy Policy (GDPR)',
         "<p>This Privacy Policy explains how the Provider handles personal data in connection with the Software, in line with the EU/UK General Data Protection Regulation (GDPR).</p>"
        . "<p><b>Local processing.</b> Most data the Software handles — server logs, IP addresses, account and process information, and security findings — is processed <b>locally on your Server</b> and is not sent to the Provider. For that data <b>you are the data controller</b> and the Provider acts, at most, as a processor through the software you operate.</p>"
        . "<p><b>Data the Provider receives.</b> For licensing and product operation the Provider receives: your licence key, the Server’s IP address, a hardware fingerprint, hostname, operating-system and control-panel version, plan, and basic telemetry (such as plugin version, load, CPU/RAM/disk, and uptime). If you contact support, we process the details you provide.</p>"
        . "<p><b>Purposes &amp; legal bases.</b> Licence validation and providing the Software — performance of a contract (Art. 6(1)(b)); fraud prevention, security, and product improvement — legitimate interests (Art. 6(1)(f)); compliance with legal obligations (Art. 6(1)(c)).</p>"
        . "<p><b>Recipients.</b> Data is shared only with our licensing infrastructure and service providers acting on our behalf. We do not sell personal data.</p>"
        . "<p><b>International transfers.</b> Where data is transferred outside the EEA/UK, we use appropriate safeguards such as the European Commission’s Standard Contractual Clauses.</p>"
        . "<p><b>Retention.</b> We keep licensing and telemetry data for as long as your licence is active and as needed for legal, accounting, and security purposes, then delete or anonymise it.</p>"
        . "<p><b>Your rights.</b> Subject to applicable law, you may request access, rectification, erasure, restriction, portability, and object to processing, and you may lodge a complaint with your local data-protection supervisory authority. To exercise your rights, contact <span class=\"lg-mono\">{$E}</span>.</p>"
        . "<p><b>Security.</b> We apply technical and organisational measures appropriate to the risk (including encryption of sensitive material and access controls). No method of transmission or storage is completely secure.</p>"],

        ['16. Refund &amp; right of withdrawal',
         "<p><b>EU/UK consumers — 14-day right of withdrawal.</b> If you are a Consumer, you normally have the right to withdraw from the purchase within 14 days without giving a reason. <b>Digital content exception:</b> because the Software is digital content supplied and activated immediately, by purchasing and activating you expressly request immediate performance and acknowledge that you lose the right of withdrawal once supply has begun, to the extent permitted by Directive (EU) 2019/770 and 2011/83/EU. Where the right still applies, contact us within 14 days to withdraw.</p>"
        . "<p><b>Business customers.</b> The statutory right of withdrawal generally does not apply to purchases made for business purposes; refunds for business customers are at the Provider’s discretion or as stated at purchase.</p>"
        . "<p><b>How to request.</b> Email <span class=\"lg-mono\">{$E}</span> with your licence key and order details. Approved refunds are issued to the original payment method within the period required by applicable law (and in any case without undue delay).</p>"],

        ['17. Contact',
         "<p>{$N} — {$P}." . ($c['address'] !== '' ? ' ' . smpro_h($c['address']) . '.' : '') . " Web: <span class=\"lg-mono\">{$S}</span> · Email: <span class=\"lg-mono\">{$E}</span>.</p>"],
    ];
}

/** Echo the document body (sections). */
function smpro_legal_render_doc() {
    $c = smpro_legal_company();
    echo '<p class="lg-meta">Version ' . smpro_h(smpro_legal_version()) . ' · Effective ' . smpro_h($c['effective']) . '</p>';
    foreach (smpro_legal_sections() as $sec) {
        echo '<h3 class="lg-h">' . smpro_h($sec[0]) . '</h3>';
        echo '<div class="lg-b">' . $sec[1] . '</div>';   // bodies are trusted, builder-controlled HTML
    }
}

/** CSS shared by the gate + the menu page. */
function smpro_legal_css() {
    return '<style>'
      . '.lg-wrap{max-width:900px;margin:0 auto}'
      . '.lg-meta{color:var(--muted);font-size:12px;margin:0 0 14px}'
      . '.lg-h{font-size:15px;color:var(--ink);margin:18px 0 6px;border-top:1px solid var(--line);padding-top:14px}'
      . '.lg-h:first-of-type{border-top:0;padding-top:0}'
      . '.lg-b{font-size:13px;line-height:1.7;color:var(--ink)}'
      . '.lg-b p{margin:0 0 9px}.lg-b ul{margin:0 0 9px;padding-left:20px}.lg-b li{margin:3px 0}'
      . '.lg-mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--bg);padding:1px 6px;border-radius:6px}'
      . '.lg-scroll{max-height:52vh;overflow:auto;border:1px solid var(--line);border-radius:11px;padding:16px 20px;background:var(--card)}'
      . '</style>';
}

/** First-run / re-acceptance gate — a self-contained full page (no sidebar) with an Agree action. */
function smpro_legal_render_gate() {
    $c = smpro_legal_company();
    $csrf = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('legal') : '';
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . smpro_h($c['product']) . ' — Terms</title>';
    // self-contained theme (the gate renders before the normal layout/theme CSS) — light default + dark mode
    echo '<style>:root{--bg:#f4f6fb;--card:#fff;--ink:#0f1b33;--brand:#3b5bdb;--brand-bg:#eef2ff;--line:#e3e8f2;--muted:#6b7686;--good:#1f9d55;--warn:#b76b00;--dang:#d93b3b}'
       . '@media(prefers-color-scheme:dark){:root{--bg:#0f1320;--card:#171c2b;--ink:#e6ebf5;--line:#283048;--muted:#9aa6c0;--brand-bg:#1c2540}}</style>';
    echo smpro_legal_css();
    echo '<style>body{margin:0;background:var(--bg);font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif}'
       . '.lg-gate{max-width:920px;margin:24px auto;padding:0 16px}'
       . '.lg-card{background:var(--card,#fff);border:1px solid var(--line,#e3e8f2);border-radius:14px;padding:22px 24px}'
       . '.lg-title{font-size:20px;font-weight:800;color:var(--ink,#0f1b33);margin:0 0 4px}'
       . '.lg-sub{color:var(--muted,#6b7686);font-size:13px;margin:0 0 16px}'
       . '.lg-actions{display:flex;gap:10px;align-items:center;margin-top:16px;flex-wrap:wrap}'
       . '.lg-btn{appearance:none;border:0;border-radius:9px;padding:10px 18px;font-size:14px;font-weight:700;cursor:pointer}'
       . '.lg-agree{background:var(--brand,#3b5bdb);color:#fff}.lg-agree:disabled{opacity:.5;cursor:not-allowed}'
       . '.lg-note{color:var(--muted,#6b7686);font-size:12px}</style></head><body>';
    echo '<div class="lg-gate"><div class="lg-card">';
    echo '<h1 class="lg-title">&#128220; ' . smpro_h($c['product']) . ' — Terms &amp; Conditions</h1>';
    echo '<p class="lg-sub">Please read and accept the Terms &amp; Conditions, Privacy Policy, and Refund Policy to continue.</p>';
    echo '<div class="lg-scroll" id="lgScroll">'; smpro_legal_render_doc(); echo '</div>';
    echo '<div class="lg-actions">'
       . '<button class="lg-btn lg-agree" id="lgAgree" type="button">I have read and agree</button>'
       . '<span class="lg-note">By clicking you accept these Terms for this server.</span></div>';
    echo '<div class="lg-note" id="lgMsg" style="margin-top:8px"></div>';
    echo '</div></div>';
    echo '<script>(function(){var b=document.getElementById("lgAgree");b.addEventListener("click",function(){'
       . 'b.disabled=true;b.textContent="Saving…";'
       . 'var fd=new URLSearchParams();fd.set("smpro_csrf",' . json_encode($csrf) . ');'
       . 'fetch("index.cgi?legal_accept=1",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd.toString()})'
       . '.then(function(r){return r.json();}).then(function(j){ if(j&&j.ok){location.href="index.cgi?page=dashboard";} else {document.getElementById("lgMsg").textContent=(j&&j.msg)||"Could not save. Try again.";b.disabled=false;b.textContent="I have read and agree";} })'
       . '.catch(function(){document.getElementById("lgMsg").textContent="Network error. Try again.";b.disabled=false;b.textContent="I have read and agree";});'
       . '});})();</script></body></html>';
}
