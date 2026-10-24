<?php
/**
 * legal.php - Terms & Conditions + Privacy Policy (GDPR) + Refund/Withdrawal.
 *   - Shown as a one-time ACCEPTANCE gate the first time the plugin is opened.
 *   - Always available as the "Terms & Legal" page (last item under Settings).
 * Acceptance is recorded at SMPRO_VARLIB/legal_accepted.json {version, ts, actor, ip}.
 * Bump smpro_legal_version() whenever the text materially changes to re-prompt acceptance.
 *
 * NOTE: this is a practical, EU/US-aware template - NOT legal advice. The Provider should fill in the
 * company details below (registered address, governing law) and have the final text reviewed and adapted
 * by qualified counsel for its jurisdiction before relying on it.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ----- editable company / product identity (change here only) ----- */
function smpro_legal_company() {
    return [
        'product' => defined('SMPRO_NAME') ? SMPRO_NAME : 'Safety Monitor Pro',
        'name'    => defined('SMPRO_BRAND_COMPANY') ? SMPRO_BRAND_COMPANY : 'HostGuard.org',  // company / brand
        'address' => '',                                         // TODO: registered business address
        'contact' => 'support@hostguard.org',                   // legal/privacy/support contact email
        'site'    => defined('SMPRO_BRAND_URL') ? SMPRO_BRAND_URL : 'https://hostguard.org',
        'law'     => 'the laws applicable at the Provider’s principal place of business',  // ⚠️ TODO (set with counsel): the governing jurisdiction, e.g. 'the laws of England & Wales' or 'the laws of the State of Delaware, USA'. Also fill 'address' above. These + venue are the biggest enforceability items.
        'effective' => '2026-07-03',
    ];
}
/** Document version - change to re-trigger first-run acceptance for everyone. */
function smpro_legal_version() { return '2026-07-03'; }

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
        . "<li><b>Compliance verification.</b> The Provider may verify your compliance with the Licence — including the number of activated Servers and the integrity of the installation — through the licensing service and reasonable audits, and you agree to provide information reasonably necessary to confirm compliance.</li>"
        . "</ul>"
        . "<p><b>Detection &amp; automated enforcement.</b> The Software and the licensing service may automatically detect tampering, forgery, cloning, integrity failure, or licence expiry/suspension and, as a graduated and proportionate response, may <b>warn, degrade, suspend, disable, or terminate</b> the Software and the associated services on the affected Server — in whole or in part, automatically and without prior notice — and a confirmed tamper, suspected piracy, or operator-ordered termination may cause the Software to disable itself or remove itself from the Server. The Provider may also suspend or terminate the Licence. <b>These measures are a contractual remedy for breach and an essential part of the product’s security model, and you expressly consent to them.</b> Legitimate, reversible conditions (such as a temporary loss of connectivity, or a normal expiry pending renewal) are handled with grace periods and are restored automatically once the condition is resolved or the Licence is renewed. These measures act on the Software and its own components; they are not designed or intended to delete, destroy, or corrupt your sites, accounts, or Customer data, and the parties agree they are a genuine, proportionate estimate of the protection reasonably required for the Provider’s security and licensing model and are a contractual remedy, not a penalty.</p>"
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
         "<p>The Software runs with administrative (root) privileges on your Server and can create, change, or remove firewall rules, block or allow IP addresses and networks, throttle or stop processes, lock, quarantine, move, or modify files, alter mail/Exim and PHP settings, and take other automated or manual security and remediation actions. Accordingly:</p>"
        . "<ul>"
        . "<li><b>Authorised systems only.</b> You may install and use the Software only on Servers and systems that you own or are expressly authorised to administer, and only for lawful purposes.</li>"
        . "<li><b>Your responsibility.</b> You are solely responsible for your Server and hosting environment, your data and for maintaining independent backups and out-of-band access, your configuration and policy choices (including which automated actions you enable), reviewing the Software’s recommendations and actions, and for the effect of those actions on your systems, your customers, and third parties.</li>"
        . "<li><b>Prohibited uses.</b> You must not use the Software to attack, scan, disrupt, overload, degrade, or gain or attempt to gain unauthorised access to any system, network, account, or data; to intercept, collect, monitor, or process the personal data of any person unlawfully or without a valid legal basis; to block, throttle, or interfere with traffic, services, or persons unlawfully or in a manner prohibited by law; to circumvent or attack the security of others; or to act in violation of any applicable law, regulation, or third-party agreement or right.</li>"
        . "<li><b>Compliance.</b> You are responsible for ensuring that your use of the Software — including any logging, monitoring, IP or geo blocking, and processing of visitor or account data — complies with all laws applicable to you and your users (including data-protection, privacy, communications, consumer-protection, and computer-misuse laws) and with your agreements with your hosting provider, upstream networks, and customers.</li>"
        . "</ul>"],

        ['8A. Responsibility for security &amp; automated actions',
         "<p>Security tools operate on signals and heuristics and can produce false positives and false negatives. You acknowledge and agree that:</p>"
        . "<ul>"
        . "<li>The Software may block, rate-limit, quarantine, lock, throttle, or otherwise affect traffic, IP addresses, processes, files, accounts, or services that are in fact legitimate, and may fail to detect or prevent some threats, attacks, downtime, data loss, or compromise.</li>"
        . "<li>You are responsible for configuring, testing, monitoring, and reviewing the automated and manual actions you enable (including auto-block, load throttling, file hardening/immutability, quarantine, and emergency responses), and for maintaining backups and a recovery path (including out-of-band access to your Server) in case a security action affects legitimate traffic or data or locks you out.</li>"
        . "<li>To the maximum extent permitted by law, the Provider is not liable for any interruption, loss of access, blocked or dropped legitimate traffic, loss of business or revenue, or loss of or damage to data arising from any action taken (or not taken) by the Software — whether automated, recommended, or performed on your instruction — or from your configuration choices or misuse.</li>"
        . "</ul>"
        . "<p>These allocations of responsibility are reflected in the Disclaimers and the Limitation of Liability below and do not affect any liability that cannot be excluded under applicable law or, where you are a Consumer, your mandatory statutory rights.</p>"],

        ['9. Third-party services',
         "<p>The Software can integrate with third-party tools and services (for example Imunify360, ConfigServer/CSF, cPanel/WHM, and messaging or AI providers such as Telegram, WhatsApp, Pushbullet, and AI model providers). You are responsible for your own accounts, API keys, and compliance with those third parties’ terms. The Provider is not responsible for third-party services.</p>"],

        ['9A. Trademarks &amp; no affiliation',
         "<p>{$P} is an independent product. All third-party names, logos, and trademarks are the property of their respective owners and are used for identification and interoperability only. In particular, <b>cPanel®</b> and <b>WHM®</b> are trademarks of cPanel, L.L.C.; <b>WordPress®</b> is a trademark of the WordPress Foundation; and <b>Cloudflare®</b>, <b>Imunify360®</b>, <b>ConfigServer®/CSF</b>, <b>Telegram®</b>, and <b>WhatsApp®</b> are trademarks of their respective owners. The Provider is <b>not affiliated with, sponsored by, endorsed by, or certified by</b> any of these parties. Your use of any third-party platform (including cPanel/WHM) remains subject to that party’s own terms, and you are responsible for holding the necessary licences and rights to run it.</p>"],

        ['10. Disclaimers',
         "<p>To the maximum extent permitted by law, the Software is provided “<b>as is</b>” and “<b>as available</b>”, without warranties of any kind, whether express, implied, or statutory, including any implied warranties of merchantability, fitness for a particular purpose, and non-infringement. Security tools reduce risk but cannot guarantee detection or prevention of all threats, downtime, data loss, or compromise. This section does not affect statutory rights that cannot be excluded, including the statutory guarantees that apply to Consumers.</p>"],

        ['11. Limitation of liability',
         "<p>To the maximum extent permitted by law, the Provider will not be liable for any indirect, incidental, special, consequential, or punitive damages, for loss of profits, revenue, data, or goodwill, or for any consequences of security or remediation actions taken or not taken by the Software (including blocked or dropped legitimate traffic, service interruption, lock-out, or affected data). The Provider’s total aggregate liability arising out of or related to the Software will not exceed the amount you paid for the Software in the twelve (12) months before the event giving rise to the claim. The remedies expressly stated in these Terms are your sole and exclusive remedies for any failure of, or issue with, the Software. <b>Nothing in these Terms excludes or limits liability that cannot be excluded or limited under applicable law</b>, including liability for death or personal injury caused by negligence, for fraud, or for any other liability that may not be limited by law; and where you are a Consumer, your mandatory statutory rights are not affected.</p>"],

        ['12. Indemnification &amp; your warranties',
         "<p>You represent and warrant that you own, or are expressly authorised to administer, each Server and system on which you use the Software, and that your use of it — including every automated action you enable and all data you process with it — is and will remain lawful.</p>"
        . "<p>To the maximum extent permitted by law, and except where you are a Consumer acting outside a trade or business, you will defend, indemnify, and hold harmless the Provider and its affiliates, officers, and personnel from and against any third-party claim, demand, or proceeding, and any resulting loss, liability, damage, cost, or expense (including reasonable legal fees), arising out of or related to: (a) your use or misuse of the Software; (b) your breach of these Terms or of any applicable law; (c) your configuration choices and the security or remediation actions you enabled or instructed — including any traffic, IP address, file, account, or service affected and any claim brought by your customers, end-users, visitors, or upstream networks; (d) your data and your collection, monitoring, or processing of any person’s personal data; or (e) your violation of any third-party right. The Provider will give you prompt notice of the claim, reasonable cooperation at your expense, and sole control of the defence and settlement; you must not settle any claim in a way that imposes any obligation, payment, or admission on the Provider without its prior written consent.</p>"],

        ['13. Governing law &amp; disputes',
         "<p>These Terms are governed by {$L}, without regard to conflict-of-law rules. <b>Informal resolution first.</b> Before starting formal proceedings, you agree to contact the Provider and attempt in good faith to resolve any dispute informally for at least 30 days. Subject to any mandatory rights of Consumers, the courts of the Provider’s principal place of business have exclusive jurisdiction over any dispute arising out of or relating to the Software or these Terms; the Provider may nonetheless seek injunctive or equitable relief in any court of competent jurisdiction to protect its intellectual-property or licensing rights. If you are a Consumer resident in the European Union (or the UK), you benefit from any mandatory consumer-protection provisions of the law of your country of residence and may bring proceedings in your local courts; the EU Online Dispute Resolution platform is available at <span class=\"lg-mono\">https://ec.europa.eu/consumers/odr</span>.</p>"],

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
        . "<p><b>Security.</b> We apply technical and organisational measures appropriate to the risk (including encryption of sensitive material and access controls). No method of transmission or storage is completely secure.</p>"
        . "<p><b>Controller/processor &amp; sub-processors.</b> For data processed locally on your Server you are the controller and the Provider is not a recipient. For the limited licensing and telemetry data the Provider receives, the Provider acts as a controller for licence administration and, where it processes personal data on your behalf, as your processor; in that case this Policy and, where required, a separate <b>Data Processing Addendum (available on request)</b> govern that processing. The Provider engages vetted sub-processors under written terms and remains responsible for their compliance.</p>"
        . "<p><b>United States — state privacy rights.</b> Where U.S. state privacy laws apply (for example the California Consumer Privacy Act as amended by the CPRA, and comparable laws in Virginia, Colorado, Connecticut, Utah, and other states), you may have rights to know, access, correct, delete, and obtain a copy of personal information, and to opt out of its sale or sharing. <b>The Provider does not “sell” or “share” personal information</b> (as those terms are defined under such laws) and does not use it for cross-context behavioural advertising. To exercise any right, contact <span class=\"lg-mono\">{$E}</span>; we will not discriminate against you for exercising your rights.</p>"],

        ['16. Refund &amp; right of withdrawal',
         "<p><b>EU/UK consumers — 14-day right of withdrawal.</b> If you are a Consumer, you normally have the right to withdraw from the purchase within 14 days without giving a reason. <b>Digital content exception:</b> because the Software is digital content supplied and activated immediately, by purchasing and activating you expressly request immediate performance and acknowledge that you lose the right of withdrawal once supply has begun, to the extent permitted by Directive (EU) 2019/770 and 2011/83/EU. Where the right still applies, contact us within 14 days to withdraw.</p>"
        . "<p><b>Business customers.</b> The statutory right of withdrawal generally does not apply to purchases made for business purposes; refunds for business customers are at the Provider’s discretion or as stated at purchase.</p>"
        . "<p><b>How to request.</b> Email <span class=\"lg-mono\">{$E}</span> with your licence key and order details. Approved refunds are issued to the original payment method within the period required by applicable law (and in any case without undue delay).</p>"],

        ['16A. Export controls, sanctions &amp; lawful-use compliance',
         "<p>You represent and warrant that you are not located in, and are not a national or resident of, any country or territory subject to comprehensive government sanctions or embargo, and that you are not on any government restricted-party or denied-party list. You agree to comply with all applicable export-control, sanctions, and trade laws (including those of the United States and the European Union) and not to use, export, re-export, or make the Software available in violation of them.</p>"
        . "<p><b>U.S. Government end users.</b> The Software is “commercial computer software” and “commercial computer software documentation”; if licensed to or on behalf of the U.S. Government, it is provided with only the rights granted to all other end users under these Terms, consistent with FAR 12.212 and DFARS 227.7202.</p>"],

        ['16B. Beta &amp; pre-release features',
         "<p>The Software may make available beta, preview, early-access, or other pre-release features or builds (for example through a beta update channel). Pre-release features are provided <b>for evaluation only</b>, <b>“as is”</b> and <b>“as available”</b>, may be incomplete or unstable, may change or be withdrawn at any time, and are excluded from any service commitment and, to the maximum extent permitted by law, from warranties. Use them at your own risk and not in production unless you accept that risk.</p>"],

        ['16C. Eligibility',
         "<p>You must be at least 18 years old (or the age of majority in your jurisdiction) and able to form a binding contract to use the Software. The Software is intended for business and professional server administration and is not directed to children.</p>"],

        ['16D. General provisions',
         "<p><b>Entire agreement.</b> These Terms, together with any order and any separate written agreement you have with the Provider, are the entire agreement between you and the Provider regarding the Software and supersede prior discussions. <b>Severability.</b> If any provision is held unenforceable, the remaining provisions remain in full force, and the unenforceable provision will be modified to the minimum extent necessary to make it enforceable. <b>No waiver.</b> A failure to enforce any provision is not a waiver of it. <b>Assignment.</b> You may not assign these Terms without the Provider’s prior written consent; the Provider may assign them to an affiliate or a successor in connection with a merger, acquisition, or sale of assets. <b>No third-party beneficiaries.</b> These Terms do not create rights for any third party. <b>Force majeure.</b> Neither party is liable for any delay or failure to perform caused by events beyond its reasonable control. <b>Notices.</b> Legal notices to the Provider should be sent to <span class=\"lg-mono\">{$E}</span>; the Provider may give notice to you within the Software, by email, or via its website. <b>Survival.</b> Provisions that by their nature should survive termination (including ownership, licence security, disclaimers, limitation of liability, indemnification, and governing law) survive. <b>Headings</b> are for convenience only and do not affect interpretation.</p>"],

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

/** First-run / re-acceptance gate - a self-contained full page (no sidebar) with an Agree action. */
function smpro_legal_render_gate() {
    $c = smpro_legal_company();
    $csrf = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('legal') : '';
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . smpro_h($c['product']) . ' — Terms</title>';
    // self-contained theme (the gate renders before the normal layout/theme CSS) - light default + dark mode
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
