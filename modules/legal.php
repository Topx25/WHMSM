<?php
/** legal.php — the "Terms & Legal" page (last item under Settings). Read-only view of the full
 *  Terms & Conditions + Privacy Policy + Refund/Withdrawal, plus this server's acceptance record. */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

smpro_layout_header('Terms & Legal');
$c  = smpro_legal_company();
$st = smpro_legal_state();
$acc = smpro_legal_accepted();
echo smpro_legal_css();
?>
<div class="lg-wrap">
  <p class="sub"><?= smpro_h($c['product']) ?> — Terms &amp; Conditions, Privacy Policy (GDPR), and Refund / Right-of-Withdrawal.</p>

  <div class="card" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;<?= $acc ? '' : 'border-color:var(--warn)' ?>">
    <div style="font-size:22px"><?= $acc ? '&#9989;' : '&#9888;' ?></div>
    <div style="flex:1;min-width:220px">
      <?php if ($acc): ?>
        <b style="color:var(--good)">Accepted on this server</b>
        <div class="meta">Version <?= smpro_h((string)($st['version'] ?? '')) ?> · accepted <?= smpro_h(!empty($st['ts']) ? date('Y-m-d H:i', (int)$st['ts']) : '—') ?><?= !empty($st['actor']) ? ' · by ' . smpro_h($st['actor']) : '' ?></div>
      <?php else: ?>
        <b style="color:var(--warn)">Not yet accepted</b>
        <div class="meta">The Terms are shown for acceptance the first time the plugin is opened.</div>
      <?php endif; ?>
    </div>
  </div>

  <div class="card">
    <?php smpro_legal_render_doc(); ?>
  </div>
</div>
<?php
smpro_layout_footer();
