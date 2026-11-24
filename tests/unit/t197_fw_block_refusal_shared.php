<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/intrusion.php';   // smpro_ip_is_cloudflare, smpro_im_allowlisted
require_once SMPRO_BASE . '/includes/fwallow.php';     // smpro_fw_never_block, smpro_fw_block_refusal
/**
 * t197 - the Firewall page refused to block certain addresses (Cloudflare edge, never-block mail providers, the
 * Intrusion Monitor allow-list) in its TEMPORARY block path, but the PERMANENT block path only refused a
 * Cloudflare edge - smpro_csf_deny_add never checked the mail-provider or allow-list reasons. So a permanent
 * manual block could black-hole customer mail or override the operator's own allow-list, while the temporary
 * block correctly refused both. Both paths now go through ONE guard, smpro_fw_block_refusal(), so they agree.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$fw  = $src('modules/firewall-status.php');
$fa  = $src('includes/fwallow.php');

// --- A. the shared guard exists, in fwallow.php next to never_block ---
ok(function_exists('smpro_fw_block_refusal'), 'A1: smpro_fw_block_refusal() is defined (the one shared guard)');
has($fa, 'function smpro_fw_block_refusal(', 'A2: it lives in fwallow.php');

// --- B. it refuses each off-limits reason and allows an ordinary address ---
// (no Cloudflare/provider/allow-list data is loaded in the sandbox, so an arbitrary public IP is blockable)
is_eq(smpro_fw_block_refusal('203.0.113.77'), '', 'B1: an ordinary public IP may be blocked (empty refusal)');
// the guard consults the three predicates by name - prove each branch is wired by its message text
has($fa, 'is a Cloudflare edge IP',              'B2: refuses a Cloudflare edge IP');
has($fa, 'blocking it would bounce your customers', 'B3: refuses a never-block mail provider');
has($fa, 'is on the Intrusion Monitor allow-list',  'B4: refuses an allow-listed address');
has($fa, 'smpro_ip_is_cloudflare', 'B5: ...via the real Cloudflare predicate');
has($fa, 'smpro_fw_never_block',   'B6: ...the real never-block predicate');
has($fa, 'smpro_im_allowlisted',   'B7: ...and the real allow-list predicate');

// --- C. BOTH block paths in the module go through the shared guard (the real fix: permanent was unguarded) ---
is_eq(substr_count($fw, 'smpro_fw_block_refusal('), 2, 'C1: both the temporary and the permanent path call the shared guard');
// the old hand-inlined refusal messages must be gone from the module (one source of truth now)
is_eq(substr_count($fw, 'blocking it would bounce your customers'), 0, 'C2: the inlined never-block message no longer lives in the module');
is_eq(substr_count($fw, 'is on the Intrusion Monitor allow-list'),  0, 'C3: the inlined allow-list message no longer lives in the module');

// --- D. a refused permanent block is audited as refused, not as a silent success ---
has($fw, "'refused'=>true", 'D1: a refused permanent block records refused=true in the audit trail');
