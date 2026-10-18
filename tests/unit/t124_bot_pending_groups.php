<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/botguard.php';
/** t124 - the pending-bots notice groups by identity and fires on a NEW identity only; Google's prefetch proxy is a known, verifiable Google service. */
is_eq(smpro_bg_identity(['name' => 'Googlebot']), 'Googlebot', 'U1: a catalog name wins');
is_eq(smpro_bg_identity(['ua' => 'Mozilla/5.0 (compatible; ExaSearchBot/1.0; +https://crawler.exa.ai/)']), 'ExaSearchBot (declared, not verified)', 'U1: a crawler that names itself is one identity');
is_eq(smpro_bg_identity(['ua' => 'Mozilla/5.0 (Macintosh)', 'provider' => 'AMAZON-02, US']), 'unnamed clients on AMAZON-02', 'U1: otherwise its network');
is_eq(smpro_bg_identity([]), 'unnamed clients, unknown network', 'U1: never empty');
$cat = smpro_bg_catalog_builtin();
ok(isset($cat['google_prefetch']) && preg_match($cat['google_prefetch']['ua'], 'Chrome Privacy Preserving Prefetch Proxy'), 'U2: the prefetch proxy is in the catalog');
is_eq($cat['google_prefetch']['ranges'], 'googlebot', 'U2: ...verified by the Google ranges');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
has($src, "\$newGroups = array_values(array_filter(array_keys(\$groups), fn(\$g) => !isset(\$known[\$g])));", 'U3: only a NEW identity triggers the notice');
has($src, "'  NEW  ' . \$g . ' — ' . \$groups[\$g] . ' address'", 'U3: one line per identity with its address count');
hasnt($src, "array_slice(\$d['new_pending'], 0, 12)", 'U3: no list of raw addresses');
