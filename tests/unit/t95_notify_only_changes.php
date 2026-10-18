<?php
require __DIR__ . '/../support/bootstrap.php';
/** t95 - "only when it changes": an unchanged report is not repeated after the remind window; a changed one is. */
$n = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($n, "\$onlyChanges = !empty(\$cfg['types'][\$type]['only_changes']);", 'U1: the engine reads the per-type switch');
has($n, "if (\$sameSig && \$sameChan && (\$fresh || \$onlyChanges)) return;", 'U1: an UNCHANGED signature is held back when the switch is on, whatever the remind window says');
// the signature of the foreign-login report is built from the rows themselves, so a new account/address changes it
has($n, "\$ids = array_unique(array_map(\$rowId, \$fp)); sort(\$ids);", 'U1: the cPanel/webmail foreign-login signature is built from the identity of every row - a new account, country or network changes it');
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/notifications.php'));
has($m, "if (\$act === 'only_changes') {", 'U2: the page has the toggle action');
has($m, "'only_changes' => !empty(\$cfg['types'][\$k]['only_changes']),   // preserved too", 'U2: a settings save does not reset it');
has($m, 'class="tp-btn t-onlychg', 'U2: the button is on every alert row');
has($m, "fd.set('ntf_action','only_changes')", 'U2: ...and posts the toggle');
/* ---------- U3: the alert table has selection, filter and bulk actions, and the old per-row controls keep their classes ---------- */
has($m, 'id="ntAll"', 'U3: select-all'); has($m, 'class="nt-pick"', 'U3: per-row pick');
has($m, 'data-bulk="email:1"', 'U3: bulk channel on'); has($m, 'data-bulkx="snooze:24"', 'U3: bulk snooze'); has($m, 'data-bulkx="only:1"', 'U3: bulk repeat mode');
has($m, 'id="ntFind"', 'U3: search'); has($m, 'class="nt-sev on" data-sev=""', 'U3: severity chips');
foreach (['t-on', 't-email', 't-tg', 't-pb', 't-wa', 't-snooze', 'tp-btn t-onlychg'] as $cl) has($m, 'class="' . $cl, 'U3: row control ' . $cl . ' kept for the save/snooze code');
has($m, "uksort(\$types, fn(\$a, \$b) => (\$sevOrder[", 'U3: rows ordered by severity');
/* ---------- U4: the foreign-login signature is account|country|network, not the bare address ---------- */
$n2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($n2, "return (string)(\$d['user'] ?? '') . '|' . \$cc . '|' . (\$asn !== '' ? \$asn : \$ip);", 'U4: row identity = user|country|ASN (address only when the network is unknown)');
has($n2, "\$ids = array_unique(array_map(\$rowId, \$fp)); sort(\$ids);", 'U4: the cPanel/webmail signature is built from those identities, order-free');
hasnt($n2, "\$key  = 'cplogin:' . md5(implode(',', array_map(fn(\$d) => \$d['ip'] . \$d['user'], \$fp)));", 'U4: the old address-based signature is gone');
/* ---------- U5: the Threat Report table pages, sorts, filters, pins malware first, and carries the repeat buttons ---------- */
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fw, "a._rank=a._cls==='live'?0:(a._cls==='in'?1:2)", 'U5: malware on disk ranks first, then accepted foreign password, then attempts');
has($fw, 'data-f="live"', 'U5: malware filter chip'); has($fw, 'id="grSort"', 'U5: sort'); has($fw, 'function ccList(obj, max)', 'U5b: country lists are capped with a +N more tooltip'); has($fw, '<th style="width:120px;text-align:right">Last seen</th>', 'U5b: three columns, dates on one line'); has($fw, 'id="grPer"', 'U5: page size'); has($fw, 'id="grFind"', 'U5: search');
has($fw, "window.GR_PICKED=picked;", 'U5: the selection survives paging and filtering');
has($fw, "var users=(window.GR_PICKED?Object.keys(window.GR_PICKED)", 'U5: the reset reads that selection, not only the visible boxes');
has($fw, 'data-type="foreign_login"', 'U5: repeat button for the foreign-login alert'); has($fw, 'data-type="malware_active"', 'U5: ...and for active malware');
has($fw, "var NTF_CSRF2=<?= json_encode(smpro_csrf_generate('ntf_act')) ?>;", 'U5: ...with the Notifications endpoint token');
/* ---------- U6: Firewall page overview + navigator ---------- */
$fw2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fw2, 'class="fw-kpis"', 'U6: overview strip'); has($fw2, 'id="fwNav"', 'U6: section navigator');
foreach (['gr', 'gl', 'gh', 'gw', 'cbp', 'addip', 'layers', 'plan', 'deny', 'cfg', 'ports'] as $id) has($fw2, 'id="' . $id . '"', 'U6: card id ' . $id . ' exists for the navigator');
has($fw2, "function openCard(id, scroll)", 'U6: jumping to a section opens it');
hasnt($fw2, "smpro_gh_status()\n", 'U6: the overview reads config files only (no API on the render path)');
