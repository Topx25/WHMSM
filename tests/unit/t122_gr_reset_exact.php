<?php
require __DIR__ . '/../support/bootstrap.php';
/** t122 - a bulk password reset changes exactly the ticked identities: a mailbox changes only itself, an account only its own password; all mailboxes only on an explicit choice. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$g = $r('includes/georeport.php');
has($g, "function smpro_gr_reset_bulk(array \$users, string \$reason, string \$by, bool \$allMailboxes = false): array {", 'U1: every-mailbox expansion is OFF by default');
has($g, "\$r = smpro_gr_set_mail_password(\$p['owner'], \$p['id'], \$pw);", 'U2: a ticked mailbox changes that mailbox only');
has($g, "\$r = smpro_gr_set_password(\$p['id'], \$pw);", 'U3: a ticked account changes the account password');
has($g, "if (\$allMailboxes && \$p['kind'] === 'account') {", 'U4: siblings only for a ticked ACCOUNT and only when chosen');
hasnt($g, "\$targets[\$o['account']][] = \$u;", 'U5: a mailbox is never escalated to its owning account');
has($g, "At most 200 identities in one reset - nothing was changed.", 'U6: over the cap refuses whole, never silently trims');
$fw = $r('modules/firewall-status.php');
has($fw, "(string)(\$_POST['all_mailboxes'] ?? '') === '1')", 'U7: the page passes the explicit choice');
has($fw, 'id="grAllBoxes"', 'U7: ...from an unticked box');
has($fw, "var exact='\\n\\nExactly these change, nothing else:'", 'U8: the dialog names every identity that will change');
