<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t89_ipwhy_imunify.php — "Why is an IP blocked?" looks at Imunify360 too.
 *
 * A customer could not open the sites. The report said "NOT blocked" - true of CSF, which held nothing - while
 * Imunify360 had the address on its gray list and WebShield served its challenge page instead of the site. The
 * operator added the address to the allow list "so it would work", and it worked because Allow also puts the
 * address on Imunify's white list. The report now reads Imunify's lists, incidents and console decisions, and
 * names that layer in the verdict.
 */
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/reports-center.php'));
has($m, "foreach (['white', 'black', 'gray'] as \$lname) {", 'U1: Imunify\'s three lists are read and matched for the address (the agent has no per-address query)');
hasnt($m, 'get --by-ip', 'U1: the command the agent does not have is gone');
has($m, "smpro_in_cidr_match(\$ip, \$entry)", 'U1: a CIDR entry that contains the address counts');
has($m, "list incidents --by-abuser", 'U1: and its incidents');
has($m, "/var/log/imunify360/console.log", 'U1: and its own decisions');
has($m, "if (\$ln === 'GRAY')  \$im['graylisted']  = true;", 'U2: gray list is recognised');
has($m, "'Imunify360 gray list (WebShield challenge / splash page)'", 'U2: and counted as a block, because the customer feels it as one');
has($m, "CHALLENGED by Imunify360 (gray list)", 'U3: the verdict names the layer');
has($m, "CSF holds nothing for this address", 'U3: and says CSF is not the cause');
has($m, "and Imunify360 has it on no list.", 'U3: a genuinely clear address is said to be clear on BOTH layers');
has($m, "WebShield is on", 'U3: and WebShield being on is stated when the address is not white-listed');
$posIm = strpos($m, "// 5b) Imunify360"); $posV = strpos($m, "// 7) verdict + fix");
ok($posIm !== false && $posV !== false && $posIm < $posV, 'U4: Imunify is read before the verdict is written');
has($m, '<b>Imunify360</b>', 'U5: the page renders the Imunify block');
