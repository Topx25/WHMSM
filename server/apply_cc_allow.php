<?php
/** One-shot: add Arab countries to CSF CC_ALLOW (never-block) + fix MM_LICENSE_KEY + csf -r.
 *  Backs up csf.conf. Read result from stdout. Delete after. */
if (PHP_SAPI !== 'cli') exit("cli only\n");
$conf = '/etc/csf/csf.conf';
if (!is_writable($conf)) { fwrite(STDERR, "csf.conf not writable\n"); exit(1); }
$ARAB = ['SA','EG','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'];
$val = implode(',', $ARAB);

function csf_set(&$c, $k, $v) {
    $line = $k . ' = "' . $v . '"';
    if (preg_match('/^[ \t]*' . preg_quote($k,'/') . '[ \t]*=.*$/m', $c))
        $c = preg_replace('/^[ \t]*' . preg_quote($k,'/') . '[ \t]*=.*$/m', $line, $c, 1);
    else $c .= "\n" . $line . "\n";
}

$content = file_get_contents($conf);
$bak = $conf . '.smpro.ccbak_' . date('Ymd_His');
copy($conf, $bak);
echo "backup: $bak\n";

if (preg_match('/^[ \t]*MM_LICENSE_KEY[ \t]*=[ \t]*"([^"]*)"/m', $content, $mm)) {
    $clean = trim($mm[1]);
    csf_set($content, 'MM_LICENSE_KEY', $clean);
    echo "MM_LICENSE_KEY trimmed (had " . (strlen($mm[1]) - strlen($clean)) . " stray space(s))\n";
}
csf_set($content, 'CC_ALLOW', $val);
csf_set($content, 'CC_ALLOW_FILTER', '');
file_put_contents($conf, $content);
echo "CC_ALLOW set to: $val\n";

$csf = is_executable('/usr/sbin/csf') ? '/usr/sbin/csf' : '/usr/local/csf/bin/csf';
echo "=== csf -r (reload) ===\n";
$out = (string)shell_exec('timeout 90 ' . escapeshellarg($csf) . ' -r 2>&1');
// surface any GeoIP / CC errors
foreach (explode("\n", $out) as $l) {
    if (stripos($l, 'error') !== false || stripos($l, 'CC_ALLOW') !== false || stripos($l, 'geoip') !== false || stripos($l, 'maxmind') !== false)
        echo "  " . trim($l) . "\n";
}
echo "=== verify ===\n";
echo "CC_ALLOW now: " . trim((string)shell_exec("grep -m1 '^CC_ALLOW ' $conf")) . "\n";
echo "csf allow ipset (cc) count: " . trim((string)shell_exec("csf -g 2>/dev/null; ipset list 2>/dev/null | grep -c . || echo n/a")) . "\n";
echo "DONE\n";
