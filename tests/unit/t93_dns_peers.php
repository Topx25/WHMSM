<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/domains.php';
/**
 * t93_dns_peers.php — the DNS-cluster peer reader takes only the peer files, never cPanel's sibling files, and
 * the health probe is served from a memo on the render path.
 */
$sb = $GLOBALS['__sandbox']; $d = $sb . '/cluster/root/config'; @mkdir($d, 0700, true);
foreach (['46.224.153.156', '46.224.153.156.cache', '46.224.153.156-dnsrole', '46.224.153.156-state.json', 'ns2.example.test', 'ns2.example.test-dnsrole', 'ns2.example.test-state.json', '.hidden', 'x.tmp'] as $f) file_put_contents($d . '/' . $f, "dnsrole=write-only\n");
file_put_contents($sb . '/useclusteringdns', '1');
$peers = smpro_dns_cluster_peers($sb . '/cluster/*/config/*', $sb . '/useclusteringdns');
is_eq(array_column($peers, 'host'), ['46.224.153.156', 'ns2.example.test'], 'U1: only the two real peers - not .cache, -dnsrole, -state.json, hidden or temp files');
is_eq($peers[0]['role'], 'write-only', 'U1: the role is read from the peer file');
is_eq(smpro_dns_cluster_peers($sb . '/cluster/*/config/*', $sb . '/no-such-switch'), [], 'U1: clustering off = no peers, no probes');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/domains.php'));
has($src, "smpro_memo('dns_cluster_health_' . \$slowMs, 300", 'U2: the probe result is memoised for five minutes on the render path');
has($src, 'function smpro_dns_cluster_health_live', 'U2: ...with the live probe still callable');
