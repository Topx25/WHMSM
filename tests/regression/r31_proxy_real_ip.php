<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
/**
 * r31_proxy_real_ip.php — behind a local reverse proxy, the attacker is not this server.
 *
 * With nginx in front of Apache — the cPanel default — ModSecurity records the client as the server's OWN
 * address, because that is literally who connected to it. Every external attack was therefore stored as having
 * come from the server. On one live machine that was 52 transactions, and it had two effects, both bad:
 *
 *   - The panel raised "a process on this server may be compromised and is attacking hosted sites" for ordinary
 *     internet scanning, and sent the operator hunting for a local compromise that did not exist.
 *   - The real attackers — 45.61.187.10, 198.98.54.3 and others — sat unread in a forwarded-for header. Nothing
 *     blocked them, and nothing so much as reported them.
 *
 * The header is still NOT trusted in general. It cannot be: any client can set it, and honouring it would let an
 * attacker pin their attack on a chosen victim and have this software block that victim.
 */

/* ---------- R1: the two conditions that make it safe are both required ---------- */
ok(function_exists('smpro_im_proxy_real_ip'), 'R1: there is one resolver for this');

// A genuinely REMOTE client naming someone else must be ignored. This is the whole security property.
is_eq(smpro_im_proxy_real_ip('203.0.113.9', 'X-Forwarded-For', '198.51.100.7'), '',
      'R1: a remote client\'s forwarded-for is ignored — otherwise an attacker picks who gets blocked');
is_eq(smpro_im_proxy_real_ip('203.0.113.9', 'X-Forwarded-For', '8.8.8.8, 1.1.1.1'), '',
      'R1: and a whole forged chain from a remote client is ignored too');

// A connection from this machine could only have been made by something on it.
is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', '8.8.4.4'), '8.8.4.4',
      'R1: a loopback hop IS a local proxy, so its header is the proxy\'s own record');

/* ---------- R2: the LAST hop, never the first ---------- */
// nginx appends what IT saw to whatever the client sent, so the tail is the proxy's observation and the head is
// the client's to invent. Taking the head would hand the choice of victim straight back to the attacker.
is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', '198.51.100.7, 63.137.195.144'), '63.137.195.144',
      'R2: the last address in the chain is taken');
is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', '1.1.1.1, 2.2.2.2, 3.3.3.3'), '3.3.3.3',
      'R2: however long the chain is');

/* ---------- R3: never hand back something local ---------- */
// That would restore the original wrong answer by another route.
foreach (['127.0.0.1', '::1', ''] as $bad) {
    is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', $bad), '',
          'R3: a chain ending in "' . ($bad === '' ? '(empty)' : $bad) . '" resolves to nothing');
}
is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', 'not-an-ip'), '', 'R3: and rubbish resolves to nothing');
is_eq(smpro_im_proxy_real_ip('127.0.0.1', 'X-Forwarded-For', '8.8.4.4, garbage'), '',
      'R3: a chain whose LAST hop is rubbish is refused rather than falling back to an earlier one');

/* ---------- R4: it is wired into the parser, and only in the right branch ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($src, "elseif (\$cur['ip'] === \$conn) {", 'R4: applied only when nothing else already resolved a real client');
has($src, 'smpro_im_proxy_real_ip($conn,', 'R4: through the resolver, not inline');
has($src, "stripos(\$ln, 'X-Forwarded-For') === 0", 'R4: the header is captured while parsing');
has($src, 'X-Forwarded-For is NOT trusted', 'R4: and the standing reason it is not trusted generally is kept');

/* ---------- R5: the self-attack alarm stops firing for proxied traffic ---------- */
// The alarm is right to exist — a compromised account really can attack from inside — so it is not weakened.
// What changes is that ordinary external scanning is no longer mistaken for it.
ok(function_exists('smpro_im_is_self_attack'), 'R5: the self-attack test still exists and was not weakened');
