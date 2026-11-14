<?php
/**
 * Origin watch (report-only).
 * One licence is one machine, and one machine checks in from one address. The address read here is the one the
 * connection really came from, never the one the client reports about itself. Two addresses of the same family
 * that BOTH keep checking in over the same stretch of the last hour mean the licence is running in two places
 * with a copied identity. Nothing is stopped: one log row a day (the panel already lists this result) and a dated
 * note on the licence, for a person to review.
 *  - a machine that answers over IPv4 and IPv6 is one origin: the families are counted apart, IPv6 by its /64
 *  - a plain address change is not a signal: the old address stops before the new one starts (no overlap)
 */
function smlic_origin_watch(string $licenseKey, int $licId): void {
    if ($licenseKey === '' || $licId <= 0) return;
    $q = db()->prepare("SELECT request_ip, COUNT(*) n, UNIX_TIMESTAMP(MIN(created_at)) t0, UNIX_TIMESTAMP(MAX(created_at)) t1
                        FROM license_logs
                        WHERE license_key=? AND result='ok' AND action IN ('check','license-check') AND request_ip<>''
                          AND created_at >= (NOW() - INTERVAL 60 MINUTE)
                        GROUP BY request_ip");
    if (!$q) return;
    $q->bind_param('s', $licenseKey); $q->execute();
    $res = $q->get_result(); $fam = [4 => [], 6 => []];
    while ($res && ($x = $res->fetch_assoc())) {
        $ip = (string)$x['request_ip']; $n = (int)$x['n']; $t0 = (int)$x['t0']; $t1 = (int)$x['t1'];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $f = 4; $k = $ip; }
        elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $p = @inet_pton($ip); if ($p === false) continue; $f = 6; $k = bin2hex(substr($p, 0, 8)); }
        else continue;
        if (!isset($fam[$f][$k])) $fam[$f][$k] = ['n' => 0, 't0' => $t0, 't1' => $t1];
        $fam[$f][$k]['n'] += $n; $fam[$f][$k]['t0'] = min($fam[$f][$k]['t0'], $t0); $fam[$f][$k]['t1'] = max($fam[$f][$k]['t1'], $t1);
    }
    $q->close();
    $found = 0;
    foreach ($fam as $set) {
        $set = array_values(array_filter($set, fn($o) => $o['n'] >= 3));           // an origin that checked in several times
        $c = count($set);
        for ($i = 0; $i < $c; $i++) for ($j = $i + 1; $j < $c; $j++)
            if ($set[$i]['t0'] < $set[$j]['t1'] && $set[$j]['t0'] < $set[$i]['t1']) $found = max($found, 2);   // both active over the same stretch
        if ($found && $c > 2) $found = max($found, $c);
    }
    if ($found < 2) return;
    $seen = 0;
    if ($s = db()->prepare("SELECT COUNT(*) FROM license_logs WHERE license_key=? AND result='clone_suspected' AND message LIKE 'Origin watch:%' AND created_at >= CURDATE()")) {
        $s->bind_param('s', $licenseKey); $s->execute(); $s->bind_result($seen); $s->fetch(); $s->close();
    }
    if ((int)$seen > 0) return;                                                       // one row a day per licence
    log_event($licenseKey, 'check', 'clone_suspected', 'Origin watch: this licence checked in from ' . $found . ' different addresses over the same hour, each several times - it may be running on more than one machine.', []);
    $mark = '[origins? ' . date('Y-m-d') . ']';
    if ($u = db()->prepare("UPDATE licenses SET notes = TRIM(CONCAT_WS(' ', COALESCE(NULLIF(notes,''),''), ?)) WHERE id=? AND (notes IS NULL OR notes NOT LIKE ?)")) {
        $like = '%' . $mark . '%';
        $u->bind_param('sis', $mark, $licId, $like); $u->execute(); $u->close();
    }
}
