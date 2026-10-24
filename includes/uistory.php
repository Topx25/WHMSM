<?php
/**
 * uistory.php - the investigation told in plain words.
 *
 * The timeline is 2,000 rows of evidence. An operator asked for the thing the rows are evidence OF: who came,
 * from where, what they did, and whether it mattered. That is a story, and a story has episodes: one address,
 * one stretch of time, one set of actions. So the events (timeline + file changes) are grouped by address, split
 * where the address falls silent for a while, and each episode is described in one sentence a person can read,
 * with its counts underneath and its rows one click away.
 *
 * Every number here is derived from the same events the tables show. Nothing is inferred that the rows do not
 * contain; where the page could not look (file changes blind, logins unreadable) the story says so instead of
 * describing an absence as calm.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_STORY_GAP')) define('SMPRO_STORY_GAP', 1800);       // 30 min of silence ends an episode

/** Country code for an address, through whichever helper this build has. '' when unknown. */
function smpro_story_cc(string $ip): string {
    static $cache = [];
    if ($ip === '' || isset($cache[$ip])) return $cache[$ip] ?? '';
    $cc = '';
    if (function_exists('smpro_geoip_cc'))      $cc = (string)smpro_geoip_cc($ip);
    elseif (function_exists('smpro_gl_country')) $cc = (string)smpro_gl_country($ip);
    return $cache[$ip] = strtoupper($cc);
}

/** Is this address one of the server's own (loopback / the host itself)? Those are the panel talking to itself. */
function smpro_story_is_self(string $ip): bool {
    if ($ip === '' || $ip === '127.0.0.1' || $ip === '::1') return true;
    static $mine = null;
    if ($mine === null) {
        $mine = [];
        $out = (string)@shell_exec('timeout 5 hostname -I 2>/dev/null');
        foreach (preg_split('/\s+/', trim($out)) ?: [] as $a) if ($a !== '') $mine[$a] = true;
    }
    return isset($mine[$ip]);
}

/**
 * Build the episodes.
 *   $events  the timeline rows from smpro_ui_collect()   (source, actor_ip, action, target, ts, severity, fx?)
 *   $fa      smpro_fa_events() result or null            (events: door, actor, ip, op, path, ts)
 */
function smpro_ui_story(array $events, ?array $fa, int $from, int $to): array {
    $byIp = [];
    $push = function (string $ip, array $e) use (&$byIp) { $byIp[$ip][] = $e; };

    foreach ($events as $e) {
        $ip = (string)($e['actor_ip'] ?? '');
        $src = (string)($e['source'] ?? '');
        $act = (string)($e['action'] ?? '');
        $kind = 'other';
        if ($src === 'login') {
            if (stripos($act, 'Successful') !== false)       $kind = 'login';
            elseif (stripos($act, 'Operator') !== false)      $kind = 'operator';
            elseif (stripos($act, 'Failed') !== false)        $kind = 'failed';
            else                                              $kind = 'login_other';
        } elseif ($src === 'cpanel_panel')       $kind = 'panel';
        elseif ($src === 'web_attack') {
            $o = (string)($e['fx']['outcome'] ?? '');
            $kind = ($o === 'reached') ? 'reached' : 'blocked';
        } elseif ($src === 'outbound_mail')      $kind = 'mail';
        elseif ($src === 'webshell_suspect')     $kind = 'webshell';
        $push($ip, ['ts' => (int)$e['ts'], 'kind' => $kind, 'what' => $act, 'detail' => (string)($e['target'] ?? ''), 'domain' => (string)($e['domain'] ?? '')]);
    }
    if (is_array($fa)) {
        foreach ((array)($fa['events'] ?? []) as $r) {
            $ip = (string)($r['ip'] ?? '');
            $push($ip, ['ts' => (int)$r['ts'], 'kind' => 'file', 'op' => (string)$r['op'], 'path' => (string)$r['path'],
                        'door' => (string)$r['door'], 'actor' => (string)$r['actor'], 'what' => $r['op'] . ' ' . $r['path']]);
        }
    }

    // ---- split every address's events into episodes at gaps of silence
    $episodes = [];
    foreach ($byIp as $ip => $list) {
        usort($list, fn($a, $b) => $a['ts'] <=> $b['ts']);
        $cur = null;
        foreach ($list as $e) {
            if ($cur === null || $e['ts'] - $cur['end'] > SMPRO_STORY_GAP) {
                if ($cur !== null) $episodes[] = $cur;
                $cur = ['ip' => (string)$ip, 'start' => $e['ts'], 'end' => $e['ts'], 'ev' => []];
            }
            $cur['end'] = max($cur['end'], $e['ts']);
            $cur['ev'][] = $e;
        }
        if ($cur !== null) $episodes[] = $cur;
    }

    // ---- describe each episode
    foreach ($episodes as &$ep) $ep = smpro_story_describe($ep);
    unset($ep);

    // Blocked-only attack episodes are the bulk of any window and say the same thing; they are folded into one
    // paragraph so the person-shaped episodes are not buried under two hundred cards that all read "blocked".
    $noise = []; $kept = [];
    foreach ($episodes as $ep) { if ($ep['class'] === 'blocked') $noise[] = $ep; else $kept[] = $ep; }
    usort($kept, fn($a, $b) => ($b['weight'] <=> $a['weight']) ?: ($b['start'] <=> $a['start']));

    $blocked = ['n' => 0, 'ips' => [], 'cc' => [], 'targets' => [], 'first' => 0, 'last' => 0];
    foreach ($noise as $ep) {
        $blocked['n'] += $ep['c']['blocked'];
        $blocked['ips'][$ep['ip']] = ($blocked['ips'][$ep['ip']] ?? 0) + $ep['c']['blocked'];
        if ($ep['cc'] !== '') $blocked['cc'][$ep['cc']] = ($blocked['cc'][$ep['cc']] ?? 0) + $ep['c']['blocked'];
        foreach ($ep['targets'] as $t => $n) $blocked['targets'][$t] = ($blocked['targets'][$t] ?? 0) + $n;
        $blocked['first'] = $blocked['first'] ? min($blocked['first'], $ep['start']) : $ep['start'];
        $blocked['last']  = max($blocked['last'], $ep['end']);
    }
    arsort($blocked['ips']); arsort($blocked['cc']); arsort($blocked['targets']);

    // ---- the bottom line
    $people = 0; $addrs = []; $ccs = []; $files = 0; $reached = 0; $failed = 0; $fileBy = [];
    foreach ($kept as $ep) {
        if (in_array($ep['class'], ['owner', 'operator', 'person'], true)) { $people++; if ($ep['ip'] !== '') $addrs[$ep['ip']] = 1; if ($ep['cc'] !== '') $ccs[$ep['cc']] = 1; }
        $files += $ep['c']['file']; $reached += $ep['c']['reached']; $failed += $ep['c']['failed'];
        foreach ($ep['doors'] as $d => $n) $fileBy[$d] = ($fileBy[$d] ?? 0) + $n;
    }
    $blind = [];
    if (is_array($fa) && empty($fa['ok'])) $blind[] = 'file changes: ' . (string)$fa['why'];
    if (is_array($fa) && !empty($fa['ok']) && !empty($fa['partial'])) $blind[] = 'file changes are only recorded from ' . gmdate('d M H:i', (int)$fa['covered_from']) . ' UTC onwards';

    // The web-attack collector returns at most 2,000 rows; a window that hits the cap has MORE than the story can
    // count, and a round 2,000 printed as exact would be read as exact.
    $attackRows = 0; foreach ($events as $e) if (($e['source'] ?? '') === 'web_attack') $attackRows++;
    if ($attackRows >= 2000) $blind[] = 'attack rows are capped at 2,000 in this window - the blocked count is a floor, not a total';
    return ['episodes' => $kept, 'blocked' => $blocked, 'blind' => $blind, 'capped' => $attackRows >= 2000, 'signins' => smpro_ui_signins($events, $fa),
            'bottom' => ['people' => $people, 'addrs' => count($addrs), 'ccs' => array_keys($ccs), 'files' => $files, 'file_by' => $fileBy,
                         'reached' => $reached, 'failed' => $failed, 'blocked' => $blocked['n'], 'blocked_ips' => count($blocked['ips'])]];
}

/** One episode -> its class, weight, counts, and the sentence. */
function smpro_story_describe(array $ep): array {
    $c = ['login' => 0, 'operator' => 0, 'failed' => 0, 'panel' => 0, 'blocked' => 0, 'reached' => 0, 'mail' => 0, 'webshell' => 0, 'file' => 0, 'other' => 0, 'login_other' => 0];
    $ops = []; $targets = []; $fileOps = []; $doors = []; $paths = []; $services = []; $actors = [];
    foreach ($ep['ev'] as $e) {
        $c[$e['kind']] = ($c[$e['kind']] ?? 0) + 1;
        if ($e['kind'] === 'panel') {
            // "POST Fileman::upload_files" -> "Fileman"
            $m = preg_match('/([A-Za-z0-9_]+)::([A-Za-z0-9_]+)/', $e['what'], $mm) ? $mm[1] : trim(preg_replace('/^(GET|POST|PUT|DELETE)\s+/', '', $e['what']));
            $ops[$m] = ($ops[$m] ?? 0) + 1;
        }
        if ($e['kind'] === 'blocked' || $e['kind'] === 'reached') {
            $t = $e['what'];                                         // e.g. "Sensitive File Access (403)"
            $t = trim(preg_replace('/\s*\(\d{3}\)\s*$/', '', $t));
            $targets[$t] = ($targets[$t] ?? 0) + 1;
        }
        if ($e['kind'] === 'login' || $e['kind'] === 'operator') { $s = preg_replace('/\s*\(.*$/', '', $e['detail']); if ($s !== '') $services[$s] = 1; }
        if ($e['kind'] === 'file') {
            $fileOps[$e['op']] = ($fileOps[$e['op']] ?? 0) + 1;
            $doors[$e['door']] = ($doors[$e['door']] ?? 0) + 1;
            if (count($paths) < 6 && !in_array($e['path'], $paths, true)) $paths[] = $e['path'];
            if ($e['actor'] !== '') $actors[$e['actor']] = 1;
        }
    }
    arsort($ops); arsort($targets);
    $ip = $ep['ip']; $cc = $ip !== '' ? smpro_story_cc($ip) : '';
    $self = $ip !== '' && smpro_story_is_self($ip);
    $who = $ip === '' ? 'Something with no network address' : ($self ? 'The server itself (' . $ip . ')' : $ip . ($cc !== '' ? ' (' . $cc . ')' : ''));

    // ---- classify
    $class = 'other'; $weight = 0;
    if ($c['login'] > 0 || $c['operator'] > 0 || $c['panel'] > 0 || ($c['file'] > 0 && $ip !== '')) {
        if ($c['login'] > 0)            { $class = 'owner';    $weight = 50; }      // signed in with the password
        elseif ($c['operator'] > 0)     { $class = 'operator'; $weight = 40; }      // WHM / root opened it
        else                            { $class = 'person';   $weight = 45; }      // acted through a person's door
        if ($c['file'] > 0)  $weight += 20;
        if ($c['failed'] > 3) $weight += 10;                                        // guessed before getting in
    } elseif ($c['file'] > 0 && $ip === '') { $class = 'machine'; $weight = 30; }   // web / cron changed files, no address
    elseif ($c['reached'] > 0 || $c['webshell'] > 0) { $class = 'reached'; $weight = 80 + min(20, $c['reached']); }   // above any person: this is the one to read first
    elseif ($c['failed'] >= 5)        { $class = 'bruteforce'; $weight = 35 + min(20, intdiv($c['failed'], 10)); }
    elseif ($c['mail'] > 0)           { $class = 'mail'; $weight = 30; }
    elseif ($c['blocked'] > 0 && $c['failed'] === 0) { $class = 'blocked'; $weight = 5; }
    elseif ($c['failed'] > 0)         { $class = 'failed'; $weight = 10; }

    // ---- the sentence
    $when = gmdate('d M H:i', $ep['start']) . ($ep['end'] - $ep['start'] > 60 ? '–' . gmdate($ep['end'] - $ep['start'] > 86400 ? 'd M H:i' : 'H:i', $ep['end']) : '') . ' UTC';
    $bits = [];
    if ($c['failed'] > 0)   $bits[] = $c['failed'] . ' failed sign-in' . ($c['failed'] > 1 ? 's' : '');
    if ($c['login'] > 0)    $bits[] = 'signed in with the account password' . (count($services) ? ' (' . implode(', ', array_keys($services)) . ')' : '') . ($c['login'] > 1 ? ' ×' . $c['login'] : '');
    if ($c['operator'] > 0) $bits[] = 'opened the account from WHM without the password' . ($c['operator'] > 1 ? ' ×' . $c['operator'] : '');
    if ($c['panel'] > 0)    $bits[] = 'ran ' . $c['panel'] . ' panel operation' . ($c['panel'] > 1 ? 's' : '') . ' (' . implode(', ', array_slice(array_keys($ops), 0, 4)) . (count($ops) > 4 ? ', …' : '') . ')';
    if ($c['file'] > 0) {
        $fo = [];
        foreach (['deleted', 'renamed', 'created', 'modified'] as $o) if (!empty($fileOps[$o])) $fo[] = $fileOps[$o] . ' ' . $o;
        $dl = ['cpanel' => 'File Manager', 'ftp' => 'FTP', 'sftp' => 'SFTP', 'shell' => 'SSH', 'web' => 'a web request (PHP)', 'cron' => 'cron', 'system' => 'a system process', 'other' => 'an unknown door'];
        $dn = array_map(fn($d) => $dl[$d] ?? $d, array_keys($doors));
        $bits[] = 'changed ' . $c['file'] . ' file' . ($c['file'] > 1 ? 's' : '') . ' through ' . implode(' and ', $dn) . ' (' . implode(', ', $fo) . ')' . (count($actors) === 1 && $ip !== '' ? ' as ' . array_key_first($actors) : '');
    }
    if ($c['reached'] > 0)  $bits[] = $c['reached'] . ' attack request' . ($c['reached'] > 1 ? 's' : '') . ' REACHED the site (not blocked): ' . implode(', ', array_slice(array_keys($targets), 0, 3));
    if ($c['blocked'] > 0)  $bits[] = $c['blocked'] . ' attack request' . ($c['blocked'] > 1 ? 's' : '') . ' blocked (' . implode(', ', array_slice(array_keys($targets), 0, 3)) . ')';
    if ($c['mail'] > 0)     $bits[] = $c['mail'] . ' outbound-mail event' . ($c['mail'] > 1 ? 's' : '');
    if ($c['webshell'] > 0) $bits[] = $c['webshell'] . ' web-shell-shaped request' . ($c['webshell'] > 1 ? 's' : '');
    $sentence = $who . ' — ' . $when . ': ' . ($bits ? implode('; ', $bits) : 'activity with nothing notable') . '.';

    $verdict = [
        'owner'      => 'Someone holding the password. If this is not the customer or a person they know, the password is compromised.',
        'operator'   => 'Access from the server side (WHM or root), not with the customer\'s password.',
        'person'     => 'A person acting through the panel or a file door without a recorded sign-in in this window.',
        'machine'    => 'Files changed by the site\'s own code or a scheduled job — no person, no address. Normal for caches; look closer if the paths are code.',
        'reached'    => 'Attack traffic that was NOT blocked. Check the file changes at these minutes.',
        'bruteforce' => 'Password guessing. Nothing got in from this address in the window.',
        'mail'       => 'Mail sent from the account without a sign-in — a script or a mailbox password.',
        'blocked'    => 'Blocked at the door. Nothing reached the site.',
        'failed'     => 'A few failed sign-ins — typos or a light probe.',
        'other'      => '',
    ][$class];

    return ['ip' => $ip, 'cc' => $cc, 'self' => $self, 'start' => $ep['start'], 'end' => $ep['end'], 'n' => count($ep['ev']),
            'class' => $class, 'weight' => $weight, 'c' => $c, 'ops' => $ops, 'targets' => $targets, 'doors' => $doors, 'paths' => $paths,
            'sentence' => $sentence, 'verdict' => $verdict, 'ev' => $ep['ev']];
}

/**
 * Who got in, and everything each of those addresses did in the window.
 *
 * The episodes above answer "what happened"; this answers the operator's narrower question: "show me only the
 * successful sign-ins, and for every address that got in, all of its actions". Not the 30-minute episode - ALL
 * of it, across the whole window, because an address that signed in on Monday and came back Thursday to
 * change files is one actor. Addresses that never signed in are not here at all.
 *
 * Returns a list ordered by most actions first:
 *   ip, cc, self, logins[] {ts, kind(password|operator), service}, panel[] {ts, op, detail}, files[] {ts, op, path, door, actor},
 *   mail[] {ts, detail}, attacks {blocked, reached}, first, last, n
 */
function smpro_ui_signins(array $events, ?array $fa): array {
    $in = [];
    foreach ($events as $e) {
        if (($e['source'] ?? '') !== 'login') continue;
        $act = (string)($e['action'] ?? ''); $ip = (string)($e['actor_ip'] ?? '');
        if ($ip === '') continue;
        $kind = stripos($act, 'Successful') !== false ? 'password' : (stripos($act, 'Operator') !== false ? 'operator' : '');
        if ($kind === '') continue;
        $in[$ip]['logins'][] = ['ts' => (int)$e['ts'], 'kind' => $kind, 'service' => trim(preg_replace('/\s*\(.*$/', '', (string)($e['target'] ?? '')))];
    }
    if (!$in) return [];
    foreach ($in as $ip => &$a) { $a += ['panel' => [], 'files' => [], 'mail' => [], 'attacks' => ['blocked' => 0, 'reached' => 0], 'ip' => $ip, 'cc' => smpro_story_cc($ip), 'self' => smpro_story_is_self($ip)]; }
    unset($a);
    foreach ($events as $e) {
        $ip = (string)($e['actor_ip'] ?? '');
        if (!isset($in[$ip])) continue;
        $src = (string)($e['source'] ?? '');
        if ($src === 'cpanel_panel') {
            $op = preg_match('/([A-Za-z0-9_]+::[A-Za-z0-9_]+)/', (string)$e['action'], $m) ? $m[1] : (string)$e['action'];
            $in[$ip]['panel'][] = ['ts' => (int)$e['ts'], 'op' => $op, 'detail' => (string)($e['target'] ?? '')];
        } elseif ($src === 'outbound_mail') {
            $in[$ip]['mail'][] = ['ts' => (int)$e['ts'], 'detail' => (string)($e['action'] ?? '')];
        } elseif ($src === 'web_attack') {
            $in[$ip]['attacks'][(($e['fx']['outcome'] ?? '') === 'reached') ? 'reached' : 'blocked']++;
        }
    }
    if (is_array($fa)) foreach ((array)($fa['events'] ?? []) as $r) {
        $ip = (string)($r['ip'] ?? '');
        if (!isset($in[$ip])) continue;
        $in[$ip]['files'][] = ['ts' => (int)$r['ts'], 'op' => (string)$r['op'], 'path' => (string)$r['path'], 'door' => (string)$r['door'], 'actor' => (string)$r['actor']];
    }
    $out = [];
    foreach ($in as $ip => $a) {
        $all = array_merge(array_column($a['logins'], 'ts'), array_column($a['panel'], 'ts'), array_column($a['files'], 'ts'), array_column($a['mail'], 'ts'));
        usort($a['logins'], fn($x, $y) => $x['ts'] <=> $y['ts']);
        usort($a['panel'],  fn($x, $y) => $x['ts'] <=> $y['ts']);
        usort($a['files'],  fn($x, $y) => $x['ts'] <=> $y['ts']);
        $a['first'] = $all ? min($all) : 0; $a['last'] = $all ? max($all) : 0;
        $a['n'] = count($a['panel']) + count($a['files']) + count($a['mail']);
        // what this address ran, by module, so a hundred list_files calls read as "Fileman x100" not a hundred lines
        $mods = [];
        foreach ($a['panel'] as $p) { $m = explode('::', $p['op'])[0]; $mods[$m] = ($mods[$m] ?? 0) + 1; }
        arsort($mods); $a['modules'] = $mods;
        $out[] = $a;
    }
    usort($out, fn($x, $y) => ($y['n'] <=> $x['n']) ?: ($y['last'] <=> $x['last']));
    return $out;
}

/** The story as plain text, for the report download. */
function smpro_ui_story_text(string $account, int $from, int $to, array $story): string {
    $b = $story['bottom'];
    $l = ['INVESTIGATION REPORT — ' . $account, 'Window: ' . gmdate('Y-m-d H:i', $from) . ' → ' . gmdate('Y-m-d H:i', $to) . ' UTC', ''];
    $l[] = 'BOTTOM LINE';
    $l[] = sprintf('  %d person session(s) from %d address(es)%s.', $b['people'], $b['addrs'], $b['ccs'] ? ' in ' . implode(', ', $b['ccs']) : '');
    $l[] = sprintf('  %d file change(s)%s.', $b['files'], $b['file_by'] ? ' (' . implode(', ', array_map(fn($k, $v) => "$v via $k", array_keys($b['file_by']), $b['file_by'])) . ')' : '');
    $l[] = sprintf('  %d attack request(s) blocked from %d address(es); %d reached the site; %d failed sign-in(s).', $b['blocked'], $b['blocked_ips'], $b['reached'], $b['failed']);
    foreach ($story['blind'] as $x) $l[] = '  COULD NOT LOOK: ' . $x;
    $l[] = '';
    $l[] = 'WHAT HAPPENED, BY EPISODE (most important first)';
    foreach ($story['episodes'] as $i => $ep) {
        $l[] = sprintf('%2d. %s', $i + 1, $ep['sentence']);
        if ($ep['verdict'] !== '') $l[] = '    → ' . $ep['verdict'];
        foreach ($ep['paths'] as $p) $l[] = '      file: ' . $p;
    }
    if (!empty($story['signins'])) {
        $l[] = '';
        $l[] = 'WHO SIGNED IN, AND EVERYTHING EACH ADDRESS DID';
        foreach ($story['signins'] as $s) {
            $l[] = sprintf('  %s%s%s - %d sign-in(s), %d panel operation(s), %d file change(s), %d mail event(s)', $s['ip'], $s['cc'] !== '' ? ' (' . $s['cc'] . ')' : '', $s['self'] ? ' [the server itself]' : '',
                           count($s['logins']), count($s['panel']), count($s['files']), count($s['mail']));
            foreach ($s['logins'] as $g) $l[] = sprintf('     %s  signed in  %-9s %s', gmdate('d M H:i:s', $g['ts']), $g['kind'], $g['service']);
            if ($s['modules']) $l[] = '     panel: ' . implode(', ', array_map(fn($k, $v) => "$k x$v", array_keys($s['modules']), $s['modules']));
            foreach (array_slice($s['files'], 0, 40) as $f) $l[] = sprintf('     %s  %-8s %s  [%s]', gmdate('d M H:i:s', $f['ts']), $f['op'], $f['path'], $f['door']);
            if (count($s['files']) > 40) $l[] = '     ... and ' . (count($s['files']) - 40) . ' more file changes';
        }
    }
    if ($story['blocked']['n'] > 0) {
        $bl = $story['blocked'];
        $l[] = '';
        $l[] = sprintf('BLOCKED ATTACK TRAFFIC: %d request(s) from %d address(es) between %s and %s UTC — all refused at the door.',
            $bl['n'], count($bl['ips']), gmdate('d M H:i', $bl['first']), gmdate('d M H:i', $bl['last']));
        $l[] = '  what they tried: ' . implode('; ', array_map(fn($k, $v) => "$k ($v)", array_slice(array_keys($bl['targets']), 0, 5), array_slice($bl['targets'], 0, 5)));
        $l[] = '  top addresses: ' . implode(', ', array_map(fn($k, $v) => "$k ($v)", array_slice(array_keys($bl['ips']), 0, 8), array_slice($bl['ips'], 0, 8)));
        if ($bl['cc']) $l[] = '  countries: ' . implode(', ', array_map(fn($k, $v) => "$k ($v)", array_slice(array_keys($bl['cc']), 0, 8), array_slice($bl['cc'], 0, 8))) . (count($bl['cc']) > 8 ? ' and ' . (count($bl['cc']) - 8) . ' more' : '');
    }
    return implode("\n", $l) . "\n";
}
