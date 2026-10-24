<?php
/**
 * pkg.php - one-click installer for the optional HELPER tools the plugin can use (cpulimit, lm-sensors,
 * whois, curl, e2fsprogs/chattr). Lets the UI show a real "Install" button instead of only telling the
 * admin to run a command by hand. Whitelisted tools only; runs the host package manager (apt/dnf/yum/
 * zypper) as root (this is a WHM root plugin); best-effort, bounded, audited. install.sh installs these
 * at setup time too - this is the after-setup path for anything still missing (or a newer server).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

// tool key => { check binary, per-manager package name, needs EPEL?, human label }
function smpro_pkg_catalog(): array {
    return [
        'cpulimit' => ['check' => 'cpulimit', 'apt' => 'cpulimit',  'dnf' => 'cpulimit',  'yum' => 'cpulimit',  'zypper' => 'cpulimit',  'epel' => true,  'label' => 'cpulimit — real CPU cap for Cooler mode / Auto Load Guard'],
        'sensors'  => ['check' => 'sensors',  'apt' => 'lm-sensors', 'dnf' => 'lm_sensors', 'yum' => 'lm_sensors', 'zypper' => 'sensors',   'epel' => false, 'label' => 'lm-sensors — header temperature gauge'],
        'whois'    => ['check' => 'whois',    'apt' => 'whois',     'dnf' => 'whois',     'yum' => 'whois',     'zypper' => 'whois',     'epel' => false, 'label' => 'whois — IP intelligence'],
        'curl'     => ['check' => 'curl',     'apt' => 'curl',      'dnf' => 'curl',      'yum' => 'curl',      'zypper' => 'curl',      'epel' => false, 'label' => 'curl — AI / Telegram / WhatsApp notifications'],
        'chattr'   => ['check' => 'chattr',   'apt' => 'e2fsprogs', 'dnf' => 'e2fsprogs', 'yum' => 'e2fsprogs', 'zypper' => 'e2fsprogs', 'epel' => false, 'label' => 'chattr/lsattr — PHP-Harden file locking'],
        // Site Doctor "Optimize" image tools (group=image) - auto-installed on demand so image/WebP become one-click.
        'jpegoptim' => ['check' => 'jpegoptim', 'apt' => 'jpegoptim', 'dnf' => 'jpegoptim', 'yum' => 'jpegoptim', 'zypper' => 'jpegoptim', 'epel' => true, 'group' => 'image', 'label' => 'jpegoptim — lossless JPEG recompression'],
        'optipng'   => ['check' => 'optipng',   'apt' => 'optipng',   'dnf' => 'optipng',   'yum' => 'optipng',   'zypper' => 'optipng',   'epel' => true, 'group' => 'image', 'label' => 'optipng — lossless PNG recompression'],
        'gifsicle'  => ['check' => 'gifsicle',  'apt' => 'gifsicle',  'dnf' => 'gifsicle',  'yum' => 'gifsicle',  'zypper' => 'gifsicle',  'epel' => true, 'group' => 'image', 'label' => 'gifsicle — GIF optimization'],
        'cwebp'     => ['check' => 'cwebp',      'apt' => 'webp',      'dnf' => 'libwebp-tools', 'yum' => 'libwebp-tools', 'zypper' => 'libwebp-tools', 'epel' => true, 'group' => 'image', 'label' => 'cwebp (libwebp-tools) — WebP conversion'],
    ];
}

// Is the host package manager currently busy (a transaction in flight - e.g. cPanel's upcp / dnf-automatic)?
// We NEVER wait behind or kill it; if busy, the installer returns busy=true and changes nothing.
function smpro_pkg_mgr_busy(): bool {
    $out = trim((string) @shell_exec("timeout 5 sh -c 'pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 || pgrep -x rpm >/dev/null 2>&1 || pgrep -x packagekitd >/dev/null 2>&1 || fuser /var/lib/rpm/.rpm.lock /run/dnf.pid /var/run/yum.pid >/dev/null 2>&1; echo $?'"));
    return $out === '0';   // sh's last exit 0 => one of the checks matched => busy
}

// Install a WHOLE whitelisted GROUP of tools in ONE transaction (used by Site Doctor Optimize for the
// 'image' group). Idempotent, lock-safe, EPEL scoped to THIS transaction only (never runs dnf update),
// bounded, honest partial-success. Returns ['ok','already','busy','installed'=>[per-tool bool],'msg'].
function smpro_pkg_install_group(string $group): array {
    if (!in_array($group, ['image'], true)) return ['ok' => false, 'msg' => 'Unknown tool group.'];   // whitelist only ('minify' deliberately excluded)
    $cat = smpro_pkg_catalog();
    $members = array_filter($cat, fn($t) => ($t['group'] ?? '') === $group);
    if (!$members) return ['ok' => false, 'msg' => 'No tools in that group.'];
    // idempotent: already all present?
    $have = []; foreach ($members as $k => $t) $have[$k] = smpro_pkg_have($t['check']);
    if (!in_array(false, $have, true)) return ['ok' => true, 'already' => true, 'installed' => $have, 'msg' => 'Image tools are already installed.'];
    if (smpro_pkg_mgr_busy()) return ['ok' => false, 'busy' => true, 'installed' => $have, 'msg' => 'The server package manager is busy (a system update is running). Try again in a few minutes.'];

    // FIXED literal package list per manager (zero scan/user input reaches the shell).
    if (smpro_pkg_have('dnf')) {
        $pkgs = 'jpegoptim optipng gifsicle libwebp-tools';
        $cmd = 'dnf install -y epel-release >/dev/null 2>&1 || dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel 2>/dev/null).noarch.rpm" >/dev/null 2>&1; '
             . 'dnf --enablerepo=epel --setopt=install_weak_deps=False install -y ' . $pkgs;   // EPEL scoped to THIS transaction; never dnf update
    } elseif (smpro_pkg_have('yum')) {
        $pkgs = 'jpegoptim optipng gifsicle libwebp-tools';
        $cmd = 'yum install -y epel-release >/dev/null 2>&1 || yum install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel 2>/dev/null).noarch.rpm" >/dev/null 2>&1; '
             . 'yum --enablerepo=epel install -y ' . $pkgs;
    } elseif (smpro_pkg_have('apt-get')) {
        $cmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y jpegoptim optipng gifsicle webp';
    } elseif (smpro_pkg_have('zypper')) {
        $cmd = 'zypper -n install jpegoptim optipng gifsicle libwebp-tools';
    } else {
        return ['ok' => false, 'installed' => $have, 'msg' => 'No supported package manager (dnf/yum/apt/zypper) — install jpegoptim optipng gifsicle libwebp-tools manually.'];
    }
    // -k 10 240: hard wall-clock cap; the busy pre-check + bounded timeout keep a hung dnf from blocking the request.
    $log = (string) @shell_exec('timeout -k 10 240 sh -c ' . escapeshellarg($cmd) . ' 2>&1');
    clearstatcache();
    $now = []; foreach ($members as $k => $t) $now[$k] = smpro_pkg_have($t['check']);
    $allNow = !in_array(false, $now, true);
    $newly = []; foreach ($now as $k => $v) if ($v && empty($have[$k])) $newly[] = $k;
    if (function_exists('smpro_audit')) smpro_audit('sitedoctor_optimize_install', ['group' => $group, 'ok' => $allNow, 'newly' => implode(',', $newly)]);
    $tail = trim(mb_substr($log, -400));
    return ['ok' => $allNow, 'already' => false, 'installed' => $now, 'newly' => $newly,
        'msg' => $allNow ? ('Installed image tools: ' . implode(', ', array_keys($members)) . '. You can now optimize images and generate WebP.')
                         : (count($newly) ? ('Installed ' . implode(', ', $newly) . '. Some tools are still missing — the ones that installed are now usable; retry or install the rest manually.' . ($tail ? ' [' . $tail . ']' : ''))
                                          : ('Could not install the image tools automatically (repo/network). Install them via SSH: dnf install -y jpegoptim optipng gifsicle libwebp-tools.' . ($tail ? ' [' . $tail . ']' : '')))];
}

function smpro_pkg_have(string $bin): bool {
    return trim((string) @shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null')) !== '';
}

// Fallback: install the cpulimit binary SHIPPED WITH THE PLUGIN (static, no repo, no network) - for
// servers that can't reach EPEL/mirrors (the exact "could not be installed" case). Placed in
// /usr/local/bin because the plugin dir may be mounted noexec.
function smpro_pkg_bundled_cpulimit(): bool {
    $bin = SMPRO_BASE . '/bin/cpulimit-bundle/cpulimit';
    if (!is_file($bin)) return false;
    $dst = '/usr/local/bin/cpulimit';
    if (!@copy($bin, $dst)) @shell_exec('cp -f ' . escapeshellarg($bin) . ' ' . escapeshellarg($dst) . ' 2>/dev/null');
    @chmod($dst, 0755);
    $runs = is_executable($dst) && stripos((string) @shell_exec('timeout 5 ' . escapeshellarg($dst) . ' --help 2>&1'), 'usage') !== false;
    if (function_exists('smpro_audit')) smpro_audit('pkg_bundled_cpulimit', ['ok' => $runs]);
    return $runs || smpro_pkg_have('cpulimit');
}

// Current install state of every catalog tool (for status UIs).
function smpro_pkg_status(): array {
    $out = [];
    foreach (smpro_pkg_catalog() as $k => $t) $out[$k] = ['present' => smpro_pkg_have($t['check']), 'label' => $t['label']];
    return $out;
}

// Install one whitelisted tool via the host package manager. Returns ['ok','installed','msg'].
function smpro_pkg_install(string $tool): array {
    $cat = smpro_pkg_catalog();
    $t = $cat[$tool] ?? null;
    if (!$t) return ['ok' => false, 'msg' => 'Unknown tool.'];
    if (smpro_pkg_have($t['check'])) return ['ok' => true, 'installed' => true, 'msg' => ucfirst($tool) . ' is already installed.'];

    if (smpro_pkg_have('apt-get')) {
        $cmd = 'DEBIAN_FRONTEND=noninteractive apt-get install -y ' . escapeshellarg($t['apt']);
    } elseif (smpro_pkg_have('dnf')) {
        // EPEL fallback chain: repo package, else the canonical EPEL-latest RPM by URL (works when epel-release isn't in the base repos).
        $epel = !empty($t['epel']) ? 'dnf install -y epel-release >/dev/null 2>&1 || dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel 2>/dev/null).noarch.rpm" >/dev/null 2>&1; ' : '';
        $cmd = $epel . 'dnf install -y ' . escapeshellarg($t['dnf']);
    } elseif (smpro_pkg_have('yum')) {
        $epel = !empty($t['epel']) ? 'yum install -y epel-release >/dev/null 2>&1 || yum install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel 2>/dev/null).noarch.rpm" >/dev/null 2>&1; ' : '';
        $cmd = $epel . 'yum install -y ' . escapeshellarg($t['yum']);
    } elseif (smpro_pkg_have('zypper')) {
        $cmd = 'zypper -n install ' . escapeshellarg($t['zypper']);
    } else {
        return ['ok' => false, 'msg' => 'No supported package manager found (apt/dnf/yum/zypper) — install ' . $tool . ' manually.'];
    }

    @shell_exec('timeout 180 sh -c ' . escapeshellarg($cmd) . ' >/dev/null 2>&1');
    $ok = smpro_pkg_have($t['check']);
    if (!$ok && $tool === 'cpulimit') $ok = smpro_pkg_bundled_cpulimit();   // ship-with-plugin static binary - no repo/network needed
    if (function_exists('smpro_audit')) smpro_audit('pkg_install', ['tool' => $tool, 'ok' => $ok]);
    $failMsg = $tool === 'cpulimit'
        ? 'cpulimit could not be installed (repo/network) — no problem: the plugin uses its BUILT-IN CPU throttle instead, so the cap still works. Retry later for slightly lower overhead.'
        : (ucfirst($tool) . ' could not be installed automatically (repo/network). It will be retried on the next plugin update, or install it manually.');
    return ['ok' => $ok, 'installed' => $ok, 'msg' => $ok ? (ucfirst($tool) . ' installed successfully.') : $failMsg];
}
