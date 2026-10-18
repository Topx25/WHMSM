# Safety Monitor Pro (smpro) — Full Source & Documentation

> Unobfuscated production source + complete reference. Current version: **1.0.51**.
> Codename history: `smprov1` → renamed to **`smpro`** (slug, paths, function prefix `smpro_`).
> Build directory name stays `smprov1_build` for history; the code inside is **smpro**.

---

## 1. What it is
A self-contained **WHM/cPanel security & monitoring plugin** (root WHM addon) plus a **license server**
(`plugins.hostguard.org` / direct host `dl.hostguard.org`). The plugin adapts to whatever is installed on the
host (cPanel, Imunify360, CSF, Exim, JetBackup, CloudLinux…) — missing pieces only disable the feature
that needs them, never break the rest.

- **Read-only by default.** Every state-changing action is POST + CSRF + root + audit-logged, reversible,
  and never bypasses Cloudflare or touches another product's files.
- **Licensed** per server via a hardware fingerprint (`sha256(machine-id | hostname | SALT)`), validated
  live against the license server; in-plugin self-update.
- **AI-assisted** (free-first providers, OpenAI-compatible) with a fallback chain so tokens never exhaust.

---

## 2. Repository layout (this archive)
```
includes/        core engine (boot, auth, license, intrusion, ai, notify, layout, menu, …)
modules/         one file per UI page (dashboard, intrusion-monitor, server-tuning, …)
bin/             cron workers (notify_check.php, tgbot_poll.php, cooler_tick.php)
assets/          (app.js/app.css were MailShield-derived and REMOVED; styling is in layout.php)
lang/            i18n strings
packaging/       install.sh, uninstall.sh, smpro.conf (AppConfig), smpro.png (icon), README
server/          LICENSE-SERVER source (auth_otp.php, mailer.php, wa_link.php, download/update ext)
index.php        front controller / router (page routing + JSON endpoints)
index.cgi        bash wrapper that sets env and runs index.php under WHM
DOCUMENTATION.md this file
```
> Build artifacts (`_obf_src/ _obf_out/ _pkg/ *.tar.gz`) and secrets are excluded — see `.gitignore`.

---

## 3. Core includes (`includes/`)
- **defines.php** — single source of truth: `SMPRO_SLUG=smpro`, `SMPRO_VERSION`, paths
  `SMPRO_VARLIB=/var/lib/smpro`, `SMPRO_VARLOG=/var/log/smpro`, audit log, resource limits.
- **env.php** — capability detection (`smpro_capabilities`, `smpro_missing_capabilities`,
  `smpro_env_install`); the header "missing components" banner with one-click installs. **CSF installs as
  the `cpanel-csf` package** (NOT `csf`) on cPanel.
- **helpers.php** — `smpro_h`, `smpro_collect_metrics` (load/cpu/ram/disk/swap), `smpro_top_processes`,
  audit, misc.
- **license.php** — fingerprint, `smpro_lic_*` (check/activate/heartbeat/authorized), `SMPRO_LIC_BASE=https://dl.hostguard.org`,
  fixed salt `SMPRO_LIC_FP_SALT='smprov1'` (decoupled from slug so renames never break licenses).
- **auth.php / csrf.php** — WHM root ACL gate, signed CSRF tokens (1h TTL). `smpro_fail()` returns JSON on
  JSON endpoints, HTML otherwise (so AJAX gets parseable errors, not "Request failed").
- **secret.php** — AES-256-GCM at-rest encryption for notify secrets (`/var/lib/smpro/.secret.key`).
- **intrusion.php** — live web-attack detection from ModSecurity audit log; emergency auto-block of
  scanners; verified-crawler guard (forward-confirmed rDNS); auto-block (CSF/Cloudflare).
- **ai.php** — `smpro_ai_ready`, `smpro_ai_chat` (multi-candidate **fallback chain**: series=primary-first,
  parallel=round-robin to spread quota), `smpro_ai_exec_mode`, decision packs for executable AI actions.
- **ai_catalog.php** — provider catalog (groq/cerebras free, gemini/openrouter/mistral/qwen free-limited,
  openai paid); live model fetch via token (`/models`, filtered to chat-capable, drops inactive),
  multi-select, **probe-based verify** (`smpro_ai_provider_verify` keeps only API-accepted models + reads
  real `x-ratelimit-*` limits), "select all free", masked tokens, usage tracking.
- **notify.php** — alert types + thresholds, channels (email/SMTP, Telegram, Pushbullet, WhatsApp/WAHA),
  `smpro_notify` dispatch (deduped, remind window), load-cause in high-load alerts.
- **digest.php** — "Grouped alerts" quiet mode: batch routine alerts into one periodic digest; **load &
  AI-classified "maximum danger" bypass immediately**; `smpro_dg_ai_classify` lets the AI pick critical types.
- **reports.php** — scheduled security+health reports (daily/3-day/weekly/monthly/custom + channels).
- **tuning.php** — Server Tune-up: detect engines (Apache/Nginx/MySQL-MariaDB/CSF/CloudLinux/Imunify/PHP/SSH),
  recommend perf/security fixes with **accessibility ("can lock you out") warnings**, AI optimization,
  timestamped config backups + profiles, install `cpanel-csf`.
- **cooler.php** — **Cooler mode + auto load guard**: detect the load source, throttle (renice/ionice, or
  `cpulimit` cap) for a duration, auto-revert. **Hard safety invariant:** never throttles web/db/mail/DNS/SSH/
  cPanel services (`smpro_cool_is_critical`); the unattended guard also skips per-site PHP
  (`smpro_cool_is_site_engine` = php-cgi/lsphp/php); never kills, never suspends.
- **tgbot.php** — Telegram control bot (cron getUpdates): `/status /services /restart /cooler /scan /harden
  /block /update …`; smart service discovery (`smpro_tg_pick_unit` prefers the ACTIVE unit — mariadb vs
  mysql, **pdns vs named**); proactive service-down alerts.
- **shortcuts.php** — Dashboard widgets: `smpro_dash_attention` (live critical detection: load/RAM/disk/swap/
  blocks/service-down, smart-reconfirmed), most-used + pinned shortcuts, `smpro_dash_sections` section cards.
- **profiles.php** — Protection Profiles (Medium/Maximum/AI/Custom + dated archive); friendly field
  names + balloon explanations; backup-then-apply.
- **update.php** — in-plugin self-update from the license server (`/api/version`, `/api/update`),
  SHA-256 verified, backup + overlay + re-register AppConfig, auto-update toggle.
- **layout.php / menu.php** — shared sidebar shell + menu registry (single source of truth). Universal
  top progress bar for any scan/AJAX (debounced, polling excluded). Footer is clean product name + version.

## 4. Modules (`modules/`) — one per page
dashboard · intrusion-monitor · forensics-audit · security-health · server-tuning · imunify360-reports ·
spam-phishing · database-cleanup · account-audit · firewall-status · php-harden · load-monitor (Cooler +
guard) · top-processes · disk-storage · network · backup-monitor · cpanel-services · profiles ·
notifications · whatsapp · telegram-bot · ai-providers · auto-reports · updates · license.

Menu order: **Dashboard first**, then Reports, Security & Access, Core Monitoring, Settings.

---

## 5. Cron workers (`bin/`)
- **notify_check.php** — every 15 min: license heartbeat, auto-update, scheduled reports, live alert checks,
  digest flush.
- **tgbot_poll.php** — every minute (when the bot is enabled): Telegram getUpdates + service-down watch.
- **cooler_tick.php** — every minute (only while the load guard is enabled): revert expired throttles +
  enforce the load ceiling.

---

## 6. License server (`server/`) — on plugins.hostguard.org (Ubuntu 24.04, nginx + php8.3-fpm, MySQL)
Front controller `public/index.php` (huge; lives on the server). Additive includes wired into its dispatch:
- **auth_otp.php** — admin login. `/login` = email OTP (6-digit, 3-min, single-use, hashed, 5-try cap,
  60s resend, neutral message); `/login-pw` = username+password fallback + **"send a fresh password to
  WhatsApp/email"** (per enabled channel); codes delivered via WhatsApp and/or email.
- **mailer.php** — `/settings/smtp` page; admin-configurable SMTP (AES-encrypted password) with a
  self-contained SMTP client (else local postfix); WAHA WhatsApp gateway (`wa_send` etc.).
- **wa_link.php** — WhatsApp **login-link responder** (webhook `POST /api/wa-hook`): admin texts the gateway
  the keyword `login`/`رابط`/`دخول` → replies with a **dynamic one-time login link** (10-min, survives the
  WhatsApp link-preview prefetch; matched by the admin's privacy **LID**).
- **ADMIN GATE** (in index.php): the whole admin UI is hidden from the public (404) behind a secret
  knock URL `?k=<secret>` (60-day cookie) **or** a dynamic time-limited token; `/api/*` and `/install.sh`
  stay public for customers.
- **download_ext / update_ext** — `/api/check`, `/api/activate`, `/api/version`, `/api/update`,
  `/api/download` (license + fingerprint gated). Customer-facing `/api/*` are served on the direct,
  no-Cloudflare host `dl.hostguard.org`.

### Hosting topology
- `plugins.hostguard.org` — admin panel, behind Cloudflare. Gated.
- `dl.hostguard.org` — DNS-only (grey-cloud) direct host; serves ONLY `/install.sh` (static) + `/api/*`
  (so curl|bash installs and plugin↔server API bypass the CF bot challenge).
- Cloudflare real-IP restored via `/etc/nginx/conf.d/cloudflare-realip.conf`.

---

## 7. Build, deploy, version
- **Source** (this tree) is unobfuscated. Production builds run it through **YAK Pro PHP obfuscator**
  (string-scramble; function names preserved; staged under the build drive). Assets copied as-is.
- **Install:** `curl -fsSL https://dl.hostguard.org/install.sh | bash -s -- <LICENSE_KEY>` — registers the
  WHM AppConfig (name=smpro, entryurl + icon → menu shows), seeds the license, self-validates.
- **Self-update:** Settings → Updates (Check / Update now / Auto). License server publishes
  `releases/smpro-latest.tar.gz` + `VERSION`.
- **Data (outside web root):** `/var/lib/smpro` (db, cache, locks, backups, license state, ai, profiles,
  digest, cooler, tgbot state) · `/var/log/smpro/audit.log`.

---

## 8. Security model (invariants — keep)
- Never bypass Cloudflare (`--resolve`/`-k`); never grep/dump DB credentials; no files shared with another
  product (e.g. MailShield); plugin data only under its own paths (+ allowed `/home/backup/detections`).
- `/root/.my.cnf` changes require panel approval.
- Cooler/guard: never throttle services/site-PHP, never kill, never suspend an account; all reversible.
- All secrets encrypted at rest; nothing sensitive exposed in the UI.
- License server admin UI hidden from public; OTP/dynamic-link + password layers; no plaintext codes on disk.

---

## 9. Notable fixes (recent)
- AI: real models via token + multi-select + parallel/series + fallback chain + probe-verify + API limits;
  dropped non-chat/decommissioned models; removed MailShield app.js/app.css leak.
- Service monitoring: smart active-unit discovery (mariadb/mysql, **pdns/named**) — no false "service down".
- Dashboard: live "Needs attention" critical detection + section cards + shortcuts.
- CSRF/auth failures return JSON on AJAX endpoints (fixes misleading "Request failed").
- License-server hardening: secret-knock gate, 12–14-char emergency password, otp.log removed, WhatsApp
  dynamic one-time login link via webhook.
