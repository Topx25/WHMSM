# Safety Monitor Pro (smpro) — Production Package

A WHM/cPanel plugin: server security & monitoring — Forensics, Account Audit,
Login monitoring, Imunify360 reports, Spam & Phishing blocker, PHP Harden,
Firewall, Backup Monitor, Disk/Storage, Hardware & Platform (live), AI Providers,
Notifications (Email/SMTP, Telegram, Pushbullet, WhatsApp).

## Requirements

- A **cPanel & WHM** server. cPanel runs on **AlmaLinux / CentOS / CloudLinux /
  Rocky / RHEL** — it does **not** run on Ubuntu/Debian, so this WHM plugin can
  only be installed on a cPanel server.
- root access.
- PHP CLI (cPanel ships one at `/usr/local/cpanel/3rdparty/bin/php`).
- Optional (auto-detected, features degrade gracefully if missing):
  `imunify360-agent`, `csf`, `exim`, `jetbackup5api`, `lsattr/chattr`, `curl`.

## Install

```bash
# on the target WHM server, as root:
tar -xzf smpro-<version>.tar.gz
cd smpro-<version>
sudo bash install.sh
```

Then open **WHM → Home → Plugins → Safety Monitor Pro**, or browse to:
`https://<server-hostname>:2087/cgi/addons/smpro/index.cgi`

## What the installer does

1. Verifies it's a cPanel/WHM server (RHEL-family) and finds the PHP binary.
2. Copies the plugin to `/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro/`.
3. Creates isolated, root-only data dirs under `/var/lib/smpro` and logs in
   `/var/log/smpro`.
4. Restores SELinux context (AlmaLinux/CentOS/Rocky).
5. Registers the plugin in WHM via `register_appconfig`.

No customer accounts are touched. The legacy `safety_monitor` plugin (if present)
is left untouched — this plugin is fully isolated under the `smpro` namespace.

## Post-install configuration (in the UI)

- **AI Providers** — add a provider + API key to enable the AI decision buttons.
- **Notifications** — enable Email/SMTP, Telegram, Pushbullet and/or WhatsApp,
  pick which alert types fire on which channel, and (optionally) turn on the
  15-minute auto-checker cron.
- **WhatsApp** — set the gateway URL + `X-API-Key`, create/start a session, scan
  the QR to link a phone.

## Update

Re-run `sudo bash install.sh` from a newer package. It overwrites the code in
place and keeps your data/config under `/var/lib/smpro`.

## Uninstall

```bash
sudo bash uninstall.sh          # remove plugin + WHM registration, keep data
sudo bash uninstall.sh --purge  # also remove /var/lib/smpro + logs + crons
```

## Data & privacy

- All state (config, reports, notification settings, AI vault, PHP-Harden
  manifests) lives under `/var/lib/smpro` with `0700` permissions (root only).
- Detection/file backups are stored **outside** customer accounts under
  `/home/backup/detections` and are restorable.
- The package ships **no credentials** — every API key / token is entered on the
  target server via the UI.
