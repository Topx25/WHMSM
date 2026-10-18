-- Phase A — additive tables for the Servers/Installations tab + remote actions.
-- Safe: CREATE IF NOT EXISTS only; touches no existing table, no data, no security logic.
-- Apply: mysql <db> < migrate_telemetry.sql   (run on the license server)

-- Latest telemetry snapshot per license (one row per key; UPSERT on each check-in).
CREATE TABLE IF NOT EXISTS license_telemetry (
  license_key   VARCHAR(90)  NOT NULL PRIMARY KEY,
  hostname      VARCHAR(255) DEFAULT NULL,
  server_ip     VARCHAR(45)  DEFAULT NULL,
  mac           VARCHAR(64)  DEFAULT NULL,
  os            VARCHAR(120) DEFAULT NULL,
  panel         VARCHAR(80)  DEFAULT NULL,
  cpu_cores     INT          DEFAULT NULL,
  ram_mb        INT          DEFAULT NULL,
  uptime_sec    BIGINT       DEFAULT NULL,
  load1         DECIMAL(7,2) DEFAULT NULL,
  load15        DECIMAL(7,2) DEFAULT NULL,
  version       VARCHAR(20)  DEFAULT NULL,
  reported_at   DATETIME     DEFAULT NULL,
  INDEX idx_reported_at (reported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Pull-based command queue: panel enqueues, plugin executes on next check-in.
CREATE TABLE IF NOT EXISTS license_commands (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  license_key VARCHAR(90) NOT NULL,
  command     ENUM('update','restart','revoke') NOT NULL,
  args        VARCHAR(190) DEFAULT NULL,        -- e.g. target version for 'update'
  status      ENUM('pending','sent','done','failed') NOT NULL DEFAULT 'pending',
  result      TEXT DEFAULT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at     DATETIME DEFAULT NULL,
  done_at     DATETIME DEFAULT NULL,
  INDEX idx_key_status (license_key, status),
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
