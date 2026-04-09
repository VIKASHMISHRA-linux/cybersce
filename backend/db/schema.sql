-- ============================================================
-- CyberSec Dashboard — MySQL Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybersec_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE cybersec_db;

-- ── USERS ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  email         VARCHAR(128) NOT NULL UNIQUE,
  password_hash VARCHAR(256) NOT NULL,
  role          ENUM('admin','user') NOT NULL DEFAULT 'user',
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,
  last_login    DATETIME,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_role (role),
  INDEX idx_active (is_active)
) ENGINE=InnoDB;

-- ── BLOCKED IPs ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blocked_ips (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  reason     VARCHAR(255),
  blocked_by INT UNSIGNED,
  blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_ip (ip_address)
) ENGINE=InnoDB;

-- ── LOGS ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS logs (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address     VARCHAR(45)  NOT NULL,
  message        TEXT         NOT NULL,
  risk_level     ENUM('low','medium','high','critical') NOT NULL DEFAULT 'low',
  risk_score     TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 0-100
  attack_type    VARCHAR(64),
  country        VARCHAR(64),
  city           VARCHAR(64),
  isp            VARCHAR(128),
  latitude       DECIMAL(9,6),
  longitude      DECIMAL(9,6),
  is_anomaly     TINYINT(1)   NOT NULL DEFAULT 0,
  raw_data       JSON,
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_ip        (ip_address),
  INDEX idx_risk      (risk_level),
  INDEX idx_score     (risk_score),
  INDEX idx_created   (created_at),
  INDEX idx_anomaly   (is_anomaly),
  INDEX idx_country   (country)
) ENGINE=InnoDB;

-- ── ALERTS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  log_id       BIGINT UNSIGNED,
  ip_address   VARCHAR(45)  NOT NULL,
  alert_type   VARCHAR(64)  NOT NULL,
  severity     ENUM('medium','high','critical') NOT NULL,
  message      TEXT         NOT NULL,
  risk_score   TINYINT UNSIGNED NOT NULL,
  is_read      TINYINT(1)   NOT NULL DEFAULT 0,
  email_sent   TINYINT(1)   NOT NULL DEFAULT 0,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  FOREIGN KEY (log_id) REFERENCES logs(id) ON DELETE SET NULL,
  INDEX idx_severity  (severity),
  INDEX idx_read      (is_read),
  INDEX idx_created   (created_at),
  INDEX idx_ip        (ip_address)
) ENGINE=InnoDB;

-- ── ATTACK SUMMARY ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_summary (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  summary_date DATE         NOT NULL,
  attack_type  VARCHAR(64)  NOT NULL,
  country      VARCHAR(64),
  total_count  INT UNSIGNED NOT NULL DEFAULT 0,
  high_risk    INT UNSIGNED NOT NULL DEFAULT 0,
  top_ip       VARCHAR(45),
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_date_type_country (summary_date, attack_type, country),
  INDEX idx_date    (summary_date),
  INDEX idx_type    (attack_type),
  INDEX idx_country (country)
) ENGINE=InnoDB;

-- ── IP REPUTATION CACHE ────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_reputation (
  ip_address   VARCHAR(45)  NOT NULL PRIMARY KEY,
  country      VARCHAR(64),
  city         VARCHAR(64),
  isp          VARCHAR(128),
  latitude     DECIMAL(9,6),
  longitude    DECIMAL(9,6),
  abuse_score  TINYINT UNSIGNED NOT NULL DEFAULT 0,
  request_count INT UNSIGNED   NOT NULL DEFAULT 0,
  fail_count   INT UNSIGNED    NOT NULL DEFAULT 0,
  is_blocked   TINYINT(1)      NOT NULL DEFAULT 0,
  last_seen    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  cached_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_abuse   (abuse_score),
  INDEX idx_blocked (is_blocked),
  INDEX idx_country (country)
) ENGINE=InnoDB;

-- ── REFRESH TOKENS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  token_hash VARCHAR(256) NOT NULL UNIQUE,
  expires_at DATETIME     NOT NULL,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user    (user_id),
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB;

-- ── DEFAULT ADMIN USER (password: Admin@123) ───────────────
INSERT IGNORE INTO users (username, email, password_hash, role)
VALUES (
  'admin',
  'admin@cybersec.local',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iYOi',
  'admin'
);
