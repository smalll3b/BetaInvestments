-- Beta Investments secure stock trading demo schema.
--
-- Security note:
-- If your MySQL edition supports tablespace / transparent encryption,
-- enable it at the database layer as well. This application already uses
-- AES-256-GCM field encryption for sensitive values such as the TOTP secret.

CREATE DATABASE IF NOT EXISTS beta_investments
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE beta_investments;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  cash_balance DECIMAL(15,2) NOT NULL DEFAULT 100000.00,
  two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
  totp_secret_enc TEXT NULL,
  failed_login_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS stocks (
  symbol VARCHAR(12) NOT NULL,
  company_name VARCHAR(150) NOT NULL,
  current_price DECIMAL(10,2) NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (symbol)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_portfolio (
  user_id BIGINT UNSIGNED NOT NULL,
  symbol VARCHAR(12) NOT NULL,
  quantity INT UNSIGNED NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (user_id, symbol),
  CONSTRAINT fk_portfolio_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_portfolio_stock FOREIGN KEY (symbol) REFERENCES stocks (symbol) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS trades (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  symbol VARCHAR(12) NOT NULL,
  trade_type ENUM('buy', 'sell') NOT NULL,
  quantity INT UNSIGNED NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  total_amount DECIMAL(15,2) NOT NULL,
  status ENUM('filled', 'rejected', 'pending') NOT NULL DEFAULT 'filled',
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY idx_trades_user_time (user_id, created_at),
  KEY idx_trades_symbol_time (symbol, created_at),
  CONSTRAINT fk_trades_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_trades_stock FOREIGN KEY (symbol) REFERENCES stocks (symbol) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NULL,
  event_type VARCHAR(80) NOT NULL,
  event_detail VARCHAR(500) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY idx_audit_user_time (user_id, created_at),
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT INTO stocks (symbol, company_name, current_price, updated_at) VALUES
('BARC', 'Barclays PLC', 2.10, NOW()),
('HSBA', 'HSBC Holdings PLC', 7.35, NOW()),
('LLOY', 'Lloyds Banking Group', 0.52, NOW()),
('VOD', 'Vodafone Group', 0.78, NOW()),
('BP', 'BP PLC', 4.22, NOW())
ON DUPLICATE KEY UPDATE
  company_name = VALUES(company_name),
  current_price = VALUES(current_price),
  updated_at = VALUES(updated_at);

