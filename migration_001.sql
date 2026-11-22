ALTER TABLE users ADD COLUMN name TEXT;
ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN password_salt TEXT;

ALTER TABLE affiliates ADD COLUMN user_id INTEGER;
ALTER TABLE affiliates ADD COLUMN status TEXT DEFAULT 'active';

CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip TEXT,
  success INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE payouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  affiliate_code TEXT NOT NULL,
  amount_usd REAL NOT NULL,
  address TEXT NOT NULL,
  txid TEXT,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_sessions_email ON sessions(email);
CREATE INDEX idx_orders_email ON orders(email);
CREATE INDEX idx_licenses_email ON licenses(email);
CREATE INDEX idx_referrals_code ON referrals(affiliate_code);
CREATE INDEX idx_attempts_email ON login_attempts(email, created_at);