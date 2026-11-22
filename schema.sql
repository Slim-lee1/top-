CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  plan TEXT NOT NULL,
  amount_usd REAL NOT NULL,
  provider TEXT,
  provider_ref TEXT,
  status TEXT DEFAULT 'pending',
  affiliate_code TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL,
  email TEXT NOT NULL,
  license_key TEXT UNIQUE NOT NULL,
  mt_account TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE affiliates (
  code TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  payout_address TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE referrals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  affiliate_code TEXT NOT NULL,
  order_id TEXT NOT NULL,
  commission_usd REAL NOT NULL,
  status TEXT DEFAULT 'pending'
);

CREATE TABLE webhook_events (
  id TEXT PRIMARY KEY,
  received_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  expires_at TEXT NOT NULL
);