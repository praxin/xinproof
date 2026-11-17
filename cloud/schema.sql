-- Xinproof Cloud v0 schema (Cloudflare D1 / SQLite). See docs/DESIGN-cloud.md §4.
-- Times are RFC 3339 UTC strings.

CREATE TABLE IF NOT EXISTS workspaces (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  webhook_url TEXT,
  stale_hours INTEGER NOT NULL DEFAULT 26,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  github_id    INTEGER NOT NULL,
  login        TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'owner',
  PRIMARY KEY (workspace_id, github_id)
);
CREATE INDEX IF NOT EXISTS members_by_user ON members(github_id);

CREATE TABLE IF NOT EXISTS tokens (
  id           TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name         TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS keys (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  key_id       TEXT NOT NULL,
  public_key   TEXT NOT NULL, -- base64 raw 32 bytes
  note         TEXT,
  tofu         INTEGER NOT NULL DEFAULT 0, -- pinned on first use, not yet confirmed
  added_at     TEXT NOT NULL,
  revoked_at   TEXT,
  PRIMARY KEY (workspace_id, key_id)
);

CREATE TABLE IF NOT EXISTS assets (
  workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
  key             TEXT NOT NULL,
  engine          TEXT,
  last_receipt_id TEXT,
  last_result     TEXT,
  last_issued_at  TEXT,
  last_pass_at    TEXT,
  last_restore_s  REAL,
  alert_state     TEXT NOT NULL DEFAULT 'ok', -- ok | failing | stale (last state we alerted on)
  created_at      TEXT NOT NULL,
  PRIMARY KEY (workspace_id, key)
);

CREATE TABLE IF NOT EXISTS receipts (
  workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
  id              TEXT NOT NULL,
  asset_key       TEXT NOT NULL,
  issued_at       TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  result          TEXT NOT NULL,
  reason          TEXT,
  source          TEXT NOT NULL,
  size            INTEGER,
  restore_seconds REAL,
  key_id          TEXT NOT NULL,
  seq             INTEGER,
  prev            TEXT,
  hash            TEXT NOT NULL,
  linked          INTEGER NOT NULL DEFAULT 0, -- 1 if seq 1 or prev matches a stored receipt
  json            TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS receipts_by_asset ON receipts(workspace_id, asset_key, issued_at DESC);
CREATE INDEX IF NOT EXISTS receipts_by_hash ON receipts(workspace_id, hash);
CREATE INDEX IF NOT EXISTS receipts_by_day ON receipts(workspace_id, received_at);

CREATE TABLE IF NOT EXISTS share_links (
  token_hash   TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  label        TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  revoked_at   TEXT
);
