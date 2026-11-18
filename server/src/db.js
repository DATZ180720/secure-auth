import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const MIGRATIONS = `
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    name            TEXT    NOT NULL,
    password_hash   TEXT    NOT NULL,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    token_version   INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
  );

  -- Refresh tokens are stored hashed (SHA-256), never in plain text.
  -- family_id groups every token produced by rotation from one login,
  -- so a reused (stolen) token can revoke the whole chain.
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT    NOT NULL UNIQUE,
    family_id   TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER,
    replaced_by TEXT,
    created_at  INTEGER NOT NULL,
    user_agent  TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_user   ON refresh_tokens(user_id);

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    event      TEXT    NOT NULL,
    ip         TEXT,
    created_at INTEGER NOT NULL
  );
`;

export function openDatabase(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(MIGRATIONS);
  return db;
}
