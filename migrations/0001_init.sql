-- OKR Tracker — initial schema for the Org Durable Object SQLite store.
-- Spec §4 data model. Forward-only, additive; see docs/RUNBOOK.md for the
-- expand→migrate→contract policy on destructive changes (§13.2).
--
-- Booleans are stored as INTEGER (0/1). Times are epoch-milliseconds (INTEGER).
-- Complex fields (transports, notification payload) are stored as JSON TEXT.

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  short_name      TEXT NOT NULL UNIQUE,
  webauthn_handle TEXT NOT NULL UNIQUE,
  is_admin        INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id                     TEXT PRIMARY KEY,
  user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  webauthn_credential_id TEXT NOT NULL UNIQUE,
  public_key             TEXT NOT NULL,   -- base64url COSE/SEC1 key
  sign_count             INTEGER NOT NULL DEFAULT 0,
  aaguid                 TEXT NOT NULL DEFAULT '',
  transports             TEXT NOT NULL DEFAULT '[]',
  created_at             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS reg_codes (
  code       TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_reg_codes_user ON reg_codes(user_id);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Short-lived WebAuthn ceremony challenges (registration/login/bootstrap).
CREATE TABLE IF NOT EXISTS challenges (
  id         TEXT PRIMARY KEY,   -- random ceremony id returned to the client
  kind       TEXT NOT NULL,      -- 'register' | 'login' | 'bootstrap'
  challenge  TEXT NOT NULL,      -- base64url random
  user_id    TEXT,               -- bound user (register)
  data       TEXT,               -- JSON: pending user attrs for bootstrap
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
  id                   TEXT PRIMARY KEY,
  human_ref            TEXT NOT NULL UNIQUE,
  current_version      INTEGER NOT NULL,
  next_version_counter INTEGER NOT NULL,
  created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_versions (
  group_id       TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  version        INTEGER NOT NULL,
  name           TEXT NOT NULL,
  description_md TEXT NOT NULL DEFAULT '',
  valid          INTEGER NOT NULL DEFAULT 1,
  author_id      TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (group_id, version)
);

CREATE TABLE IF NOT EXISTS okrs (
  id                   TEXT PRIMARY KEY,
  human_ref            TEXT NOT NULL UNIQUE,
  group_id             TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  current_version      INTEGER NOT NULL,
  next_version_counter INTEGER NOT NULL,
  created_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_okrs_group ON okrs(group_id);

CREATE TABLE IF NOT EXISTS okr_versions (
  okr_id         TEXT NOT NULL REFERENCES okrs(id) ON DELETE CASCADE,
  version        INTEGER NOT NULL,
  objective_md   TEXT NOT NULL DEFAULT '',
  key_results_md TEXT NOT NULL DEFAULT '',
  valid          INTEGER NOT NULL DEFAULT 1,
  author_id      TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (okr_id, version)
);

CREATE TABLE IF NOT EXISTS okr_assignees (
  okr_id  TEXT NOT NULL REFERENCES okrs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (okr_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_assignees_user ON okr_assignees(user_id);

CREATE TABLE IF NOT EXISTS okr_done (
  okr_id  TEXT NOT NULL REFERENCES okrs(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  done    INTEGER NOT NULL,
  set_by  TEXT NOT NULL,
  set_at  INTEGER NOT NULL,
  PRIMARY KEY (okr_id, version, set_at)
);

CREATE TABLE IF NOT EXISTS updates (
  id         TEXT PRIMARY KEY,
  okr_id     TEXT NOT NULL REFERENCES okrs(id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  author_id  TEXT NOT NULL,
  body_md    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  edited_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_updates_okr ON updates(okr_id);

CREATE TABLE IF NOT EXISTS notifications (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  payload    TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  read_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint   TEXT NOT NULL UNIQUE,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_push_user ON push_subscriptions(user_id);

-- Rate-limit counters, one row per (bucket, window-start).
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  hits         INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);
