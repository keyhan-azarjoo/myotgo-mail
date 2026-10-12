"""SQLite: the one database for users, permissions, sessions, tokens and the audit log."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  disabled INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  totp_secret TEXT,              -- encrypted
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  recovery_codes TEXT NOT NULL DEFAULT '[]',   -- sha256 hashes
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  last_login_at REAL
);
CREATE TABLE IF NOT EXISTS mailboxes (
  address TEXT PRIMARY KEY COLLATE NOCASE,
  password TEXT,                 -- encrypted; NULL = not linked yet
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox TEXT NOT NULL COLLATE NOCASE,
  can_read INTEGER NOT NULL DEFAULT 0,
  can_send INTEGER NOT NULL DEFAULT 0,
  can_organize INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, mailbox)
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  mfa_ok INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  last_seen REAL NOT NULL,
  ip TEXT
);
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL,
  last_used_at REAL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  info TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  redirect_explicit INTEGER NOT NULL,
  expires_at REAL NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
  family TEXT NOT NULL,          -- all tokens from one authorization share a family
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  expires_at REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT
);
CREATE TABLE IF NOT EXISTS rate (
  key TEXT NOT NULL,
  ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_key ON rate(key, ts);
CREATE INDEX IF NOT EXISTS rate_ts ON rate(ts);
CREATE TABLE IF NOT EXISTS email_codes (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at REAL NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox TEXT NOT NULL,
  kind TEXT NOT NULL,             -- send, reply, forward
  subject TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL,          -- the exact message, encrypted: what is approved is what is sent
  recipients TEXT NOT NULL,       -- json list (includes Bcc)
  after TEXT NOT NULL DEFAULT '{}',
  requested_by TEXT NOT NULL,     -- the app or token that asked
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending, sent, rejected, expired, failed
  decided_at REAL,
  result TEXT
);
CREATE INDEX IF NOT EXISTS outbox_user ON outbox(user_id, status);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


@contextmanager
def tx():
    """A connection inside one transaction (committed on success, rolled back on error)."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def query(sql: str, args=()) -> list[sqlite3.Row]:
    conn = connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def one(sql: str, args=()):
    rows = query(sql, args)
    return rows[0] if rows else None


def execute(sql: str, args=()) -> int:
    with tx() as conn:
        cur = conn.execute(sql, args)
        return cur.lastrowid


def init() -> None:
    os.umask(0o077)   # the database and its -wal/-shm files are readable by the app only
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        # columns added after the first release
        ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        if "two_step_method" not in ucols:   # 'totp' (authenticator app) or 'email'
            conn.execute("ALTER TABLE users ADD COLUMN two_step_method TEXT")
            conn.execute("UPDATE users SET two_step_method = 'totp' WHERE totp_enabled = 1")
        if "two_step_email" not in ucols:    # where email codes go (never the user's own mailbox)
            conn.execute("ALTER TABLE users ADD COLUMN two_step_email TEXT")
            # email codes used to go to the login address itself, which shares its password:
            # those users set two-step up again at their next sign-in
            ids = [r[0] for r in conn.execute("SELECT id FROM users WHERE two_step_method IN ('email', 'email_pending')")]
            for uid in ids:
                conn.execute("UPDATE users SET totp_enabled = 0, two_step_method = NULL, recovery_codes = '[]', "
                             "must_change_password = 1 WHERE id = ?", (uid,))
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
                conn.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = ?", (uid,))
                conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE user_id = ?", (uid,))
        for table in ("api_tokens", "oauth_tokens", "oauth_codes"):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if "mfa" not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0")
            if "direct_send" not in cols:   # 1 = may send without the owner approving each message
                conn.execute(f"ALTER TABLE {table} ADD COLUMN direct_send INTEGER NOT NULL DEFAULT 0")
    finally:
        conn.close()
    config.DB_PATH.chmod(0o600)


def setting(key: str, default: str = "") -> str:
    row = one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value))


def audit(actor: str | None, action: str, target: str | None = None, detail=None, ip: str | None = None) -> None:
    if detail is not None and not isinstance(detail, str):
        detail = json.dumps(detail, default=str)
    execute("INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
            (time.time(), actor, action, target, detail, ip))
