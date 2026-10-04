export const migrations: string[] = [
  `
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL,
    imap_security TEXT NOT NULL CHECK (imap_security IN ('tls','starttls','none')),
    imap_password_enc TEXT NOT NULL,
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL,
    smtp_security TEXT NOT NULL CHECK (smtp_security IN ('tls','starttls','none')),
    smtp_username TEXT NOT NULL,
    smtp_password_enc TEXT,
    auto_saves_sent INTEGER NOT NULL DEFAULT 0,
    permission_level TEXT NOT NULL DEFAULT 'draft' CHECK (permission_level IN ('read','draft','full')),
    send_limit_per_hour INTEGER,
    needs_reauth INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
  );
  CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT,
    metadata TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE oauth_pending (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    last_used_at INTEGER
  );
  CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
  CREATE INDEX oauth_tokens_user ON oauth_tokens(user_id);
  CREATE TABLE sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE send_log (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sent_at INTEGER NOT NULL
  );
  CREATE INDEX send_log_user ON send_log(user_id, sent_at);
  CREATE TABLE login_attempts (
    key TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
  );
  CREATE INDEX login_attempts_key ON login_attempts(key, attempted_at);
  `,
];
