CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS user_keys_user_id_idx ON user_keys(user_id, enabled);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    built_in INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS user_roles_role_id_idx ON user_roles(role_id);

CREATE TABLE IF NOT EXISTS role_global_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission = 'admin'),
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    deleted_at INTEGER,
    enrollment_token_hash TEXT,
    enrollment_expires_at INTEGER,
    agent_token_hash TEXT UNIQUE,
    agent_certificate_der BLOB,
    agent_certificate_fingerprint TEXT,
    enrolled_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS target_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission = 'ssh_connect'),
    PRIMARY KEY (role_id, target_id, permission)
);
CREATE INDEX IF NOT EXISTS target_permissions_target_idx ON target_permissions(target_id, permission);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('password', 'ssh_key')),
    created_at INTEGER NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx ON auth_sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    replaced_by_hash TEXT
);
CREATE INDEX IF NOT EXISTS refresh_tokens_session_idx ON refresh_tokens(session_id);

CREATE TABLE IF NOT EXISTS ssh_login_challenges (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    public_key TEXT NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    key_id TEXT REFERENCES user_keys(id) ON DELETE SET NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ssh_login_challenges_expiry_idx ON ssh_login_challenges(expires_at);

CREATE TABLE IF NOT EXISTS tunnel_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    auth_session_id TEXT NOT NULL REFERENCES auth_sessions(id),
    target_id TEXT NOT NULL REFERENCES targets(id),
    client_public_key TEXT NOT NULL,
    ticket TEXT NOT NULL,
    probe_token TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'closed')),
    selected_path TEXT CHECK (selected_path IN ('quic', 'relay')),
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    closed_at INTEGER
);
CREATE INDEX IF NOT EXISTS tunnel_sessions_target_status_idx ON tunnel_sessions(target_id, status);

INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, unixepoch());
