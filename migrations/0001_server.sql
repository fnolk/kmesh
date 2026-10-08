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
    system_role TEXT NOT NULL CHECK (system_role IN ('member', 'admin')),
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

CREATE TABLE IF NOT EXISTS access_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_access_groups (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS user_access_groups_group_id_idx ON user_access_groups(group_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_tokens_user_id_idx ON api_tokens(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    deleted_at INTEGER,
    enrollment_token_hash TEXT,
    enrollment_expires_at INTEGER,
    agent_token_hash TEXT UNIQUE,
    agent_endpoint_id TEXT UNIQUE,
    enrolled_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_target_permissions (
    group_id TEXT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission = 'ssh_connect'),
    PRIMARY KEY (group_id, target_id, permission)
);
CREATE INDEX IF NOT EXISTS group_target_permissions_target_idx ON group_target_permissions(target_id, permission);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    auth_session_id TEXT REFERENCES auth_sessions(id),
    api_token_id TEXT REFERENCES api_tokens(id),
    target_id TEXT NOT NULL REFERENCES targets(id),
    client_endpoint_id TEXT NOT NULL,
    target_endpoint_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'closed')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    activated_at INTEGER,
    closed_at INTEGER,
    CHECK (
        (auth_session_id IS NOT NULL AND api_token_id IS NULL) OR
        (auth_session_id IS NULL AND api_token_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS tunnel_sessions_target_status_idx ON tunnel_sessions(target_id, status);
CREATE INDEX IF NOT EXISTS tunnel_sessions_client_endpoint_idx ON tunnel_sessions(client_endpoint_id, status, expires_at);
CREATE INDEX IF NOT EXISTS tunnel_sessions_target_endpoint_idx ON tunnel_sessions(target_endpoint_id, status, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS tunnel_sessions_client_live_idx ON tunnel_sessions(client_endpoint_id) WHERE status IN ('pending', 'active');

CREATE TABLE IF NOT EXISTS admin_audit (
    id TEXT PRIMARY KEY,
    occurred_at INTEGER NOT NULL,
    actor_user_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT,
    context_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_audit_actor_time_idx ON admin_audit(actor_user_id, occurred_at);
CREATE INDEX IF NOT EXISTS admin_audit_object_idx ON admin_audit(object_type, object_id, occurred_at);

INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (6, unixepoch());
