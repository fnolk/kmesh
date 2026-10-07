use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

#[derive(Clone)]
pub(crate) struct Database {
    pub pool: SqlitePool,
}

impl Database {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .with_context(|| format!("open SQLite database {}", path.as_ref().display()))?;
        Ok(Self { pool })
    }

    pub async fn apply_schema(&self) -> Result<()> {
        let schema_table_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        )
        .fetch_one(&self.pool)
        .await?;
        if schema_table_exists != 0 {
            let version =
                sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM schema_migrations")
                    .fetch_one(&self.pool)
                    .await?;
            if let Some(version) = version {
                anyhow::ensure!(
                    version == 4,
                    "server database schema version {version} requires a fresh data directory"
                );
            }
        }
        sqlx::raw_sql(include_str!("../../migrations/0001_server.sql"))
            .execute(&self.pool)
            .await
            .context("apply server database schema")?;
        Ok(())
    }

    pub async fn initialize(
        &self,
        issuer: &str,
        admin_username: &str,
        initial_api_token_hash: Option<String>,
    ) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("begin server initialization")?;
        let current_issuer =
            sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = 'issuer'")
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(current) = current_issuer {
            if current != issuer {
                bail!("issuer differs from initialized server configuration");
            }
        } else {
            sqlx::query("INSERT INTO settings(key, value) VALUES ('issuer', ?1)")
                .bind(issuer)
                .execute(&mut *tx)
                .await?;
        }

        let user_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        if user_count == 0 {
            let initial_api_token_hash = initial_api_token_hash
                .context("initial administrator API token hash is required")?;
            let user_id = uuid::Uuid::new_v4();
            let role_id = uuid::Uuid::new_v4();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO users(id, username, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, 1, ?3, ?3)",
            )
            .bind(user_id.to_string())
            .bind(admin_username)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("create initial management user")?;
            sqlx::query(
                "INSERT INTO roles(id, name, built_in, created_at) VALUES (?1, 'admin', 1, ?2)",
            )
            .bind(role_id.to_string())
            .bind(now)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO role_global_permissions(role_id, permission) VALUES (?1, 'admin')",
            )
            .bind(role_id.to_string())
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO user_roles(user_id, role_id) VALUES (?1, ?2)")
                .bind(user_id.to_string())
                .bind(role_id.to_string())
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO api_tokens(id, user_id, token_hash, label, created_at) \
                 VALUES (?1, ?2, ?3, 'initial administrator token', ?4)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(user_id.to_string())
            .bind(initial_api_token_hash)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("create initial administrator API token")?;
        }
        tx.commit().await.context("commit server initialization")?;
        Ok(())
    }

    pub async fn user_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT value FROM settings WHERE key = ?1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn is_admin(&self, user_id: uuid::Uuid) -> Result<bool> {
        let found = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(\
                SELECT 1 FROM user_roles ur \
                JOIN role_global_permissions gp ON gp.role_id = ur.role_id \
                JOIN users u ON u.id = ur.user_id \
                JOIN roles r ON r.id = ur.role_id \
                WHERE ur.user_id = ?1 AND gp.permission = 'admin' \
                  AND u.enabled = 1 AND r.name = 'admin'\
            )",
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(found != 0)
    }

    pub async fn is_session_active(
        &self,
        user_id: uuid::Uuid,
        session_id: uuid::Uuid,
    ) -> Result<bool> {
        let found = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.id = ?1 AND s.user_id = ?2 AND s.revoked_at IS NULL \
               AND (s.api_token_id IS NULL OR EXISTS (\
                 SELECT 1 FROM api_tokens t WHERE t.id = s.api_token_id AND t.revoked_at IS NULL\
               )) \
               AND s.refresh_expires_at > ?3 AND u.enabled = 1)",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .bind(unix_time())
        .fetch_one(&self.pool)
        .await?;
        Ok(found != 0)
    }

    pub async fn target_endpoint_id(&self, target_id: uuid::Uuid) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT agent_endpoint_id FROM targets \
             WHERE id = ?1 AND enabled = 1 AND deleted_at IS NULL AND agent_token_hash IS NOT NULL",
        )
        .bind(target_id.to_string())
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn endpoint_can_use_relay(&self, endpoint_id: &str) -> Result<bool> {
        let now = unix_time();
        let found = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(\
                SELECT 1 FROM tunnel_sessions \
                WHERE client_endpoint_id = ?1 \
                  AND (status = 'active' OR (status = 'pending' AND expires_at > ?2))\
             )",
        )
        .bind(endpoint_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(found != 0)
    }

    pub async fn tunnel_session_can_use_relay(&self, session_id: uuid::Uuid) -> Result<bool> {
        let now = unix_time();
        let found = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(\
                SELECT 1 FROM tunnel_sessions \
                WHERE id = ?1 AND \
                  (status = 'active' OR (status = 'pending' AND expires_at > ?2))\
             )",
        )
        .bind(session_id.to_string())
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(found != 0)
    }
}

pub(crate) fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs() as i64
}

pub(crate) fn row_uuid(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<uuid::Uuid> {
    let value: String = row.try_get(column)?;
    uuid::Uuid::parse_str(&value).with_context(|| format!("invalid database UUID in {column}"))
}
