use crate::core::models::{
    AttackLog, IpAccessEntry, NewAttackLog, NewIpAccessEntry, NewUser, UpdateIpAccessEntry, User,
};
use anyhow::{Context, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, SqlitePool,
};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn connect(db_path: &Path) -> Result<Self> {
        let connect_options = SqliteConnectOptions::from_str("sqlite://")
            .context("failed to build base SQLite connection options")?
            .filename(db_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options.disable_statement_logging())
            .await
            .with_context(|| format!("failed to connect to SQLite database '{}'", db_path.display()))?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ip_access_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                list_type TEXT NOT NULL CHECK (list_type IN ('white', 'black')),
                comment TEXT,
                expires_at DATETIME,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed to create table ip_access_lists")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                request_method TEXT,
                request_url TEXT,
                matched_rule_id TEXT,
                attack_type TEXT,
                payload TEXT,
                action_taken TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed to create table attack_logs")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed to create table users")?;

        Ok(())
    }

    pub async fn upsert_ip_access_entry(&self, entry: &NewIpAccessEntry) -> Result<IpAccessEntry> {
        sqlx::query(
            r#"
            INSERT INTO ip_access_lists (ip_address, list_type, comment, expires_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(ip_address) DO UPDATE SET
                list_type = excluded.list_type,
                comment = excluded.comment,
                expires_at = excluded.expires_at
            "#,
        )
        .bind(&entry.ip_address)
        .bind(entry.list_type.as_str())
        .bind(&entry.comment)
        .bind(&entry.expires_at)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to upsert ip access entry '{}'", entry.ip_address))?;

        self.get_ip_access_entry(&entry.ip_address).await?.with_context(|| {
            format!(
                "ip access entry '{}' was written but could not be reloaded",
                entry.ip_address
            )
        })
    }

    pub async fn get_ip_access_entry(&self, ip_address: &str) -> Result<Option<IpAccessEntry>> {
        let entry = sqlx::query_as::<_, IpAccessEntry>(
            r#"
            SELECT id, ip_address, list_type, comment, expires_at, created_at
            FROM ip_access_lists
            WHERE ip_address = ?1
            "#,
        )
        .bind(ip_address)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("failed to fetch ip access entry '{}'", ip_address))?;

        Ok(entry)
    }

    pub async fn list_ip_access_entries(&self) -> Result<Vec<IpAccessEntry>> {
        let entries = sqlx::query_as::<_, IpAccessEntry>(
            r#"
            SELECT id, ip_address, list_type, comment, expires_at, created_at
            FROM ip_access_lists
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to list ip access entries")?;

        Ok(entries)
    }

    pub async fn update_ip_access_entry(
        &self,
        ip_address: &str,
        update: &UpdateIpAccessEntry,
    ) -> Result<Option<IpAccessEntry>> {
        let result = sqlx::query(
            r#"
            UPDATE ip_access_lists
            SET list_type = ?1, comment = ?2, expires_at = ?3
            WHERE ip_address = ?4
            "#,
        )
        .bind(update.list_type.as_str())
        .bind(&update.comment)
        .bind(&update.expires_at)
        .bind(ip_address)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to update ip access entry '{}'", ip_address))?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.get_ip_access_entry(ip_address).await
    }

    pub async fn delete_ip_access_entry(&self, ip_address: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM ip_access_lists WHERE ip_address = ?1")
            .bind(ip_address)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to delete ip access entry '{}'", ip_address))?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn create_attack_log(&self, log: &NewAttackLog) -> Result<AttackLog> {
        let result = sqlx::query(
            r#"
            INSERT INTO attack_logs (
                source_ip,
                request_method,
                request_url,
                matched_rule_id,
                attack_type,
                payload,
                action_taken
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(&log.source_ip)
        .bind(&log.request_method)
        .bind(&log.request_url)
        .bind(&log.matched_rule_id)
        .bind(&log.attack_type)
        .bind(&log.payload)
        .bind(&log.action_taken)
        .execute(&self.pool)
        .await
        .context("failed to insert attack log")?;

        let attack_log = sqlx::query_as::<_, AttackLog>(
            r#"
            SELECT id, timestamp, source_ip, request_method, request_url, matched_rule_id, attack_type, payload, action_taken
            FROM attack_logs
            WHERE id = ?1
            "#,
        )
        .bind(result.last_insert_rowid())
        .fetch_one(&self.pool)
        .await
        .context("failed to reload inserted attack log")?;

        Ok(attack_log)
    }

    pub async fn list_attack_logs(&self, limit: i64) -> Result<Vec<AttackLog>> {
        let sanitized_limit = if limit <= 0 { 100 } else { limit };

        let logs = sqlx::query_as::<_, AttackLog>(
            r#"
            SELECT id, timestamp, source_ip, request_method, request_url, matched_rule_id, attack_type, payload, action_taken
            FROM attack_logs
            ORDER BY timestamp DESC, id DESC
            LIMIT ?1
            "#,
        )
        .bind(sanitized_limit)
        .fetch_all(&self.pool)
        .await
        .context("failed to list attack logs")?;

        Ok(logs)
    }

    pub async fn list_all_attack_logs(&self) -> Result<Vec<AttackLog>> {
        let logs = sqlx::query_as::<_, AttackLog>(
            r#"
            SELECT id, timestamp, source_ip, request_method, request_url, matched_rule_id, attack_type, payload, action_taken
            FROM attack_logs
            ORDER BY timestamp DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to list all attack logs")?;

        Ok(logs)
    }

    pub async fn get_attack_log(&self, id: i64) -> Result<Option<AttackLog>> {
        let log = sqlx::query_as::<_, AttackLog>(
            r#"
            SELECT id, timestamp, source_ip, request_method, request_url, matched_rule_id, attack_type, payload, action_taken
            FROM attack_logs
            WHERE id = ?1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("failed to fetch attack log '{}'", id))?;

        Ok(log)
    }

    pub async fn delete_attack_log(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM attack_logs WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to delete attack log '{}'", id))?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn clear_attack_logs(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM attack_logs")
            .execute(&self.pool)
            .await
            .context("failed to clear attack logs")?;

        Ok(result.rows_affected())
    }

    pub async fn create_user(&self, user: &NewUser) -> Result<User> {
        let result = sqlx::query(
            r#"
            INSERT INTO users (username, password_hash, role)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to create user '{}'", user.username))?;

        let created_user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, password_hash, role, created_at
            FROM users
            WHERE id = ?1
            "#,
        )
        .bind(result.last_insert_rowid())
        .fetch_one(&self.pool)
        .await
        .context("failed to reload inserted user")?;

        Ok(created_user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, password_hash, role, created_at
            FROM users
            WHERE username = ?1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("failed to fetch user '{}'", username))?;

        Ok(user)
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, password_hash, role, created_at
            FROM users
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to list users")?;

        Ok(users)
    }

    pub async fn delete_user(&self, username: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE username = ?1")
            .bind(username)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to delete user '{}'", username))?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn update_user(
        &self,
        username: &str,
        password_hash: Option<&str>,
        role: Option<&str>,
    ) -> Result<Option<User>> {
        let result = sqlx::query(
            r#"
            UPDATE users
            SET
                password_hash = COALESCE(?1, password_hash),
                role = COALESCE(?2, role)
            WHERE username = ?3
            "#,
        )
        .bind(password_hash)
        .bind(role)
        .bind(username)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to update user '{}'", username))?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.get_user_by_username(username).await
    }
}
