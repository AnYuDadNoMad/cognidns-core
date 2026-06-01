use std::fs;
use std::path::PathBuf;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand_core::OsRng;
use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;

#[derive(Debug, Clone)]
pub struct DbAuthUser {
    pub username: String,
    pub token: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct DbAuthConfig {
    pub admin_token: Option<String>,
    pub users: Vec<DbAuthUser>,
}

#[derive(Debug, Clone)]
pub struct DbAuthIdentity {
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct DbAuditLogEntry {
    pub timestamp: String,
    pub operation: String,
    pub instance_id: String,
    pub instance_name: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DbAuditOperationCount {
    pub operation: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct DbAuditDailyCount {
    pub day: String,
    pub total: u64,
    pub success: u64,
    pub failed: u64,
}

#[derive(Debug, Clone)]
pub struct DbAuditSummary {
    pub total: u64,
    pub success: u64,
    pub failed: u64,
    pub operations: Vec<DbAuditOperationCount>,
    pub daily: Vec<DbAuditDailyCount>,
}

#[derive(Debug, Clone)]
pub struct DbBackupEntry {
    pub id: String,
    pub created_at: String,
    pub file_count: usize,
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PlatformDb {
    path: PathBuf,
}

fn hash_token(token: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map(|v| v.to_string())
        .map_err(|err| format!("failed to hash token: {err}"))
}

fn token_matches(stored: &str, provided: &str) -> bool {
    if stored.starts_with("$argon2") {
        let Ok(hash) = PasswordHash::new(stored) else {
            return false;
        };
        Argon2::default()
            .verify_password(provided.as_bytes(), &hash)
            .is_ok()
    } else {
        stored == provided
    }
}

impl PlatformDb {
    pub fn open(path: &str) -> Result<Self, String> {
        let db = Self {
            path: PathBuf::from(path),
        };
        db.ensure_parent_dir()?;
        db.init_schema()?;
        Ok(db)
    }

    pub fn bootstrap_auth_from_config(&self, auth: Option<&DbAuthConfig>) -> Result<(), String> {
        let mut conn = self.connect()?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("failed to start transaction: {err}"))?;

        let user_count: i64 = tx
            .query_row("SELECT COUNT(*) FROM platform_users", [], |row| row.get(0))
            .map_err(|err| format!("failed to count users: {err}"))?;

        let admin_token: Option<String> = tx
            .query_row(
                "SELECT value FROM platform_meta WHERE key='admin_token'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| format!("failed to read admin token: {err}"))?;

        let has_state = user_count > 0 || admin_token.as_deref().unwrap_or("").trim().len() > 0;
        if !has_state {
            if let Some(auth) = auth {
                let admin_token = auth
                    .admin_token
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .map(hash_token)
                    .transpose()?
                    .unwrap_or_default();
                tx.execute(
                    "INSERT OR REPLACE INTO platform_meta(key, value) VALUES('admin_token', ?1)",
                    params![admin_token],
                )
                .map_err(|err| format!("failed to save admin token: {err}"))?;

                for user in &auth.users {
                    let token_hash = hash_token(&user.token)?;
                    tx.execute(
                        "INSERT INTO platform_users(username, token, role) VALUES (?1, ?2, ?3)",
                        params![user.username, token_hash, user.role],
                    )
                    .map_err(|err| format!("failed to insert user '{}': {err}", user.username))?;
                }
            }
        }

        tx.commit()
            .map_err(|err| format!("failed to commit bootstrap transaction: {err}"))
    }

    pub fn replace_auth_from_config(&self, auth: Option<&DbAuthConfig>) -> Result<(), String> {
        let mut conn = self.connect()?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("failed to start transaction: {err}"))?;

        tx.execute("DELETE FROM platform_users", [])
            .map_err(|err| format!("failed to clear users: {err}"))?;

        let admin_token = auth
            .and_then(|value| value.admin_token.as_deref())
            .filter(|v| !v.trim().is_empty())
            .map(hash_token)
            .transpose()?
            .unwrap_or_default();
        tx.execute(
            "INSERT OR REPLACE INTO platform_meta(key, value) VALUES('admin_token', ?1)",
            params![admin_token],
        )
        .map_err(|err| format!("failed to replace admin token: {err}"))?;

        if let Some(auth) = auth {
            for user in &auth.users {
                let token_hash = hash_token(&user.token)?;
                tx.execute(
                    "INSERT INTO platform_users(username, token, role) VALUES (?1, ?2, ?3)",
                    params![user.username, token_hash, user.role],
                )
                .map_err(|err| format!("failed to insert user '{}': {err}", user.username))?;
            }
        }

        tx.commit()
            .map_err(|err| format!("failed to commit replace transaction: {err}"))
    }

    pub fn load_auth_config(&self) -> Result<Option<DbAuthConfig>, String> {
        let conn = self.connect()?;

        let admin_token: Option<String> = conn
            .query_row(
                "SELECT value FROM platform_meta WHERE key='admin_token'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| format!("failed to read admin token: {err}"))?;

        let mut stmt = conn
            .prepare("SELECT username, token, role FROM platform_users ORDER BY username COLLATE NOCASE ASC")
            .map_err(|err| format!("failed to prepare users query: {err}"))?;

        let users_iter = stmt
            .query_map([], |row| {
                Ok(DbAuthUser {
                    username: row.get(0)?,
                    token: row.get(1)?,
                    role: row.get(2)?,
                })
            })
            .map_err(|err| format!("failed to query users: {err}"))?;

        let mut users = Vec::new();
        for item in users_iter {
            users.push(item.map_err(|err| format!("failed to decode user row: {err}"))?);
        }

        let cleaned_admin =
            admin_token.and_then(|v| if v.trim().is_empty() { None } else { Some(v) });

        if cleaned_admin.is_none() && users.is_empty() {
            return Ok(None);
        }

        Ok(Some(DbAuthConfig {
            admin_token: cleaned_admin,
            users,
        }))
    }

    pub fn is_auth_required(&self) -> Result<bool, String> {
        let auth = self.load_auth_config()?;
        Ok(match auth {
            None => false,
            Some(value) => value.admin_token.is_some() || !value.users.is_empty(),
        })
    }

    pub fn resolve_token(&self, token: &str) -> Result<Option<DbAuthIdentity>, String> {
        let auth = self.load_auth_config()?;
        let Some(auth) = auth else {
            return Ok(Some(DbAuthIdentity {
                username: "admin".to_string(),
                role: "admin".to_string(),
            }));
        };

        let token = token.trim();
        if token.is_empty() {
            return Ok(None);
        }

        if auth
            .admin_token
            .as_deref()
            .map(|v| token_matches(v, token))
            .unwrap_or(false)
        {
            return Ok(Some(DbAuthIdentity {
                username: "admin".to_string(),
                role: "admin".to_string(),
            }));
        }

        Ok(auth
            .users
            .into_iter()
            .find(|user| token_matches(&user.token, token))
            .map(|user| DbAuthIdentity {
                username: user.username,
                role: user.role,
            }))
    }

    pub fn verify_user_token(
        &self,
        username: &str,
        token: &str,
    ) -> Result<Option<DbAuthIdentity>, String> {
        let auth = self.load_auth_config()?;
        let Some(auth) = auth else {
            return Ok(Some(DbAuthIdentity {
                username: "admin".to_string(),
                role: "admin".to_string(),
            }));
        };

        let username = username.trim();
        let token = token.trim();

        if username.is_empty() || token.is_empty() {
            return Ok(None);
        }

        if username.eq_ignore_ascii_case("admin")
            && auth
                .admin_token
                .as_deref()
                .map(|v| token_matches(v, token))
                .unwrap_or(false)
        {
            return Ok(Some(DbAuthIdentity {
                username: "admin".to_string(),
                role: "admin".to_string(),
            }));
        }

        Ok(auth
            .users
            .into_iter()
            .find(|user| {
                user.username.eq_ignore_ascii_case(username) && token_matches(&user.token, token)
            })
            .map(|user| DbAuthIdentity {
                username: user.username,
                role: user.role,
            }))
    }

    pub fn list_users(&self) -> Result<Vec<DbAuthUser>, String> {
        let auth = self.load_auth_config()?;
        Ok(auth.map(|value| value.users).unwrap_or_default())
    }

    pub fn get_user(&self, username: &str) -> Result<Option<DbAuthUser>, String> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT username, token, role FROM platform_users WHERE lower(username) = lower(?1)",
            params![username],
            |row| {
                Ok(DbAuthUser {
                    username: row.get(0)?,
                    token: row.get(1)?,
                    role: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|err| format!("failed to query user '{}': {err}", username))
    }

    pub fn create_user(&self, user: &DbAuthUser) -> Result<(), String> {
        let conn = self.connect()?;
        let token_hash = hash_token(&user.token)?;
        conn.execute(
            "INSERT INTO platform_users(username, token, role) VALUES (?1, ?2, ?3)",
            params![user.username, token_hash, user.role],
        )
        .map_err(|err| format!("failed to create user '{}': {err}", user.username))?;
        Ok(())
    }

    pub fn update_user(
        &self,
        username: &str,
        new_username: Option<&str>,
        new_role: Option<&str>,
    ) -> Result<DbAuthUser, String> {
        let mut current = self
            .get_user(username)?
            .ok_or_else(|| format!("user '{}' not found", username))?;

        if let Some(value) = new_username {
            current.username = value.to_string();
        }
        if let Some(value) = new_role {
            current.role = value.to_string();
        }

        let conn = self.connect()?;
        conn.execute(
            "UPDATE platform_users SET username = ?1, role = ?2 WHERE lower(username) = lower(?3)",
            params![current.username, current.role, username],
        )
        .map_err(|err| format!("failed to update user '{}': {err}", username))?;

        self.get_user(&current.username)?
            .ok_or_else(|| format!("user '{}' not found after update", current.username))
    }

    pub fn delete_user(&self, username: &str) -> Result<(), String> {
        let conn = self.connect()?;
        let rows = conn
            .execute(
                "DELETE FROM platform_users WHERE lower(username) = lower(?1)",
                params![username],
            )
            .map_err(|err| format!("failed to delete user '{}': {err}", username))?;
        if rows == 0 {
            return Err(format!("user '{}' not found", username));
        }
        Ok(())
    }

    pub fn regen_user_token(&self, username: &str, token: &str) -> Result<DbAuthUser, String> {
        let conn = self.connect()?;
        let token_hash = hash_token(token)?;
        let rows = conn
            .execute(
                "UPDATE platform_users SET token = ?1 WHERE lower(username) = lower(?2)",
                params![token_hash, username],
            )
            .map_err(|err| format!("failed to regenerate token for '{}': {err}", username))?;
        if rows == 0 {
            return Err(format!("user '{}' not found", username));
        }
        self.get_user(username)?
            .ok_or_else(|| format!("user '{}' not found after token update", username))
    }

    pub fn count_admin_users(&self) -> Result<usize, String> {
        let conn = self.connect()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM platform_users WHERE lower(role) = 'admin'",
                [],
                |row| row.get(0),
            )
            .map_err(|err| format!("failed to count admin users: {err}"))?;
        Ok(count.max(0) as usize)
    }

    pub fn append_audit_log(&self, entry: &DbAuditLogEntry) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO audit_logs(timestamp, operation, instance_id, instance_name, status, message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.timestamp,
                entry.operation,
                entry.instance_id,
                entry.instance_name,
                entry.status,
                entry.message
            ],
        )
        .map_err(|err| format!("failed to append audit log: {err}"))?;
        Ok(())
    }

    pub fn list_audit_logs(
        &self,
        instance_id: Option<&str>,
        operation: Option<&str>,
        status: Option<&str>,
        from_ts: Option<&str>,
        to_ts: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DbAuditLogEntry>, String> {
        let limit = limit.max(1).min(1000);
        let offset = offset.min(100_000);

        let conn = self.connect()?;
        let mut stmt = conn
            .prepare(
                "SELECT timestamp, operation, instance_id, instance_name, status, message
                 FROM audit_logs
                 WHERE (?1 IS NULL OR lower(instance_id) = lower(?1))
                   AND (?2 IS NULL OR lower(operation) = lower(?2))
                   AND (?3 IS NULL OR lower(status) = lower(?3))
                   AND (?4 IS NULL OR timestamp >= ?4)
                   AND (?5 IS NULL OR timestamp <= ?5)
                 ORDER BY id DESC
                 LIMIT ?6 OFFSET ?7",
            )
            .map_err(|err| format!("failed to prepare audit query: {err}"))?;

        let iter = stmt
            .query_map(
                params![
                    instance_id,
                    operation,
                    status,
                    from_ts,
                    to_ts,
                    limit as i64,
                    offset as i64
                ],
                |row| {
                    Ok(DbAuditLogEntry {
                        timestamp: row.get(0)?,
                        operation: row.get(1)?,
                        instance_id: row.get(2)?,
                        instance_name: row.get(3)?,
                        status: row.get(4)?,
                        message: row.get(5)?,
                    })
                },
            )
            .map_err(|err| format!("failed to query audit logs: {err}"))?;

        let mut items = Vec::new();
        for row in iter {
            items.push(row.map_err(|err| format!("failed to decode audit row: {err}"))?);
        }

        Ok(items)
    }

    pub fn summarize_audit_logs(
        &self,
        instance_id: Option<&str>,
        operation: Option<&str>,
        status: Option<&str>,
        from_ts: Option<&str>,
        to_ts: Option<&str>,
        day_limit: usize,
    ) -> Result<DbAuditSummary, String> {
        let conn = self.connect()?;
        let day_limit = day_limit.max(1).min(90);

        let (total, success, failed) = conn
            .query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN lower(status)='success' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN lower(status)='failed' THEN 1 ELSE 0 END), 0)
                 FROM audit_logs
                 WHERE (?1 IS NULL OR lower(instance_id) = lower(?1))
                   AND (?2 IS NULL OR lower(operation) = lower(?2))
                   AND (?3 IS NULL OR lower(status) = lower(?3))
                   AND (?4 IS NULL OR timestamp >= ?4)
                   AND (?5 IS NULL OR timestamp <= ?5)",
                params![instance_id, operation, status, from_ts, to_ts],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .map_err(|err| format!("failed to aggregate audit totals: {err}"))?;

        let mut op_stmt = conn
            .prepare(
                "SELECT operation, COUNT(*) AS c
                 FROM audit_logs
                 WHERE (?1 IS NULL OR lower(instance_id) = lower(?1))
                   AND (?2 IS NULL OR lower(operation) = lower(?2))
                   AND (?3 IS NULL OR lower(status) = lower(?3))
                   AND (?4 IS NULL OR timestamp >= ?4)
                   AND (?5 IS NULL OR timestamp <= ?5)
                 GROUP BY operation
                 ORDER BY c DESC
                 LIMIT 10",
            )
            .map_err(|err| format!("failed to prepare audit operation summary: {err}"))?;

        let mut operations = Vec::new();
        let op_iter = op_stmt
            .query_map(
                params![instance_id, operation, status, from_ts, to_ts],
                |row| {
                    Ok(DbAuditOperationCount {
                        operation: row.get(0)?,
                        count: row.get::<_, i64>(1)?.max(0) as u64,
                    })
                },
            )
            .map_err(|err| format!("failed to query audit operation summary: {err}"))?;
        for row in op_iter {
            operations.push(
                row.map_err(|err| format!("failed to decode audit operation summary: {err}"))?,
            );
        }

        let mut day_stmt = conn
            .prepare(
                "SELECT
                    substr(timestamp, 1, 10) AS day,
                    COUNT(*) AS total,
                    SUM(CASE WHEN lower(status)='success' THEN 1 ELSE 0 END) AS success,
                    SUM(CASE WHEN lower(status)='failed' THEN 1 ELSE 0 END) AS failed
                 FROM audit_logs
                 WHERE (?1 IS NULL OR lower(instance_id) = lower(?1))
                   AND (?2 IS NULL OR lower(operation) = lower(?2))
                   AND (?3 IS NULL OR lower(status) = lower(?3))
                   AND (?4 IS NULL OR timestamp >= ?4)
                   AND (?5 IS NULL OR timestamp <= ?5)
                 GROUP BY day
                 ORDER BY day DESC
                 LIMIT ?6",
            )
            .map_err(|err| format!("failed to prepare audit daily summary: {err}"))?;

        let mut daily = Vec::new();
        let day_iter = day_stmt
            .query_map(
                params![
                    instance_id,
                    operation,
                    status,
                    from_ts,
                    to_ts,
                    day_limit as i64
                ],
                |row| {
                    Ok(DbAuditDailyCount {
                        day: row.get(0)?,
                        total: row.get::<_, i64>(1)?.max(0) as u64,
                        success: row.get::<_, i64>(2)?.max(0) as u64,
                        failed: row.get::<_, i64>(3)?.max(0) as u64,
                    })
                },
            )
            .map_err(|err| format!("failed to query audit daily summary: {err}"))?;
        for row in day_iter {
            daily.push(row.map_err(|err| format!("failed to decode audit daily summary: {err}"))?);
        }
        daily.reverse();

        Ok(DbAuditSummary {
            total,
            success,
            failed,
            operations,
            daily,
        })
    }

    pub fn upsert_backup_entry(&self, entry: &DbBackupEntry) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO backup_entries(id, created_at, file_count, size_bytes)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
               created_at = excluded.created_at,
               file_count = excluded.file_count,
               size_bytes = excluded.size_bytes",
            params![
                entry.id,
                entry.created_at,
                entry.file_count as i64,
                entry.size_bytes as i64
            ],
        )
        .map_err(|err| format!("failed to upsert backup entry '{}': {err}", entry.id))?;
        Ok(())
    }

    pub fn list_backup_entries(&self, limit: usize) -> Result<Vec<DbBackupEntry>, String> {
        let limit = limit.max(1).min(5000);
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_at, file_count, size_bytes
                 FROM backup_entries
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .map_err(|err| format!("failed to prepare backup query: {err}"))?;

        let iter = stmt
            .query_map(params![limit as i64], |row| {
                Ok(DbBackupEntry {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    file_count: row.get::<_, i64>(2)?.max(0) as usize,
                    size_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                })
            })
            .map_err(|err| format!("failed to query backup entries: {err}"))?;

        let mut items = Vec::new();
        for row in iter {
            items.push(row.map_err(|err| format!("failed to decode backup row: {err}"))?);
        }
        Ok(items)
    }

    pub fn delete_backup_entry(&self, id: &str) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute("DELETE FROM backup_entries WHERE id = ?1", params![id])
            .map_err(|err| format!("failed to delete backup entry '{}': {err}", id))?;
        Ok(())
    }

    fn ensure_parent_dir(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "failed to create db parent directory {}: {err}",
                        parent.display()
                    )
                })?;
            }
        }
        Ok(())
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE IF NOT EXISTS platform_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platform_users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                token TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                instance_name TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backup_entries (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                file_count INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_instance ON audit_logs(instance_id);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
            COMMIT;",
        )
        .map_err(|err| format!("failed to initialize platform db schema: {err}"))?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection, String> {
        let conn = Connection::open(&self.path)
            .map_err(|err| format!("failed to open platform db {}: {err}", self.path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|err| format!("failed to enable sqlite WAL mode: {err}"))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|err| format!("failed to set sqlite synchronous mode: {err}"))?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(|err| format!("failed to set sqlite busy_timeout: {err}"))?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path(name: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("cognidns-platform-db-{name}-{ts}.sqlite3"))
            .display()
            .to_string()
    }

    #[test]
    fn summarize_audit_logs_returns_zero_counts_when_empty() {
        let path = temp_db_path("summary-empty");
        let db = PlatformDb::open(&path).expect("open db");

        let summary = db
            .summarize_audit_logs(None, None, None, None, None, 14)
            .expect("summarize empty logs");

        assert_eq!(summary.total, 0);
        assert_eq!(summary.success, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.operations.is_empty());
        assert!(summary.daily.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn summarize_audit_logs_aggregates_counts_and_time_filters() {
        let path = temp_db_path("summary-data");
        let db = PlatformDb::open(&path).expect("open db");

        db.append_audit_log(&DbAuditLogEntry {
            timestamp: "2026-05-20T10:00:00Z".to_string(),
            operation: "view.update".to_string(),
            instance_id: "local-dev".to_string(),
            instance_name: "Local CogniDNS".to_string(),
            status: "success".to_string(),
            message: "ok".to_string(),
        })
        .expect("append log 1");
        db.append_audit_log(&DbAuditLogEntry {
            timestamp: "2026-05-20T11:00:00Z".to_string(),
            operation: "view.update".to_string(),
            instance_id: "local-dev".to_string(),
            instance_name: "Local CogniDNS".to_string(),
            status: "failed".to_string(),
            message: "fail".to_string(),
        })
        .expect("append log 2");
        db.append_audit_log(&DbAuditLogEntry {
            timestamp: "2026-05-21T09:00:00Z".to_string(),
            operation: "instance.reload".to_string(),
            instance_id: "local-dev".to_string(),
            instance_name: "Local CogniDNS".to_string(),
            status: "success".to_string(),
            message: "ok".to_string(),
        })
        .expect("append log 3");

        let summary = db
            .summarize_audit_logs(
                None,
                None,
                None,
                Some("2026-05-20T00:00:00Z"),
                Some("2026-05-20T23:59:59Z"),
                14,
            )
            .expect("summarize filtered logs");

        assert_eq!(summary.total, 2);
        assert_eq!(summary.success, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.operations.len(), 1);
        assert_eq!(summary.operations[0].operation, "view.update");
        assert_eq!(summary.operations[0].count, 2);
        assert_eq!(summary.daily.len(), 1);
        assert_eq!(summary.daily[0].day, "2026-05-20");
        assert_eq!(summary.daily[0].total, 2);
        assert_eq!(summary.daily[0].success, 1);
        assert_eq!(summary.daily[0].failed, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn auth_tokens_are_hashed_and_verifiable() {
        let path = temp_db_path("auth-hash");
        let db = PlatformDb::open(&path).expect("open db");

        db.replace_auth_from_config(Some(&DbAuthConfig {
            admin_token: Some("admin-secret".to_string()),
            users: vec![DbAuthUser {
                username: "alice".to_string(),
                token: "alice-secret".to_string(),
                role: "viewer".to_string(),
            }],
        }))
        .expect("replace auth with hashes");

        let conn = db.connect().expect("open connection");
        let raw_admin: String = conn
            .query_row(
                "SELECT value FROM platform_meta WHERE key='admin_token'",
                [],
                |row| row.get(0),
            )
            .expect("read admin token");
        assert!(raw_admin.starts_with("$argon2"));

        let raw_user_token: String = conn
            .query_row(
                "SELECT token FROM platform_users WHERE username='alice'",
                [],
                |row| row.get(0),
            )
            .expect("read user token");
        assert!(raw_user_token.starts_with("$argon2"));

        let admin_identity = db
            .resolve_token("admin-secret")
            .expect("resolve admin")
            .expect("admin identity");
        assert_eq!(admin_identity.username, "admin");
        assert_eq!(admin_identity.role, "admin");

        let user_identity = db
            .verify_user_token("alice", "alice-secret")
            .expect("verify user")
            .expect("user identity");
        assert_eq!(user_identity.username, "alice");
        assert_eq!(user_identity.role, "viewer");

        assert!(db
            .verify_user_token("alice", "wrong-secret")
            .expect("verify user wrong token")
            .is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plaintext_tokens_remain_backward_compatible() {
        let path = temp_db_path("auth-legacy");
        let db = PlatformDb::open(&path).expect("open db");

        // Simulate legacy rows that existed before hashing support.
        let conn = db.connect().expect("open connection");
        conn.execute(
            "INSERT OR REPLACE INTO platform_meta(key, value) VALUES('admin_token', ?1)",
            params!["legacy-admin"],
        )
        .expect("insert legacy admin token");
        conn.execute(
            "INSERT INTO platform_users(username, token, role) VALUES(?1, ?2, ?3)",
            params!["legacy-user", "legacy-token", "operator"],
        )
        .expect("insert legacy user token");

        assert!(db
            .resolve_token("legacy-admin")
            .expect("resolve legacy admin")
            .is_some());
        assert!(db
            .verify_user_token("legacy-user", "legacy-token")
            .expect("verify legacy user")
            .is_some());

        let _ = std::fs::remove_file(path);
    }
}
