use chrono::Utc;
use ink_api::{KeyParamsData, SessionBody, SyncItem, UserData};
use ink_core::{InkError, InkResult};
use ink_fs::WorkspacePaths;
use rusqlite::{Connection, Error as SqlError, ErrorCode, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub profile: String,
    pub server: String,
    pub email: String,
    pub authenticated_at: String,
    pub refreshed_at: Option<String>,
    #[serde(default)]
    pub master_key: Option<String>,
    pub session: SessionBody,
    pub access_token_cookie: Option<String>,
    pub refresh_token_cookie: Option<String>,
    pub user: Option<UserData>,
    pub key_params: Option<KeyParamsData>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub sync_token: Option<String>,
    pub cursor_token: Option<String>,
    pub last_pulled_at: Option<String>,
    pub last_pushed_at: Option<String>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub item_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppState {
    pub last_auth_at: Option<String>,
    pub last_pull_at: Option<String>,
    pub last_push_at: Option<String>,
    pub last_sync_at: Option<String>,
    pub last_sync_status: Option<String>,
    #[serde(default)]
    pub conflicts: Vec<SyncConflict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub id: String,
    pub uuid: Option<String>,
    pub title: String,
    pub file: String,
    pub reason: String,
    pub detected_at: String,
    pub remote_updated_at: Option<String>,
    pub local_updated_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    db_path: PathBuf,
    sessions_dir: PathBuf,
    sync_dir: PathBuf,
    state_json_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct EnvCredentials {
    pub email: String,
    pub password: String,
}

impl AppState {
    pub fn mark_auth_ok(&mut self) {
        self.last_auth_at = Some(Utc::now().to_rfc3339());
    }

    pub fn mark_pull_ok(&mut self) {
        let now = Utc::now().to_rfc3339();
        self.last_pull_at = Some(now.clone());
        self.last_sync_at = Some(now);
        self.last_sync_status = Some("ok".to_string());
    }

    pub fn mark_push_ok(&mut self) {
        let now = Utc::now().to_rfc3339();
        self.last_push_at = Some(now.clone());
        self.last_sync_at = Some(now);
        self.last_sync_status = Some("ok".to_string());
    }

    pub fn mark_error(&mut self, message: &str) {
        self.last_sync_status = Some(format!("error: {message}"));
    }
}

impl SessionStore {
    pub fn from_workspace(paths: &WorkspacePaths) -> InkResult<Self> {
        fs::create_dir_all(&paths.sessions_dir).map_err(|err| {
            InkError::io(format!(
                "failed to create sessions directory '{}': {}",
                paths.sessions_dir.display(),
                err
            ))
        })?;

        let sync_dir = paths.cache_dir.join("sync");
        fs::create_dir_all(&sync_dir).map_err(|err| {
            InkError::io(format!(
                "failed to create sync cache directory '{}': {}",
                sync_dir.display(),
                err
            ))
        })?;

        let store = Self {
            db_path: paths.state_db_path.clone(),
            sessions_dir: paths.sessions_dir.clone(),
            sync_dir,
            state_json_path: paths.ink_dir.join("state.json"),
        };

        let conn = store.connection()?;
        store.initialize_schema(&conn)?;
        store.migrate_legacy_json_if_needed(&conn)?;

        Ok(store)
    }

    pub fn load(&self, profile: &str) -> InkResult<Option<StoredSession>> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM sessions WHERE profile = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| sqlite_error("load session", &self.db_path, err))?;

        let Some(payload) = payload else {
            return Ok(None);
        };

        let parsed = serde_json::from_str::<StoredSession>(&payload).map_err(|err| {
            InkError::io(format!(
                "failed to parse stored session in '{}': {}",
                self.db_path.display(),
                err
            ))
        })?;

        Ok(Some(parsed))
    }

    pub fn save(&self, profile: &str, session: &StoredSession) -> InkResult<()> {
        let key = profile_key(profile);
        let payload = serde_json::to_string(session)
            .map_err(|err| InkError::io(format!("failed to serialize session data: {err}")))?;

        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO sessions (profile, payload_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(profile) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            params![key, payload, Utc::now().to_rfc3339()],
        )
        .map_err(|err| sqlite_error("save session", &self.db_path, err))?;

        Ok(())
    }

    pub fn remove(&self, profile: &str) -> InkResult<()> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        conn.execute("DELETE FROM sessions WHERE profile = ?1", params![key])
            .map_err(|err| sqlite_error("remove session", &self.db_path, err))?;
        Ok(())
    }

    pub fn mark_refreshed(
        &self,
        profile: &str,
        session_body: SessionBody,
        access_token_cookie: Option<String>,
        refresh_token_cookie: Option<String>,
    ) -> InkResult<StoredSession> {
        let mut current = self.load(profile)?.ok_or_else(|| {
            InkError::auth(format!(
                "no active session for profile '{profile}'; run `ink auth login` first"
            ))
        })?;

        current.session = session_body;
        if access_token_cookie.is_some() {
            current.access_token_cookie = access_token_cookie;
        }
        if refresh_token_cookie.is_some() {
            current.refresh_token_cookie = refresh_token_cookie;
        }
        current.refreshed_at = Some(Utc::now().to_rfc3339());
        self.save(profile, &current)?;
        Ok(current)
    }

    pub fn load_sync_state(&self, profile: &str) -> InkResult<SyncState> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM sync_state WHERE profile = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| sqlite_error("load sync state", &self.db_path, err))?;

        let Some(payload) = payload else {
            return Ok(SyncState::default());
        };

        serde_json::from_str::<SyncState>(&payload).map_err(|err| {
            InkError::io(format!(
                "failed to parse sync state in '{}': {}",
                self.db_path.display(),
                err
            ))
        })
    }

    pub fn save_sync_state(&self, profile: &str, state: &SyncState) -> InkResult<()> {
        let key = profile_key(profile);
        let payload = serde_json::to_string(state)
            .map_err(|err| InkError::io(format!("failed to encode sync state: {err}")))?;

        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO sync_state (profile, payload_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(profile) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            params![key, payload, Utc::now().to_rfc3339()],
        )
        .map_err(|err| sqlite_error("save sync state", &self.db_path, err))?;

        Ok(())
    }

    pub fn load_cached_items(&self, profile: &str) -> InkResult<Vec<SyncItem>> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        let mut statement = conn
            .prepare("SELECT payload_json FROM sync_items WHERE profile = ?1 ORDER BY uuid ASC")
            .map_err(|err| sqlite_error("prepare cached items query", &self.db_path, err))?;

        let rows = statement
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|err| sqlite_error("query cached items", &self.db_path, err))?;

        let mut items = Vec::new();
        for row in rows {
            let payload =
                row.map_err(|err| sqlite_error("read cached item row", &self.db_path, err))?;
            let parsed = serde_json::from_str::<SyncItem>(&payload).map_err(|err| {
                InkError::io(format!(
                    "failed to parse cached sync item in '{}': {}",
                    self.db_path.display(),
                    err
                ))
            })?;
            items.push(parsed);
        }

        Ok(items)
    }

    pub fn save_cached_items(&self, profile: &str, items: &[SyncItem]) -> InkResult<()> {
        let key = profile_key(profile);
        let mut conn = self.connection()?;
        let transaction = conn
            .transaction()
            .map_err(|err| sqlite_error("start cached items transaction", &self.db_path, err))?;

        transaction
            .execute("DELETE FROM sync_items WHERE profile = ?1", params![key])
            .map_err(|err| sqlite_error("clear cached items", &self.db_path, err))?;

        for item in items {
            let payload = serde_json::to_string(item)
                .map_err(|err| InkError::io(format!("failed to encode cached item: {err}")))?;
            transaction
                .execute(
                    "INSERT INTO sync_items (profile, uuid, payload_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    params![key, item.uuid, payload, Utc::now().to_rfc3339()],
                )
                .map_err(|err| sqlite_error("insert cached item", &self.db_path, err))?;
        }

        transaction
            .commit()
            .map_err(|err| sqlite_error("commit cached items transaction", &self.db_path, err))?;

        Ok(())
    }

    pub fn clear_sync_cache(&self, profile: &str) -> InkResult<()> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        conn.execute("DELETE FROM sync_state WHERE profile = ?1", params![key])
            .map_err(|err| sqlite_error("clear sync state", &self.db_path, err))?;
        conn.execute("DELETE FROM sync_items WHERE profile = ?1", params![key])
            .map_err(|err| sqlite_error("clear cached items", &self.db_path, err))?;
        Ok(())
    }

    pub fn load_app_state(&self, profile: &str) -> InkResult<AppState> {
        let key = profile_key(profile);
        let conn = self.connection()?;
        let payload = conn
            .query_row(
                "SELECT payload_json FROM app_state WHERE profile = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| sqlite_error("load app state", &self.db_path, err))?;

        if let Some(payload) = payload {
            return serde_json::from_str::<AppState>(&payload).map_err(|err| {
                InkError::io(format!(
                    "failed to parse app state in '{}': {}",
                    self.db_path.display(),
                    err
                ))
            });
        }

        let migrated = self.load_legacy_state_json()?;
        if let Some(legacy_state) = migrated {
            self.save_app_state(profile, &legacy_state)?;
            return Ok(legacy_state);
        }

        Ok(AppState::default())
    }

    pub fn save_app_state(&self, profile: &str, state: &AppState) -> InkResult<()> {
        let key = profile_key(profile);
        let payload = serde_json::to_string(state)
            .map_err(|err| InkError::io(format!("failed to serialize app state: {err}")))?;

        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO app_state (profile, payload_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(profile) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            params![key, payload, Utc::now().to_rfc3339()],
        )
        .map_err(|err| sqlite_error("save app state", &self.db_path, err))?;

        Ok(())
    }

    fn connection(&self) -> InkResult<Connection> {
        Connection::open(&self.db_path)
            .map_err(|err| sqlite_error("open state database", &self.db_path, err))
    }

    fn initialize_schema(&self, conn: &Connection) -> InkResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS sessions (
                 profile TEXT PRIMARY KEY,
                 payload_json TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_state (
                 profile TEXT PRIMARY KEY,
                 payload_json TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_items (
                 profile TEXT NOT NULL,
                 uuid TEXT NOT NULL,
                 payload_json TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY (profile, uuid)
             );
             CREATE TABLE IF NOT EXISTS app_state (
                 profile TEXT PRIMARY KEY,
                 payload_json TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );",
        )
        .map_err(|err| sqlite_error("initialize schema", &self.db_path, err))?;

        Ok(())
    }

    fn migrate_legacy_json_if_needed(&self, conn: &Connection) -> InkResult<()> {
        if table_is_empty(conn, "sessions", &self.db_path)? {
            self.migrate_legacy_sessions(conn)?;
        }

        if table_is_empty(conn, "sync_state", &self.db_path)? {
            self.migrate_legacy_sync_state(conn)?;
        }

        if table_is_empty(conn, "sync_items", &self.db_path)? {
            self.migrate_legacy_sync_items(conn)?;
        }

        Ok(())
    }

    fn migrate_legacy_sessions(&self, conn: &Connection) -> InkResult<()> {
        let entries = fs::read_dir(&self.sessions_dir).map_err(|err| {
            InkError::io(format!(
                "failed to list legacy sessions directory '{}': {}",
                self.sessions_dir.display(),
                err
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|err| {
                InkError::io(format!("failed to read session directory entry: {err}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let raw = fs::read_to_string(&path).map_err(|err| {
                InkError::io(format!(
                    "failed to read legacy session file '{}': {}",
                    path.display(),
                    err
                ))
            })?;
            if raw.trim().is_empty() {
                continue;
            }

            let session = serde_json::from_str::<StoredSession>(&raw).map_err(|err| {
                InkError::io(format!(
                    "failed to parse legacy session file '{}': {}",
                    path.display(),
                    err
                ))
            })?;

            let key = profile_key(&session.profile);
            let payload = serde_json::to_string(&session)
                .map_err(|err| InkError::io(format!("failed to encode migrated session: {err}")))?;
            conn.execute(
                "INSERT INTO sessions (profile, payload_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(profile) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![key, payload, Utc::now().to_rfc3339()],
            )
            .map_err(|err| sqlite_error("migrate legacy sessions", &self.db_path, err))?;
        }

        Ok(())
    }

    fn migrate_legacy_sync_state(&self, conn: &Connection) -> InkResult<()> {
        let entries = fs::read_dir(&self.sync_dir).map_err(|err| {
            InkError::io(format!(
                "failed to list legacy sync cache directory '{}': {}",
                self.sync_dir.display(),
                err
            ))
        })?;

        for entry in entries {
            let entry = entry
                .map_err(|err| InkError::io(format!("failed to read sync cache entry: {err}")))?;
            let path = entry.path();
            let Some(profile) = legacy_profile_from_path(&path, "-state.json") else {
                continue;
            };

            let raw = fs::read_to_string(&path).map_err(|err| {
                InkError::io(format!(
                    "failed to read legacy sync state '{}': {}",
                    path.display(),
                    err
                ))
            })?;
            if raw.trim().is_empty() {
                continue;
            }

            let state = serde_json::from_str::<SyncState>(&raw).map_err(|err| {
                InkError::io(format!(
                    "failed to parse legacy sync state '{}': {}",
                    path.display(),
                    err
                ))
            })?;

            let payload = serde_json::to_string(&state).map_err(|err| {
                InkError::io(format!("failed to encode migrated sync state: {err}"))
            })?;
            conn.execute(
                "INSERT INTO sync_state (profile, payload_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(profile) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![profile, payload, Utc::now().to_rfc3339()],
            )
            .map_err(|err| sqlite_error("migrate legacy sync state", &self.db_path, err))?;
        }

        Ok(())
    }

    fn migrate_legacy_sync_items(&self, conn: &Connection) -> InkResult<()> {
        let entries = fs::read_dir(&self.sync_dir).map_err(|err| {
            InkError::io(format!(
                "failed to list legacy sync cache directory '{}': {}",
                self.sync_dir.display(),
                err
            ))
        })?;

        for entry in entries {
            let entry = entry
                .map_err(|err| InkError::io(format!("failed to read sync cache entry: {err}")))?;
            let path = entry.path();
            let Some(profile) = legacy_profile_from_path(&path, "-items.json") else {
                continue;
            };

            let raw = fs::read_to_string(&path).map_err(|err| {
                InkError::io(format!(
                    "failed to read legacy cached items '{}': {}",
                    path.display(),
                    err
                ))
            })?;
            if raw.trim().is_empty() {
                continue;
            }

            let items = serde_json::from_str::<Vec<SyncItem>>(&raw).map_err(|err| {
                InkError::io(format!(
                    "failed to parse legacy cached items '{}': {}",
                    path.display(),
                    err
                ))
            })?;

            for item in items {
                let payload = serde_json::to_string(&item).map_err(|err| {
                    InkError::io(format!("failed to encode migrated cached item: {err}"))
                })?;
                conn.execute(
                    "INSERT INTO sync_items (profile, uuid, payload_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    params![profile, item.uuid, payload, Utc::now().to_rfc3339()],
                )
                .map_err(|err| sqlite_error("migrate legacy cached items", &self.db_path, err))?;
            }
        }

        Ok(())
    }

    fn load_legacy_state_json(&self) -> InkResult<Option<AppState>> {
        if !self.state_json_path.exists() {
            return Ok(None);
        }

        let raw = fs::read_to_string(&self.state_json_path).map_err(|err| {
            InkError::io(format!(
                "failed to read legacy state file '{}': {}",
                self.state_json_path.display(),
                err
            ))
        })?;

        if raw.trim().is_empty() {
            return Ok(None);
        }

        let state = serde_json::from_str::<AppState>(&raw).map_err(|err| {
            InkError::io(format!(
                "failed to parse legacy state file '{}': {}",
                self.state_json_path.display(),
                err
            ))
        })?;

        Ok(Some(state))
    }
}

pub fn resolve_env_credentials(workspace_root: &Path) -> InkResult<Option<EnvCredentials>> {
    if let Some(creds) = credentials_from_env() {
        return Ok(Some(creds));
    }

    if let Some(path) = resolve_env_file(workspace_root) {
        let values = load_env_file(&path)?;
        let email = values
            .get("SN_EMAIL")
            .or_else(|| values.get("STANDARDNOTES_EMAIL"))
            .cloned();
        let password = values
            .get("SN_PASSWORD")
            .or_else(|| values.get("STANDARDNOTES_PASSWORD"))
            .cloned();

        if let (Some(email), Some(password)) = (email, password)
            && !email.trim().is_empty()
            && !password.is_empty()
        {
            return Ok(Some(EnvCredentials { email, password }));
        }
    }

    Ok(None)
}

fn credentials_from_env() -> Option<EnvCredentials> {
    let email = std::env::var("SN_EMAIL")
        .ok()
        .or_else(|| std::env::var("STANDARDNOTES_EMAIL").ok())?;
    let password = std::env::var("SN_PASSWORD")
        .ok()
        .or_else(|| std::env::var("STANDARDNOTES_PASSWORD").ok())?;

    if email.trim().is_empty() || password.is_empty() {
        return None;
    }

    Some(EnvCredentials { email, password })
}

fn resolve_env_file(workspace_root: &Path) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("INK_ENV_FILE") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    if let Ok(cwd) = std::env::current_dir()
        && let Some(found) = search_upwards_for(&cwd, Path::new(".env"))
    {
        return Some(found);
    }

    search_upwards_for(workspace_root, Path::new(".env"))
}

fn search_upwards_for(start: &Path, relative_path: &Path) -> Option<PathBuf> {
    let mut cursor = Some(start);

    while let Some(path) = cursor {
        let candidate = path.join(relative_path);
        if candidate.exists() {
            return Some(candidate);
        }
        cursor = path.parent();
    }

    None
}

fn load_env_file(path: &Path) -> InkResult<BTreeMap<String, String>> {
    let raw = fs::read_to_string(path).map_err(|err| {
        InkError::io(format!(
            "failed to read env file '{}': {}",
            path.display(),
            err
        ))
    })?;

    let mut vars = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };

        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }

        vars.insert(key.to_string(), value);
    }

    Ok(vars)
}

fn legacy_profile_from_path(path: &Path, suffix: &str) -> Option<String> {
    let filename = path.file_name()?.to_str()?;
    let prefix = filename.strip_suffix(suffix)?;
    if prefix.is_empty() {
        None
    } else {
        Some(prefix.to_string())
    }
}

fn table_is_empty(conn: &Connection, table: &str, db_path: &Path) -> InkResult<bool> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = conn
        .query_row(&query, [], |row| row.get(0))
        .map_err(|err| sqlite_error("count table rows", db_path, err))?;
    Ok(count == 0)
}

fn sqlite_error(action: &str, db_path: &Path, err: SqlError) -> InkError {
    if let SqlError::SqliteFailure(code, message) = &err
        && (code.code == ErrorCode::DatabaseCorrupt || code.code == ErrorCode::NotADatabase)
    {
        let detail = message.as_deref().unwrap_or("sqlite reported corruption");
        return InkError::io(format!(
            "failed to {action}: state database '{}' is corrupted ({detail}); remove '.ink/state.db' (or reinitialize the workspace) and run `ink sync pull` to rebuild local cache",
            db_path.display()
        ));
    }

    InkError::io(format!(
        "failed to {action} using state database '{}': {}",
        db_path.display(),
        err
    ))
}

fn profile_key(profile: &str) -> String {
    let mut output = String::with_capacity(profile.len());
    for ch in profile.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() {
        "default".to_string()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_sanitization_is_stable() {
        assert_eq!(profile_key("default"), "default");
        assert_eq!(profile_key("my profile"), "my_profile");
        assert_eq!(profile_key(""), "default");
    }
}
