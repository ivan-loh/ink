use chrono::Utc;
use ink_api::{ItemsSyncRequest, ItemsSyncResponseData, StandardNotesApi, SyncItem, SyncItemInput};
use ink_core::{ErrorKind, InkError, InkResult};
use ink_crypto::{decrypt_item_payload_004, encrypt_item_payload_004};
use ink_store::{SessionStore, StoredSession};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::Duration;

const DEFAULT_PAGE_LIMIT: u32 = 150;
const DEFAULT_MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullOutcome {
    pub retrieved: usize,
    pub conflicts: usize,
    pub pages: usize,
    pub cached_total: usize,
    pub sync_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushOutcome {
    pub pushed: usize,
    pub saved: usize,
    pub retrieved: usize,
    pub conflicts: usize,
    pub pages: usize,
    pub cached_total: usize,
    pub sync_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedNote {
    pub uuid: String,
    pub title: String,
    pub text: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedTag {
    pub uuid: String,
    pub title: String,
    pub references: Vec<String>,
    pub parent_uuid: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemsKeyMaterial {
    pub uuid: String,
    pub items_key: String,
    pub updated_at_timestamp: Option<i64>,
}

#[derive(Debug)]
pub struct SyncEngine<'a> {
    api: &'a StandardNotesApi,
    store: &'a SessionStore,
    profile: String,
    page_limit: u32,
    max_retries: u32,
}

impl<'a> SyncEngine<'a> {
    pub fn new(
        api: &'a StandardNotesApi,
        store: &'a SessionStore,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            api,
            store,
            profile: profile.into(),
            page_limit: DEFAULT_PAGE_LIMIT,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    pub fn with_page_limit(mut self, page_limit: u32) -> Self {
        self.page_limit = page_limit.max(1);
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn pull_all(&self) -> InkResult<PullOutcome> {
        let mut session = self.require_session()?;
        let mut state = self.store.load_sync_state(&self.profile)?;

        let mut pulled = Vec::new();
        let mut cursor = state.cursor_token.clone();
        let mut sync_token = state.sync_token.clone();
        let mut conflicts = 0usize;
        let mut pages = 0usize;

        loop {
            pages += 1;
            let response = match self.request_with_retry(
                &mut session,
                &ItemsSyncRequest {
                    items: Vec::new(),
                    limit: Some(self.page_limit),
                    sync_token: sync_token.clone(),
                    cursor_token: cursor.clone(),
                },
            ) {
                Ok(response) => response,
                Err(error) => {
                    state.last_error = Some(error.message.clone());
                    self.store.save_sync_state(&self.profile, &state)?;
                    return Err(error);
                }
            };

            conflicts += response.conflicts.len();
            pulled.extend(response.retrieved_items);

            if let Some(token) = response.sync_token {
                sync_token = Some(token);
            }

            cursor = response.cursor_token;
            if cursor.is_none() {
                break;
            }
        }

        let mut cached = self.store.load_cached_items(&self.profile)?;
        merge_items(&mut cached, pulled.clone());

        state.sync_token = sync_token.clone();
        state.cursor_token = None;
        state.last_pulled_at = Some(Utc::now().to_rfc3339());
        state.last_error = None;
        state.item_count = cached.len();

        self.store.save_cached_items(&self.profile, &cached)?;
        self.store.save_sync_state(&self.profile, &state)?;

        Ok(PullOutcome {
            retrieved: pulled.len(),
            conflicts,
            pages,
            cached_total: cached.len(),
            sync_token,
        })
    }

    pub fn push_items(&self, items: Vec<SyncItemInput>) -> InkResult<PushOutcome> {
        let mut session = self.require_session()?;
        let mut state = self.store.load_sync_state(&self.profile)?;
        let mut cached = self.store.load_cached_items(&self.profile)?;
        let pushed_lookup: HashMap<String, SyncItemInput> = items
            .iter()
            .cloned()
            .map(|item| (item.uuid.clone(), item))
            .collect();

        let total_pushed = items.len();
        let mut pending_items = Some(items);
        let mut cursor: Option<String> = None;

        let mut total_saved = 0usize;
        let mut total_retrieved = 0usize;
        let mut total_conflicts = 0usize;
        let mut pages = 0usize;

        loop {
            pages += 1;

            let response = match self.request_with_retry(
                &mut session,
                &ItemsSyncRequest {
                    items: pending_items.take().unwrap_or_default(),
                    limit: Some(self.page_limit),
                    sync_token: state.sync_token.clone(),
                    cursor_token: cursor.clone(),
                },
            ) {
                Ok(response) => response,
                Err(error) => {
                    state.last_error = Some(error.message.clone());
                    self.store.save_sync_state(&self.profile, &state)?;
                    return Err(error);
                }
            };

            total_saved += response.saved_items.len();
            total_retrieved += response.retrieved_items.len();
            total_conflicts += response.conflicts.len();

            let mut merged = response.saved_items;
            merged.extend(response.retrieved_items);
            hydrate_server_items_from_pushed_inputs(&mut merged, &pushed_lookup);
            merge_items(&mut cached, merged);

            if let Some(token) = response.sync_token {
                state.sync_token = Some(token);
            }

            cursor = response.cursor_token;
            if cursor.is_none() {
                break;
            }
        }

        state.cursor_token = None;
        state.last_pushed_at = Some(Utc::now().to_rfc3339());
        state.last_error = if total_conflicts > 0 {
            Some(format!("{total_conflicts} conflicts returned from server"))
        } else {
            None
        };
        state.item_count = cached.len();

        self.store.save_cached_items(&self.profile, &cached)?;
        self.store.save_sync_state(&self.profile, &state)?;

        Ok(PushOutcome {
            pushed: total_pushed,
            saved: total_saved,
            retrieved: total_retrieved,
            conflicts: total_conflicts,
            pages,
            cached_total: cached.len(),
            sync_token: state.sync_token,
        })
    }

    pub fn cached_items(&self) -> InkResult<Vec<SyncItem>> {
        self.store.load_cached_items(&self.profile)
    }

    pub fn clear_sync_state(&self) -> InkResult<()> {
        self.store.clear_sync_cache(&self.profile)
    }

    pub fn decrypted_items_keys(&self, master_key: &str) -> InkResult<Vec<ItemsKeyMaterial>> {
        let cached = self.store.load_cached_items(&self.profile)?;
        let mut keys = Vec::new();

        for item in cached {
            if item.content_type != "SN|ItemsKey" || item.deleted {
                continue;
            }

            let decrypted =
                match decrypt_item_payload_004(&item.content, &item.enc_item_key, master_key) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

            let Some(items_key) = decrypted.get("itemsKey").and_then(|value| value.as_str()) else {
                continue;
            };

            keys.push(ItemsKeyMaterial {
                uuid: item.uuid,
                items_key: items_key.to_string(),
                updated_at_timestamp: item.updated_at_timestamp,
            });
        }

        keys.sort_by(|left, right| {
            right
                .updated_at_timestamp
                .unwrap_or_default()
                .cmp(&left.updated_at_timestamp.unwrap_or_default())
        });

        Ok(keys)
    }

    pub fn default_items_key(&self, master_key: &str) -> InkResult<Option<ItemsKeyMaterial>> {
        Ok(self.decrypted_items_keys(master_key)?.into_iter().next())
    }

    pub fn decrypted_notes(&self, master_key: &str) -> InkResult<Vec<DecryptedNote>> {
        let cached = self.store.load_cached_items(&self.profile)?;
        let items_keys = self.decrypted_items_keys(master_key)?;
        let key_lookup: HashMap<String, String> = items_keys
            .into_iter()
            .map(|item| (item.uuid, item.items_key))
            .collect();

        let mut notes = Vec::new();
        let mut last_error: Option<InkError> = None;

        for item in cached {
            if item.deleted || item.content_type != "Note" {
                continue;
            }

            let Some(items_key_id) = item.items_key_id.as_deref() else {
                continue;
            };
            let Some(items_key) = key_lookup.get(items_key_id) else {
                continue;
            };

            match decrypt_item_payload_004(&item.content, &item.enc_item_key, items_key) {
                Ok(content) => {
                    let title = content
                        .get("title")
                        .and_then(|value| value.as_str())
                        .unwrap_or("Untitled")
                        .to_string();
                    let text = content
                        .get("text")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();

                    notes.push(DecryptedNote {
                        uuid: item.uuid,
                        title,
                        text,
                        updated_at: item.updated_at,
                    });
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        if notes.is_empty()
            && let Some(error) = last_error
        {
            return Err(error);
        }

        Ok(notes)
    }

    pub fn decrypted_tags(&self, master_key: &str) -> InkResult<Vec<DecryptedTag>> {
        let cached = self.store.load_cached_items(&self.profile)?;
        let items_keys = self.decrypted_items_keys(master_key)?;
        let key_lookup: HashMap<String, String> = items_keys
            .into_iter()
            .map(|item| (item.uuid, item.items_key))
            .collect();

        let mut tags = Vec::new();
        let mut last_error: Option<InkError> = None;

        for item in cached {
            if item.deleted || item.content_type != "Tag" {
                continue;
            }

            let Some(items_key_id) = item.items_key_id.as_deref() else {
                continue;
            };
            let Some(items_key) = key_lookup.get(items_key_id) else {
                continue;
            };

            match decrypt_item_payload_004(&item.content, &item.enc_item_key, items_key) {
                Ok(content) => {
                    let title = content
                        .get("title")
                        .and_then(|value| value.as_str())
                        .unwrap_or("Untitled")
                        .to_string();
                    let references = extract_note_references(&content);
                    let parent_uuid = extract_parent_uuid(&content);

                    tags.push(DecryptedTag {
                        uuid: item.uuid,
                        title,
                        references,
                        parent_uuid,
                        updated_at: item.updated_at,
                    });
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        if tags.is_empty()
            && let Some(error) = last_error
        {
            return Err(error);
        }

        Ok(tags)
    }

    pub fn make_encrypted_note_item(
        &self,
        uuid: &str,
        title: &str,
        text: &str,
        items_key_id: &str,
        items_key: &str,
    ) -> InkResult<SyncItemInput> {
        let encrypted = encrypt_item_payload_004(
            &json_note_content(title, text),
            items_key,
            uuid,
            None,
            None,
            None,
        )?;

        Ok(SyncItemInput {
            uuid: uuid.to_string(),
            content_type: "Note".to_string(),
            content: encrypted.content,
            enc_item_key: encrypted.enc_item_key,
            items_key_id: Some(items_key_id.to_string()),
            deleted: Some(false),
            ..SyncItemInput::default()
        })
    }

    pub fn make_encrypted_tag_item(
        &self,
        uuid: &str,
        title: &str,
        references: &[String],
        parent_uuid: Option<&str>,
        items_key_id: &str,
        items_key: &str,
    ) -> InkResult<SyncItemInput> {
        let encrypted = encrypt_item_payload_004(
            &json_tag_content(title, references, parent_uuid),
            items_key,
            uuid,
            None,
            None,
            None,
        )?;

        Ok(SyncItemInput {
            uuid: uuid.to_string(),
            content_type: "Tag".to_string(),
            content: encrypted.content,
            enc_item_key: encrypted.enc_item_key,
            items_key_id: Some(items_key_id.to_string()),
            deleted: Some(false),
            ..SyncItemInput::default()
        })
    }

    pub fn make_encrypted_items_key_item(
        &self,
        uuid: &str,
        items_key: &str,
        master_key: &str,
        key_params: Option<&Value>,
    ) -> InkResult<SyncItemInput> {
        let encrypted = encrypt_item_payload_004(
            &json!({"itemsKey": items_key, "version": "004"}),
            master_key,
            uuid,
            key_params,
            None,
            None,
        )?;

        Ok(SyncItemInput {
            uuid: uuid.to_string(),
            content_type: "SN|ItemsKey".to_string(),
            content: encrypted.content,
            enc_item_key: encrypted.enc_item_key,
            items_key_id: None,
            deleted: Some(false),
            ..SyncItemInput::default()
        })
    }

    fn require_session(&self) -> InkResult<StoredSession> {
        self.store.load(&self.profile)?.ok_or_else(|| {
            InkError::auth(format!(
                "no active session for profile '{}'; run `ink auth login` first",
                self.profile
            ))
        })
    }

    fn request_with_retry(
        &self,
        session: &mut StoredSession,
        request: &ItemsSyncRequest,
    ) -> InkResult<ItemsSyncResponseData> {
        let mut refreshed = false;
        let mut attempt = 0u32;

        loop {
            let result = self.api.sync_items(
                &session.session.access_token,
                session.access_token_cookie.as_deref(),
                request,
            );

            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    if error.kind == ErrorKind::Auth && !refreshed {
                        refreshed = true;
                        let refresh = self.api.refresh_session(
                            &session.session.access_token,
                            &session.session.refresh_token,
                            session.refresh_token_cookie.as_deref(),
                        )?;

                        let refreshed_session = refresh.session.ok_or_else(|| {
                            InkError::auth(
                                "session refresh response did not include updated session payload",
                            )
                        })?;

                        let updated = self.store.mark_refreshed(
                            &self.profile,
                            refreshed_session,
                            refresh.access_token_cookie,
                            refresh.refresh_token_cookie,
                        )?;
                        *session = updated;
                        continue;
                    }

                    if attempt < self.max_retries && is_retryable_sync_error(&error) {
                        thread::sleep(retry_delay(attempt, &error));
                        attempt += 1;
                        continue;
                    }

                    return Err(error);
                }
            }
        }
    }
}

fn json_note_content(title: &str, text: &str) -> Value {
    let mut map = Map::new();
    map.insert("title".to_string(), Value::String(title.to_string()));
    map.insert("text".to_string(), Value::String(text.to_string()));
    map.insert("references".to_string(), Value::Array(Vec::new()));
    Value::Object(map)
}

fn json_tag_content(title: &str, references: &[String], parent_uuid: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("title".to_string(), Value::String(title.to_string()));
    map.insert(
        "references".to_string(),
        Value::Array(
            references
                .iter()
                .map(|uuid| json!({"uuid": uuid, "content_type": "Note"}))
                .collect(),
        ),
    );

    if let Some(parent_uuid) = parent_uuid
        && !parent_uuid.trim().is_empty()
    {
        map.insert(
            "appData".to_string(),
            json!({
                "org.standardnotes.sn": {
                    "parentId": parent_uuid.trim()
                }
            }),
        );
    }

    Value::Object(map)
}

fn extract_note_references(content: &Value) -> Vec<String> {
    let Some(references) = content.get("references").and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for reference in references {
        match reference {
            Value::String(uuid) => out.push(uuid.clone()),
            Value::Object(map) => {
                let Some(uuid) = map.get("uuid").and_then(|value| value.as_str()) else {
                    continue;
                };
                let content_type = map
                    .get("content_type")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Note");
                if content_type == "Note" {
                    out.push(uuid.to_string());
                }
            }
            _ => {}
        }
    }

    out.sort();
    out.dedup();
    out
}

fn extract_parent_uuid(content: &Value) -> Option<String> {
    content
        .get("appData")
        .and_then(|value| value.get("org.standardnotes.sn"))
        .and_then(|value| value.get("parentId"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn is_retryable_sync_error(error: &InkError) -> bool {
    if error.kind != ErrorKind::Sync {
        return false;
    }

    if error.message.contains("network request failed") {
        return true;
    }

    let Some(status) = extract_http_status(&error.message) else {
        return false;
    };

    status >= 500 || status == 429
}

fn retry_delay(attempt: u32, error: &InkError) -> Duration {
    let backoff = backoff_duration(attempt);
    if let Some(seconds) = extract_retry_after_seconds(&error.message) {
        return backoff.max(Duration::from_secs(seconds));
    }

    backoff
}

fn extract_http_status(message: &str) -> Option<u16> {
    let marker = "[http_status=";
    let start = message.find(marker)?;
    let rest = &message[start + marker.len()..];
    let end = rest.find(']')?;
    rest[..end].parse::<u16>().ok()
}

fn extract_retry_after_seconds(message: &str) -> Option<u64> {
    let marker = "[retry_after_seconds=";
    let start = message.find(marker)?;
    let rest = &message[start + marker.len()..];
    let end = rest.find(']')?;
    rest[..end].parse::<u64>().ok()
}

fn backoff_duration(attempt: u32) -> Duration {
    let base_ms = 250u64;
    let multiplier = 1u64 << attempt.min(6);
    Duration::from_millis(base_ms * multiplier)
}

fn merge_items(cached: &mut Vec<SyncItem>, incoming: Vec<SyncItem>) {
    let mut merged: BTreeMap<String, SyncItem> = cached
        .drain(..)
        .map(|item| (item.uuid.clone(), item))
        .collect();

    for item in incoming {
        match merged.get(&item.uuid) {
            Some(existing) => {
                if should_replace_item(existing, &item) {
                    merged.insert(item.uuid.clone(), merge_sync_item(existing, item));
                }
            }
            None => {
                merged.insert(item.uuid.clone(), item);
            }
        }
    }

    *cached = merged.into_values().collect();
}

fn should_replace_item(existing: &SyncItem, incoming: &SyncItem) -> bool {
    let existing_ts = existing.updated_at_timestamp.unwrap_or_default();
    let incoming_ts = incoming.updated_at_timestamp.unwrap_or_default();

    if incoming_ts > existing_ts {
        return true;
    }

    if incoming_ts == existing_ts {
        return incoming.updated_at > existing.updated_at;
    }

    false
}

fn merge_sync_item(existing: &SyncItem, mut incoming: SyncItem) -> SyncItem {
    if incoming.content.is_empty() {
        incoming.content = existing.content.clone();
    }
    if incoming.enc_item_key.is_empty() {
        incoming.enc_item_key = existing.enc_item_key.clone();
    }
    if incoming.content_type.is_empty() {
        incoming.content_type = existing.content_type.clone();
    }
    if incoming.items_key_id.is_none() {
        incoming.items_key_id = existing.items_key_id.clone();
    }
    if incoming.created_at.is_none() {
        incoming.created_at = existing.created_at.clone();
    }
    if incoming.created_at_timestamp.is_none() {
        incoming.created_at_timestamp = existing.created_at_timestamp;
    }
    if incoming.key_system_identifier.is_none() {
        incoming.key_system_identifier = existing.key_system_identifier.clone();
    }
    if incoming.shared_vault_uuid.is_none() {
        incoming.shared_vault_uuid = existing.shared_vault_uuid.clone();
    }
    if incoming.user_uuid.is_none() {
        incoming.user_uuid = existing.user_uuid.clone();
    }
    if incoming.updated_with_session.is_none() {
        incoming.updated_with_session = existing.updated_with_session.clone();
    }

    incoming
}

fn hydrate_server_items_from_pushed_inputs(
    server_items: &mut [SyncItem],
    pushed_lookup: &HashMap<String, SyncItemInput>,
) {
    for item in server_items {
        let Some(pushed) = pushed_lookup.get(&item.uuid) else {
            continue;
        };

        if item.content_type.is_empty() {
            item.content_type = pushed.content_type.clone();
        }
        if item.content.is_empty() {
            item.content = pushed.content.clone();
        }
        if item.enc_item_key.is_empty() {
            item.enc_item_key = pushed.enc_item_key.clone();
        }
        if item.items_key_id.is_none() {
            item.items_key_id = pushed.items_key_id.clone();
        }

        if item.created_at.is_none() {
            item.created_at = pushed.created_at.clone();
        }
        if item.updated_at.is_none() {
            item.updated_at = pushed.updated_at.clone();
        }
        if item.created_at_timestamp.is_none() {
            item.created_at_timestamp = pushed.created_at_timestamp;
        }
        if item.updated_at_timestamp.is_none() {
            item.updated_at_timestamp = pushed.updated_at_timestamp;
        }
        if item.key_system_identifier.is_none() {
            item.key_system_identifier = pushed.key_system_identifier.clone();
        }
        if item.shared_vault_uuid.is_none() {
            item.shared_vault_uuid = pushed.shared_vault_uuid.clone();
        }

        if !item.deleted {
            item.deleted = pushed.deleted.unwrap_or(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::POST;
    use httpmock::MockServer;
    use ink_api::{KeyParamsData, SessionBody};
    use ink_core::{ErrorKind, InkError};
    use ink_crypto::make_item_authenticated_data_004;
    use ink_fs::init_workspace;
    use ink_store::StoredSession;
    use serde_json::json;

    fn fixture_session(server: &str) -> StoredSession {
        StoredSession {
            profile: "default".to_string(),
            server: server.to_string(),
            email: "user@example.com".to_string(),
            authenticated_at: "2026-02-28T00:00:00Z".to_string(),
            refreshed_at: None,
            master_key: Some(
                "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed".to_string(),
            ),
            session: SessionBody {
                access_token: "2:access-1".to_string(),
                refresh_token: "2:refresh-1".to_string(),
                access_expiration: 4_102_444_800,
                refresh_expiration: 4_102_448_400,
                readonly_access: false,
            },
            access_token_cookie: Some("access_token_a=one".to_string()),
            refresh_token_cookie: Some("refresh_token_a=one".to_string()),
            user: None,
            key_params: Some(KeyParamsData {
                identifier: Some("user@example.com".to_string()),
                pw_cost: None,
                pw_nonce: Some(
                    "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9".to_string(),
                ),
                version: Some("004".to_string()),
                pw_salt: None,
                email: None,
                pw_func: None,
                pw_alg: None,
                pw_key_size: None,
                origination: None,
                created: None,
            }),
        }
    }

    #[test]
    fn pull_all_paginates_and_persists_cache() {
        let server = MockServer::start();

        let first_page = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one")
                .json_body_partial(
                    json!({
                        "sync_token": "sync-old",
                        "items": [],
                    })
                    .to_string(),
                );
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [{
                        "uuid": "note-1",
                        "content_type": "Note",
                        "items_key_id": "ik-1",
                        "enc_item_key": "004:key-1",
                        "content": "004:payload-1",
                        "deleted": false,
                        "updated_at_timestamp": 10
                    }],
                    "saved_items": [],
                    "conflicts": [],
                    "sync_token": "sync-new",
                    "cursor_token": "cursor-1"
                }
            }));
        });

        let second_page = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one")
                .json_body_partial(
                    json!({
                        "sync_token": "sync-new",
                        "cursor_token": "cursor-1",
                        "items": [],
                    })
                    .to_string(),
                );
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [{
                        "uuid": "note-2",
                        "content_type": "Note",
                        "items_key_id": "ik-1",
                        "enc_item_key": "004:key-2",
                        "content": "004:payload-2",
                        "deleted": false,
                        "updated_at_timestamp": 20
                    }],
                    "saved_items": [],
                    "conflicts": [],
                    "sync_token": "sync-new"
                }
            }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");
        store
            .save_sync_state(
                "default",
                &ink_store::SyncState {
                    sync_token: Some("sync-old".to_string()),
                    ..ink_store::SyncState::default()
                },
            )
            .expect("save sync state");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default");

        let outcome = engine.pull_all().expect("pull all");
        assert_eq!(outcome.retrieved, 2);
        assert_eq!(outcome.pages, 2);
        assert_eq!(outcome.sync_token.as_deref(), Some("sync-new"));

        let cached = engine.cached_items().expect("cached items");
        assert_eq!(cached.len(), 2);

        first_page.assert_hits(1);
        second_page.assert_hits(1);
    }

    #[test]
    fn push_items_refreshes_session_on_auth_error() {
        let server = MockServer::start();

        let failed_push = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1");
            then.status(401).json_body(json!({
                "data": {
                    "error": {
                        "message": "Invalid login credentials"
                    }
                }
            }));
        });

        let refresh = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/sessions/refresh")
                .header("authorization", "Bearer 2:refresh-1")
                .header("cookie", "refresh_token_a=one");
            then.status(200)
                .header("set-cookie", "access_token_b=two; Path=/")
                .header("set-cookie", "refresh_token_b=two; Path=/")
                .json_body(json!({
                    "session": {
                        "access_token": "2:access-2",
                        "refresh_token": "2:refresh-2",
                        "access_expiration": 4102449000i64,
                        "refresh_expiration": 4102452600i64,
                        "readonly_access": false
                    }
                }));
        });

        let successful_push = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-2")
                .header("cookie", "access_token_b=two");
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [],
                    "saved_items": [{
                        "uuid": "new-note",
                        "content_type": "Note",
                        "items_key_id": "ik-1",
                        "enc_item_key": "004:key",
                        "content": "004:content",
                        "deleted": false,
                        "updated_at_timestamp": 99
                    }],
                    "conflicts": [],
                    "sync_token": "sync-after-push"
                }
            }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default").with_max_retries(0);

        let outcome = engine
            .push_items(vec![SyncItemInput {
                uuid: "new-note".to_string(),
                content_type: "Note".to_string(),
                content: "004:content".to_string(),
                enc_item_key: "004:key".to_string(),
                items_key_id: Some("ik-1".to_string()),
                deleted: Some(false),
                ..SyncItemInput::default()
            }])
            .expect("push items");

        assert_eq!(outcome.saved, 1);
        assert_eq!(outcome.sync_token.as_deref(), Some("sync-after-push"));

        let updated_session = store
            .load("default")
            .expect("load session")
            .expect("stored session");
        assert_eq!(updated_session.session.access_token, "2:access-2");
        assert_eq!(
            updated_session.access_token_cookie.as_deref(),
            Some("access_token_b=two")
        );

        failed_push.assert_hits(1);
        refresh.assert_hits(1);
        successful_push.assert_hits(1);
    }

    #[test]
    fn push_items_paginates_updates_sync_state_and_cache() {
        let server = MockServer::start();

        let first_page = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one")
                .json_body_partial(
                    json!({
                        "sync_token": "sync-old",
                        "items": [{
                            "uuid": "note-1"
                        }]
                    })
                    .to_string(),
                );
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [],
                    "saved_items": [{
                        "uuid": "note-1",
                        "content_type": "Note",
                        "items_key_id": "ik-1",
                        "enc_item_key": "004:key-1",
                        "content": "004:content-1",
                        "deleted": false,
                        "updated_at_timestamp": 100
                    }],
                    "conflicts": [],
                    "sync_token": "sync-new",
                    "cursor_token": "cursor-1"
                }
            }));
        });

        let second_page = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one")
                .json_body_partial(
                    json!({
                        "sync_token": "sync-new",
                        "cursor_token": "cursor-1",
                        "items": []
                    })
                    .to_string(),
                );
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [{
                        "uuid": "note-2",
                        "content_type": "Note",
                        "items_key_id": "ik-1",
                        "enc_item_key": "004:key-2",
                        "content": "004:content-2",
                        "deleted": false,
                        "updated_at_timestamp": 200
                    }],
                    "saved_items": [],
                    "conflicts": [],
                    "sync_token": "sync-new"
                }
            }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");
        store
            .save_sync_state(
                "default",
                &ink_store::SyncState {
                    sync_token: Some("sync-old".to_string()),
                    ..ink_store::SyncState::default()
                },
            )
            .expect("save sync state");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default");

        let outcome = engine
            .push_items(vec![SyncItemInput {
                uuid: "note-1".to_string(),
                content_type: "Note".to_string(),
                content: "004:content-1".to_string(),
                enc_item_key: "004:key-1".to_string(),
                items_key_id: Some("ik-1".to_string()),
                deleted: Some(false),
                ..SyncItemInput::default()
            }])
            .expect("push items");

        assert_eq!(outcome.pushed, 1);
        assert_eq!(outcome.saved, 1);
        assert_eq!(outcome.retrieved, 1);
        assert_eq!(outcome.pages, 2);
        assert_eq!(outcome.cached_total, 2);
        assert_eq!(outcome.sync_token.as_deref(), Some("sync-new"));

        let sync_state = store.load_sync_state("default").expect("sync state");
        assert_eq!(sync_state.sync_token.as_deref(), Some("sync-new"));
        assert!(sync_state.cursor_token.is_none());
        assert!(sync_state.last_pushed_at.is_some());
        assert!(sync_state.last_error.is_none());
        assert_eq!(sync_state.item_count, 2);

        let cached = engine.cached_items().expect("cached items");
        assert_eq!(cached.len(), 2);
        assert!(cached.iter().any(|item| item.uuid == "note-1"));
        assert!(cached.iter().any(|item| item.uuid == "note-2"));

        first_page.assert_hits(1);
        second_page.assert_hits(1);
    }

    #[test]
    fn pull_all_retries_on_server_errors_until_limit() {
        let server = MockServer::start();

        let failing_sync = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one");
            then.status(500).json_body(json!({
                "error": {"message": "temporary server failure"}
            }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default").with_max_retries(1);

        let error = engine.pull_all().expect_err("pull should fail");
        assert_eq!(error.kind, ErrorKind::Sync);
        assert!(error.message.contains("http_status=500"));
        let sync_state = store.load_sync_state("default").expect("sync state");
        assert_eq!(
            sync_state.last_error.as_deref(),
            Some(error.message.as_str())
        );

        failing_sync.assert_hits(2);
    }

    #[test]
    fn push_items_persists_last_error_on_rate_limit() {
        let server = MockServer::start();

        let rate_limited = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one");
            then.status(429)
                .header("retry-after", "3")
                .json_body(json!({
                    "error": {
                        "message": "Too many requests"
                    }
                }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default").with_max_retries(0);

        let error = engine
            .push_items(vec![SyncItemInput {
                uuid: "note-rate-limit".to_string(),
                content_type: "Note".to_string(),
                content: "004:content".to_string(),
                enc_item_key: "004:key".to_string(),
                items_key_id: Some("ik-1".to_string()),
                deleted: Some(false),
                ..SyncItemInput::default()
            }])
            .expect_err("push should fail");

        assert_eq!(error.kind, ErrorKind::Sync);
        assert!(error.message.contains("http_status=429"));
        assert!(error.message.contains("retry_after_seconds=3"));

        let sync_state = store.load_sync_state("default").expect("sync state");
        assert_eq!(
            sync_state.last_error.as_deref(),
            Some(error.message.as_str())
        );

        rate_limited.assert_hits(1);
    }

    #[test]
    fn push_items_sets_last_error_when_server_reports_conflicts() {
        let server = MockServer::start();

        let push = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/items")
                .header("authorization", "Bearer 2:access-1")
                .header("cookie", "access_token_a=one");
            then.status(200).json_body(json!({
                "data": {
                    "retrieved_items": [],
                    "saved_items": [],
                    "conflicts": [{
                        "type": "sync_conflict"
                    }],
                    "sync_token": "sync-conflict"
                }
            }));
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        store
            .save("default", &fixture_session(&server.base_url()))
            .expect("save session");

        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default");

        let outcome = engine
            .push_items(vec![SyncItemInput {
                uuid: "note-conflict".to_string(),
                content_type: "Note".to_string(),
                content: "004:content".to_string(),
                enc_item_key: "004:key".to_string(),
                items_key_id: Some("ik-1".to_string()),
                deleted: Some(false),
                ..SyncItemInput::default()
            }])
            .expect("push items");

        assert_eq!(outcome.conflicts, 1);
        assert_eq!(outcome.sync_token.as_deref(), Some("sync-conflict"));

        let sync_state = store.load_sync_state("default").expect("load sync state");
        assert!(sync_state.last_pushed_at.is_some());
        assert_eq!(
            sync_state.last_error.as_deref(),
            Some("1 conflicts returned from server")
        );

        push.assert_hits(1);
    }

    #[test]
    fn decrypted_notes_uses_decrypted_items_key_material() {
        let server = MockServer::start();

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default");

        let master_key =
            "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed".to_string();
        let items_key =
            "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677".to_string();

        let authenticated = make_item_authenticated_data_004(
            "ik-1",
            Some(&json!({
                "identifier": "user@example.com",
                "pw_nonce": "nonce",
                "version": "004",
            })),
            None,
            None,
        )
        .expect("authenticated data");
        let encrypted_items_key = encrypt_item_payload_004(
            &json!({"itemsKey": items_key, "version": "004"}),
            &master_key,
            "ik-1",
            authenticated.get("kp"),
            None,
            None,
        )
        .expect("encrypt items key");

        let encrypted_note = engine
            .make_encrypted_note_item("note-1", "Hello", "World", "ik-1", &items_key)
            .expect("encrypt note");

        store
            .save_cached_items(
                "default",
                &[
                    SyncItem {
                        uuid: "ik-1".to_string(),
                        content_type: "SN|ItemsKey".to_string(),
                        items_key_id: None,
                        content: encrypted_items_key.content,
                        enc_item_key: encrypted_items_key.enc_item_key,
                        deleted: false,
                        updated_at_timestamp: Some(10),
                        ..SyncItem::default()
                    },
                    SyncItem {
                        uuid: encrypted_note.uuid,
                        content_type: encrypted_note.content_type,
                        items_key_id: encrypted_note.items_key_id,
                        content: encrypted_note.content,
                        enc_item_key: encrypted_note.enc_item_key,
                        deleted: false,
                        updated_at_timestamp: Some(11),
                        ..SyncItem::default()
                    },
                ],
            )
            .expect("save cache");

        let notes = engine
            .decrypted_notes(&master_key)
            .expect("decrypt notes from cache");

        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "Hello");
        assert_eq!(notes[0].text, "World");
    }

    #[test]
    fn decrypted_tags_uses_decrypted_items_key_material() {
        let server = MockServer::start();

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some(&server.base_url())).expect("init workspace");

        let store = SessionStore::from_workspace(&init.paths).expect("session store");
        let api = StandardNotesApi::new(&server.base_url()).expect("api client");
        let engine = SyncEngine::new(&api, &store, "default");

        let master_key =
            "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed".to_string();
        let items_key =
            "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677".to_string();

        let authenticated = make_item_authenticated_data_004(
            "ik-1",
            Some(&json!({
                "identifier": "user@example.com",
                "pw_nonce": "nonce",
                "version": "004",
            })),
            None,
            None,
        )
        .expect("authenticated data");
        let encrypted_items_key = encrypt_item_payload_004(
            &json!({"itemsKey": items_key, "version": "004"}),
            &master_key,
            "ik-1",
            authenticated.get("kp"),
            None,
            None,
        )
        .expect("encrypt items key");

        let encrypted_tag = engine
            .make_encrypted_tag_item(
                "tag-1",
                "Work",
                &[String::from("note-1")],
                Some("parent-1"),
                "ik-1",
                &items_key,
            )
            .expect("encrypt tag");

        store
            .save_cached_items(
                "default",
                &[
                    SyncItem {
                        uuid: "ik-1".to_string(),
                        content_type: "SN|ItemsKey".to_string(),
                        items_key_id: None,
                        content: encrypted_items_key.content,
                        enc_item_key: encrypted_items_key.enc_item_key,
                        deleted: false,
                        updated_at_timestamp: Some(10),
                        ..SyncItem::default()
                    },
                    SyncItem {
                        uuid: encrypted_tag.uuid,
                        content_type: encrypted_tag.content_type,
                        items_key_id: encrypted_tag.items_key_id,
                        content: encrypted_tag.content,
                        enc_item_key: encrypted_tag.enc_item_key,
                        deleted: false,
                        updated_at_timestamp: Some(11),
                        ..SyncItem::default()
                    },
                ],
            )
            .expect("save cache");

        let tags = engine
            .decrypted_tags(&master_key)
            .expect("decrypt tags from cache");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].title, "Work");
        assert_eq!(tags[0].references, vec![String::from("note-1")]);
        assert_eq!(tags[0].parent_uuid.as_deref(), Some("parent-1"));
    }

    #[test]
    fn merge_preserves_encrypted_fields_when_saved_items_omit_them() {
        let mut cached = vec![SyncItem {
            uuid: "note-1".to_string(),
            content_type: "Note".to_string(),
            content: "004:content".to_string(),
            enc_item_key: "004:key".to_string(),
            items_key_id: Some("ik-1".to_string()),
            updated_at_timestamp: Some(100),
            ..SyncItem::default()
        }];

        let incoming = vec![SyncItem {
            uuid: "note-1".to_string(),
            content_type: "Note".to_string(),
            content: String::new(),
            enc_item_key: String::new(),
            items_key_id: None,
            updated_at_timestamp: Some(200),
            ..SyncItem::default()
        }];

        merge_items(&mut cached, incoming);

        assert_eq!(cached.len(), 1);
        let merged = &cached[0];
        assert_eq!(merged.content, "004:content");
        assert_eq!(merged.enc_item_key, "004:key");
        assert_eq!(merged.items_key_id.as_deref(), Some("ik-1"));
        assert_eq!(merged.updated_at_timestamp, Some(200));
    }

    #[test]
    fn hydrate_saved_items_backfills_missing_fields_from_pushed_inputs() {
        let mut server_items = vec![SyncItem {
            uuid: "note-new".to_string(),
            content_type: String::new(),
            content: String::new(),
            enc_item_key: String::new(),
            items_key_id: None,
            deleted: false,
            ..SyncItem::default()
        }];

        let mut pushed_lookup: HashMap<String, SyncItemInput> = HashMap::new();
        pushed_lookup.insert(
            "note-new".to_string(),
            SyncItemInput {
                uuid: "note-new".to_string(),
                content_type: "Note".to_string(),
                content: "004:content-new".to_string(),
                enc_item_key: "004:key-new".to_string(),
                items_key_id: Some("ik-1".to_string()),
                deleted: Some(false),
                created_at: Some("2026-02-28T00:00:00.000000Z".to_string()),
                updated_at: Some("2026-02-28T00:00:01.000000Z".to_string()),
                created_at_timestamp: Some(1772236800000000),
                updated_at_timestamp: Some(1772236801000000),
                key_system_identifier: Some("ks-1".to_string()),
                shared_vault_uuid: Some("vault-1".to_string()),
            },
        );

        hydrate_server_items_from_pushed_inputs(&mut server_items, &pushed_lookup);

        let hydrated = &server_items[0];
        assert_eq!(hydrated.content_type, "Note");
        assert_eq!(hydrated.content, "004:content-new");
        assert_eq!(hydrated.enc_item_key, "004:key-new");
        assert_eq!(hydrated.items_key_id.as_deref(), Some("ik-1"));
        assert_eq!(
            hydrated.created_at.as_deref(),
            Some("2026-02-28T00:00:00.000000Z")
        );
        assert_eq!(
            hydrated.updated_at.as_deref(),
            Some("2026-02-28T00:00:01.000000Z")
        );
        assert_eq!(hydrated.created_at_timestamp, Some(1772236800000000));
        assert_eq!(hydrated.updated_at_timestamp, Some(1772236801000000));
        assert_eq!(hydrated.key_system_identifier.as_deref(), Some("ks-1"));
        assert_eq!(hydrated.shared_vault_uuid.as_deref(), Some("vault-1"));
        assert!(!hydrated.deleted);
    }

    #[test]
    fn retryable_error_classification_matches_sync_network_and_http_status() {
        assert!(is_retryable_sync_error(&InkError::sync(
            "network request failed: connection reset"
        )));
        assert!(is_retryable_sync_error(&InkError::sync(
            "request failed [http_status=429]"
        )));
        assert!(is_retryable_sync_error(&InkError::sync(
            "request failed [http_status=500]"
        )));
        assert!(!is_retryable_sync_error(&InkError::sync(
            "request failed [http_status=400]"
        )));
        assert!(!is_retryable_sync_error(&InkError::auth(
            "request failed [http_status=500]"
        )));
    }

    #[test]
    fn retry_delay_uses_retry_after_when_present() {
        let error = InkError::sync("request failed [retry_after_seconds=5] [http_status=429]");
        assert_eq!(retry_delay(0, &error), Duration::from_secs(5));

        let error = InkError::sync("request failed [retry_after_seconds=1] [http_status=429]");
        assert_eq!(retry_delay(3, &error), Duration::from_secs(2));
    }

    #[test]
    fn backoff_duration_uses_exponential_steps_with_cap() {
        assert_eq!(backoff_duration(0), Duration::from_millis(250));
        assert_eq!(backoff_duration(1), Duration::from_millis(500));
        assert_eq!(backoff_duration(2), Duration::from_millis(1000));
        assert_eq!(backoff_duration(6), Duration::from_millis(16000));
        assert_eq!(backoff_duration(10), Duration::from_millis(16000));
    }
}
