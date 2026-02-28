use ink_api::{SessionBody, SyncItem};
use ink_fs::init_workspace;
use ink_store::{AppState, SessionStore, StoredSession, SyncConflict, SyncState};
use std::fs;

fn fixture_session(access: &str, refresh: &str) -> SessionBody {
    SessionBody {
        access_token: access.to_string(),
        refresh_token: refresh.to_string(),
        access_expiration: 2_000_000_000,
        refresh_expiration: 2_100_000_000,
        readonly_access: false,
    }
}

#[test]
fn save_load_remove_session_round_trip() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    let store = SessionStore::from_workspace(&init.paths).expect("session store");
    let stored = StoredSession {
        profile: "default".to_string(),
        server: "https://api.example.com".to_string(),
        email: "user@example.com".to_string(),
        authenticated_at: "2026-02-28T00:00:00Z".to_string(),
        refreshed_at: None,
        master_key: Some("master-1".to_string()),
        session: fixture_session("access-1", "refresh-1"),
        access_token_cookie: Some("access_token_abc=one".to_string()),
        refresh_token_cookie: Some("refresh_token_abc=one".to_string()),
        user: None,
        key_params: None,
    };

    store.save("default", &stored).expect("save");

    let loaded = store
        .load("default")
        .expect("load")
        .expect("stored session");
    assert_eq!(loaded.email, "user@example.com");
    assert_eq!(loaded.session.access_token, "access-1");
    assert_eq!(loaded.session.refresh_token, "refresh-1");
    assert_eq!(
        loaded.access_token_cookie.as_deref(),
        Some("access_token_abc=one")
    );
    assert_eq!(
        loaded.refresh_token_cookie.as_deref(),
        Some("refresh_token_abc=one")
    );
    assert_eq!(loaded.master_key.as_deref(), Some("master-1"));

    store.remove("default").expect("remove");
    assert!(store.load("default").expect("load after remove").is_none());
}

#[test]
fn mark_refreshed_updates_tokens_and_timestamp() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    let store = SessionStore::from_workspace(&init.paths).expect("session store");
    let stored = StoredSession {
        profile: "default".to_string(),
        server: "https://api.example.com".to_string(),
        email: "user@example.com".to_string(),
        authenticated_at: "2026-02-28T00:00:00Z".to_string(),
        refreshed_at: None,
        master_key: Some("master-old".to_string()),
        session: fixture_session("access-old", "refresh-old"),
        access_token_cookie: Some("access_token_old=abc".to_string()),
        refresh_token_cookie: Some("refresh_token_old=abc".to_string()),
        user: None,
        key_params: None,
    };
    store.save("default", &stored).expect("save");

    let updated = store
        .mark_refreshed(
            "default",
            fixture_session("access-new", "refresh-new"),
            Some("access_token_new=xyz".to_string()),
            Some("refresh_token_new=xyz".to_string()),
        )
        .expect("refresh");

    assert_eq!(updated.session.access_token, "access-new");
    assert_eq!(updated.session.refresh_token, "refresh-new");
    assert_eq!(
        updated.access_token_cookie.as_deref(),
        Some("access_token_new=xyz")
    );
    assert_eq!(
        updated.refresh_token_cookie.as_deref(),
        Some("refresh_token_new=xyz")
    );
    assert!(updated.refreshed_at.is_some());

    let loaded = store.load("default").expect("load").expect("session");
    assert_eq!(loaded.session.access_token, "access-new");
    assert_eq!(loaded.session.refresh_token, "refresh-new");
    assert_eq!(
        loaded.access_token_cookie.as_deref(),
        Some("access_token_new=xyz")
    );
    assert_eq!(
        loaded.refresh_token_cookie.as_deref(),
        Some("refresh_token_new=xyz")
    );
    assert!(loaded.refreshed_at.is_some());
    assert_eq!(loaded.master_key.as_deref(), Some("master-old"));
}

#[test]
fn sync_state_round_trip_and_cache_clear() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    let store = SessionStore::from_workspace(&init.paths).expect("session store");
    let state = SyncState {
        sync_token: Some("sync-1".to_string()),
        cursor_token: Some("cursor-1".to_string()),
        last_pulled_at: Some("2026-02-28T00:00:00Z".to_string()),
        last_pushed_at: None,
        last_error: None,
        item_count: 42,
    };

    store
        .save_sync_state("default", &state)
        .expect("save sync state");
    let loaded = store.load_sync_state("default").expect("load sync state");
    assert_eq!(loaded.sync_token.as_deref(), Some("sync-1"));
    assert_eq!(loaded.cursor_token.as_deref(), Some("cursor-1"));
    assert_eq!(loaded.item_count, 42);

    let items = vec![SyncItem {
        uuid: "note-1".to_string(),
        content_type: "Note".to_string(),
        content: "004:payload".to_string(),
        enc_item_key: "004:key".to_string(),
        items_key_id: Some("items-key-1".to_string()),
        deleted: false,
        ..SyncItem::default()
    }];
    store
        .save_cached_items("default", &items)
        .expect("save cached items");
    let loaded_items = store
        .load_cached_items("default")
        .expect("load cached items");
    assert_eq!(loaded_items.len(), 1);
    assert_eq!(loaded_items[0].uuid, "note-1");

    store
        .clear_sync_cache("default")
        .expect("clear sync cache for profile");
    let reset_state = store.load_sync_state("default").expect("load reset state");
    let reset_items = store
        .load_cached_items("default")
        .expect("load reset items");
    assert!(reset_state.sync_token.is_none());
    assert!(reset_items.is_empty());
}

#[test]
fn app_state_is_scoped_by_profile() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");
    let store = SessionStore::from_workspace(&init.paths).expect("session store");

    let mut default_state = AppState {
        last_sync_status: Some("default-ready".to_string()),
        ..AppState::default()
    };
    default_state.conflicts.push(SyncConflict {
        id: "conflict-default".to_string(),
        uuid: Some("uuid-default".to_string()),
        title: "Default".to_string(),
        file: "notes/default.md".to_string(),
        reason: "default conflict".to_string(),
        detected_at: "2026-02-28T00:00:00Z".to_string(),
        remote_updated_at: None,
        local_updated_at: None,
    });

    let work_state = AppState {
        last_sync_status: Some("work-ready".to_string()),
        ..AppState::default()
    };

    store
        .save_app_state("default", &default_state)
        .expect("save default app state");
    store
        .save_app_state("work", &work_state)
        .expect("save work app state");

    let loaded_default = store
        .load_app_state("default")
        .expect("load default app state");
    let loaded_work = store.load_app_state("work").expect("load work app state");

    assert_eq!(
        loaded_default.last_sync_status.as_deref(),
        Some("default-ready")
    );
    assert_eq!(loaded_default.conflicts.len(), 1);
    assert_eq!(loaded_work.last_sync_status.as_deref(), Some("work-ready"));
    assert!(loaded_work.conflicts.is_empty());
}

#[test]
fn migrates_legacy_json_payloads_on_first_open() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    let legacy_session = StoredSession {
        profile: "default".to_string(),
        server: "https://api.example.com".to_string(),
        email: "legacy@example.com".to_string(),
        authenticated_at: "2026-02-28T00:00:00Z".to_string(),
        refreshed_at: None,
        master_key: Some("legacy-master".to_string()),
        session: fixture_session("legacy-access", "legacy-refresh"),
        access_token_cookie: None,
        refresh_token_cookie: None,
        user: None,
        key_params: None,
    };

    fs::write(
        init.paths.sessions_dir.join("default.json"),
        serde_json::to_string(&legacy_session).expect("encode legacy session"),
    )
    .expect("write legacy session");

    let legacy_sync_state = SyncState {
        sync_token: Some("legacy-sync".to_string()),
        cursor_token: Some("legacy-cursor".to_string()),
        last_pulled_at: Some("2026-02-28T00:00:00Z".to_string()),
        last_pushed_at: None,
        last_error: None,
        item_count: 7,
    };

    let sync_dir = init.paths.cache_dir.join("sync");
    fs::create_dir_all(&sync_dir).expect("create legacy sync dir");
    fs::write(
        sync_dir.join("default-state.json"),
        serde_json::to_string(&legacy_sync_state).expect("encode legacy sync state"),
    )
    .expect("write legacy sync state");

    let legacy_items = vec![SyncItem {
        uuid: "legacy-note".to_string(),
        content_type: "Note".to_string(),
        content: "004:legacy-content".to_string(),
        enc_item_key: "004:legacy-key".to_string(),
        items_key_id: Some("legacy-items-key".to_string()),
        deleted: false,
        ..SyncItem::default()
    }];
    fs::write(
        sync_dir.join("default-items.json"),
        serde_json::to_string(&legacy_items).expect("encode legacy items"),
    )
    .expect("write legacy items");

    let mut legacy_app_state = AppState {
        last_sync_status: Some("legacy-state".to_string()),
        ..AppState::default()
    };
    legacy_app_state.conflicts.push(SyncConflict {
        id: "legacy-conflict".to_string(),
        uuid: None,
        title: "Legacy".to_string(),
        file: "notes/legacy.md".to_string(),
        reason: "legacy reason".to_string(),
        detected_at: "2026-02-28T00:00:00Z".to_string(),
        remote_updated_at: None,
        local_updated_at: None,
    });
    fs::write(
        init.paths.ink_dir.join("state.json"),
        serde_json::to_string(&legacy_app_state).expect("encode legacy app state"),
    )
    .expect("write legacy app state");

    let store = SessionStore::from_workspace(&init.paths).expect("session store");

    let migrated_session = store
        .load("default")
        .expect("load migrated session")
        .expect("session present");
    assert_eq!(migrated_session.email, "legacy@example.com");
    assert_eq!(migrated_session.session.access_token, "legacy-access");

    let migrated_sync_state = store
        .load_sync_state("default")
        .expect("load migrated sync state");
    assert_eq!(
        migrated_sync_state.sync_token.as_deref(),
        Some("legacy-sync")
    );
    assert_eq!(migrated_sync_state.item_count, 7);

    let migrated_items = store
        .load_cached_items("default")
        .expect("load migrated items");
    assert_eq!(migrated_items.len(), 1);
    assert_eq!(migrated_items[0].uuid, "legacy-note");

    let migrated_app_state = store
        .load_app_state("default")
        .expect("load migrated app state");
    assert_eq!(
        migrated_app_state.last_sync_status.as_deref(),
        Some("legacy-state")
    );
    assert_eq!(migrated_app_state.conflicts.len(), 1);
}

#[test]
fn corrupt_state_db_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("workspace");
    let init =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    fs::write(&init.paths.state_db_path, "this is not sqlite").expect("write corrupt db bytes");
    let error = SessionStore::from_workspace(&init.paths).expect_err("corrupt db should fail");
    assert!(error.message.contains("is corrupted"));
    assert!(error.message.contains(".ink/state.db"));
    assert!(error.message.contains("ink sync pull"));
}
