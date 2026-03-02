use assert_cmd::Command;
use httpmock::Method::POST;
use httpmock::MockServer;
use ink_api::SyncItem;
use ink_crypto::derive_root_credentials_004;
use ink_fs::{load_config, resolve_workspace};
use ink_store::{AppState, SessionStore, StoredSession, SyncState};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_PW_NONCE: &str = "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9";

#[test]
fn auth_login_status_logout_round_trip() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_cost": 110000,
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let derived = derive_root_credentials_004("password-123", "user@example.com", TEST_PW_NONCE)
        .expect("derive server password");

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login").json_body_partial(
            json!({
                    "api": "20240226",
                "email": "user@example.com",
                "password": derived.server_password,
                "ephemeral": false
            })
            .to_string(),
        );
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-login",
                "refresh_token": "refresh-login",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            },
            "key_params": {
                "identifier": "user@example.com",
                "version": "004"
            }
        }));
    });

    let logout = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/logout")
            .header("authorization", "Bearer access-login");
        then.status(200).json_body(json!({"success": true}));
    });

    init_workspace(&workspace.path, &server.base_url());

    let login_json = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );
    assert_eq!(login_json["ok"], true);
    assert_eq!(login_json["result"]["email"], "user@example.com");

    assert!(
        load_session_fixture(&workspace.path).is_some(),
        "session should exist after login"
    );

    let status_json = run_auth_command(&workspace.path, &["auth", "status", "--json"], None);
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["result"]["authenticated"], true);
    assert_eq!(status_json["result"]["refreshed"], false);

    let logout_json = run_auth_command(&workspace.path, &["auth", "logout", "--json"], None);
    assert_eq!(logout_json["ok"], true);
    assert_eq!(logout_json["result"]["remote_sign_out"], true);
    assert!(
        load_session_fixture(&workspace.path).is_none(),
        "session should be removed"
    );

    login_params.assert_hits(1);
    login.assert_hits(1);
    logout.assert_hits(1);
}

#[test]
fn auth_refresh_updates_persisted_session_tokens() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-old",
                "refresh_token": "refresh-old",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let refresh = server.mock(|when, then| {
        when.method(POST).path("/v1/sessions/refresh");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-new",
                "refresh_token": "refresh-new",
                "access_expiration": 4102450000i64,
                "refresh_expiration": 4102453600i64,
                "readonly_access": false
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let refresh_json = run_auth_command(&workspace.path, &["auth", "refresh", "--json"], None);
    assert_eq!(refresh_json["ok"], true);
    assert_eq!(refresh_json["result"]["email"], "user@example.com");

    let stored = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(stored.session.access_token, "access-new");
    assert_eq!(stored.session.refresh_token, "refresh-new");

    login_params.assert_hits(1);
    login.assert_hits(1);
    refresh.assert_hits(1);
}

#[test]
fn auth_status_auto_refreshes_expiring_session() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-expired",
                "refresh_token": "refresh-expired",
                "access_expiration": 1i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let refresh = server.mock(|when, then| {
        when.method(POST).path("/v1/sessions/refresh");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-after-status",
                "refresh_token": "refresh-after-status",
                "access_expiration": 4102450000i64,
                "refresh_expiration": 4102453600i64,
                "readonly_access": false
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let status_json = run_auth_command(&workspace.path, &["auth", "status", "--json"], None);
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["result"]["authenticated"], true);
    assert_eq!(status_json["result"]["refreshed"], true);

    let stored = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(stored.session.access_token, "access-after-status");
    assert_eq!(stored.session.refresh_token, "refresh-after-status");

    login_params.assert_hits(1);
    login.assert_hits(1);
    refresh.assert_hits(1);
}

#[test]
fn auth_login_invalid_credentials_exits_with_auth_code() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(401).json_body(json!({
            "data": {
                "error": {
                    "message": "Invalid email or password"
                }
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "login", "--json"])
        .env("SN_EMAIL", "user@example.com")
        .env("SN_PASSWORD", "wrong-password");

    let assert = cmd.assert().code(3);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let payload: Value = serde_json::from_str(&stderr).expect("json stderr");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error"]["kind"], "auth");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("http_status=401")
    );

    assert!(load_session_fixture(&workspace.path).is_none());

    login_params.assert_hits(1);
    login.assert_hits(1);
}

#[test]
fn auth_status_no_session_returns_auth_exit_code() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    init_workspace(&workspace.path, &server.base_url());

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "status", "--json"]);

    let assert = cmd.assert().code(3);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["result"]["authenticated"], false);
    assert_eq!(payload["result"]["reason"], "no stored session");
}

#[test]
fn auth_preflight_without_session_reports_needs_login() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    init_workspace(&workspace.path, &server.base_url());

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "preflight", "--json"]);

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["result"]["authenticated"], false);
    assert_eq!(payload["result"]["needs_login"], true);
}

#[test]
fn auth_preflight_with_session_reports_state() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-login",
                "refresh_token": "refresh-login",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "preflight", "--json"]);

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["result"]["authenticated"], true);
    assert_eq!(payload["result"]["needs_login"], false);
    assert_eq!(payload["result"]["needs_refresh"], false);
    assert_eq!(payload["result"]["email"], "user@example.com");

    login_params.assert_hits(1);
    login.assert_hits(1);
}

#[test]
fn auth_logout_remote_failure_still_removes_local_session() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-login",
                "refresh_token": "refresh-login",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let logout = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/logout")
            .header("authorization", "Bearer access-login");
        then.status(401).json_body(json!({
            "data": {
                "error": {
                    "message": "invalid session"
                }
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    assert!(
        load_session_fixture(&workspace.path).is_some(),
        "session should exist before logout"
    );

    let logout_json = run_auth_command(&workspace.path, &["auth", "logout", "--json"], None);
    assert_eq!(logout_json["ok"], true);
    assert_eq!(logout_json["result"]["remote_sign_out"], false);
    assert!(
        logout_json["result"]["warning"]
            .as_str()
            .expect("warning")
            .contains("http_status=401")
    );
    assert!(
        load_session_fixture(&workspace.path).is_none(),
        "session should be removed even if remote logout fails"
    );

    login_params.assert_hits(1);
    login.assert_hits(1);
    logout.assert_hits(1);
}

#[test]
fn auth_logout_purge_requires_yes_flag() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    init_workspace(&workspace.path, &server.base_url());

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "logout", "--purge", "--json"]);

    let assert = cmd.assert().code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let payload: Value = serde_json::from_str(&stderr).expect("json stderr");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error"]["kind"], "usage");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("--yes")
    );
}

#[test]
fn auth_logout_purge_clears_profile_state_and_mirror() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-login",
                "refresh_token": "refresh-login",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let logout = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/logout")
            .header("authorization", "Bearer access-login");
        then.status(200).json_body(json!({"success": true}));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let paths = resolve_workspace(Some(&workspace.path)).expect("resolve workspace");
    let store = SessionStore::from_workspace(&paths).expect("session store");

    store
        .save_sync_state(
            "default",
            &SyncState {
                sync_token: Some("sync-token".to_string()),
                cursor_token: None,
                last_pulled_at: None,
                last_pushed_at: None,
                last_error: None,
                item_count: 1,
            },
        )
        .expect("save sync state");
    store
        .save_cached_items(
            "default",
            &[SyncItem {
                uuid: "item-1".to_string(),
                content_type: "Note".to_string(),
                content: "encrypted".to_string(),
                enc_item_key: "wrapped".to_string(),
                ..SyncItem::default()
            }],
        )
        .expect("save cached items");
    store
        .save_app_state(
            "default",
            &AppState {
                last_auth_at: Some("2025-01-01T00:00:00Z".to_string()),
                last_pull_at: Some("2025-01-01T00:00:00Z".to_string()),
                last_push_at: None,
                last_sync_at: Some("2025-01-01T00:00:00Z".to_string()),
                last_sync_status: Some("ok".to_string()),
                conflicts: Vec::new(),
            },
        )
        .expect("save app state");

    let note_path = workspace.path.join("notes/mainaccount-note.md");
    fs::write(&note_path, "# persisted note\n").expect("write mirrored note");
    fs::write(
        &paths.mirror_index_path,
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "entries": [{
                "uuid": "item-1",
                "title": "Persisted",
                "path": "notes/mainaccount-note.md",
                "sha256": "dummy",
                "remote_updated_at": "2025-01-01T00:00:00.000Z"
            }]
        }))
        .expect("encode mirror index"),
    )
    .expect("write mirror index");

    let logout_json = run_auth_command(
        &workspace.path,
        &["--yes", "auth", "logout", "--purge", "--json"],
        None,
    );
    assert_eq!(logout_json["ok"], true);
    assert_eq!(logout_json["result"]["remote_sign_out"], true);
    assert_eq!(logout_json["result"]["purged_local_state"], true);
    assert_eq!(logout_json["result"]["removed_mirror_files"], 1);

    assert!(
        load_session_fixture(&workspace.path).is_none(),
        "session should be removed"
    );

    let reset_sync = store.load_sync_state("default").expect("load sync state");
    assert!(reset_sync.sync_token.is_none());
    assert_eq!(reset_sync.item_count, 0);

    let reset_items = store
        .load_cached_items("default")
        .expect("load cached items");
    assert!(reset_items.is_empty());

    let reset_app = store.load_app_state("default").expect("load app state");
    assert!(reset_app.last_auth_at.is_none());
    assert!(reset_app.last_pull_at.is_none());
    assert!(reset_app.last_sync_at.is_none());
    assert!(reset_app.last_sync_status.is_none());
    assert!(reset_app.conflicts.is_empty());

    assert!(
        !note_path.exists(),
        "mirrored note should be removed during purge"
    );

    let mirror_index_raw =
        fs::read_to_string(&paths.mirror_index_path).expect("read reset mirror index");
    let mirror_index: Value = serde_json::from_str(&mirror_index_raw).expect("parse mirror index");
    assert_eq!(mirror_index["entries"], json!([]));

    login_params.assert_hits(1);
    login.assert_hits(1);
    logout.assert_hits(1);
}

#[test]
fn auth_login_refuses_switching_bound_profile_without_rebind_flag() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params_user1 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login-params")
            .body_contains(r#""email":"user1@example.com""#);
        then.status(200).json_body(json!({
            "identifier": "user1@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });
    let login_user1 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .body_contains(r#""email":"user1@example.com""#);
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-user1",
                "refresh_token": "refresh-user1",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user1-uuid",
                "email": "user1@example.com"
            }
        }));
    });
    let login_params_user2_probe = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login-params")
            .body_contains(r#""email":"user2@example.com""#);
        then.status(200).json_body(json!({
            "identifier": "user2@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });
    let login_user2_probe = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .body_contains(r#""email":"user2@example.com""#);
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-user2",
                "refresh_token": "refresh-user2",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user2-uuid",
                "email": "user2@example.com"
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user1@example.com", "password-123")),
    );

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "login", "--json"])
        .env("SN_EMAIL", "user2@example.com")
        .env("SN_PASSWORD", "password-123");
    let assert = cmd.assert().code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let payload: Value = serde_json::from_str(&stderr).expect("json stderr");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error"]["kind"], "usage");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("is bound to")
    );

    let stored = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(stored.email, "user1@example.com");

    let paths = resolve_workspace(Some(&workspace.path)).expect("resolve workspace");
    let config = load_config(&paths).expect("load workspace config");
    assert_eq!(
        config
            .profiles
            .get("default")
            .and_then(|profile| profile.bound_email.as_deref()),
        Some("user1@example.com")
    );

    login_params_user1.assert_hits(1);
    login_user1.assert_hits(1);
    login_params_user2_probe.assert_hits(0);
    login_user2_probe.assert_hits(0);
}

#[test]
fn auth_login_rebind_account_with_yes_clears_mirror_and_updates_binding() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params_user1 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login-params")
            .body_contains(r#""email":"user1@example.com""#);
        then.status(200).json_body(json!({
            "identifier": "user1@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });
    let login_user1 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .body_contains(r#""email":"user1@example.com""#);
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-user1",
                "refresh_token": "refresh-user1",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user1-uuid",
                "email": "user1@example.com"
            }
        }));
    });
    let login_params_user2 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login-params")
            .body_contains(r#""email":"user2@example.com""#);
        then.status(200).json_body(json!({
            "identifier": "user2@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });
    let login_user2 = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .body_contains(r#""email":"user2@example.com""#);
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-user2",
                "refresh_token": "refresh-user2",
                "access_expiration": 4102450000i64,
                "refresh_expiration": 4102453600i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user2-uuid",
                "email": "user2@example.com"
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user1@example.com", "password-123")),
    );

    let note_path = workspace.path.join("notes/rebind-test.md");
    fs::create_dir_all(
        note_path
            .parent()
            .expect("test note should have a parent directory"),
    )
    .expect("create parent directory");
    fs::write(&note_path, "# stale mirror note\n").expect("write stale mirror note");

    let paths = resolve_workspace(Some(&workspace.path)).expect("resolve workspace");
    fs::write(
        &paths.mirror_index_path,
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "entries": [{
                "uuid": "note-1",
                "title": "Rebind Stale",
                "path": "notes/rebind-test.md",
                "sha256": "dummy",
                "remote_updated_at": "2026-02-28T00:00:00.000000Z"
            }]
        }))
        .expect("encode mirror index"),
    )
    .expect("write mirror index");

    let rebind = run_auth_command(
        &workspace.path,
        &["--yes", "auth", "login", "--rebind-account", "--json"],
        Some(("user2@example.com", "password-123")),
    );
    assert_eq!(rebind["ok"], true);
    assert_eq!(rebind["result"]["email"], "user2@example.com");

    assert!(!note_path.exists(), "stale mirror note should be cleared");

    let mirror_index_raw =
        fs::read_to_string(&paths.mirror_index_path).expect("read reset mirror index");
    let mirror_index: Value = serde_json::from_str(&mirror_index_raw).expect("parse mirror index");
    assert_eq!(mirror_index["entries"], json!([]));

    let stored = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(stored.email, "user2@example.com");

    let config = load_config(&paths).expect("load workspace config");
    assert_eq!(
        config
            .profiles
            .get("default")
            .and_then(|profile| profile.bound_email.as_deref()),
        Some("user2@example.com")
    );

    login_params_user1.assert_hits(1);
    login_user1.assert_hits(1);
    login_params_user2.assert_hits(1);
    login_user2.assert_hits(1);
}

#[test]
fn auth_refresh_fails_without_reauthentication_fallback() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-old",
                "refresh_token": "refresh-old",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let refresh = server.mock(|when, then| {
        when.method(POST).path("/v1/sessions/refresh");
        then.status(500).json_body(json!({
            "message": "refresh unavailable"
        }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "refresh", "--json"])
        .env("SN_EMAIL", "user@example.com")
        .env("SN_PASSWORD", "password-123");

    let assert = cmd.assert().code(4);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let payload: Value = serde_json::from_str(&stderr).expect("json stderr");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error"]["kind"], "sync");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("http_status=500")
    );

    login_params.assert_hits(1);
    login.assert_hits(1);
    refresh.assert_hits(3);
}

#[test]
fn auth_login_and_refresh_persist_cookie_tokens() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200)
            .header("set-cookie", "access_token_abc=one; Path=/; HttpOnly")
            .header("set-cookie", "refresh_token_abc=one; Path=/; HttpOnly")
            .json_body(json!({
                "session": {
                    "access_token": "2:access-old",
                    "refresh_token": "2:refresh-old",
                    "access_expiration": 4102444800i64,
                    "refresh_expiration": 4102448400i64,
                    "readonly_access": false
                },
                "user": {
                    "uuid": "user-uuid",
                    "email": "user@example.com"
                }
            }));
    });

    let refresh = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/sessions/refresh")
            .header("cookie", "access_token_abc=one; refresh_token_abc=one")
            .json_body(json!({
                "access_token": "2:access-old",
                "refresh_token": "2:refresh-old"
            }));
        then.status(200)
            .header("set-cookie", "access_token_new=two; Path=/; HttpOnly")
            .header("set-cookie", "refresh_token_new=two; Path=/; HttpOnly")
            .json_body(json!({
                "session": {
                    "access_token": "2:access-new",
                    "refresh_token": "2:refresh-new",
                    "access_expiration": 4102450000i64,
                    "refresh_expiration": 4102453600i64,
                    "readonly_access": false
                }
            }));
    });

    init_workspace(&workspace.path, &server.base_url());
    let _ = run_auth_command(
        &workspace.path,
        &["auth", "login", "--json"],
        Some(("user@example.com", "password-123")),
    );

    let stored_after_login = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(
        stored_after_login.access_token_cookie.as_deref(),
        Some("access_token_abc=one")
    );
    assert_eq!(
        stored_after_login.refresh_token_cookie.as_deref(),
        Some("refresh_token_abc=one")
    );

    let refresh_json = run_auth_command(&workspace.path, &["auth", "refresh", "--json"], None);
    assert_eq!(refresh_json["ok"], true);
    assert_eq!(refresh_json["result"]["reauthenticated"], false);

    let stored_after_refresh = load_session_fixture(&workspace.path).expect("stored session");
    assert_eq!(stored_after_refresh.session.access_token, "2:access-new");
    assert_eq!(stored_after_refresh.session.refresh_token, "2:refresh-new");
    assert_eq!(
        stored_after_refresh.access_token_cookie.as_deref(),
        Some("access_token_new=two")
    );
    assert_eq!(
        stored_after_refresh.refresh_token_cookie.as_deref(),
        Some("refresh_token_new=two")
    );
    assert!(stored_after_refresh.refreshed_at.is_some());
    assert_eq!(
        stored_after_refresh
            .refresh_transport_mode
            .map(|mode| mode.as_str()),
        Some("dual_cookie_token_body")
    );
    assert!(
        stored_after_refresh
            .refresh_transport_confirmed_at
            .is_some()
    );

    login_params.assert_hits(1);
    login.assert_hits(1);
    refresh.assert_hits(1);
}

#[test]
fn auth_login_uses_native_runtime_only() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    let login_params = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_nonce": TEST_PW_NONCE,
            "version": "004"
        }));
    });

    let login = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-login",
                "refresh_token": "refresh-login",
                "access_expiration": 4102444800i64,
                "refresh_expiration": 4102448400i64,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    init_workspace(&workspace.path, &server.base_url());

    let mut cmd = base_command(&workspace.path);
    cmd.args(["auth", "login", "--json"])
        .env("SN_EMAIL", "user@example.com")
        .env("SN_PASSWORD", "password-123");

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["result"]["email"], "user@example.com");

    login_params.assert_hits(1);
    login.assert_hits(1);
}

fn init_workspace(workspace: &Path, server_url: &str) {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ink");
    cmd.args([
        "init",
        "--workspace",
        workspace.to_str().expect("workspace path"),
        "--server",
        server_url,
        "--json",
    ]);

    cmd.assert().success();
}

fn run_auth_command(workspace: &Path, args: &[&str], credentials: Option<(&str, &str)>) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args);

    if let Some((email, password)) = credentials {
        cmd.env("SN_EMAIL", email).env("SN_PASSWORD", password);
    }

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    serde_json::from_str(&stdout).expect("json stdout")
}

fn base_command(workspace: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ink");
    cmd.current_dir(workspace)
        .env_remove("INK_ENV_FILE")
        .env_remove("SN_EMAIL")
        .env_remove("SN_PASSWORD")
        .env_remove("STANDARDNOTES_EMAIL")
        .env_remove("STANDARDNOTES_PASSWORD")
        .args(["--workspace", workspace.to_str().expect("workspace path")]);
    cmd
}

#[derive(Debug)]
struct TestWorkspace {
    _temp: TempDir,
    path: PathBuf,
}

fn temp_workspace() -> TestWorkspace {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace_path = temp.path().join("workspace");
    fs::create_dir_all(&workspace_path).expect("create workspace dir");
    TestWorkspace {
        _temp: temp,
        path: workspace_path,
    }
}

fn load_session_fixture(workspace: &Path) -> Option<StoredSession> {
    let paths = resolve_workspace(Some(workspace)).expect("resolve workspace");
    let store = SessionStore::from_workspace(&paths).expect("session store");
    store.load("default").expect("load stored session")
}
