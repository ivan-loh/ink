use assert_cmd::Command;
use httpmock::Method::POST;
use httpmock::MockServer;
use ink_crypto::derive_root_credentials_004;
use ink_fs::resolve_workspace;
use ink_store::{SessionStore, StoredSession};
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
    refresh.assert_hits(1);
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
            .header("authorization", "Bearer 2:refresh-old")
            .header("cookie", "refresh_token_abc=one");
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
