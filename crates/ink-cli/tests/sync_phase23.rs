use assert_cmd::Command;
use httpmock::Method::POST;
use httpmock::MockServer;
use ink_api::SessionBody;
use ink_crypto::encrypt_item_payload_004;
use ink_fs::resolve_workspace;
use ink_store::{SessionStore, StoredSession};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn sync_pull_decrypts_and_mirrors_notes_via_native_engine() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url());

    let items_key_uuid = "11111111-1111-4111-8111-111111111111";
    let note_uuid = "22222222-2222-4222-8222-222222222222";
    let master_key = "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed";
    let items_key = "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";

    let encrypted_items_key = encrypt_item_payload_004(
        &json!({"itemsKey": items_key, "version": "004"}),
        master_key,
        items_key_uuid,
        None,
        None,
        None,
    )
    .expect("encrypt items key");

    let encrypted_note = encrypt_item_payload_004(
        &json!({"title": "Fixture Title", "text": "Fixture Body"}),
        items_key,
        note_uuid,
        None,
        None,
        None,
    )
    .expect("encrypt note");

    let pull = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body_partial(
                json!({
                    "api": "20240226",
                    "items": []
                })
                .to_string(),
            );
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [
                    {
                        "uuid": items_key_uuid,
                        "content_type": "SN|ItemsKey",
                        "items_key_id": null,
                        "enc_item_key": encrypted_items_key.enc_item_key,
                        "content": encrypted_items_key.content,
                        "deleted": false,
                        "created_at": "2026-02-28T00:00:00.000000Z",
                        "updated_at": "2026-02-28T00:00:00.000000Z",
                        "created_at_timestamp": 1772236800000000i64,
                        "updated_at_timestamp": 1772236800000000i64
                    },
                    {
                        "uuid": note_uuid,
                        "content_type": "Note",
                        "items_key_id": items_key_uuid,
                        "enc_item_key": encrypted_note.enc_item_key,
                        "content": encrypted_note.content,
                        "deleted": false,
                        "created_at": "2026-02-28T00:01:00.000000Z",
                        "updated_at": "2026-02-28T00:02:00.000000Z",
                        "created_at_timestamp": 1772236860000000i64,
                        "updated_at_timestamp": 1772236920000000i64
                    }
                ],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-token-1"
            }
        }));
    });

    let output = run_command(&workspace.path, &["sync", "pull", "--json"]);
    assert_eq!(output["ok"], true);
    assert_eq!(output["result"]["pulled_notes"], 1);
    assert_eq!(output["result"]["mirrored_notes"], 1);

    let notes_dir = workspace.path.join("notes");
    let entries = fs::read_dir(&notes_dir).expect("read notes dir");
    let mut note_file: Option<PathBuf> = None;
    for entry in entries {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("md") {
            note_file = Some(path);
            break;
        }
    }

    let note_file = note_file.expect("mirrored note file");
    let rendered = fs::read_to_string(&note_file).expect("read mirrored file");
    assert!(rendered.contains("Fixture Title"));
    assert!(rendered.contains("Fixture Body"));

    pull.assert_hits(1);
}

#[test]
fn sync_push_updates_remote_via_native_engine_and_refreshes_status() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url());

    let items_key_uuid = "11111111-1111-4111-8111-111111111111";
    let note_uuid = "22222222-2222-4222-8222-222222222222";
    let master_key = "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed";
    let items_key = "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";

    let encrypted_items_key = encrypt_item_payload_004(
        &json!({"itemsKey": items_key, "version": "004"}),
        master_key,
        items_key_uuid,
        None,
        None,
        None,
    )
    .expect("encrypt items key");
    let encrypted_note_before = encrypt_item_payload_004(
        &json!({"title": "Fixture Title", "text": "Fixture Body"}),
        items_key,
        note_uuid,
        None,
        None,
        None,
    )
    .expect("encrypt note");
    let encrypted_note_after = encrypt_item_payload_004(
        &json!({"title": "Fixture Title", "text": "Edited Body"}),
        items_key,
        note_uuid,
        None,
        None,
        None,
    )
    .expect("encrypt updated note");

    let initial_pull = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({"api": "20240226", "items": [], "limit": 150}));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [
                    {
                        "uuid": items_key_uuid,
                        "content_type": "SN|ItemsKey",
                        "items_key_id": null,
                        "enc_item_key": encrypted_items_key.enc_item_key,
                        "content": encrypted_items_key.content,
                        "deleted": false,
                        "updated_at": "2026-02-28T00:00:00.000000Z",
                        "updated_at_timestamp": 1772236800000000i64
                    },
                    {
                        "uuid": note_uuid,
                        "content_type": "Note",
                        "items_key_id": items_key_uuid,
                        "enc_item_key": encrypted_note_before.enc_item_key,
                        "content": encrypted_note_before.content,
                        "deleted": false,
                        "updated_at": "2026-02-28T00:02:00.000000Z",
                        "updated_at_timestamp": 1772236920000000i64
                    }
                ],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-1"
            }
        }));
    });

    let pre_push_pull = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({
                "api": "20240226",
                "items": [],
                "limit": 150,
                "sync_token": "sync-1"
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [{
                    "uuid": note_uuid,
                    "content_type": "Note",
                    "items_key_id": items_key_uuid,
                    "enc_item_key": encrypted_note_before.enc_item_key,
                    "content": encrypted_note_before.content,
                    "deleted": false,
                    "updated_at": "2026-02-28T00:02:00.000000Z",
                    "updated_at_timestamp": 1772236920000000i64
                }],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-1"
            }
        }));
    });

    let push = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains(r#""api":"20240226""#)
            .body_contains(r#""sync_token":"sync-1""#)
            .body_contains(r#""items":[{"#)
            .body_contains(format!(r#""uuid":"{note_uuid}""#))
            .body_contains(r#""content_type":"Note""#)
            .body_contains(format!(r#""items_key_id":"{items_key_uuid}""#));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [{
                    "uuid": note_uuid,
                    "content_type": "Note",
                    "items_key_id": items_key_uuid,
                    "enc_item_key": "",
                    "content": "",
                    "deleted": false,
                    "updated_at": "2026-02-28T00:03:00.000000Z",
                    "updated_at_timestamp": 1772236980000000i64
                }],
                "conflicts": [],
                "sync_token": "sync-2"
            }
        }));
    });

    let post_push_pull = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({
                "api": "20240226",
                "items": [],
                "limit": 150,
                "sync_token": "sync-2"
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [{
                    "uuid": note_uuid,
                    "content_type": "Note",
                    "items_key_id": items_key_uuid,
                    "enc_item_key": encrypted_note_after.enc_item_key,
                    "content": encrypted_note_after.content,
                    "deleted": false,
                    "updated_at": "2026-02-28T00:04:00.000000Z",
                    "updated_at_timestamp": 1772237040000000i64
                }],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-2"
            }
        }));
    });

    let pull_output = run_command(&workspace.path, &["sync", "pull", "--json"]);
    assert_eq!(pull_output["ok"], true);
    assert_eq!(pull_output["result"]["pulled_notes"], 1);

    let note_file = find_first_note_file(&workspace.path).expect("note file");
    let raw = fs::read_to_string(&note_file).expect("read note");
    let edited = raw.replace("Fixture Body", "Edited Body");
    fs::write(&note_file, edited).expect("write edited note");

    let push_output = run_command(&workspace.path, &["sync", "push", "--json"]);
    assert_eq!(push_output["ok"], true);
    assert_eq!(push_output["result"]["updated"], 1);
    assert_eq!(push_output["result"]["created"], 0);
    assert_eq!(push_output["result"]["conflicts"], 0);

    let status_output = run_command(&workspace.path, &["sync", "status", "--json"]);
    assert_eq!(status_output["ok"], true);
    assert_eq!(status_output["result"]["sync_token"], "sync-2");
    assert_eq!(status_output["result"]["last_sync_status"], "ok");

    let rendered = fs::read_to_string(&note_file).expect("read mirrored note");
    assert!(rendered.contains("Edited Body"));

    initial_pull.assert_hits(1);
    pre_push_pull.assert_hits(1);
    push.assert_hits(1);
    post_push_pull.assert_hits(1);
}

fn seed_session(workspace: &Path, server_url: &str) {
    let paths = resolve_workspace(Some(workspace)).expect("resolve workspace");
    let sessions = SessionStore::from_workspace(&paths).expect("session store");

    let session = StoredSession {
        profile: "default".to_string(),
        server: server_url.to_string(),
        email: "user@example.com".to_string(),
        authenticated_at: "2026-02-28T00:00:00Z".to_string(),
        refreshed_at: None,
        master_key: Some(
            "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed".to_string(),
        ),
        session: SessionBody {
            access_token: "access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
            access_expiration: 4_102_444_800,
            refresh_expiration: 4_102_448_400,
            readonly_access: false,
        },
        access_token_cookie: None,
        refresh_token_cookie: None,
        user: None,
        key_params: None,
    };

    sessions.save("default", &session).expect("save session");
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

fn run_command(workspace: &Path, args: &[&str]) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args);

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    serde_json::from_str(&stdout).expect("json stdout")
}

fn find_first_note_file(workspace: &Path) -> Option<PathBuf> {
    let notes_dir = workspace.join("notes");
    let entries = fs::read_dir(notes_dir).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("md") {
            return Some(path);
        }
    }
    None
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
