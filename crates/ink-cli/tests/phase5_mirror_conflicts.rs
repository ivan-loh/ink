use assert_cmd::Command;
use httpmock::Method::POST;
use httpmock::{Mock, MockServer};
use ink_api::SessionBody;
use ink_crypto::encrypt_item_payload_004;
use ink_fs::resolve_workspace;
use ink_store::{AppState, SessionStore, StoredSession, SyncConflict};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn phase5_mirror_rename_preserves_uuid_mapping_on_push() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let pull_mock = mock_pull_any_pull_request(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );

    let pull = run_command(&workspace.path, &["sync", "pull", "--json"]);
    assert_eq!(pull["ok"], true);

    let original_file = find_first_note_file(&workspace.path).expect("original mirrored file");
    let moved_file = workspace.path.join("notes/renamed/phase5-note.md");
    fs::create_dir_all(
        moved_file
            .parent()
            .expect("moved file should have parent directory"),
    )
    .expect("create parent directory");
    fs::rename(&original_file, &moved_file).expect("rename mirrored file");

    let push = run_command(&workspace.path, &["sync", "push", "--json"]);
    assert_eq!(push["ok"], true);
    assert_eq!(push["result"]["updated"], 0);
    assert_eq!(push["result"]["created"], 0);
    assert_eq!(push["result"]["conflicts"], 0);

    let mirror_index_path = workspace.path.join(".ink/mirror-index.json");
    let mirror_index_raw = fs::read_to_string(&mirror_index_path).expect("read mirror index");
    let mirror_index: Value = serde_json::from_str(&mirror_index_raw).expect("parse mirror index");
    assert_eq!(
        mirror_index["entries"].as_array().expect("entries").len(),
        1
    );
    assert_eq!(mirror_index["entries"][0]["uuid"], fixtures.note_uuid);
    assert_eq!(
        mirror_index["entries"][0]["path"],
        "notes/renamed/phase5-note.md"
    );

    assert!(moved_file.exists(), "moved file should stay present");
    assert!(
        !original_file.exists(),
        "old mirrored file path should not reappear"
    );

    pull_mock.assert_hits(3);
}

#[test]
fn phase5_push_conflict_preserves_local_edit_and_lists_conflict() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let initial_pull = mock_pull_without_sync(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let pre_push_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-1",
        "Remote Changed On Server",
        "2026-02-28T00:05:00.000000Z",
        1_772_237_100_000_000,
        "sync-2",
    );
    let no_push = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[{");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-unexpected-push"
            }
        }));
    });

    let pull = run_command(&workspace.path, &["sync", "pull", "--json"]);
    assert_eq!(pull["ok"], true);

    let note_file = find_first_note_file(&workspace.path).expect("mirrored note");
    let raw = fs::read_to_string(&note_file).expect("read mirrored note");
    let edited = raw.replace("Remote Body", "Local Edited Body");
    fs::write(&note_file, edited).expect("write edited mirror note");

    let push = run_command_expect_exit(&workspace.path, &["sync", "push", "--json"], 4);
    assert_eq!(push["ok"], false);
    assert_eq!(push["result"]["conflicts"], 1);

    let local_after = fs::read_to_string(&note_file).expect("read local file after conflict");
    assert!(
        local_after.contains("Local Edited Body"),
        "local edits must remain after a detected conflict"
    );

    let conflicts = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    assert_eq!(conflicts["ok"], true);
    let rows = conflicts["result"].as_array().expect("conflict array");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]["reason"]
            .as_str()
            .expect("reason")
            .contains("remote note changed since last pull")
    );

    initial_pull.assert_hits(1);
    pre_push_pull.assert_hits(1);
    no_push.assert_hits(0);
}

#[test]
fn phase5_duplicate_uuid_files_are_reported_as_conflict() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let initial_pull = mock_pull_without_sync(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let pre_push_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-1",
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let no_push = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[{");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-unexpected-push"
            }
        }));
    });

    let _ = run_command(&workspace.path, &["sync", "pull", "--json"]);

    let original = find_first_note_file(&workspace.path).expect("mirrored note file");
    let duplicate = workspace.path.join("notes/duplicates/dup.md");
    fs::create_dir_all(
        duplicate
            .parent()
            .expect("duplicate path should have parent directory"),
    )
    .expect("create duplicate directory");
    fs::copy(&original, &duplicate).expect("copy duplicate note file");

    let push = run_command_expect_exit(&workspace.path, &["sync", "push", "--json"], 4);
    assert_eq!(push["ok"], false);
    assert_eq!(push["result"]["conflicts"], 1);

    let conflicts = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    let rows = conflicts["result"].as_array().expect("conflicts");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]["reason"]
            .as_str()
            .expect("reason")
            .contains("multiple mirrored files share UUID")
    );

    initial_pull.assert_hits(1);
    pre_push_pull.assert_hits(1);
    no_push.assert_hits(0);
}

#[test]
fn phase5_resolve_local_fails_when_conflict_persists() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let _initial_pull = mock_pull_without_sync(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let _pre_push_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-1",
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );

    let _ = run_command(&workspace.path, &["sync", "pull", "--json"]);

    let original = find_first_note_file(&workspace.path).expect("mirrored note file");
    let duplicate = workspace.path.join("notes/duplicates/persisting-dup.md");
    fs::create_dir_all(
        duplicate
            .parent()
            .expect("duplicate path should have parent directory"),
    )
    .expect("create duplicate directory");
    fs::copy(&original, &duplicate).expect("copy duplicate note file");

    let _ = run_command_expect_exit(&workspace.path, &["sync", "push", "--json"], 4);
    let conflicts = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    let conflict_id = conflicts["result"][0]["id"].as_str().expect("conflict id");

    let resolve = run_command_expect_exit_error(
        &workspace.path,
        &["sync", "resolve", conflict_id, "--use", "local", "--json"],
        4,
    );
    assert_eq!(resolve["ok"], false);
    assert!(
        resolve["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("still unresolved")
    );

    let after = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    assert!(
        !after["result"].as_array().expect("conflicts").is_empty(),
        "conflicts should remain until duplicate file is fixed"
    );
}

#[test]
fn phase5_resolve_local_rejects_remote_only_conflict() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    init_workspace(&workspace.path, &server.base_url());

    let mut state = AppState::default();
    state.conflicts.push(SyncConflict {
        id: "remote-only-1".to_string(),
        uuid: None,
        title: "Server conflict".to_string(),
        file: "<remote>".to_string(),
        reason: "server reported conflict".to_string(),
        detected_at: "2026-02-28T00:00:00.000000Z".to_string(),
        remote_updated_at: None,
        local_updated_at: None,
    });
    save_app_state(&workspace.path, "default", &state);

    let err = run_command_expect_exit_error(
        &workspace.path,
        &[
            "sync",
            "resolve",
            "remote-only-1",
            "--use",
            "local",
            "--json",
        ],
        2,
    );
    assert_eq!(err["ok"], false);
    assert_eq!(err["error"]["kind"], "usage");
    assert!(
        err["error"]["message"]
            .as_str()
            .expect("message")
            .contains("use `--use server`")
    );
}

#[test]
fn phase5_local_resolve_preserves_unrelated_conflicts() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let _initial_pull = mock_pull_without_sync(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let _ = run_command(&workspace.path, &["sync", "pull", "--json"]);

    let note_file = find_first_note_file(&workspace.path).expect("note file");
    let note_relative = note_file
        .strip_prefix(&workspace.path)
        .expect("relative path")
        .to_string_lossy()
        .to_string();

    let state = AppState {
        conflicts: vec![
            SyncConflict {
                id: "target-conflict".to_string(),
                uuid: Some(fixtures.note_uuid.clone()),
                title: "Phase 5 Note".to_string(),
                file: note_relative,
                reason: "remote note changed since last pull".to_string(),
                detected_at: "2026-02-28T00:10:00.000000Z".to_string(),
                remote_updated_at: Some("2026-02-28T00:09:00.000000Z".to_string()),
                local_updated_at: Some("2026-02-28T00:08:00.000000Z".to_string()),
            },
            SyncConflict {
                id: "other-conflict".to_string(),
                uuid: Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string()),
                title: "Other note".to_string(),
                file: "notes/other-note.md".to_string(),
                reason: "manual-review-required".to_string(),
                detected_at: "2026-02-28T00:11:00.000000Z".to_string(),
                remote_updated_at: None,
                local_updated_at: None,
            },
        ],
        ..AppState::default()
    };
    save_app_state(&workspace.path, "default", &state);

    let pre_resolve_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-1",
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let resolve_push = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"sync_token\":\"sync-1\"")
            .body_contains("\"items\":[{")
            .body_contains("\"uuid\":\"22222222-2222-4222-8222-222222222222\"")
            .body_contains("\"content_type\":\"Note\"");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [{
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "content_type": "Note",
                    "items_key_id": "11111111-1111-4111-8111-111111111111",
                    "enc_item_key": "",
                    "content": "",
                    "deleted": false,
                    "updated_at": "2026-02-28T00:12:00.000000Z",
                    "updated_at_timestamp": 1772237520000000i64
                }],
                "conflicts": [],
                "sync_token": "sync-2"
            }
        }));
    });
    let post_resolve_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-2",
        "Remote Body",
        "2026-02-28T00:12:00.000000Z",
        1_772_237_520_000_000,
        "sync-2",
    );

    let resolve = run_command(
        &workspace.path,
        &[
            "sync",
            "resolve",
            "target-conflict",
            "--use",
            "local",
            "--json",
        ],
    );
    assert_eq!(resolve["ok"], true);

    let remaining = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    let rows = remaining["result"].as_array().expect("remaining conflicts");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], "other-conflict");

    pre_resolve_pull.assert_hits(1);
    resolve_push.assert_hits(1);
    post_resolve_pull.assert_hits(1);
}

#[test]
fn phase5_resolve_local_works_after_conflict_file_move() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let initial_pull = mock_pull_without_sync(
        &server,
        &fixtures,
        "Remote Body",
        "2026-02-28T00:02:00.000000Z",
        1_772_236_920_000_000,
        "sync-1",
    );
    let conflict_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-1",
        "Remote Changed On Server",
        "2026-02-28T00:05:00.000000Z",
        1_772_237_100_000_000,
        "sync-2",
    );
    let resolve_pre_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-2",
        "Remote Changed On Server",
        "2026-02-28T00:05:00.000000Z",
        1_772_237_100_000_000,
        "sync-2",
    );
    let resolve_push = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"sync_token\":\"sync-2\"")
            .body_contains("\"items\":[{")
            .body_contains("\"uuid\":\"22222222-2222-4222-8222-222222222222\"")
            .body_contains("\"content_type\":\"Note\"");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [{
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "content_type": "Note",
                    "items_key_id": "11111111-1111-4111-8111-111111111111",
                    "enc_item_key": "",
                    "content": "",
                    "deleted": false,
                    "updated_at": "2026-02-28T00:07:00.000000Z",
                    "updated_at_timestamp": 1772237220000000i64
                }],
                "conflicts": [],
                "sync_token": "sync-3"
            }
        }));
    });
    let resolve_post_pull = mock_pull_with_sync_token(
        &server,
        &fixtures,
        "sync-3",
        "Local Forced Body",
        "2026-02-28T00:08:00.000000Z",
        1_772_237_280_000_000,
        "sync-3",
    );

    let _ = run_command(&workspace.path, &["sync", "pull", "--json"]);

    let original_file = find_first_note_file(&workspace.path).expect("mirrored note file");
    let raw = fs::read_to_string(&original_file).expect("read mirrored note");
    let edited = raw.replace("Remote Body", "Local Forced Body");
    fs::write(&original_file, edited).expect("write local conflict edit");

    let conflict_push = run_command_expect_exit(&workspace.path, &["sync", "push", "--json"], 4);
    assert_eq!(conflict_push["result"]["conflicts"], 1);

    let moved_file = workspace.path.join("notes/moved/local-resolution.md");
    fs::create_dir_all(
        moved_file
            .parent()
            .expect("moved file should have parent directory"),
    )
    .expect("create moved parent");
    fs::rename(&original_file, &moved_file).expect("move conflicted file");

    let conflicts = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    let conflict_rows = conflicts["result"].as_array().expect("conflict rows");
    assert_eq!(conflict_rows.len(), 1);
    let conflict_id = conflict_rows[0]["id"]
        .as_str()
        .expect("conflict id")
        .to_string();

    let resolve = run_command(
        &workspace.path,
        &["sync", "resolve", &conflict_id, "--use", "local", "--json"],
    );
    assert_eq!(resolve["ok"], true);

    let conflicts_after = run_command(&workspace.path, &["sync", "conflicts", "--json"]);
    assert_eq!(
        conflicts_after["result"]
            .as_array()
            .expect("conflicts")
            .len(),
        0
    );

    let moved_contents = fs::read_to_string(&moved_file).expect("read moved file");
    assert!(moved_contents.contains("Local Forced Body"));
    assert!(
        !original_file.exists(),
        "original path should stay absent after local resolve"
    );

    initial_pull.assert_hits(1);
    conflict_pull.assert_hits(1);
    resolve_pre_pull.assert_hits(1);
    resolve_push.assert_hits(1);
    resolve_post_pull.assert_hits(1);
}

#[derive(Debug, Clone)]
struct Fixtures {
    master_key: String,
    items_key: String,
    items_key_uuid: String,
    note_uuid: String,
}

impl Fixtures {
    fn new() -> Self {
        Self {
            master_key: "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed"
                .to_string(),
            items_key: "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677"
                .to_string(),
            items_key_uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            note_uuid: "22222222-2222-4222-8222-222222222222".to_string(),
        }
    }

    fn items_key_item(&self) -> Value {
        let encrypted = encrypt_item_payload_004(
            &json!({"itemsKey": self.items_key, "version": "004"}),
            &self.master_key,
            &self.items_key_uuid,
            None,
            None,
            None,
        )
        .expect("encrypt items key");

        json!({
            "uuid": self.items_key_uuid,
            "content_type": "SN|ItemsKey",
            "items_key_id": null,
            "enc_item_key": encrypted.enc_item_key,
            "content": encrypted.content,
            "deleted": false,
            "created_at": "2026-02-28T00:00:00.000000Z",
            "updated_at": "2026-02-28T00:00:00.000000Z",
            "created_at_timestamp": 1772236800000000i64,
            "updated_at_timestamp": 1772236800000000i64
        })
    }

    fn note_item(&self, text: &str, updated_at: &str, updated_at_timestamp: i64) -> Value {
        let encrypted = encrypt_item_payload_004(
            &json!({"title": "Phase 5 Note", "text": text, "references": []}),
            &self.items_key,
            &self.note_uuid,
            None,
            None,
            None,
        )
        .expect("encrypt note payload");

        json!({
            "uuid": self.note_uuid,
            "content_type": "Note",
            "items_key_id": self.items_key_uuid,
            "enc_item_key": encrypted.enc_item_key,
            "content": encrypted.content,
            "deleted": false,
            "created_at": "2026-02-28T00:01:00.000000Z",
            "updated_at": updated_at,
            "created_at_timestamp": 1772236860000000i64,
            "updated_at_timestamp": updated_at_timestamp
        })
    }
}

fn mock_pull_without_sync<'a>(
    server: &'a MockServer,
    fixtures: &Fixtures,
    note_text: &str,
    note_updated_at: &str,
    note_updated_at_timestamp: i64,
    sync_token: &str,
) -> Mock<'a> {
    let items_key_item = fixtures.items_key_item();
    let note_item = fixtures.note_item(note_text, note_updated_at, note_updated_at_timestamp);

    server.mock(move |when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({
                "api": "20240226",
                "items": [],
                "limit": 150
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [items_key_item, note_item],
                "saved_items": [],
                "conflicts": [],
                "sync_token": sync_token
            }
        }));
    })
}

fn mock_pull_any_pull_request<'a>(
    server: &'a MockServer,
    fixtures: &Fixtures,
    note_text: &str,
    note_updated_at: &str,
    note_updated_at_timestamp: i64,
    sync_token: &str,
) -> Mock<'a> {
    let items_key_item = fixtures.items_key_item();
    let note_item = fixtures.note_item(note_text, note_updated_at, note_updated_at_timestamp);

    server.mock(move |when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[]");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [items_key_item, note_item],
                "saved_items": [],
                "conflicts": [],
                "sync_token": sync_token
            }
        }));
    })
}

fn mock_pull_with_sync_token<'a>(
    server: &'a MockServer,
    fixtures: &Fixtures,
    request_sync_token: &str,
    note_text: &str,
    note_updated_at: &str,
    note_updated_at_timestamp: i64,
    response_sync_token: &str,
) -> Mock<'a> {
    let note_item = fixtures.note_item(note_text, note_updated_at, note_updated_at_timestamp);

    server.mock(move |when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({
                "api": "20240226",
                "items": [],
                "limit": 150,
                "sync_token": request_sync_token
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [note_item],
                "saved_items": [],
                "conflicts": [],
                "sync_token": response_sync_token
            }
        }));
    })
}

fn seed_session(workspace: &Path, server_url: &str, master_key: &str) {
    let paths = resolve_workspace(Some(workspace)).expect("resolve workspace");
    let sessions = SessionStore::from_workspace(&paths).expect("session store");

    let session = StoredSession {
        profile: "default".to_string(),
        server: server_url.to_string(),
        email: "user@example.com".to_string(),
        authenticated_at: "2026-02-28T00:00:00Z".to_string(),
        refreshed_at: None,
        master_key: Some(master_key.to_string()),
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

fn save_app_state(workspace: &Path, profile: &str, state: &AppState) {
    let paths = resolve_workspace(Some(workspace)).expect("resolve workspace");
    let sessions = SessionStore::from_workspace(&paths).expect("session store");
    sessions
        .save_app_state(profile, state)
        .expect("save app state");
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

fn run_command_expect_exit(workspace: &Path, args: &[&str], code: i32) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args);
    let assert = cmd.assert().code(code);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    serde_json::from_str(&stdout).expect("json stdout")
}

fn run_command_expect_exit_error(workspace: &Path, args: &[&str], code: i32) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args);
    let assert = cmd.assert().code(code);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    serde_json::from_str(&stderr).expect("json stderr")
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
