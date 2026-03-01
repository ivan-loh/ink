use assert_cmd::Command;
use httpmock::Method::POST;
use httpmock::{Mock, MockServer};
use ink_api::SessionBody;
use ink_crypto::encrypt_item_payload_004;
use ink_fs::resolve_workspace;
use ink_store::{SessionStore, StoredSession};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn phase4_note_commands_native_flow() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let pull = mock_pull(&server, &fixtures);
    let push = mock_push(&server);

    let list = run_command(&workspace.path, &["note", "list", "--json"]);
    assert_eq!(list["ok"], true);
    assert_eq!(list["result"][0]["content"]["title"], fixtures.note_title);

    let list_by_tag = run_command(
        &workspace.path,
        &["note", "list", "--tag", &fixtures.tag_title, "--json"],
    );
    assert_eq!(list_by_tag["ok"], true);
    assert_eq!(list_by_tag["result"].as_array().expect("array").len(), 1);

    let get_uuid = run_command(
        &workspace.path,
        &["note", "get", &fixtures.note_uuid, "--json"],
    );
    assert_eq!(get_uuid["ok"], true);
    assert_eq!(get_uuid["result"][0]["uuid"], fixtures.note_uuid);

    let get_title = run_command(
        &workspace.path,
        &["note", "get", &fixtures.note_title, "--json"],
    );
    assert_eq!(get_title["ok"], true);
    assert_eq!(
        get_title["result"][0]["content"]["title"],
        fixtures.note_title
    );

    let search = run_command(
        &workspace.path,
        &[
            "note",
            "search",
            "--query",
            "Fixture",
            "--tag",
            &fixtures.tag_title,
            "--limit",
            "5",
            "--json",
        ],
    );
    assert_eq!(search["ok"], true);
    assert_eq!(search["result"].as_array().expect("array").len(), 1);

    let search_fuzzy_offline = run_command(
        &workspace.path,
        &[
            "note",
            "search",
            "--query",
            "fxbod",
            "--fuzzy",
            "--offline",
            "--json",
        ],
    );
    assert_eq!(search_fuzzy_offline["ok"], true);
    assert_eq!(
        search_fuzzy_offline["result"]
            .as_array()
            .expect("array")
            .len(),
        1
    );

    let created = run_command(
        &workspace.path,
        &[
            "note",
            "new",
            "--title",
            "Created Note",
            "--text",
            "Created Body",
            "--tag",
            &fixtures.tag_title,
            "--json",
        ],
    );
    assert_eq!(created["ok"], true);
    assert_eq!(created["result"]["title"], "Created Note");
    assert!(created["result"]["uuid"].as_str().is_some());

    let edited = run_command(
        &workspace.path,
        &[
            "note",
            "edit",
            &fixtures.note_uuid,
            "--text",
            "Edited Body",
            "--json",
        ],
    );
    assert_eq!(edited["ok"], true);
    assert_eq!(edited["result"]["uuid"], fixtures.note_uuid);

    let deleted = run_command(
        &workspace.path,
        &["note", "delete", &fixtures.note_uuid, "--yes", "--json"],
    );
    assert_eq!(deleted["ok"], true);
    assert_eq!(deleted["result"]["uuid"], fixtures.note_uuid);

    pull.assert_hits(11);
    push.assert_hits(3);
}

#[test]
fn phase4_tag_commands_native_flow() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let pull = mock_pull(&server, &fixtures);
    let push = mock_push(&server);

    let list = run_command(&workspace.path, &["tag", "list", "--json"]);
    assert_eq!(list["ok"], true);
    assert_eq!(list["result"][0]["content"]["title"], fixtures.tag_title);

    let added = run_command(
        &workspace.path,
        &[
            "tag",
            "add",
            "Child Tag",
            "--parent",
            &fixtures.tag_title,
            "--json",
        ],
    );
    assert_eq!(added["ok"], true);
    assert_eq!(added["result"]["title"], "Child Tag");
    assert!(added["result"]["parent_uuid"].as_str().is_some());

    let renamed = run_command(
        &workspace.path,
        &[
            "tag",
            "rename",
            &fixtures.tag_title,
            "Work Renamed",
            "--json",
        ],
    );
    assert_eq!(renamed["ok"], true);
    assert_eq!(renamed["result"]["old"], fixtures.tag_title);
    assert_eq!(renamed["result"]["new"], "Work Renamed");

    let applied = run_command(
        &workspace.path,
        &[
            "tag",
            "apply",
            "--note",
            &fixtures.note_uuid,
            "--tag",
            &fixtures.tag_title,
            "--purge",
            "--json",
        ],
    );
    assert_eq!(applied["ok"], true);
    assert_eq!(applied["result"]["note_uuid"], fixtures.note_uuid);
    assert_eq!(applied["result"]["tag_title"], fixtures.tag_title);
    assert_eq!(applied["result"]["purge"], true);

    let deleted = run_command(
        &workspace.path,
        &["tag", "delete", &fixtures.tag_title, "--yes", "--json"],
    );
    assert_eq!(deleted["ok"], true);
    assert_eq!(deleted["result"]["title"], fixtures.tag_title);

    pull.assert_hits(9);
    push.assert_hits(4);
}

#[test]
fn phase4_note_file_and_case_sensitive_branches() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let _pull = mock_pull(&server, &fixtures);
    let _push = mock_push(&server);

    let new_file = workspace.path.join("lorem-draft.txt");
    fs::write(
        &new_file,
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    )
    .expect("write new note file");
    let new_file_str = new_file.to_str().expect("new file path");

    let created = run_command(
        &workspace.path,
        &["note", "new", "--file", new_file_str, "--json"],
    );
    assert_eq!(created["ok"], true);
    assert_eq!(created["result"]["title"], "lorem-draft");

    let edit_file = workspace.path.join("edited-body.txt");
    fs::write(
        &edit_file,
        "Edited from file path to cover --file update branch.",
    )
    .expect("write edit note file");
    let edit_file_str = edit_file.to_str().expect("edit file path");

    let edited = run_command(
        &workspace.path,
        &[
            "note",
            "edit",
            &fixtures.note_uuid,
            "--file",
            edit_file_str,
            "--json",
        ],
    );
    assert_eq!(edited["ok"], true);
    assert_eq!(edited["result"]["uuid"], fixtures.note_uuid);

    let lower_case_sensitive = run_command(
        &workspace.path,
        &[
            "note",
            "search",
            "--query",
            "fixture",
            "--case-sensitive",
            "--json",
        ],
    );
    assert_eq!(lower_case_sensitive["ok"], true);
    assert_eq!(
        lower_case_sensitive["result"]
            .as_array()
            .expect("array")
            .len(),
        0
    );

    let proper_case_sensitive = run_command(
        &workspace.path,
        &[
            "note",
            "search",
            "--query",
            "Fixture",
            "--case-sensitive",
            "--json",
        ],
    );
    assert_eq!(proper_case_sensitive["ok"], true);
    assert_eq!(
        proper_case_sensitive["result"]
            .as_array()
            .expect("array")
            .len(),
        1
    );
}

#[test]
fn phase4_tag_parent_uuid_and_apply_auto_create_without_purge() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let _pull = mock_pull(&server, &fixtures);
    let _push = mock_push(&server);

    let added = run_command(
        &workspace.path,
        &[
            "tag",
            "add",
            "Child Via Uuid",
            "--parent-uuid",
            &fixtures.tag_uuid,
            "--json",
        ],
    );
    assert_eq!(added["ok"], true);
    assert_eq!(added["result"]["title"], "Child Via Uuid");
    assert_eq!(added["result"]["parent_uuid"], fixtures.tag_uuid);

    let applied = run_command(
        &workspace.path,
        &[
            "tag",
            "apply",
            "--note",
            &fixtures.note_uuid,
            "--tag",
            "Auto Created Tag",
            "--json",
        ],
    );
    assert_eq!(applied["ok"], true);
    assert_eq!(applied["result"]["note_uuid"], fixtures.note_uuid);
    assert_eq!(applied["result"]["tag_title"], "Auto Created Tag");
    assert_eq!(applied["result"]["purge"], false);
}

#[test]
fn phase4_usage_errors_require_yes() {
    let server = MockServer::start();
    let workspace = temp_workspace();

    init_workspace(&workspace.path, &server.base_url());

    let note_err =
        run_command_fail_json(&workspace.path, &["note", "delete", "anything", "--json"]);
    assert_eq!(note_err["ok"], false);
    assert_eq!(note_err["contract_version"], "v1");
    assert_eq!(note_err["error"]["code"], "USAGE_INVALID_INPUT");
    assert!(
        note_err["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("note delete requires --yes")
    );

    let tag_err = run_command_fail_json(&workspace.path, &["tag", "delete", "anything", "--json"]);
    assert_eq!(tag_err["ok"], false);
    assert_eq!(tag_err["error"]["code"], "USAGE_INVALID_INPUT");
    assert!(
        tag_err["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("tag delete requires --yes")
    );
}

#[test]
fn phase4_ambiguous_title_selector_errors() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let mut retrieved = fixtures.default_retrieved_items();
    retrieved.push(fixtures.note_item(
        "44444444-4444-4444-8444-444444444444",
        &fixtures.note_title,
        "Duplicate title note body",
        1772236999000000,
    ));
    retrieved.push(fixtures.tag_item(
        "55555555-5555-4555-8555-555555555555",
        &fixtures.tag_title,
        &[&fixtures.note_uuid],
        Some("root-tag"),
        1772236999500000,
    ));

    let _pull = mock_pull_with_retrieved(&server, retrieved);

    let note_err = run_command_fail(
        &workspace.path,
        &[
            "note",
            "edit",
            &fixtures.note_title,
            "--text",
            "Attempt update",
            "--json",
        ],
    );
    assert!(note_err.contains("multiple notes matched"));

    let tag_err = run_command_fail(
        &workspace.path,
        &["tag", "rename", &fixtures.tag_title, "Renamed", "--json"],
    );
    assert!(tag_err.contains("multiple tags matched"));
}

#[test]
fn phase4_conflict_from_push_fails_command() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let _pull = mock_pull(&server, &fixtures);
    let _push = mock_push_conflict(&server);

    let err = run_command_fail(
        &workspace.path,
        &[
            "note",
            "edit",
            &fixtures.note_uuid,
            "--text",
            "conflict please",
            "--json",
        ],
    );
    assert!(err.contains("server reported 1 conflicts"));
}

#[test]
fn phase4_llm_operability_resolve_upsert_and_paging() {
    let server = MockServer::start();
    let workspace = temp_workspace();
    let fixtures = Fixtures::new();

    init_workspace(&workspace.path, &server.base_url());
    seed_session(&workspace.path, &server.base_url(), &fixtures.master_key);

    let mut retrieved = fixtures.default_retrieved_items();
    retrieved.push(fixtures.note_item(
        "77777777-7777-4777-8777-777777777777",
        "Fixture Secondary",
        "Secondary Fixture Body",
        1772237100000000,
    ));

    let _pull = mock_pull_with_retrieved(&server, retrieved);
    let push = mock_push(&server);

    let resolve_exact = run_command(
        &workspace.path,
        &["note", "resolve", &fixtures.note_title, "--json"],
    );
    assert_eq!(resolve_exact["ok"], true);
    assert_eq!(resolve_exact["result"]["resolved_uuid"], fixtures.note_uuid);
    assert_eq!(resolve_exact["result"]["exact_matches"], 1);

    let resolve_partial = run_command(
        &workspace.path,
        &["note", "resolve", "Fixture", "--limit", "1", "--json"],
    );
    assert_eq!(resolve_partial["ok"], true);
    assert_eq!(resolve_partial["result"]["resolved_uuid"], Value::Null);
    assert_eq!(resolve_partial["result"]["returned"], 1);

    let list_page_1 = run_command(
        &workspace.path,
        &[
            "note",
            "list",
            "--fields",
            "uuid,title",
            "--limit",
            "1",
            "--json",
        ],
    );
    assert_eq!(list_page_1["ok"], true);
    assert_eq!(list_page_1["page"]["returned"], 1);
    assert_eq!(list_page_1["page"]["next_cursor"], "1");
    assert!(list_page_1["result"][0]["content"].is_null());
    let cursor = list_page_1["page"]["next_cursor"]
        .as_str()
        .expect("next cursor")
        .to_string();

    let list_page_2 = run_command(
        &workspace.path,
        &[
            "note",
            "list",
            "--fields",
            "uuid,title",
            "--limit",
            "1",
            "--cursor",
            &cursor,
            "--json",
        ],
    );
    assert_eq!(list_page_2["ok"], true);
    assert_eq!(list_page_2["page"]["returned"], 1);

    let updated = run_command_with_stdin(
        &workspace.path,
        &[
            "note",
            "upsert",
            "--title",
            &fixtures.note_title,
            "--text",
            "-",
            "--append",
            "--json",
        ],
        "From stdin",
    );
    assert_eq!(updated["ok"], true);
    assert_eq!(updated["result"]["action"], "updated");
    assert_eq!(updated["result"]["uuid"], fixtures.note_uuid);

    let noop = run_command(
        &workspace.path,
        &["note", "upsert", "--title", &fixtures.note_title, "--json"],
    );
    assert_eq!(noop["ok"], true);
    assert_eq!(noop["result"]["action"], "noop");

    let created = run_command(
        &workspace.path,
        &[
            "note",
            "upsert",
            "--title",
            "LLM New Note",
            "--text",
            "Created by upsert",
            "--json",
        ],
    );
    assert_eq!(created["ok"], true);
    assert_eq!(created["result"]["action"], "created");
    assert_eq!(created["result"]["title"], "LLM New Note");

    push.assert_hits(2);
}

#[derive(Debug, Clone)]
struct Fixtures {
    master_key: String,
    items_key: String,
    items_key_uuid: String,
    note_uuid: String,
    note_title: String,
    tag_uuid: String,
    tag_title: String,
    encrypted_items_key_content: String,
    encrypted_items_key_enc_key: String,
}

impl Fixtures {
    fn new() -> Self {
        let master_key =
            "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed".to_string();
        let items_key =
            "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677".to_string();
        let items_key_uuid = "11111111-1111-4111-8111-111111111111".to_string();
        let note_uuid = "22222222-2222-4222-8222-222222222222".to_string();
        let note_title = "Fixture Title".to_string();
        let tag_uuid = "33333333-3333-4333-8333-333333333333".to_string();
        let tag_title = "Work".to_string();

        let encrypted_items_key = encrypt_item_payload_004(
            &json!({"itemsKey": items_key, "version": "004"}),
            &master_key,
            &items_key_uuid,
            None,
            None,
            None,
        )
        .expect("encrypt items key");
        Self {
            master_key,
            items_key,
            items_key_uuid,
            note_uuid,
            note_title,
            tag_uuid,
            tag_title,
            encrypted_items_key_content: encrypted_items_key.content,
            encrypted_items_key_enc_key: encrypted_items_key.enc_item_key,
        }
    }

    fn items_key_item(&self) -> Value {
        json!({
            "uuid": self.items_key_uuid,
            "content_type": "SN|ItemsKey",
            "items_key_id": null,
            "enc_item_key": self.encrypted_items_key_enc_key,
            "content": self.encrypted_items_key_content,
            "deleted": false,
            "created_at": "2026-02-28T00:00:00.000000Z",
            "updated_at": "2026-02-28T00:00:00.000000Z",
            "created_at_timestamp": 1772236800000000i64,
            "updated_at_timestamp": 1772236800000000i64
        })
    }

    fn note_item(&self, uuid: &str, title: &str, text: &str, updated_at_ts: i64) -> Value {
        let encrypted_note = encrypt_item_payload_004(
            &json!({"title": title, "text": text, "references": []}),
            &self.items_key,
            uuid,
            None,
            None,
            None,
        )
        .expect("encrypt note fixture item");

        json!({
            "uuid": uuid,
            "content_type": "Note",
            "items_key_id": self.items_key_uuid,
            "enc_item_key": encrypted_note.enc_item_key,
            "content": encrypted_note.content,
            "deleted": false,
            "created_at": "2026-02-28T00:01:00.000000Z",
            "updated_at": "2026-02-28T00:02:00.000000Z",
            "created_at_timestamp": 1772236860000000i64,
            "updated_at_timestamp": updated_at_ts
        })
    }

    fn tag_item(
        &self,
        uuid: &str,
        title: &str,
        references: &[&str],
        parent_uuid: Option<&str>,
        updated_at_ts: i64,
    ) -> Value {
        let refs: Vec<Value> = references
            .iter()
            .map(|reference| json!({"uuid": reference, "content_type": "Note"}))
            .collect();
        let app_data = match parent_uuid {
            Some(parent_uuid) => json!({"org.standardnotes.sn": {"parentId": parent_uuid}}),
            None => json!({}),
        };

        let encrypted_tag = encrypt_item_payload_004(
            &json!({
                "title": title,
                "references": refs,
                "appData": app_data
            }),
            &self.items_key,
            uuid,
            None,
            None,
            None,
        )
        .expect("encrypt tag fixture item");

        json!({
            "uuid": uuid,
            "content_type": "Tag",
            "items_key_id": self.items_key_uuid,
            "enc_item_key": encrypted_tag.enc_item_key,
            "content": encrypted_tag.content,
            "deleted": false,
            "created_at": "2026-02-28T00:01:30.000000Z",
            "updated_at": "2026-02-28T00:02:30.000000Z",
            "created_at_timestamp": 1772236890000000i64,
            "updated_at_timestamp": updated_at_ts
        })
    }

    fn default_retrieved_items(&self) -> Vec<Value> {
        vec![
            self.items_key_item(),
            self.note_item(
                &self.note_uuid,
                &self.note_title,
                "Fixture Body",
                1772236920000000,
            ),
            self.tag_item(
                &self.tag_uuid,
                &self.tag_title,
                &[&self.note_uuid],
                Some("root-tag"),
                1772236950000000,
            ),
        ]
    }
}

fn mock_pull<'a>(server: &'a MockServer, fixtures: &Fixtures) -> Mock<'a> {
    mock_pull_with_retrieved(server, fixtures.default_retrieved_items())
}

fn mock_pull_with_retrieved<'a>(server: &'a MockServer, retrieved_items: Vec<Value>) -> Mock<'a> {
    server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[]");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": retrieved_items,
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-token-1"
            }
        }));
    })
}

fn mock_push<'a>(server: &'a MockServer) -> Mock<'a> {
    server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[{");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-token-1"
            }
        }));
    })
}

fn mock_push_conflict<'a>(server: &'a MockServer) -> Mock<'a> {
    server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .body_contains("\"items\":[{");
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [],
                "conflicts": [{ "type": "sync_conflict" }],
                "sync_token": "sync-token-1"
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

fn run_command_fail(workspace: &Path, args: &[&str]) -> String {
    let mut cmd = base_command(workspace);
    cmd.args(args);
    let assert = cmd.assert().failure();
    String::from_utf8_lossy(&assert.get_output().stderr).to_string()
}

fn run_command_fail_json(workspace: &Path, args: &[&str]) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args);
    let assert = cmd.assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    serde_json::from_str(&stderr).expect("json stderr")
}

fn run_command_with_stdin(workspace: &Path, args: &[&str], stdin: &str) -> Value {
    let mut cmd = base_command(workspace);
    cmd.args(args).write_stdin(stdin);
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
