use ink_core::ExitCode;
use ink_fs::{
    DEFAULT_PROFILE, init_workspace, load_config, resolve_workspace, save_config,
    set_active_profile, set_profile_server,
};

#[test]
fn init_workspace_creates_expected_layout() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result =
        init_workspace(Some(&root), Some("https://api.example.com")).expect("init workspace");

    assert!(result.paths.root.is_dir());
    assert!(result.paths.notes_dir.is_dir());
    assert!(result.paths.attachments_dir.is_dir());
    assert!(result.paths.ink_dir.is_dir());
    assert!(result.paths.sessions_dir.is_dir());
    assert!(result.paths.logs_dir.is_dir());
    assert!(result.paths.cache_dir.is_dir());
    assert!(result.paths.config_path.is_file());
    assert!(result.paths.state_db_path.is_file());
    assert!(result.paths.mirror_index_path.is_file());
    assert!(result.paths.lock_path.is_file());

    let config = load_config(&result.paths).expect("load config");
    assert_eq!(config.active_profile, DEFAULT_PROFILE);
    assert_eq!(
        config
            .profiles
            .get(DEFAULT_PROFILE)
            .map(|p| p.server.as_str()),
        Some("https://api.example.com")
    );
}

#[test]
fn resolve_workspace_fails_when_uninitialized() {
    let temp = tempfile::tempdir().expect("tempdir");

    let error =
        resolve_workspace(Some(temp.path())).expect_err("workspace should not be initialized");

    assert_eq!(error.exit_code(), ExitCode::Usage);
}

#[test]
fn profile_mutation_round_trip() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result = init_workspace(Some(&root), None).expect("init workspace");
    let mut config = load_config(&result.paths).expect("load config");

    set_profile_server(&mut config, "work", "https://work.example.com");
    set_active_profile(&mut config, "work").expect("set active profile");
    save_config(&result.paths, &config).expect("save config");

    let saved = load_config(&result.paths).expect("reload config");
    assert_eq!(saved.active_profile, "work");
    assert_eq!(
        saved
            .profiles
            .get("work")
            .map(|profile| profile.server.as_str()),
        Some("https://work.example.com")
    );
}
