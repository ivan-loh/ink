use ink_core::ExitCode;
use ink_fs::{
    DEFAULT_PROFILE, ProfileConfig, enforce_single_profile_workspace, init_workspace, load_config,
    resolve_workspace, save_config, set_active_profile, set_profile_server,
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
fn single_profile_mode_rejects_non_default_profile_mutations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result = init_workspace(Some(&root), None).expect("init workspace");
    let mut config = load_config(&result.paths).expect("load config");

    let set_server_error = set_profile_server(&mut config, "work", "https://work.example.com")
        .expect_err("non-default profile should be rejected");
    assert!(set_server_error.message.contains("only 'default' profile"));

    let set_active_error = set_active_profile(&mut config, "work")
        .expect_err("non-default profile should be rejected");
    assert!(set_active_error.message.contains("only 'default' profile"));
}

#[test]
fn single_profile_mode_rejects_workspace_with_extra_profiles() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result = init_workspace(Some(&root), None).expect("init workspace");
    let mut config = load_config(&result.paths).expect("load config");
    config.profiles.insert(
        "work".to_string(),
        ProfileConfig {
            server: "https://work.example.com".to_string(),
            bound_email: None,
        },
    );
    save_config(&result.paths, &config).expect("save config with extra profile");

    let saved = load_config(&result.paths).expect("reload config");
    let validation_error = enforce_single_profile_workspace(&saved)
        .expect_err("workspace with extra profiles should be rejected");
    assert!(validation_error.message.contains("not single-profile"));
}

#[test]
fn default_profile_server_round_trip() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result = init_workspace(Some(&root), None).expect("init workspace");
    let mut config = load_config(&result.paths).expect("load config");
    set_profile_server(&mut config, DEFAULT_PROFILE, "https://default.example.com")
        .expect("set default profile server");
    save_config(&result.paths, &config).expect("save config");

    let saved = load_config(&result.paths).expect("reload config");
    assert_eq!(saved.active_profile, DEFAULT_PROFILE);
    assert_eq!(
        saved
            .profiles
            .get(DEFAULT_PROFILE)
            .map(|profile| profile.server.as_str()),
        Some("https://default.example.com")
    );
}

#[test]
fn set_profile_server_preserves_existing_bound_email() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");

    let result = init_workspace(Some(&root), None).expect("init workspace");
    let mut config = load_config(&result.paths).expect("load config");

    config
        .profiles
        .get_mut(DEFAULT_PROFILE)
        .expect("default profile")
        .bound_email = Some("bound@example.com".to_string());

    set_profile_server(&mut config, DEFAULT_PROFILE, "https://next.example.com")
        .expect("set default profile server");

    let default_profile = config
        .profiles
        .get(DEFAULT_PROFILE)
        .expect("default profile present");
    assert_eq!(default_profile.server, "https://next.example.com");
    assert_eq!(
        default_profile.bound_email.as_deref(),
        Some("bound@example.com")
    );
}
