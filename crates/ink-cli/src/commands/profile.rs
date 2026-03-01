use ink_core::{ExitCode, InkResult};
use ink_fs::{
    init_workspace, list_profiles, load_config, resolve_profile, resolve_workspace, run_doctor,
    save_config, set_active_profile, set_profile_server,
};
use ink_store::{SessionStore, resolve_env_credentials};
use serde_json::json;

use crate::{
    GlobalOptions, InitOutput, ProfileChangedOutput, ProfileCommand, print_json, workspace_target,
};

pub(crate) fn cmd_init(globals: &GlobalOptions) -> InkResult<ExitCode> {
    let target = workspace_target(globals)?;
    let result = init_workspace(Some(&target), globals.server.as_deref())?;

    let output = InitOutput {
        workspace: result.paths.root.display().to_string(),
        created: result
            .created
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        updated: result
            .updated
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    };

    if globals.json {
        print_json(&json!({"ok": true, "result": output}))?;
    } else {
        println!("Workspace initialized: {}", output.workspace);
        println!("Created:");
        if output.created.is_empty() {
            println!("  - none");
        } else {
            for path in &output.created {
                println!("  - {path}");
            }
        }

        if output.updated.is_empty() {
            println!("Updated: none");
        } else {
            println!("Updated:");
            for path in &output.updated {
                println!("  - {path}");
            }
        }
    }

    Ok(ExitCode::Success)
}

pub(crate) fn cmd_doctor(globals: &GlobalOptions) -> InkResult<ExitCode> {
    let target = workspace_target(globals)?;
    let paths = resolve_workspace(Some(&target))?;

    let report = run_doctor(
        &paths,
        globals.profile.as_deref(),
        globals.server.as_deref(),
    )?;

    let session_store = SessionStore::from_workspace(&paths)?;
    let creds_ok = resolve_env_credentials(&paths.root)?.is_some();
    let session_ok = if let Some(profile) = report.active_profile.as_deref() {
        session_store.load(profile)?.is_some()
    } else {
        false
    };
    let auth_ready = creds_ok || session_ok;

    if globals.json {
        print_json(&json!({
            "ok": report.healthy && auth_ready,
            "result": {
                "workspace": report.workspace,
                "healthy": report.healthy,
                "checks": report.checks,
                "active_profile": report.active_profile,
                "server": report.server,
                "auth": {
                    "credentials": creds_ok,
                    "session": session_ok,
                    "ready": auth_ready
                },
                "runtime": {
                    "native_only": true
                }
            }
        }))?;
    } else {
        println!("Workspace: {}", report.workspace);
        println!(
            "Health: {}",
            if report.healthy {
                "healthy"
            } else {
                "degraded"
            }
        );

        for check in &report.checks {
            let prefix = if check.ok { "OK" } else { "FAIL" };
            println!("[{}] {} -> {}", prefix, check.name, check.details);
        }

        println!(
            "[{}] credentials -> {}",
            if creds_ok { "OK" } else { "FAIL" },
            if creds_ok {
                "SN_EMAIL/SN_PASSWORD resolved via env/.env"
            } else {
                "missing SN_EMAIL/SN_PASSWORD"
            }
        );
        println!(
            "[{}] session -> {}",
            if session_ok { "OK" } else { "FAIL" },
            if session_ok {
                "active profile session file present"
            } else {
                "no session file for active profile"
            }
        );
        println!(
            "[{}] auth_ready -> {}",
            if auth_ready { "OK" } else { "FAIL" },
            if auth_ready {
                "credentials or stored session available"
            } else {
                "missing both credentials and stored session"
            }
        );
    }

    Ok(if report.healthy && auth_ready {
        ExitCode::Success
    } else {
        ExitCode::Io
    })
}

pub(crate) fn cmd_profile(command: ProfileCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    let target = workspace_target(globals)?;
    if !target.join(".ink").is_dir() {
        init_workspace(Some(&target), globals.server.as_deref())?;
    }

    let paths = resolve_workspace(Some(&target))?;
    let mut config = load_config(&paths)?;

    match command {
        ProfileCommand::List => {
            let profiles = list_profiles(&config);
            if globals.json {
                print_json(
                    &json!({"ok": true, "result": {"active_profile": config.active_profile, "profiles": profiles}}),
                )?;
            } else {
                println!("Active profile: {}", config.active_profile);
                for profile in profiles {
                    let marker = if profile.active { "*" } else { " " };
                    println!("{} {} ({})", marker, profile.name, profile.server);
                }
            }

            Ok(ExitCode::Success)
        }
        ProfileCommand::Use { name } => {
            set_active_profile(&mut config, &name)?;
            save_config(&paths, &config)?;

            let resolved = resolve_profile(&config, Some(&name), globals.server.as_deref())?;
            let output = ProfileChangedOutput {
                profile: resolved.name,
                server: resolved.server,
            };

            if globals.json {
                print_json(&json!({"ok": true, "result": output}))?;
            } else {
                println!(
                    "Active profile set to '{}' ({})",
                    output.profile, output.server
                );
            }

            Ok(ExitCode::Success)
        }
        ProfileCommand::Set { name, server } => {
            let target_profile = name.unwrap_or_else(|| config.active_profile.clone());
            set_profile_server(&mut config, &target_profile, &server);
            save_config(&paths, &config)?;

            let resolved = resolve_profile(&config, Some(&target_profile), None)?;
            let output = ProfileChangedOutput {
                profile: resolved.name,
                server: resolved.server,
            };

            if globals.json {
                print_json(&json!({"ok": true, "result": output}))?;
            } else {
                println!(
                    "Profile '{}' server set to {}",
                    output.profile, output.server
                );
            }

            Ok(ExitCode::Success)
        }
    }
}
