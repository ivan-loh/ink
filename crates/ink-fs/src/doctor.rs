use crate::config::{load_config, resolve_profile};
use crate::workspace::WorkspacePaths;
use ink_core::InkResult;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub ok: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub workspace: String,
    pub healthy: bool,
    pub checks: Vec<DoctorCheck>,
    pub active_profile: Option<String>,
    pub server: Option<String>,
}

pub fn run_doctor(
    paths: &WorkspacePaths,
    profile_override: Option<&str>,
    server_override: Option<&str>,
) -> InkResult<DoctorReport> {
    let mut checks = vec![
        DoctorCheck {
            name: "workspace_root".to_string(),
            ok: paths.root.is_dir(),
            details: paths.root.display().to_string(),
        },
        DoctorCheck {
            name: "ink_directory".to_string(),
            ok: paths.ink_dir.is_dir(),
            details: paths.ink_dir.display().to_string(),
        },
        DoctorCheck {
            name: "notes_directory".to_string(),
            ok: paths.notes_dir.is_dir(),
            details: paths.notes_dir.display().to_string(),
        },
        DoctorCheck {
            name: "attachments_directory".to_string(),
            ok: paths.attachments_dir.is_dir(),
            details: paths.attachments_dir.display().to_string(),
        },
        DoctorCheck {
            name: "sessions_directory".to_string(),
            ok: paths.sessions_dir.is_dir(),
            details: paths.sessions_dir.display().to_string(),
        },
        DoctorCheck {
            name: "logs_directory".to_string(),
            ok: paths.logs_dir.is_dir(),
            details: paths.logs_dir.display().to_string(),
        },
        DoctorCheck {
            name: "cache_directory".to_string(),
            ok: paths.cache_dir.is_dir(),
            details: paths.cache_dir.display().to_string(),
        },
        DoctorCheck {
            name: "config_file".to_string(),
            ok: paths.config_path.is_file(),
            details: paths.config_path.display().to_string(),
        },
        DoctorCheck {
            name: "state_db_file".to_string(),
            ok: paths.state_db_path.is_file(),
            details: paths.state_db_path.display().to_string(),
        },
        DoctorCheck {
            name: "mirror_index_file".to_string(),
            ok: paths.mirror_index_path.is_file(),
            details: paths.mirror_index_path.display().to_string(),
        },
        DoctorCheck {
            name: "lock_file".to_string(),
            ok: paths.lock_path.is_file(),
            details: paths.lock_path.display().to_string(),
        },
    ];

    let mut active_profile = None;
    let mut server = None;

    if paths.config_path.is_file() {
        match load_config(paths) {
            Ok(config) => match resolve_profile(&config, profile_override, server_override) {
                Ok(resolved) => {
                    active_profile = Some(resolved.name.clone());
                    server = Some(resolved.server.clone());
                    checks.push(DoctorCheck {
                        name: "active_profile".to_string(),
                        ok: true,
                        details: format!("{} ({})", resolved.name, resolved.server),
                    });
                }
                Err(err) => checks.push(DoctorCheck {
                    name: "active_profile".to_string(),
                    ok: false,
                    details: err.message,
                }),
            },
            Err(err) => checks.push(DoctorCheck {
                name: "config_parse".to_string(),
                ok: false,
                details: err.message,
            }),
        }
    }

    let healthy = checks.iter().all(|check| check.ok);

    Ok(DoctorReport {
        workspace: paths.root.display().to_string(),
        healthy,
        checks,
        active_profile,
        server,
    })
}
