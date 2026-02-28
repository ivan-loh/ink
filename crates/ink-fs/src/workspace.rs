use crate::config::{DEFAULT_SERVER_URL, WorkspaceConfig, load_config, save_config};
use ink_core::{InkError, InkResult};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WorkspacePaths {
    pub root: PathBuf,
    pub notes_dir: PathBuf,
    pub attachments_dir: PathBuf,
    pub ink_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub config_path: PathBuf,
    pub state_db_path: PathBuf,
    pub mirror_index_path: PathBuf,
    pub sessions_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub lock_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WorkspaceInitResult {
    pub paths: WorkspacePaths,
    pub created: Vec<PathBuf>,
    pub updated: Vec<PathBuf>,
}

impl WorkspacePaths {
    pub fn from_root(root: PathBuf) -> Self {
        let ink_dir = root.join(".ink");

        Self {
            notes_dir: root.join("notes"),
            attachments_dir: root.join("attachments"),
            config_path: ink_dir.join("config.toml"),
            state_db_path: ink_dir.join("state.db"),
            mirror_index_path: ink_dir.join("mirror-index.json"),
            sessions_dir: ink_dir.join("sessions"),
            logs_dir: ink_dir.join("logs"),
            cache_dir: ink_dir.join("cache"),
            lock_path: ink_dir.join("lock"),
            root,
            ink_dir,
        }
    }
}

pub fn init_workspace(
    target: Option<&Path>,
    server: Option<&str>,
) -> InkResult<WorkspaceInitResult> {
    let root = match target {
        Some(path) => absolutize(path)?,
        None => std::env::current_dir().map_err(|err| {
            InkError::io(format!(
                "failed to resolve current directory for init: {err}"
            ))
        })?,
    };

    let paths = WorkspacePaths::from_root(root);
    let mut created = Vec::new();
    let updated = Vec::new();

    ensure_dir(&paths.root, &mut created)?;
    ensure_dir(&paths.notes_dir, &mut created)?;
    ensure_dir(&paths.attachments_dir, &mut created)?;
    ensure_dir(&paths.ink_dir, &mut created)?;
    ensure_dir(&paths.sessions_dir, &mut created)?;
    ensure_dir(&paths.logs_dir, &mut created)?;
    ensure_dir(&paths.cache_dir, &mut created)?;

    ensure_file(&paths.state_db_path, &mut created)?;
    ensure_file(&paths.mirror_index_path, &mut created)?;
    ensure_file(&paths.lock_path, &mut created)?;

    if paths.config_path.exists() {
        let _ = load_config(&paths)?;
    } else {
        let default_server = server.unwrap_or(DEFAULT_SERVER_URL);
        let config = WorkspaceConfig::with_default_server(default_server);
        save_config(&paths, &config)?;
        created.push(paths.config_path.clone());
    }

    Ok(WorkspaceInitResult {
        paths,
        created,
        updated,
    })
}

pub fn resolve_workspace(explicit: Option<&Path>) -> InkResult<WorkspacePaths> {
    let root = match explicit {
        Some(path) => absolutize(path)?,
        None => std::env::current_dir().map_err(|err| {
            InkError::io(format!(
                "failed to resolve current directory for workspace lookup: {err}"
            ))
        })?,
    };

    let paths = WorkspacePaths::from_root(root);
    if !paths.ink_dir.is_dir() {
        let root_display = paths.root.display();
        return Err(InkError::usage(format!(
            "workspace is not initialized at '{root_display}'; run `ink init --workspace {root_display}` first"
        )));
    }

    Ok(paths)
}

fn absolutize(path: &Path) -> InkResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let cwd = std::env::current_dir().map_err(|err| {
        InkError::io(format!(
            "failed to resolve current directory for path: {err}"
        ))
    })?;

    Ok(cwd.join(path))
}

fn ensure_dir(path: &Path, created: &mut Vec<PathBuf>) -> InkResult<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(InkError::io(format!(
                "expected '{}' to be a directory",
                path.display()
            )));
        }
        return Ok(());
    }

    fs::create_dir_all(path).map_err(|err| {
        InkError::io(format!(
            "failed to create directory '{}': {}",
            path.display(),
            err
        ))
    })?;
    created.push(path.to_path_buf());
    Ok(())
}

fn ensure_file(path: &Path, created: &mut Vec<PathBuf>) -> InkResult<()> {
    if path.exists() {
        if !path.is_file() {
            return Err(InkError::io(format!(
                "expected '{}' to be a file",
                path.display()
            )));
        }
        return Ok(());
    }

    fs::write(path, []).map_err(|err| {
        InkError::io(format!(
            "failed to create file '{}': {}",
            path.display(),
            err
        ))
    })?;
    created.push(path.to_path_buf());
    Ok(())
}
