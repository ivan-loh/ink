mod commands;
mod mirror;

use clap::{Parser, Subcommand, ValueEnum};
use ink_api::StandardNotesApi;
use ink_core::{ExitCode, InkError, InkResult};
use ink_fs::{WorkspacePaths, init_workspace, load_config, resolve_profile, resolve_workspace};
use ink_store::SessionStore;
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "ink",
    version,
    about = "Workspace-first Standard Notes CLI",
    arg_required_else_help = true
)]
struct Cli {
    #[arg(long, global = true)]
    profile: Option<String>,

    #[arg(long, global = true, value_name = "PATH")]
    workspace: Option<PathBuf>,

    #[arg(long, global = true)]
    server: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, global = true)]
    no_color: bool,

    #[arg(long, global = true)]
    debug: bool,

    #[arg(long, global = true)]
    yes: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Doctor,
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    Note {
        #[command(subcommand)]
        command: NoteCommand,
    },
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    List,
    Use {
        name: String,
    },
    Set {
        #[arg(long)]
        name: Option<String>,

        #[arg(long)]
        server: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login,
    Status,
    Logout,
    Refresh,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResolveStrategy {
    Local,
    Server,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    Pull,
    Push,
    Status,
    Reset,
    Conflicts,
    Resolve {
        conflict_id: String,
        #[arg(long = "use", value_enum, default_value = "local")]
        strategy: ResolveStrategy,
    },
}

#[derive(Debug, Subcommand)]
enum NoteCommand {
    List {
        #[arg(long)]
        tag: Option<String>,
    },
    Get {
        selector: String,
    },
    New {
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        tag: Option<String>,
    },
    Edit {
        selector: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Delete {
        selector: String,
    },
    Search {
        #[arg(long)]
        query: String,
        #[arg(long)]
        fuzzy: bool,
        #[arg(long)]
        case_sensitive: bool,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offline: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TagCommand {
    List,
    Add {
        title: String,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        parent_uuid: Option<String>,
    },
    Rename {
        selector: String,
        new_title: String,
    },
    Delete {
        selector: String,
    },
    Apply {
        #[arg(long)]
        note: String,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Debug, Clone)]
struct GlobalOptions {
    profile: Option<String>,
    workspace: Option<PathBuf>,
    server: Option<String>,
    json: bool,
    yes: bool,
}

#[derive(Debug)]
struct AuthContext {
    paths: WorkspacePaths,
    profile: String,
    server: String,
    api: StandardNotesApi,
    sessions: SessionStore,
}

#[derive(Debug, Serialize)]
struct InitOutput {
    workspace: String,
    created: Vec<String>,
    updated: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProfileChangedOutput {
    profile: String,
    server: String,
}

#[derive(Debug, Serialize)]
struct SyncSummary {
    pulled_notes: usize,
    mirrored_notes: usize,
    removed_files: usize,
}

#[derive(Debug, Serialize)]
struct PushSummary {
    updated: usize,
    created: usize,
    conflicts: usize,
}

fn main() {
    let cli = Cli::parse();
    configure_logging(cli.debug, cli.json, cli.no_color);

    let globals = GlobalOptions {
        profile: cli.profile,
        workspace: cli.workspace,
        server: cli.server,
        json: cli.json,
        yes: cli.yes,
    };

    let result = run_command(cli.command, &globals);

    let exit = match result {
        Ok(code) => code,
        Err(error) => {
            render_error(&error, globals.json);
            error.exit_code()
        }
    };

    std::process::exit(exit.as_i32());
}

fn configure_logging(debug: bool, json: bool, no_color: bool) {
    let default_filter = if debug { "debug" } else { "info" };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    if json {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_target(false)
            .with_writer(std::io::stderr)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(!no_color)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    }
}

fn run_command(command: Command, globals: &GlobalOptions) -> InkResult<ExitCode> {
    match command {
        Command::Init => commands::profile::cmd_init(globals),
        Command::Doctor => commands::profile::cmd_doctor(globals),
        Command::Profile { command } => commands::profile::cmd_profile(command, globals),
        Command::Auth { command } => commands::auth::cmd_auth(command, globals),
        Command::Sync { command } => commands::sync::cmd_sync(command, globals),
        Command::Note { command } => commands::note::cmd_note(command, globals),
        Command::Tag { command } => commands::tag::cmd_tag(command, globals),
    }
}

fn with_auth_context<F>(globals: &GlobalOptions, run: F) -> InkResult<ExitCode>
where
    F: FnOnce(AuthContext) -> InkResult<ExitCode>,
{
    let target = workspace_target(globals)?;
    if !target.join(".ink").is_dir() {
        init_workspace(Some(&target), globals.server.as_deref())?;
    }

    let paths = resolve_workspace(Some(&target))?;
    let config = load_config(&paths)?;
    let resolved = resolve_profile(
        &config,
        globals.profile.as_deref(),
        globals.server.as_deref(),
    )?;
    let api = StandardNotesApi::new(&resolved.server)?;
    let sessions = SessionStore::from_workspace(&paths)?;

    run(AuthContext {
        paths,
        profile: resolved.name,
        server: resolved.server,
        api,
        sessions,
    })
}

fn normalize_unix_timestamp_seconds(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn workspace_target(globals: &GlobalOptions) -> InkResult<PathBuf> {
    if let Some(path) = &globals.workspace {
        return absolutize(path);
    }

    default_workspace_path()
}

fn default_workspace_path() -> InkResult<PathBuf> {
    let cwd = std::env::current_dir().map_err(|err| {
        InkError::io(format!(
            "failed to resolve current directory for default workspace: {err}"
        ))
    })?;

    Ok(cwd.join("sandbox").join("workspace"))
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

fn resolve_user_path(path: PathBuf, workspace_root: &Path) -> InkResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }

    let cwd = std::env::current_dir().map_err(|err| {
        InkError::io(format!(
            "failed to resolve current directory for path resolution: {err}"
        ))
    })?;
    let from_cwd = cwd.join(&path);
    if from_cwd.exists() {
        return Ok(from_cwd);
    }

    Ok(workspace_root.join(path))
}

pub(crate) fn is_uuid(input: &str) -> bool {
    uuid::Uuid::parse_str(input).is_ok()
}

fn render_error(error: &InkError, json_output: bool) {
    if json_output {
        let payload = json!({
            "ok": false,
            "error": {
                "kind": error.kind,
                "message": &error.message,
            }
        });
        let serialized = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| {
            "{\"ok\":false,\"error\":{\"kind\":\"io\",\"message\":\"failed to serialize error\"}}".to_string()
        });
        eprintln!("{serialized}");
    } else {
        eprintln!("error: {}", error.message);
    }
}

fn print_json<T: Serialize>(value: &T) -> InkResult<()> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|err| InkError::io(format!("failed to render JSON output: {err}")))?;
    println!("{rendered}");
    Ok(())
}
