mod commands;
mod mirror;

use chrono::Utc;
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
    Preflight,
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
        #[arg(long)]
        fields: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        cursor: Option<String>,
    },
    Resolve {
        selector: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
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
    Upsert {
        #[arg(long)]
        title: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        append: bool,
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
        cursor: Option<String>,
        #[arg(long)]
        fields: Option<String>,
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

fn with_auth_context<F>(
    globals: &GlobalOptions,
    auto_refresh_session: bool,
    run: F,
) -> InkResult<ExitCode>
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

    let ctx = AuthContext {
        paths,
        profile: resolved.name,
        server: resolved.server,
        api,
        sessions,
    };

    if auto_refresh_session {
        refresh_session_if_needed(&ctx)?;
    }

    run(ctx)
}

fn normalize_unix_timestamp_seconds(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn refresh_session_if_needed(ctx: &AuthContext) -> InkResult<()> {
    let Some(mut stored) = ctx.sessions.load(&ctx.profile)? else {
        return Ok(());
    };

    let now = Utc::now().timestamp();
    let access_expiration = normalize_unix_timestamp_seconds(stored.session.access_expiration);
    if access_expiration > now + 60 {
        return Ok(());
    }

    let refresh_response = ctx.api.refresh_session(
        &stored.session.access_token,
        &stored.session.refresh_token,
        stored.refresh_token_cookie.as_deref(),
    )?;
    let refreshed_session = refresh_response.session.ok_or_else(|| {
        InkError::auth("session refresh response did not include updated session payload")
    })?;

    stored.session = refreshed_session;
    if refresh_response.access_token_cookie.is_some() {
        stored.access_token_cookie = refresh_response.access_token_cookie;
    }
    if refresh_response.refresh_token_cookie.is_some() {
        stored.refresh_token_cookie = refresh_response.refresh_token_cookie;
    }
    stored.refreshed_at = Some(Utc::now().to_rfc3339());
    ctx.sessions.save(&ctx.profile, &stored)?;

    let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
    state.mark_auth_ok();
    state.last_sync_status = Some("session refreshed".to_string());
    ctx.sessions.save_app_state(&ctx.profile, &state)?;

    Ok(())
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
        let retry_after_sec = parse_marker_u64(&error.message, "[retry_after_seconds=");
        let machine = machine_error_details(error);
        let payload = json!({
            "ok": false,
            "contract_version": "v1",
            "meta": {
                "timestamp": Utc::now().to_rfc3339(),
            },
            "error": {
                "kind": error.kind,
                "code": machine.code,
                "message": &error.message,
                "retryable": machine.retryable,
                "retry_after_sec": retry_after_sec,
                "hint": machine.hint,
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
    let mut payload = serde_json::to_value(value)
        .map_err(|err| InkError::io(format!("failed to encode JSON output payload: {err}")))?;

    if let Some(map) = payload.as_object_mut()
        && map.contains_key("ok")
    {
        map.entry("contract_version".to_string())
            .or_insert_with(|| json!("v1"));
        let meta = map.entry("meta".to_string()).or_insert_with(|| json!({}));
        if let Some(meta_map) = meta.as_object_mut() {
            meta_map
                .entry("timestamp".to_string())
                .or_insert_with(|| json!(Utc::now().to_rfc3339()));
        }
    }

    let rendered = serde_json::to_string_pretty(&payload)
        .map_err(|err| InkError::io(format!("failed to render JSON output: {err}")))?;
    println!("{rendered}");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct MachineErrorDetails {
    code: &'static str,
    retryable: bool,
    hint: &'static str,
}

fn machine_error_details(error: &InkError) -> MachineErrorDetails {
    let status = parse_marker_u64(&error.message, "[http_status=");
    match error.kind {
        ink_core::ErrorKind::Usage => {
            if error.message.contains("multiple notes matched")
                || error.message.contains("multiple tags matched")
            {
                MachineErrorDetails {
                    code: "USAGE_SELECTOR_AMBIGUOUS",
                    retryable: false,
                    hint: "Use UUID selector instead of title.",
                }
            } else if error.message.contains("no note found")
                || error.message.contains("no tag found")
            {
                MachineErrorDetails {
                    code: "USAGE_SELECTOR_NOT_FOUND",
                    retryable: false,
                    hint: "Run list command first and select by UUID.",
                }
            } else {
                MachineErrorDetails {
                    code: "USAGE_INVALID_INPUT",
                    retryable: false,
                    hint: "Check command flags and required arguments.",
                }
            }
        }
        ink_core::ErrorKind::Auth => {
            if error.message.contains("missing credentials") {
                MachineErrorDetails {
                    code: "AUTH_MISSING_CREDENTIALS",
                    retryable: false,
                    hint: "Set SN_EMAIL and SN_PASSWORD in environment or .env.",
                }
            } else if error.message.contains("no active session") {
                MachineErrorDetails {
                    code: "AUTH_NO_ACTIVE_SESSION",
                    retryable: false,
                    hint: "Run `ink auth login` first.",
                }
            } else if status == Some(401) {
                MachineErrorDetails {
                    code: "AUTH_UNAUTHORIZED",
                    retryable: false,
                    hint: "Re-authenticate with `ink auth login`.",
                }
            } else {
                MachineErrorDetails {
                    code: "AUTH_ERROR",
                    retryable: false,
                    hint: "Check authentication state with `ink auth status --json`.",
                }
            }
        }
        ink_core::ErrorKind::Sync => {
            if status == Some(429) {
                MachineErrorDetails {
                    code: "SYNC_RATE_LIMITED",
                    retryable: true,
                    hint: "Retry after `retry_after_sec` when present.",
                }
            } else if matches!(status, Some(code) if code >= 500) {
                MachineErrorDetails {
                    code: "SYNC_SERVER_ERROR",
                    retryable: true,
                    hint: "Retry with backoff.",
                }
            } else if error.message.contains("conflict") || error.message.contains("conflicts") {
                MachineErrorDetails {
                    code: "SYNC_CONFLICT",
                    retryable: false,
                    hint: "Inspect and resolve with `ink sync conflicts` / `ink sync resolve`.",
                }
            } else {
                MachineErrorDetails {
                    code: "SYNC_ERROR",
                    retryable: true,
                    hint: "Retry or run `ink sync status --json` for state details.",
                }
            }
        }
        ink_core::ErrorKind::Crypto => MachineErrorDetails {
            code: "CRYPTO_ERROR",
            retryable: false,
            hint: "Verify account credentials and key params, then re-login.",
        },
        ink_core::ErrorKind::Io => {
            if error.message.contains("state database") && error.message.contains("corrupted") {
                MachineErrorDetails {
                    code: "IO_STATE_DB_CORRUPT",
                    retryable: false,
                    hint: "Remove .ink/state.db and run `ink sync pull` to rebuild local state.",
                }
            } else {
                MachineErrorDetails {
                    code: "IO_ERROR",
                    retryable: false,
                    hint: "Check filesystem permissions and workspace path.",
                }
            }
        }
    }
}

fn parse_marker_u64(message: &str, marker: &str) -> Option<u64> {
    let start = message.find(marker)? + marker.len();
    let tail = &message[start..];
    let end = tail.find(']')?;
    tail[..end].parse::<u64>().ok()
}
