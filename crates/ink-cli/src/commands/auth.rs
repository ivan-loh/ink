use chrono::Utc;
use ink_api::{RefreshSessionRequest, SignInRequest};
use ink_core::{ExitCode, InkError, InkResult};
use ink_crypto::{derive_root_credentials_004, normalize_email};
use ink_fs::{load_config, profile_bound_email, save_config, set_profile_bound_email};
use ink_store::{StoredSession, resolve_env_credentials};
use serde_json::json;

use crate::{
    AuthCommand, AuthContext, GlobalOptions, mirror::clear_local_mirror,
    normalize_unix_timestamp_seconds, print_json, with_auth_context,
};

pub(crate) fn cmd_auth(command: AuthCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    with_auth_context(globals, false, |ctx| match command {
        AuthCommand::Login { rebind_account } => {
            let credentials = resolve_env_credentials(&ctx.paths.root)?.ok_or_else(|| {
                InkError::auth(
                    "missing credentials; set SN_EMAIL and SN_PASSWORD in environment or .env",
                )
            })?;
            let normalized_email = normalize_email(&credentials.email);

            enforce_profile_account_binding(&ctx, globals, &normalized_email, rebind_account)?;

            let stored =
                login_with_email_password(&ctx, &credentials.email, &credentials.password)?;

            ctx.sessions.save(&ctx.profile, &stored)?;

            let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
            state.mark_auth_ok();
            state.last_sync_status = Some("authenticated".to_string());
            ctx.sessions.save_app_state(&ctx.profile, &state)?;
            bind_profile_email(&ctx, &stored.email)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "profile": ctx.profile,
                        "server": ctx.server,
                        "email": stored.email,
                        "readonly_access": stored.session.readonly_access,
                        "access_expiration": stored.session.access_expiration,
                        "refresh_expiration": stored.session.refresh_expiration,
                    }
                }))?;
            } else {
                println!("Authenticated with {}", ctx.server);
                println!("Profile: {}", ctx.profile);
                println!("Email: {}", stored.email);
                println!("Session saved: {}", ctx.paths.state_db_path.display());
            }

            Ok(ExitCode::Success)
        }
        AuthCommand::Status => {
            let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
            let stored = ctx.sessions.load(&ctx.profile)?;

            let Some(mut stored) = stored else {
                if globals.json {
                    print_json(&json!({
                        "ok": false,
                        "result": {
                            "profile": ctx.profile,
                            "server": ctx.server,
                            "authenticated": false,
                            "reason": "no stored session",
                            "last_auth_at": state.last_auth_at,
                        }
                    }))?;
                } else {
                    println!("Server: {}", ctx.server);
                    println!("Profile: {}", ctx.profile);
                    println!("Authenticated: no");
                    println!("Reason: no stored session");
                }
                return Ok(ExitCode::Auth);
            };

            let mut refreshed = false;
            let now = Utc::now().timestamp();
            let access_expiration =
                normalize_unix_timestamp_seconds(stored.session.access_expiration);
            if access_expiration <= now + 60 {
                let refresh_request = RefreshSessionRequest::new(
                    &stored.session.access_token,
                    &stored.session.refresh_token,
                )
                .with_access_token_cookie(stored.access_token_cookie.as_deref())
                .with_refresh_token_cookie(stored.refresh_token_cookie.as_deref())
                .with_preferred_mode(stored.refresh_transport_mode);
                let refresh_response = ctx.api.refresh_session(&refresh_request)?;
                let refreshed_session = refresh_response.session.ok_or_else(|| {
                    InkError::auth(
                        "session refresh response did not include updated session payload",
                    )
                })?;

                stored = ctx.sessions.mark_refreshed(
                    &ctx.profile,
                    refreshed_session,
                    refresh_response.access_token_cookie,
                    refresh_response.refresh_token_cookie,
                    refresh_response.mode_used,
                )?;
                state.mark_auth_ok();
                state.last_sync_status = Some("session refreshed".to_string());
                ctx.sessions.save_app_state(&ctx.profile, &state)?;
                refreshed = true;
            }

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "profile": ctx.profile,
                        "server": ctx.server,
                        "authenticated": true,
                        "email": stored.email,
                        "readonly_access": stored.session.readonly_access,
                        "access_expiration": stored.session.access_expiration,
                        "refresh_expiration": stored.session.refresh_expiration,
                        "refreshed": refreshed,
                        "last_auth_at": state.last_auth_at,
                    }
                }))?;
            } else {
                println!("Server: {}", ctx.server);
                println!("Profile: {}", ctx.profile);
                println!("Authenticated: yes");
                println!("Email: {}", stored.email);
                println!(
                    "Session refreshed: {}",
                    if refreshed { "yes" } else { "no" }
                );
                println!("Access expiration: {}", stored.session.access_expiration);
                println!("Refresh expiration: {}", stored.session.refresh_expiration);
            }

            Ok(ExitCode::Success)
        }
        AuthCommand::Logout { purge } => {
            if purge && !globals.yes {
                return Err(InkError::usage(
                    "auth logout --purge is destructive; rerun with --yes",
                ));
            }

            let mut remote_sign_out = false;
            let mut remote_warning = None;
            if let Some(stored) = ctx.sessions.load(&ctx.profile)? {
                match ctx.api.sign_out(&stored.session.access_token) {
                    Ok(_) => {
                        remote_sign_out = true;
                    }
                    Err(err) => {
                        remote_warning = Some(err.message);
                    }
                }
            }

            let mut removed_mirror_files = None;
            let mut removed_mirror_dir: Option<String> = None;
            if purge {
                ctx.sessions.clear_profile_state(&ctx.profile)?;
                let mirror = clear_local_mirror(&ctx.paths, &ctx.profile)?;
                removed_mirror_files = Some(mirror.removed_files);
                removed_mirror_dir = Some(mirror.notes_dir);
            } else {
                ctx.sessions.remove(&ctx.profile)?;

                let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
                state.last_auth_at = None;
                state.last_sync_status = Some("logged out".to_string());
                ctx.sessions.save_app_state(&ctx.profile, &state)?;
            }

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "profile": ctx.profile,
                        "server": ctx.server,
                        "remote_sign_out": remote_sign_out,
                        "warning": remote_warning,
                        "purged_local_state": purge,
                        "removed_mirror_files": removed_mirror_files,
                    }
                }))?;
            } else {
                if purge {
                    println!("Local profile state purged for '{}'.", ctx.profile);
                    println!(
                        "Removed {} mirrored note file(s) from {}.",
                        removed_mirror_files.unwrap_or(0),
                        removed_mirror_dir.unwrap_or_else(|| ctx
                            .paths
                            .notes_dir
                            .display()
                            .to_string())
                    );
                } else {
                    println!("Local session removed for profile '{}'.", ctx.profile);
                }
                if remote_sign_out {
                    println!("Server session invalidated.");
                } else if let Some(warning) = remote_warning {
                    println!("Server sign-out warning: {warning}");
                }
            }

            Ok(ExitCode::Success)
        }
        AuthCommand::Refresh => {
            let stored = ctx.sessions.load(&ctx.profile)?.ok_or_else(|| {
                InkError::auth(format!(
                    "no active session for profile '{}'; run `ink auth login` first",
                    ctx.profile
                ))
            })?;

            let refresh_request = RefreshSessionRequest::new(
                &stored.session.access_token,
                &stored.session.refresh_token,
            )
            .with_access_token_cookie(stored.access_token_cookie.as_deref())
            .with_refresh_token_cookie(stored.refresh_token_cookie.as_deref())
            .with_preferred_mode(stored.refresh_transport_mode);
            let refresh_response = ctx.api.refresh_session(&refresh_request)?;
            let refreshed = refresh_response.session.ok_or_else(|| {
                InkError::auth("session refresh response did not include session payload")
            })?;

            let updated = ctx.sessions.mark_refreshed(
                &ctx.profile,
                refreshed,
                refresh_response.access_token_cookie,
                refresh_response.refresh_token_cookie,
                refresh_response.mode_used,
            )?;

            let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
            state.mark_auth_ok();
            state.last_sync_status = Some("session refreshed".to_string());
            ctx.sessions.save_app_state(&ctx.profile, &state)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "profile": ctx.profile,
                        "server": ctx.server,
                        "email": updated.email,
                        "readonly_access": updated.session.readonly_access,
                        "access_expiration": updated.session.access_expiration,
                        "refresh_expiration": updated.session.refresh_expiration,
                        "refreshed_at": updated.refreshed_at,
                        "reauthenticated": false,
                    }
                }))?;
            } else {
                println!("Session refreshed for profile '{}'.", ctx.profile);
                println!("Access expiration: {}", updated.session.access_expiration);
                println!("Refresh expiration: {}", updated.session.refresh_expiration);
            }

            Ok(ExitCode::Success)
        }
        AuthCommand::Preflight => {
            let stored = ctx.sessions.load(&ctx.profile)?;
            let env_credentials_available = resolve_env_credentials(&ctx.paths.root)?.is_some();

            let (authenticated, email, access_expiration, refresh_expiration, needs_refresh) =
                if let Some(stored) = stored {
                    let now = Utc::now().timestamp();
                    let access_expiration =
                        normalize_unix_timestamp_seconds(stored.session.access_expiration);
                    (
                        true,
                        Some(stored.email),
                        Some(stored.session.access_expiration),
                        Some(stored.session.refresh_expiration),
                        access_expiration <= now + 60,
                    )
                } else {
                    (false, None, None, None, false)
                };

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "profile": ctx.profile,
                        "server": ctx.server,
                        "authenticated": authenticated,
                        "needs_login": !authenticated,
                        "needs_refresh": needs_refresh,
                        "email": email,
                        "access_expiration": access_expiration,
                        "refresh_expiration": refresh_expiration,
                        "env_credentials_available": env_credentials_available,
                    }
                }))?;
            } else {
                println!("Server: {}", ctx.server);
                println!("Profile: {}", ctx.profile);
                println!(
                    "Authenticated: {}",
                    if authenticated { "yes" } else { "no" }
                );
                println!("Needs login: {}", if authenticated { "no" } else { "yes" });
                println!(
                    "Needs refresh: {}",
                    if needs_refresh { "yes" } else { "no" }
                );
                println!(
                    "Env credentials available: {}",
                    if env_credentials_available {
                        "yes"
                    } else {
                        "no"
                    }
                );
            }

            Ok(ExitCode::Success)
        }
    })
}

fn login_with_email_password(
    ctx: &AuthContext,
    email: &str,
    password: &str,
) -> InkResult<StoredSession> {
    let normalized_email = normalize_email(email);
    let login_params = ctx.api.get_login_params(&normalized_email)?;
    let identifier = login_params
        .key_params
        .identifier
        .clone()
        .or(login_params.key_params.email.clone())
        .unwrap_or_else(|| normalized_email.clone());
    let pw_nonce = login_params.key_params.pw_nonce.clone().ok_or_else(|| {
        InkError::auth("login params response did not include pw_nonce for protocol 004")
    })?;
    let derived = derive_root_credentials_004(password, &identifier, &pw_nonce)?;

    let sign_in = ctx.api.sign_in(&SignInRequest {
        email: normalized_email.clone(),
        server_password: derived.server_password,
        code_verifier: login_params.code_verifier,
        ephemeral: false,
    })?;

    let session = sign_in
        .session
        .ok_or_else(|| InkError::auth("login response did not include session tokens"))?;

    Ok(StoredSession {
        profile: ctx.profile.clone(),
        server: ctx.server.clone(),
        email: normalized_email,
        authenticated_at: Utc::now().to_rfc3339(),
        refreshed_at: None,
        refresh_transport_mode: None,
        refresh_transport_confirmed_at: None,
        refresh_transport_last_error: None,
        master_key: Some(derived.master_key),
        session,
        access_token_cookie: sign_in.access_token_cookie,
        refresh_token_cookie: sign_in.refresh_token_cookie,
        user: sign_in.user,
        key_params: sign_in.key_params.or(Some(login_params.key_params)),
    })
}

fn enforce_profile_account_binding(
    ctx: &AuthContext,
    globals: &GlobalOptions,
    normalized_email: &str,
    rebind_account: bool,
) -> InkResult<()> {
    let mut config = load_config(&ctx.paths)?;
    let Some(bound_email) = profile_bound_email(&config, &ctx.profile) else {
        return Ok(());
    };
    let normalized_bound_email = normalize_email(bound_email);
    if normalized_bound_email == normalized_email {
        return Ok(());
    }

    if !rebind_account {
        return Err(InkError::usage(format!(
            "profile '{}' in workspace '{}' is bound to '{}'; refusing login as '{}'. Use a different profile/workspace, or rerun with `ink --yes auth login --rebind-account` to intentionally switch this profile.",
            ctx.profile,
            ctx.paths.root.display(),
            bound_email,
            normalized_email
        )));
    }
    if !globals.yes {
        return Err(InkError::usage(
            "auth login --rebind-account is destructive for local profile state; rerun with --yes",
        ));
    }

    ctx.sessions.clear_profile_state(&ctx.profile)?;
    clear_local_mirror(&ctx.paths, &ctx.profile)?;
    set_profile_bound_email(
        &mut config,
        &ctx.profile,
        Some(normalized_email.to_string()),
    )?;
    save_config(&ctx.paths, &config)?;
    Ok(())
}

fn bind_profile_email(ctx: &AuthContext, email: &str) -> InkResult<()> {
    let normalized_email = normalize_email(email);
    let mut config = load_config(&ctx.paths)?;
    let already_bound = profile_bound_email(&config, &ctx.profile)
        .map(normalize_email)
        .as_deref()
        == Some(normalized_email.as_str());
    if already_bound {
        return Ok(());
    }

    set_profile_bound_email(&mut config, &ctx.profile, Some(normalized_email))?;
    save_config(&ctx.paths, &config)
}
