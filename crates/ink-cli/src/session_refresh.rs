use chrono::Utc;
use ink_core::{InkError, InkResult};
use ink_store::StoredSession;
use ink_sync::refresh_stored_session;

use crate::{AuthContext, normalize_unix_timestamp_seconds};

pub(crate) fn session_needs_refresh(
    stored: &StoredSession,
    now_unix_seconds: i64,
    refresh_leeway_seconds: i64,
) -> bool {
    let access_expiration = normalize_unix_timestamp_seconds(stored.session.access_expiration);
    access_expiration <= now_unix_seconds + refresh_leeway_seconds
}

pub(crate) fn refresh_session_if_needed(
    ctx: &AuthContext,
    refresh_leeway_seconds: i64,
) -> InkResult<bool> {
    let Some(stored) = ctx.sessions.load(&ctx.profile)? else {
        return Ok(false);
    };

    if !session_needs_refresh(&stored, Utc::now().timestamp(), refresh_leeway_seconds) {
        return Ok(false);
    }

    let _ = refresh_session_from_stored(ctx, &stored)?;
    Ok(true)
}

pub(crate) fn refresh_session(ctx: &AuthContext) -> InkResult<StoredSession> {
    let stored = ctx.sessions.load(&ctx.profile)?.ok_or_else(|| {
        InkError::auth(format!(
            "no active session for profile '{}'; run `ink auth login` first",
            ctx.profile
        ))
    })?;
    refresh_session_from_stored(ctx, &stored)
}

pub(crate) fn refresh_session_from_stored(
    ctx: &AuthContext,
    stored: &StoredSession,
) -> InkResult<StoredSession> {
    let updated = refresh_stored_session(&ctx.api, &ctx.sessions, &ctx.profile, stored)?;

    let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
    state.mark_auth_ok();
    state.last_sync_status = Some("session refreshed".to_string());
    ctx.sessions.save_app_state(&ctx.profile, &state)?;

    Ok(updated)
}
