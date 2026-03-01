use chrono::Utc;
use ink_core::{ExitCode, InkError, InkResult};
use ink_crypto::{derive_root_credentials_004, normalize_email};
use ink_store::{AppState, StoredSession, SyncConflict, resolve_env_credentials};
use ink_sync::{DecryptedNote, SyncEngine};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::mirror::{
    LocalMirrorNote, MirrorNote, find_entry_by_uuid, load_index, load_index as load_mirror_index,
    pull_to_mirror, scan_local_mirror,
};
use crate::{
    AuthContext, GlobalOptions, PushSummary, ResolveStrategy, SyncCommand, SyncSummary, print_json,
    with_auth_context,
};

pub(crate) fn cmd_sync(command: SyncCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    with_auth_context(globals, true, |ctx| match command {
        SyncCommand::Pull => {
            let summary = native_pull(&ctx, true)?;
            if globals.json {
                print_json(&json!({"ok": true, "result": summary}))?;
            } else {
                println!("Pulled {} notes.", summary.pulled_notes);
                println!(
                    "Mirrored {} notes into {}.",
                    summary.mirrored_notes,
                    ctx.paths.notes_dir.display()
                );
                if summary.removed_files > 0 {
                    println!("Removed {} stale mirrored files.", summary.removed_files);
                }
            }

            Ok(ExitCode::Success)
        }
        SyncCommand::Push => {
            let summary = native_push(&ctx, None, None)?;
            if globals.json {
                print_json(&json!({"ok": summary.conflicts == 0, "result": summary}))?;
            } else {
                println!(
                    "Push completed: {} updated, {} created, {} conflicts.",
                    summary.updated, summary.created, summary.conflicts
                );
            }

            Ok(if summary.conflicts == 0 {
                ExitCode::Success
            } else {
                ExitCode::Sync
            })
        }
        SyncCommand::Status => {
            let state = ctx.sessions.load_app_state(&ctx.profile)?;
            let index = load_mirror_index(&ctx.paths)?;
            let sync_state = ctx.sessions.load_sync_state(&ctx.profile)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "last_auth_at": state.last_auth_at,
                        "last_pull_at": state.last_pull_at,
                        "last_push_at": state.last_push_at,
                        "last_sync_at": state.last_sync_at,
                        "last_sync_status": state.last_sync_status,
                        "mirrored_notes": index.entries.len(),
                        "cached_items": sync_state.item_count,
                        "sync_token": sync_state.sync_token,
                        "conflicts": state.conflicts,
                    }
                }))?;
            } else {
                println!(
                    "Last pull: {}",
                    state.last_pull_at.unwrap_or_else(|| "never".to_string())
                );
                println!(
                    "Last push: {}",
                    state.last_push_at.unwrap_or_else(|| "never".to_string())
                );
                println!(
                    "Last sync: {}",
                    state.last_sync_at.unwrap_or_else(|| "never".to_string())
                );
                println!(
                    "Last status: {}",
                    state
                        .last_sync_status
                        .unwrap_or_else(|| "unknown".to_string())
                );
                println!("Mirrored notes: {}", index.entries.len());
                println!("Cached items: {}", sync_state.item_count);
                println!("Sync token: {}", sync_state.sync_token.unwrap_or_default());
                println!("Pending conflicts: {}", state.conflicts.len());
            }

            Ok(ExitCode::Success)
        }
        SyncCommand::Reset => {
            if !globals.yes {
                return Err(InkError::usage(
                    "sync reset is destructive for local cache; rerun with --yes",
                ));
            }

            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            engine.clear_sync_state()?;

            let mut state = AppState::default();
            state.mark_pull_ok();
            ctx.sessions.save_app_state(&ctx.profile, &state)?;

            let _ = native_pull(&ctx, true)?;

            if globals.json {
                print_json(
                    &json!({"ok": true, "result": {"message": "local cache reset and full pull complete"}}),
                )?;
            } else {
                println!("Local cache reset and full pull completed.");
            }

            Ok(ExitCode::Success)
        }
        SyncCommand::Conflicts => {
            let state = ctx.sessions.load_app_state(&ctx.profile)?;
            if globals.json {
                print_json(&json!({"ok": true, "result": state.conflicts}))?;
            } else if state.conflicts.is_empty() {
                println!("No conflicts.");
            } else {
                for conflict in state.conflicts {
                    println!(
                        "{} | {} | {} | {}",
                        conflict.id, conflict.title, conflict.file, conflict.reason
                    );
                }
            }

            Ok(ExitCode::Success)
        }
        SyncCommand::Resolve {
            conflict_id,
            strategy,
        } => {
            let state = ctx.sessions.load_app_state(&ctx.profile)?;
            let Some(conflict) = state
                .conflicts
                .iter()
                .find(|conflict| conflict.id == conflict_id)
                .cloned()
            else {
                return Err(InkError::usage(format!(
                    "conflict '{conflict_id}' not found"
                )));
            };

            if matches!(strategy, ResolveStrategy::Local) && conflict.uuid.is_none() {
                return Err(InkError::usage(
                    "local resolution requires a UUID-backed conflict; use `--use server` for remote-only conflicts",
                ));
            }

            match strategy {
                ResolveStrategy::Local => {
                    let _ = native_push(&ctx, Some(&conflict.file), conflict.uuid.as_deref())?;
                }
                ResolveStrategy::Server => {
                    let _ = native_pull(&ctx, false)?;
                }
            }

            let mut latest = ctx.sessions.load_app_state(&ctx.profile)?;
            if matches!(strategy, ResolveStrategy::Local)
                && latest.conflicts.iter().any(|item| {
                    conflict_matches_selector(
                        item,
                        Some(conflict.file.as_str()),
                        conflict.uuid.as_deref(),
                    )
                })
            {
                return Err(InkError::sync(
                    "conflict still unresolved after local resolution attempt; fix the underlying issue and retry",
                ));
            }

            latest.conflicts.retain(|item| item.id != conflict_id);
            ctx.sessions.save_app_state(&ctx.profile, &latest)?;

            if globals.json {
                print_json(
                    &json!({"ok": true, "result": {"resolved": conflict_id, "strategy": format!("{:?}", strategy)}}),
                )?;
            } else {
                println!("Resolved conflict '{conflict_id}' using {strategy:?} strategy.");
            }

            Ok(ExitCode::Success)
        }
    })
}

pub(crate) fn native_pull(ctx: &AuthContext, clear_conflicts: bool) -> InkResult<SyncSummary> {
    let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
    let _ = engine.pull_all()?;

    let session = load_session_with_master_key(ctx)?;
    let master_key = session
        .master_key
        .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

    let notes = engine.decrypted_notes(&master_key)?;
    let mirror_notes = to_mirror_notes(&notes);
    let mirror = pull_to_mirror(&ctx.paths, &mirror_notes)?;

    let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
    state.mark_pull_ok();
    if clear_conflicts {
        state.conflicts.clear();
    }
    ctx.sessions.save_app_state(&ctx.profile, &state)?;

    Ok(SyncSummary {
        pulled_notes: notes.len(),
        mirrored_notes: mirror.written,
        removed_files: mirror.removed,
    })
}

fn native_push(
    ctx: &AuthContext,
    only_file: Option<&str>,
    only_uuid: Option<&str>,
) -> InkResult<PushSummary> {
    let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
    let _ = engine.pull_all()?;

    let session = load_session_with_master_key(ctx)?;
    let master_key = session
        .master_key
        .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

    let remote_notes = engine.decrypted_notes(&master_key)?;
    let remote_by_uuid: HashMap<String, DecryptedNote> = remote_notes
        .iter()
        .cloned()
        .map(|note| (note.uuid.clone(), note))
        .collect();
    let remote_by_title: HashMap<String, DecryptedNote> = remote_notes
        .iter()
        .cloned()
        .map(|note| (note.title.clone(), note))
        .collect();
    let remote_items_by_uuid: HashMap<String, ink_api::SyncItem> = engine
        .cached_items()?
        .into_iter()
        .map(|item| (item.uuid.clone(), item))
        .collect();

    let default_items_key = engine.default_items_key(&master_key)?.ok_or_else(|| {
        InkError::sync("no decrypted items key available; run `ink sync pull` first")
    })?;

    let index = load_index(&ctx.paths)?;
    let local_notes = scan_local_mirror(&ctx.paths)?;

    let mut updated = 0usize;
    let mut created = 0usize;
    let mut conflicts = 0usize;

    let mut state = ctx.sessions.load_app_state(&ctx.profile)?;
    let mut next_conflicts = if only_file.is_some() || only_uuid.is_some() {
        state
            .conflicts
            .iter()
            .filter(|conflict| !conflict_matches_selector(conflict, only_file, only_uuid))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let mut push_items = Vec::new();
    let duplicate_conflicts = detect_duplicate_uuid_conflicts(&local_notes);
    let duplicate_uuids: HashSet<String> = duplicate_conflicts
        .iter()
        .filter_map(|conflict| conflict.uuid.clone())
        .collect();
    conflicts += duplicate_conflicts.len();
    next_conflicts.extend(duplicate_conflicts);

    for local_note in local_notes {
        let file_match = only_file.is_some_and(|target_file| local_note.path == target_file);
        let uuid_match =
            only_uuid.is_some_and(|target_uuid| local_note.uuid.as_deref() == Some(target_uuid));
        let target_selected = match (only_file, only_uuid) {
            (None, None) => true,
            _ => file_match || uuid_match,
        };
        if !target_selected {
            continue;
        }

        if local_note
            .uuid
            .as_ref()
            .is_some_and(|uuid| duplicate_uuids.contains(uuid))
        {
            continue;
        }

        let tracked_entry = local_note
            .uuid
            .as_deref()
            .and_then(|uuid| find_entry_by_uuid(&index, uuid));

        let changed = match tracked_entry {
            Some(entry) => entry.sha256 != local_note.sha256 || entry.title != local_note.title,
            None => true,
        };

        if !changed && only_file.is_none() && only_uuid.is_none() {
            continue;
        }

        let forcing_local = only_file.is_some() || only_uuid.is_some();

        if let Some(uuid) = local_note.uuid.as_deref() {
            if let Some(remote_note) = remote_by_uuid.get(uuid) {
                let tracked_remote_updated =
                    tracked_entry.and_then(|entry| entry.remote_updated_at.clone());
                let local_base_updated = local_note
                    .updated_at
                    .clone()
                    .or_else(|| tracked_remote_updated.clone());
                let remote_updated = remote_note.updated_at.clone();

                if !forcing_local && remote_updated != local_base_updated {
                    conflicts += 1;
                    next_conflicts.push(SyncConflict {
                        id: make_conflict_id(&local_note.path),
                        uuid: Some(uuid.to_string()),
                        title: local_note.title.clone(),
                        file: local_note.path.clone(),
                        reason: "remote note changed since last pull".to_string(),
                        detected_at: Utc::now().to_rfc3339(),
                        remote_updated_at: remote_updated,
                        local_updated_at: local_base_updated,
                    });
                    continue;
                }
            } else if !forcing_local
                && let Some(remote_title_match) = remote_by_title.get(&local_note.title)
            {
                conflicts += 1;
                next_conflicts.push(SyncConflict {
                    id: make_conflict_id(&local_note.path),
                    uuid: Some(uuid.to_string()),
                    title: local_note.title.clone(),
                    file: local_note.path.clone(),
                    reason: "remote note UUID changed for same title".to_string(),
                    detected_at: Utc::now().to_rfc3339(),
                    remote_updated_at: remote_title_match.updated_at.clone(),
                    local_updated_at: local_note.updated_at.clone(),
                });
                continue;
            }
        }

        let has_existing_remote = local_note
            .uuid
            .as_deref()
            .is_some_and(|uuid| remote_by_uuid.contains_key(uuid));
        let target_uuid = local_note
            .uuid
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let mut item = engine.make_encrypted_note_item(
            &target_uuid,
            &local_note.title,
            &local_note.text,
            &default_items_key.uuid,
            &default_items_key.items_key,
        )?;

        if let Some(remote_item) = remote_items_by_uuid.get(&target_uuid) {
            item.created_at = remote_item.created_at.clone();
            item.updated_at = remote_item.updated_at.clone();
            item.created_at_timestamp = remote_item.created_at_timestamp;
            item.updated_at_timestamp = remote_item.updated_at_timestamp;
        } else {
            let now = Utc::now().to_rfc3339();
            item.created_at = Some(now.clone());
            item.updated_at = Some(now);
        }

        push_items.push(item);

        if has_existing_remote {
            updated += 1;
        } else {
            created += 1;
        }
    }

    if !push_items.is_empty() {
        let push_outcome = engine.push_items(push_items)?;
        conflicts += push_outcome.conflicts;
        if push_outcome.conflicts > 0 {
            next_conflicts.push(SyncConflict {
                id: make_conflict_id("server"),
                uuid: None,
                title: "Server conflict".to_string(),
                file: "<remote>".to_string(),
                reason: format!("server reported {} conflicts", push_outcome.conflicts),
                detected_at: Utc::now().to_rfc3339(),
                remote_updated_at: None,
                local_updated_at: None,
            });
        }
    }

    state.conflicts = dedup_conflicts(next_conflicts);
    if conflicts == 0 {
        state.mark_push_ok();
    } else {
        state.mark_error("conflicts detected during push");
    }
    ctx.sessions.save_app_state(&ctx.profile, &state)?;

    if conflicts == 0 {
        let _ = native_pull(ctx, false)?;
    }

    Ok(PushSummary {
        updated,
        created,
        conflicts,
    })
}

fn detect_duplicate_uuid_conflicts(local_notes: &[LocalMirrorNote]) -> Vec<SyncConflict> {
    let mut by_uuid: HashMap<String, Vec<&LocalMirrorNote>> = HashMap::new();
    for note in local_notes {
        let Some(uuid) = note.uuid.as_ref() else {
            continue;
        };
        by_uuid.entry(uuid.clone()).or_default().push(note);
    }

    let mut uuids: Vec<String> = by_uuid
        .iter()
        .filter_map(|(uuid, entries)| (entries.len() > 1).then_some(uuid.clone()))
        .collect();
    uuids.sort();

    let mut conflicts = Vec::new();
    for uuid in uuids {
        let Some(entries) = by_uuid.get(&uuid) else {
            continue;
        };

        let mut files: Vec<String> = entries.iter().map(|entry| entry.path.clone()).collect();
        files.sort();
        files.dedup();

        let title = entries
            .first()
            .map(|entry| entry.title.clone())
            .unwrap_or_else(|| "Mirror duplicate UUID".to_string());
        let local_updated_at = entries.iter().find_map(|entry| entry.updated_at.clone());

        conflicts.push(SyncConflict {
            id: make_conflict_id(&format!("duplicate-{uuid}")),
            uuid: Some(uuid.clone()),
            title,
            file: files.join(", "),
            reason: format!(
                "multiple mirrored files share UUID '{uuid}'; keep one file before pushing"
            ),
            detected_at: Utc::now().to_rfc3339(),
            remote_updated_at: None,
            local_updated_at,
        });
    }

    conflicts
}

fn conflict_matches_selector(
    conflict: &SyncConflict,
    only_file: Option<&str>,
    only_uuid: Option<&str>,
) -> bool {
    let file_match = only_file.is_some_and(|file| {
        conflict
            .file
            .split(',')
            .map(|part| part.trim())
            .any(|part| part == file)
    });
    let uuid_match = only_uuid.is_some_and(|uuid| conflict.uuid.as_deref() == Some(uuid));

    file_match || uuid_match
}

fn dedup_conflicts(conflicts: Vec<SyncConflict>) -> Vec<SyncConflict> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for conflict in conflicts {
        let key = format!(
            "{}|{}|{}|{}",
            conflict.uuid.as_deref().unwrap_or_default(),
            conflict.title,
            conflict.file,
            conflict.reason
        );

        if seen.insert(key) {
            unique.push(conflict);
        }
    }

    unique
}

fn to_mirror_notes(notes: &[DecryptedNote]) -> Vec<MirrorNote> {
    notes
        .iter()
        .map(|note| MirrorNote {
            uuid: note.uuid.clone(),
            title: note.title.clone(),
            text: note.text.clone(),
            updated_at: note.updated_at.clone(),
        })
        .collect()
}

pub(crate) fn load_session_with_master_key(ctx: &AuthContext) -> InkResult<StoredSession> {
    let mut session = ctx.sessions.load(&ctx.profile)?.ok_or_else(|| {
        InkError::auth(format!(
            "no active session for profile '{}'; run `ink auth login` first",
            ctx.profile
        ))
    })?;

    if session.master_key.is_some() {
        return Ok(session);
    }

    let credentials = resolve_env_credentials(&ctx.paths.root)?.ok_or_else(|| {
        InkError::auth("missing SN_EMAIL/SN_PASSWORD to derive master key for existing session")
    })?;

    let key_params = session.key_params.clone().ok_or_else(|| {
        InkError::auth("stored session is missing key params; run `ink auth login` again")
    })?;

    let identifier = key_params
        .identifier
        .or(key_params.email)
        .unwrap_or_else(|| normalize_email(&session.email));
    let pw_nonce = key_params
        .pw_nonce
        .ok_or_else(|| InkError::auth("stored session key params are missing pw_nonce"))?;

    let derived = derive_root_credentials_004(&credentials.password, &identifier, &pw_nonce)?;
    session.master_key = Some(derived.master_key);
    ctx.sessions.save(&ctx.profile, &session)?;

    Ok(session)
}

fn make_conflict_id(seed: &str) -> String {
    let ts = Utc::now().format("%Y%m%d%H%M%S%3f");
    let sanitized = seed.replace(['/', ' '], "_");
    format!("c-{ts}-{sanitized}")
}
