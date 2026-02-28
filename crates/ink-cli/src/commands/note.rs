use chrono::Utc;
use ink_api::{SyncItem, SyncItemInput};
use ink_core::{ExitCode, InkError, InkResult};
use ink_sync::{DecryptedNote, SyncEngine};
use serde::Serialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::is_uuid;
use crate::{GlobalOptions, NoteCommand, print_json, resolve_user_path, with_auth_context};

use super::sync::{load_session_with_master_key, native_pull};

#[derive(Debug, Clone, Serialize)]
struct NoteContentView {
    title: String,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct NoteView {
    uuid: String,
    content: NoteContentView,
    created_at: Option<String>,
    updated_at: Option<String>,
    content_type: String,
}

pub(crate) fn cmd_note(command: NoteCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    with_auth_context(globals, |ctx| match command {
        NoteCommand::List { tag } => {
            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            pull_with_cache_fallback(&engine)?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

            let mut notes = engine.decrypted_notes(&master_key)?;
            if let Some(selector) = tag.as_deref() {
                notes = filter_notes_by_tag_selector(&engine, &master_key, notes, selector)?;
            }
            let views = to_note_views(&engine, &notes)?;

            if globals.json {
                print_json(&json!({"ok": true, "result": views}))?;
            } else if views.is_empty() {
                println!("No notes found.");
            } else {
                for note in views {
                    println!("{} | {}", note.uuid, note.content.title);
                }
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::Get { selector } => {
            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            pull_with_cache_fallback(&engine)?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

            let notes = engine.decrypted_notes(&master_key)?;
            let matched = select_notes_by_selector(&notes, &selector);
            let views = to_note_views(&engine, &matched)?;

            if globals.json {
                print_json(&json!({"ok": true, "result": views}))?;
            } else if views.is_empty() {
                println!("No note matched '{selector}'.");
            } else {
                for note in views {
                    println!("{}", note.content.title);
                    println!("uuid: {}", note.uuid);
                    println!("updated_at: {}", note.updated_at.unwrap_or_default());
                    println!();
                    println!("{}", note.content.text);
                    println!();
                }
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::New {
            title,
            text,
            file,
            tag,
        } => {
            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            let _ = engine.pull_all()?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;
            let default_items_key = engine.default_items_key(&master_key)?.ok_or_else(|| {
                InkError::sync("no decrypted items key available; run `ink sync pull` first")
            })?;

            let file_path = file
                .map(|path| resolve_user_path(path, &ctx.paths.root))
                .transpose()?;
            let content = read_text_or_file(text, file_path.as_ref())?;
            let final_title = resolve_new_note_title(title, file_path.as_ref())?;
            let note_uuid = Uuid::new_v4().to_string();

            let mut push_items = Vec::new();
            let mut note_item = engine.make_encrypted_note_item(
                &note_uuid,
                &final_title,
                &content,
                &default_items_key.uuid,
                &default_items_key.items_key,
            )?;
            apply_new_timestamps(&mut note_item);
            push_items.push(note_item);

            if let Some(tag_selector) = tag {
                let tags = engine.decrypted_tags(&master_key)?;
                let cached = index_cached_items(&engine.cached_items()?);
                if let Some(existing_tag) = resolve_tag_optional(&tags, &tag_selector)? {
                    let mut references = existing_tag.references.clone();
                    if !references.contains(&note_uuid) {
                        references.push(note_uuid.clone());
                    }
                    references.sort();
                    references.dedup();

                    let mut tag_item = engine.make_encrypted_tag_item(
                        &existing_tag.uuid,
                        &existing_tag.title,
                        &references,
                        existing_tag.parent_uuid.as_deref(),
                        &default_items_key.uuid,
                        &default_items_key.items_key,
                    )?;
                    apply_existing_timestamps(&mut tag_item, cached.get(&existing_tag.uuid));
                    push_items.push(tag_item);
                } else {
                    if is_uuid(&tag_selector) {
                        return Err(InkError::usage(format!(
                            "tag uuid '{tag_selector}' not found"
                        )));
                    }
                    let mut tag_item = engine.make_encrypted_tag_item(
                        &Uuid::new_v4().to_string(),
                        &tag_selector,
                        std::slice::from_ref(&note_uuid),
                        None,
                        &default_items_key.uuid,
                        &default_items_key.items_key,
                    )?;
                    apply_new_timestamps(&mut tag_item);
                    push_items.push(tag_item);
                }
            }

            push_no_conflict(&engine, push_items)?;
            let _ = native_pull(&ctx, false)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "uuid": note_uuid,
                        "title": final_title,
                    }
                }))?;
            } else {
                println!("Created note '{final_title}'.");
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::Edit {
            selector,
            title,
            text,
            file,
        } => {
            if title.is_none() && text.is_none() && file.is_none() {
                return Err(InkError::usage(
                    "interactive note edit is not supported; provide --title, --text, or --file",
                ));
            }

            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            let _ = engine.pull_all()?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;
            let default_items_key = engine.default_items_key(&master_key)?.ok_or_else(|| {
                InkError::sync("no decrypted items key available; run `ink sync pull` first")
            })?;

            let notes = engine.decrypted_notes(&master_key)?;
            let target = resolve_note_required(&notes, &selector)?;
            let file_path = file
                .map(|path| resolve_user_path(path, &ctx.paths.root))
                .transpose()?;
            let final_text =
                read_text_or_file(text, file_path.as_ref())?.if_empty_use(&target.text);
            let final_title = title.unwrap_or_else(|| target.title.clone());

            let mut item = engine.make_encrypted_note_item(
                &target.uuid,
                &final_title,
                &final_text,
                &default_items_key.uuid,
                &default_items_key.items_key,
            )?;
            let cached = index_cached_items(&engine.cached_items()?);
            apply_existing_timestamps(&mut item, cached.get(&target.uuid));

            push_no_conflict(&engine, vec![item])?;
            let _ = native_pull(&ctx, false)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "uuid": target.uuid,
                        "title": final_title,
                    }
                }))?;
            } else {
                println!("Updated note '{final_title}'.");
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::Delete { selector } => {
            if !globals.yes {
                return Err(InkError::usage(
                    "note delete requires --yes to avoid accidental deletion",
                ));
            }

            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            let _ = engine.pull_all()?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;
            let notes = engine.decrypted_notes(&master_key)?;
            let target = resolve_note_required(&notes, &selector)?;
            let cached = index_cached_items(&engine.cached_items()?);
            let remote = cached
                .get(&target.uuid)
                .ok_or_else(|| InkError::sync("note missing from cached encrypted items"))?;

            let deleted_item = SyncItemInput {
                uuid: target.uuid.clone(),
                content_type: "Note".to_string(),
                content: remote.content.clone(),
                enc_item_key: remote.enc_item_key.clone(),
                items_key_id: remote.items_key_id.clone(),
                deleted: Some(true),
                created_at: remote.created_at.clone(),
                updated_at: Some(Utc::now().to_rfc3339()),
                created_at_timestamp: remote.created_at_timestamp,
                updated_at_timestamp: remote.updated_at_timestamp,
                key_system_identifier: remote.key_system_identifier.clone(),
                shared_vault_uuid: remote.shared_vault_uuid.clone(),
            };

            push_no_conflict(&engine, vec![deleted_item])?;
            let _ = native_pull(&ctx, false)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "uuid": target.uuid,
                        "title": target.title,
                    }
                }))?;
            } else {
                println!("Deleted note '{}'.", target.title);
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::Search {
            query,
            fuzzy,
            case_sensitive,
            tag,
            limit,
            offline,
        } => {
            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            if !offline {
                pull_with_cache_fallback(&engine)?;
            }
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

            let mut notes = engine.decrypted_notes(&master_key)?;
            if let Some(selector) = tag.as_deref() {
                notes = filter_notes_by_tag_selector(&engine, &master_key, notes, selector)?;
            }

            let mut matched: Vec<DecryptedNote> = notes
                .into_iter()
                .filter(|note| note_matches_query(note, &query, fuzzy, case_sensitive))
                .collect();
            if let Some(limit) = limit {
                matched.truncate(limit);
            }
            let views = to_note_views(&engine, &matched)?;

            if globals.json {
                print_json(&json!({"ok": true, "result": views}))?;
            } else if views.is_empty() {
                println!("No notes matched '{query}'.");
            } else {
                for note in views {
                    println!("{} | {}", note.uuid, note.content.title);
                }
            }
            Ok(ExitCode::Success)
        }
    })
}

fn pull_with_cache_fallback(engine: &SyncEngine<'_>) -> InkResult<()> {
    match engine.pull_all() {
        Ok(_) => Ok(()),
        Err(error) => {
            if engine.cached_items()?.is_empty() {
                Err(error)
            } else {
                Ok(())
            }
        }
    }
}

fn push_no_conflict(engine: &SyncEngine<'_>, items: Vec<SyncItemInput>) -> InkResult<()> {
    let outcome = engine.push_items(items)?;
    if outcome.conflicts > 0 {
        return Err(InkError::sync(format!(
            "server reported {} conflicts; inspect with `ink sync conflicts`",
            outcome.conflicts
        )));
    }
    Ok(())
}

fn resolve_new_note_title(title: Option<String>, file: Option<&PathBuf>) -> InkResult<String> {
    if let Some(title) = title {
        return Ok(title);
    }
    if let Some(path) = file {
        return Ok(path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("Untitled")
            .to_string());
    }
    Err(InkError::usage(
        "note title required when --file is not provided",
    ))
}

fn read_text_or_file(text: Option<String>, file: Option<&PathBuf>) -> InkResult<String> {
    if let Some(text) = text {
        return Ok(text);
    }
    if let Some(path) = file {
        return fs::read_to_string(path).map_err(|err| {
            InkError::io(format!(
                "failed to read note file '{}': {}",
                path.display(),
                err
            ))
        });
    }
    Ok(String::new())
}

fn resolve_note_required(notes: &[DecryptedNote], selector: &str) -> InkResult<DecryptedNote> {
    if is_uuid(selector) {
        return notes
            .iter()
            .find(|note| note.uuid == selector)
            .cloned()
            .ok_or_else(|| InkError::usage(format!("no note found for '{selector}'")));
    }

    let matched: Vec<DecryptedNote> = notes
        .iter()
        .filter(|note| note.title == selector)
        .cloned()
        .collect();
    if matched.is_empty() {
        return Err(InkError::usage(format!("no note found for '{selector}'")));
    }
    if matched.len() > 1 {
        return Err(InkError::usage(format!(
            "multiple notes matched '{selector}'; use UUID"
        )));
    }
    Ok(matched[0].clone())
}

fn select_notes_by_selector(notes: &[DecryptedNote], selector: &str) -> Vec<DecryptedNote> {
    if is_uuid(selector) {
        return notes
            .iter()
            .filter(|note| note.uuid == selector)
            .cloned()
            .collect();
    }
    notes
        .iter()
        .filter(|note| note.title == selector)
        .cloned()
        .collect()
}

fn filter_notes_by_tag_selector(
    engine: &SyncEngine<'_>,
    master_key: &str,
    notes: Vec<DecryptedNote>,
    selector: &str,
) -> InkResult<Vec<DecryptedNote>> {
    let tags = engine.decrypted_tags(master_key)?;
    let Some(tag) = resolve_tag_optional(&tags, selector)? else {
        return Ok(Vec::new());
    };
    let references: HashSet<String> = tag.references.into_iter().collect();
    Ok(notes
        .into_iter()
        .filter(|note| references.contains(&note.uuid))
        .collect())
}

fn resolve_tag_optional(
    tags: &[ink_sync::DecryptedTag],
    selector: &str,
) -> InkResult<Option<ink_sync::DecryptedTag>> {
    if is_uuid(selector) {
        return Ok(tags.iter().find(|tag| tag.uuid == selector).cloned());
    }

    let matched: Vec<_> = tags
        .iter()
        .filter(|tag| tag.title == selector)
        .cloned()
        .collect();
    if matched.is_empty() {
        return Ok(None);
    }
    if matched.len() > 1 {
        return Err(InkError::usage(format!(
            "multiple tags matched '{selector}'; use UUID"
        )));
    }
    Ok(Some(matched[0].clone()))
}

fn note_matches_query(
    note: &DecryptedNote,
    query: &str,
    fuzzy: bool,
    case_sensitive: bool,
) -> bool {
    if query.is_empty() {
        return true;
    }
    let haystack = format!("{}\n{}", note.title, note.text);
    if case_sensitive {
        return if fuzzy {
            fuzzy_contains(&haystack, query)
        } else {
            haystack.contains(query)
        };
    }

    let haystack = haystack.to_lowercase();
    let query = query.to_lowercase();
    if fuzzy {
        fuzzy_contains(&haystack, &query)
    } else {
        haystack.contains(&query)
    }
}

fn fuzzy_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let mut needle_chars = needle.chars();
    let mut expected = needle_chars.next();
    for ch in haystack.chars() {
        if Some(ch) == expected {
            expected = needle_chars.next();
            if expected.is_none() {
                return true;
            }
        }
    }
    false
}

fn index_cached_items(items: &[SyncItem]) -> HashMap<String, SyncItem> {
    items
        .iter()
        .cloned()
        .map(|item| (item.uuid.clone(), item))
        .collect()
}

fn apply_new_timestamps(item: &mut SyncItemInput) {
    let now = Utc::now().to_rfc3339();
    item.created_at = Some(now.clone());
    item.updated_at = Some(now);
}

fn apply_existing_timestamps(item: &mut SyncItemInput, remote: Option<&SyncItem>) {
    if let Some(remote) = remote {
        item.created_at = remote.created_at.clone();
        item.updated_at = remote.updated_at.clone();
        item.created_at_timestamp = remote.created_at_timestamp;
        item.updated_at_timestamp = remote.updated_at_timestamp;
        item.key_system_identifier = remote.key_system_identifier.clone();
        item.shared_vault_uuid = remote.shared_vault_uuid.clone();
        return;
    }

    apply_new_timestamps(item);
}

fn to_note_views(engine: &SyncEngine<'_>, notes: &[DecryptedNote]) -> InkResult<Vec<NoteView>> {
    let item_lookup = index_cached_items(&engine.cached_items()?);
    Ok(notes
        .iter()
        .map(|note| {
            let meta = item_lookup.get(&note.uuid);
            NoteView {
                uuid: note.uuid.clone(),
                content: NoteContentView {
                    title: note.title.clone(),
                    text: note.text.clone(),
                },
                created_at: meta.and_then(|item| item.created_at.clone()),
                updated_at: note
                    .updated_at
                    .clone()
                    .or_else(|| meta.and_then(|item| item.updated_at.clone())),
                content_type: "Note".to_string(),
            }
        })
        .collect())
}

trait IfEmptyUse {
    fn if_empty_use(self, fallback: &str) -> String;
}

impl IfEmptyUse for String {
    fn if_empty_use(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}
