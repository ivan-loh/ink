use chrono::Utc;
use ink_api::{SyncItem, SyncItemInput};
use ink_core::{ExitCode, InkError, InkResult};
use ink_sync::{DecryptedNote, SyncEngine};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
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

#[derive(Debug, Clone, Serialize)]
struct PageMeta {
    cursor: String,
    next_cursor: Option<String>,
    limit: Option<usize>,
    total: usize,
    returned: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NoteField {
    Uuid,
    Title,
    Text,
    CreatedAt,
    UpdatedAt,
    ContentType,
}

#[derive(Debug, Clone, Serialize)]
struct NoteCandidate {
    uuid: String,
    title: String,
    updated_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpsertAction {
    Created,
    Updated,
    Noop,
}

pub(crate) fn cmd_note(command: NoteCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    with_auth_context(globals, true, |ctx| match command {
        NoteCommand::List {
            tag,
            fields,
            limit,
            cursor,
        } => {
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
            let field_projection = parse_note_fields(fields.as_deref())?;
            let page = paginate_slice(views.len(), cursor.as_deref(), limit)?;
            let paged_views = views[page.start..page.end].to_vec();

            if globals.json {
                let result = if let Some(fields) = field_projection.as_deref() {
                    project_note_views(&paged_views, fields)
                } else {
                    serde_json::to_value(&paged_views).map_err(|err| {
                        InkError::io(format!("failed to encode note list result: {err}"))
                    })?
                };
                print_json(&json!({"ok": true, "result": result, "page": page.meta}))?;
            } else if paged_views.is_empty() {
                println!("No notes found.");
            } else {
                for note in paged_views {
                    println!("{} | {}", note.uuid, note.content.title);
                }
                if let Some(next_cursor) = page.meta.next_cursor {
                    println!("next_cursor: {next_cursor}");
                }
            }
            Ok(ExitCode::Success)
        }
        NoteCommand::Resolve { selector, limit } => {
            if limit == 0 {
                return Err(InkError::usage("--limit must be greater than 0"));
            }

            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            pull_with_cache_fallback(&engine)?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;

            let notes = engine.decrypted_notes(&master_key)?;
            let views = to_note_views(&engine, &notes)?;
            let (exact_matches, candidates) = resolve_note_candidates(&views, &selector, limit);
            let resolved_uuid = if exact_matches.len() == 1 {
                Some(exact_matches[0].uuid.clone())
            } else {
                None
            };

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "selector": selector,
                        "resolved_uuid": resolved_uuid,
                        "exact_matches": exact_matches.len(),
                        "returned": candidates.len(),
                        "candidates": candidates,
                    }
                }))?;
            } else if candidates.is_empty() {
                println!("No notes matched '{selector}'.");
            } else {
                for candidate in &candidates {
                    println!("{} | {}", candidate.uuid, candidate.title);
                }
                println!("exact_matches: {}", exact_matches.len());
                if let Some(uuid) = resolved_uuid {
                    println!("resolved_uuid: {uuid}");
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

            if let Some(tag_selector) = tag.as_deref()
                && let Some(tag_item) = build_tag_link_item(
                    &engine,
                    &master_key,
                    &note_uuid,
                    tag_selector,
                    &default_items_key.uuid,
                    &default_items_key.items_key,
                )?
            {
                push_items.push(tag_item);
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
        NoteCommand::Upsert {
            title,
            text,
            file,
            append,
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
            let incoming_text = read_text_or_file(text, file_path.as_ref())?;
            let notes = engine.decrypted_notes(&master_key)?;
            let matched: Vec<DecryptedNote> = notes
                .iter()
                .filter(|note| note.title == title)
                .cloned()
                .collect();

            let (action, note_uuid, final_title, mut push_items) = if matched.is_empty() {
                let note_uuid = Uuid::new_v4().to_string();
                let mut note_item = engine.make_encrypted_note_item(
                    &note_uuid,
                    &title,
                    &incoming_text,
                    &default_items_key.uuid,
                    &default_items_key.items_key,
                )?;
                apply_new_timestamps(&mut note_item);
                (
                    UpsertAction::Created,
                    note_uuid,
                    title.clone(),
                    vec![note_item],
                )
            } else if matched.len() == 1 {
                let target = &matched[0];
                let final_text = if incoming_text.is_empty() {
                    target.text.clone()
                } else if append {
                    append_note_text(&target.text, &incoming_text)
                } else {
                    incoming_text
                };

                if final_text == target.text {
                    (
                        UpsertAction::Noop,
                        target.uuid.clone(),
                        target.title.clone(),
                        Vec::new(),
                    )
                } else {
                    let cached = index_cached_items(&engine.cached_items()?);
                    let mut note_item = engine.make_encrypted_note_item(
                        &target.uuid,
                        &target.title,
                        &final_text,
                        &default_items_key.uuid,
                        &default_items_key.items_key,
                    )?;
                    apply_existing_timestamps(&mut note_item, cached.get(&target.uuid));
                    (
                        UpsertAction::Updated,
                        target.uuid.clone(),
                        target.title.clone(),
                        vec![note_item],
                    )
                }
            } else {
                let duplicates = matched
                    .iter()
                    .map(|note| note.uuid.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(InkError::usage(format!(
                    "multiple notes matched title '{title}'; use UUID-based edit. Matched UUIDs: {duplicates}"
                )));
            };

            if let Some(tag_selector) = tag.as_deref()
                && let Some(tag_item) = build_tag_link_item(
                    &engine,
                    &master_key,
                    &note_uuid,
                    tag_selector,
                    &default_items_key.uuid,
                    &default_items_key.items_key,
                )?
            {
                push_items.push(tag_item);
            }

            if !push_items.is_empty() {
                push_no_conflict(&engine, push_items)?;
                let _ = native_pull(&ctx, false)?;
            }

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "action": action,
                        "uuid": note_uuid,
                        "title": final_title,
                    }
                }))?;
            } else {
                match action {
                    UpsertAction::Created => println!("Created note '{final_title}'."),
                    UpsertAction::Updated => println!("Updated note '{final_title}'."),
                    UpsertAction::Noop => println!("No changes for note '{final_title}'."),
                }
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
            cursor,
            fields,
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

            let matched: Vec<DecryptedNote> = notes
                .into_iter()
                .filter(|note| note_matches_query(note, &query, fuzzy, case_sensitive))
                .collect();
            let views = to_note_views(&engine, &matched)?;
            let field_projection = parse_note_fields(fields.as_deref())?;
            let page = paginate_slice(views.len(), cursor.as_deref(), limit)?;
            let paged_views = views[page.start..page.end].to_vec();

            if globals.json {
                let result = if let Some(fields) = field_projection.as_deref() {
                    project_note_views(&paged_views, fields)
                } else {
                    serde_json::to_value(&paged_views).map_err(|err| {
                        InkError::io(format!("failed to encode note search result: {err}"))
                    })?
                };
                print_json(&json!({"ok": true, "result": result, "page": page.meta}))?;
            } else if paged_views.is_empty() {
                println!("No notes matched '{query}'.");
            } else {
                for note in paged_views {
                    println!("{} | {}", note.uuid, note.content.title);
                }
                if let Some(next_cursor) = page.meta.next_cursor {
                    println!("next_cursor: {next_cursor}");
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
        if text == "-" {
            return read_text_from_stdin();
        }
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

fn read_text_from_stdin() -> InkResult<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|err| InkError::io(format!("failed to read note text from stdin: {err}")))?;
    Ok(buffer)
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

fn build_tag_link_item(
    engine: &SyncEngine<'_>,
    master_key: &str,
    note_uuid: &str,
    tag_selector: &str,
    items_key_id: &str,
    items_key: &str,
) -> InkResult<Option<SyncItemInput>> {
    let tags = engine.decrypted_tags(master_key)?;
    let cached = index_cached_items(&engine.cached_items()?);

    if let Some(existing_tag) = resolve_tag_optional(&tags, tag_selector)? {
        if existing_tag
            .references
            .iter()
            .any(|reference| reference == note_uuid)
        {
            return Ok(None);
        }

        let mut references = existing_tag.references.clone();
        references.push(note_uuid.to_string());
        references.sort();
        references.dedup();

        let mut tag_item = engine.make_encrypted_tag_item(
            &existing_tag.uuid,
            &existing_tag.title,
            &references,
            existing_tag.parent_uuid.as_deref(),
            items_key_id,
            items_key,
        )?;
        apply_existing_timestamps(&mut tag_item, cached.get(&existing_tag.uuid));
        return Ok(Some(tag_item));
    }

    if is_uuid(tag_selector) {
        return Err(InkError::usage(format!(
            "tag uuid '{tag_selector}' not found"
        )));
    }

    let mut tag_item = engine.make_encrypted_tag_item(
        &Uuid::new_v4().to_string(),
        tag_selector,
        &[note_uuid.to_string()],
        None,
        items_key_id,
        items_key,
    )?;
    apply_new_timestamps(&mut tag_item);
    Ok(Some(tag_item))
}

fn append_note_text(current: &str, append: &str) -> String {
    if current.is_empty() {
        return append.to_string();
    }
    if append.is_empty() {
        return current.to_string();
    }
    format!("{current}\n\n{append}")
}

fn resolve_note_candidates(
    notes: &[NoteView],
    selector: &str,
    limit: usize,
) -> (Vec<NoteCandidate>, Vec<NoteCandidate>) {
    let needle = selector.to_lowercase();
    let exact: Vec<NoteCandidate> = notes
        .iter()
        .filter(|note| note.uuid == selector || note.content.title == selector)
        .map(note_candidate)
        .collect();

    let mut candidates: Vec<NoteCandidate> = notes
        .iter()
        .filter(|note| {
            note.uuid == selector
                || note.content.title == selector
                || note.content.title.to_lowercase().contains(&needle)
                || note.content.text.to_lowercase().contains(&needle)
        })
        .map(note_candidate)
        .collect();

    candidates.sort_by(|left, right| {
        left.title
            .cmp(&right.title)
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
    candidates.truncate(limit);

    (exact, candidates)
}

fn note_candidate(note: &NoteView) -> NoteCandidate {
    NoteCandidate {
        uuid: note.uuid.clone(),
        title: note.content.title.clone(),
        updated_at: note.updated_at.clone(),
    }
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

#[derive(Debug, Clone)]
struct PageSlice {
    start: usize,
    end: usize,
    meta: PageMeta,
}

fn paginate_slice(
    total: usize,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> InkResult<PageSlice> {
    if cursor.is_some() && limit.is_none() {
        return Err(InkError::usage(
            "--limit is required when --cursor is provided",
        ));
    }

    let start = match cursor {
        Some(raw) => raw.trim().parse::<usize>().map_err(|_| {
            InkError::usage(format!("invalid cursor '{raw}'; expected integer offset"))
        })?,
        None => 0,
    };
    if start > total {
        return Err(InkError::usage(format!(
            "cursor {start} is out of range for {total} notes"
        )));
    }

    let page_size = limit.unwrap_or(total.saturating_sub(start));
    let end = start.saturating_add(page_size).min(total);
    let next_cursor = (end < total).then(|| end.to_string());
    let meta = PageMeta {
        cursor: start.to_string(),
        next_cursor,
        limit,
        total,
        returned: end.saturating_sub(start),
    };

    Ok(PageSlice { start, end, meta })
}

fn parse_note_fields(spec: Option<&str>) -> InkResult<Option<Vec<NoteField>>> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    if spec.trim().is_empty() {
        return Err(InkError::usage(
            "--fields cannot be empty (example: --fields uuid,title,updated_at)",
        ));
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in spec.split(',') {
        let field = match raw.trim() {
            "uuid" => NoteField::Uuid,
            "title" => NoteField::Title,
            "text" => NoteField::Text,
            "created_at" => NoteField::CreatedAt,
            "updated_at" => NoteField::UpdatedAt,
            "content_type" => NoteField::ContentType,
            value => {
                return Err(InkError::usage(format!(
                    "unsupported note field '{value}'; allowed: uuid,title,text,created_at,updated_at,content_type"
                )));
            }
        };
        if seen.insert(field) {
            out.push(field);
        }
    }

    Ok(Some(out))
}

fn project_note_views(views: &[NoteView], fields: &[NoteField]) -> Value {
    let projected: Vec<Value> = views
        .iter()
        .map(|note| {
            let mut map = serde_json::Map::new();
            for field in fields {
                match field {
                    NoteField::Uuid => {
                        map.insert("uuid".to_string(), json!(note.uuid));
                    }
                    NoteField::Title => {
                        map.insert("title".to_string(), json!(note.content.title));
                    }
                    NoteField::Text => {
                        map.insert("text".to_string(), json!(note.content.text));
                    }
                    NoteField::CreatedAt => {
                        map.insert("created_at".to_string(), json!(note.created_at));
                    }
                    NoteField::UpdatedAt => {
                        map.insert("updated_at".to_string(), json!(note.updated_at));
                    }
                    NoteField::ContentType => {
                        map.insert("content_type".to_string(), json!(note.content_type));
                    }
                }
            }
            Value::Object(map)
        })
        .collect();

    Value::Array(projected)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_views() -> Vec<NoteView> {
        vec![
            NoteView {
                uuid: "n1".to_string(),
                content: NoteContentView {
                    title: "Alpha".to_string(),
                    text: "Body A".to_string(),
                },
                created_at: Some("2026-01-01T00:00:00Z".to_string()),
                updated_at: Some("2026-01-01T01:00:00Z".to_string()),
                content_type: "Note".to_string(),
            },
            NoteView {
                uuid: "n2".to_string(),
                content: NoteContentView {
                    title: "Beta".to_string(),
                    text: "Body B".to_string(),
                },
                created_at: Some("2026-01-02T00:00:00Z".to_string()),
                updated_at: Some("2026-01-02T01:00:00Z".to_string()),
                content_type: "Note".to_string(),
            },
            NoteView {
                uuid: "n3".to_string(),
                content: NoteContentView {
                    title: "Gamma".to_string(),
                    text: "Body C".to_string(),
                },
                created_at: Some("2026-01-03T00:00:00Z".to_string()),
                updated_at: Some("2026-01-03T01:00:00Z".to_string()),
                content_type: "Note".to_string(),
            },
        ]
    }

    #[test]
    fn parse_note_fields_accepts_known_values_and_deduplicates() {
        let parsed = parse_note_fields(Some("uuid,title,updated_at,title"))
            .expect("parse fields")
            .expect("missing parsed fields");
        assert_eq!(
            parsed,
            vec![NoteField::Uuid, NoteField::Title, NoteField::UpdatedAt]
        );
    }

    #[test]
    fn parse_note_fields_rejects_unknown_value() {
        let error = parse_note_fields(Some("uuid,unknown")).expect_err("unknown should fail");
        assert!(error.message.contains("unsupported note field"));
    }

    #[test]
    fn paginate_slice_computes_next_cursor() {
        let first = paginate_slice(3, None, Some(2)).expect("first page");
        assert_eq!(first.start, 0);
        assert_eq!(first.end, 2);
        assert_eq!(first.meta.next_cursor.as_deref(), Some("2"));

        let second = paginate_slice(3, Some("2"), Some(2)).expect("second page");
        assert_eq!(second.start, 2);
        assert_eq!(second.end, 3);
        assert_eq!(second.meta.next_cursor, None);
    }

    #[test]
    fn project_note_views_outputs_requested_fields_only() {
        let views = fixture_views();
        let projected = project_note_views(&views, &[NoteField::Uuid, NoteField::Title]);
        let array = projected.as_array().expect("array");
        assert_eq!(array.len(), 3);
        assert_eq!(array[0]["uuid"], "n1");
        assert_eq!(array[0]["title"], "Alpha");
        assert_eq!(array[0]["text"], Value::Null);
    }

    #[test]
    fn append_note_text_handles_empty_sections() {
        assert_eq!(append_note_text("", "tail"), "tail");
        assert_eq!(append_note_text("head", ""), "head");
        assert_eq!(append_note_text("head", "tail"), "head\n\ntail");
    }

    #[test]
    fn resolve_note_candidates_reports_exact_matches_and_limits_candidates() {
        let views = fixture_views();
        let (exact, candidates) = resolve_note_candidates(&views, "Alpha", 10);
        assert_eq!(exact.len(), 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].uuid, "n1");

        let (exact_partial, candidates_partial) = resolve_note_candidates(&views, "a", 2);
        assert_eq!(exact_partial.len(), 0);
        assert_eq!(candidates_partial.len(), 2);
    }
}
