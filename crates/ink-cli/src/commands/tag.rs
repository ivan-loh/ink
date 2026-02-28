use chrono::Utc;
use ink_api::{SyncItem, SyncItemInput};
use ink_core::{ExitCode, InkError, InkResult};
use ink_sync::{DecryptedNote, DecryptedTag, SyncEngine};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

use crate::is_uuid;
use crate::{GlobalOptions, TagCommand, print_json, with_auth_context};

use super::sync::{load_session_with_master_key, native_pull};

#[derive(Debug, Clone, Serialize)]
struct TagContentView {
    title: String,
}

#[derive(Debug, Clone, Serialize)]
struct TagView {
    uuid: String,
    content: TagContentView,
    references: Vec<String>,
    parent_uuid: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    content_type: String,
}

pub(crate) fn cmd_tag(command: TagCommand, globals: &GlobalOptions) -> InkResult<ExitCode> {
    with_auth_context(globals, |ctx| match command {
        TagCommand::List => {
            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            pull_with_cache_fallback(&engine)?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;
            let tags = engine.decrypted_tags(&master_key)?;
            let views = to_tag_views(&engine, &tags)?;

            if globals.json {
                print_json(&json!({"ok": true, "result": views}))?;
            } else if views.is_empty() {
                println!("No tags found.");
            } else {
                for tag in views {
                    println!("{} | {}", tag.uuid, tag.content.title);
                }
            }
            Ok(ExitCode::Success)
        }
        TagCommand::Add {
            title,
            parent,
            parent_uuid,
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

            let tags = engine.decrypted_tags(&master_key)?;
            if tags.iter().any(|tag| tag.title == title) {
                return Err(InkError::usage(format!("tag '{title}' already exists")));
            }

            let resolved_parent_uuid = if let Some(parent_uuid) = parent_uuid {
                Some(parent_uuid)
            } else if let Some(parent_selector) = parent {
                Some(resolve_tag_required(&tags, &parent_selector)?.uuid)
            } else {
                None
            };

            let tag_uuid = Uuid::new_v4().to_string();
            let mut tag_item = engine.make_encrypted_tag_item(
                &tag_uuid,
                &title,
                &[],
                resolved_parent_uuid.as_deref(),
                &default_items_key.uuid,
                &default_items_key.items_key,
            )?;
            apply_new_timestamps(&mut tag_item);

            push_no_conflict(&engine, vec![tag_item])?;
            let _ = native_pull(&ctx, false)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "uuid": tag_uuid,
                        "title": title,
                        "parent_uuid": resolved_parent_uuid,
                    }
                }))?;
            } else {
                println!("Added tag '{title}'.");
            }
            Ok(ExitCode::Success)
        }
        TagCommand::Rename {
            selector,
            new_title,
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

            let tags = engine.decrypted_tags(&master_key)?;
            let target = resolve_tag_required(&tags, &selector)?;
            let mut item = engine.make_encrypted_tag_item(
                &target.uuid,
                &new_title,
                &target.references,
                target.parent_uuid.as_deref(),
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
                        "old": target.title,
                        "new": new_title,
                    }
                }))?;
            } else {
                println!("Renamed tag '{}' to '{}'.", target.title, new_title);
            }
            Ok(ExitCode::Success)
        }
        TagCommand::Delete { selector } => {
            if !globals.yes {
                return Err(InkError::usage(
                    "tag delete requires --yes to avoid accidental deletion",
                ));
            }

            let engine = SyncEngine::new(&ctx.api, &ctx.sessions, &ctx.profile);
            let _ = engine.pull_all()?;
            let session = load_session_with_master_key(&ctx)?;
            let master_key = session
                .master_key
                .ok_or_else(|| InkError::auth("missing master key in stored session"))?;
            let tags = engine.decrypted_tags(&master_key)?;
            let target = resolve_tag_required(&tags, &selector)?;
            let cached = index_cached_items(&engine.cached_items()?);
            let remote = cached
                .get(&target.uuid)
                .ok_or_else(|| InkError::sync("tag missing from cached encrypted items"))?;

            let item = SyncItemInput {
                uuid: target.uuid.clone(),
                content_type: "Tag".to_string(),
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

            push_no_conflict(&engine, vec![item])?;
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
                println!("Deleted tag '{}'.", target.title);
            }
            Ok(ExitCode::Success)
        }
        TagCommand::Apply { note, tag, purge } => {
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
            let target_note = resolve_note_required(&notes, &note)?;
            let mut tags = engine.decrypted_tags(&master_key)?;
            let cached = index_cached_items(&engine.cached_items()?);

            let mut target_tag = resolve_tag_optional(&tags, &tag)?;
            if target_tag.is_none() {
                if is_uuid(&tag) {
                    return Err(InkError::usage(format!("tag uuid '{tag}' not found")));
                }
                target_tag = Some(DecryptedTag {
                    uuid: Uuid::new_v4().to_string(),
                    title: tag.clone(),
                    references: Vec::new(),
                    parent_uuid: None,
                    updated_at: None,
                });
            }
            let target_tag = target_tag.expect("tag resolved");

            let mut push_items = Vec::new();
            if purge {
                for existing in &mut tags {
                    if existing.uuid == target_tag.uuid {
                        continue;
                    }
                    if !existing.references.contains(&target_note.uuid) {
                        continue;
                    }
                    existing.references.retain(|uuid| uuid != &target_note.uuid);
                    let mut item = engine.make_encrypted_tag_item(
                        &existing.uuid,
                        &existing.title,
                        &existing.references,
                        existing.parent_uuid.as_deref(),
                        &default_items_key.uuid,
                        &default_items_key.items_key,
                    )?;
                    apply_existing_timestamps(&mut item, cached.get(&existing.uuid));
                    push_items.push(item);
                }
            }

            let mut references = target_tag.references.clone();
            if !references.contains(&target_note.uuid) {
                references.push(target_note.uuid.clone());
            }
            references.sort();
            references.dedup();

            let mut target_item = engine.make_encrypted_tag_item(
                &target_tag.uuid,
                &target_tag.title,
                &references,
                target_tag.parent_uuid.as_deref(),
                &default_items_key.uuid,
                &default_items_key.items_key,
            )?;
            apply_existing_timestamps(&mut target_item, cached.get(&target_tag.uuid));
            push_items.push(target_item);

            push_no_conflict(&engine, push_items)?;
            let _ = native_pull(&ctx, false)?;

            if globals.json {
                print_json(&json!({
                    "ok": true,
                    "result": {
                        "note_uuid": target_note.uuid,
                        "tag_uuid": target_tag.uuid,
                        "tag_title": target_tag.title,
                        "purge": purge,
                    }
                }))?;
            } else {
                println!(
                    "Applied tag '{}' to note '{}'.",
                    target_tag.title, target_note.title
                );
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

fn resolve_note_required(notes: &[DecryptedNote], selector: &str) -> InkResult<DecryptedNote> {
    if is_uuid(selector) {
        return notes
            .iter()
            .find(|note| note.uuid == selector)
            .cloned()
            .ok_or_else(|| InkError::usage(format!("no note found for '{selector}'")));
    }
    let matched: Vec<_> = notes
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

fn resolve_tag_required(tags: &[DecryptedTag], selector: &str) -> InkResult<DecryptedTag> {
    resolve_tag_optional(tags, selector)?
        .ok_or_else(|| InkError::usage(format!("no tag found for '{selector}'")))
}

fn resolve_tag_optional(tags: &[DecryptedTag], selector: &str) -> InkResult<Option<DecryptedTag>> {
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

fn to_tag_views(engine: &SyncEngine<'_>, tags: &[DecryptedTag]) -> InkResult<Vec<TagView>> {
    let item_lookup = index_cached_items(&engine.cached_items()?);
    Ok(tags
        .iter()
        .map(|tag| {
            let meta = item_lookup.get(&tag.uuid);
            TagView {
                uuid: tag.uuid.clone(),
                content: TagContentView {
                    title: tag.title.clone(),
                },
                references: tag.references.clone(),
                parent_uuid: tag.parent_uuid.clone(),
                created_at: meta.and_then(|item| item.created_at.clone()),
                updated_at: tag
                    .updated_at
                    .clone()
                    .or_else(|| meta.and_then(|item| item.updated_at.clone())),
                content_type: "Tag".to_string(),
            }
        })
        .collect())
}
