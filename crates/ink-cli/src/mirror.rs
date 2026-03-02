use ink_core::{InkError, InkResult};
use ink_fs::{DEFAULT_PROFILE, WorkspacePaths};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MirrorIndex {
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<MirrorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorEntry {
    pub uuid: String,
    pub title: String,
    pub path: String,
    pub sha256: String,
    pub remote_updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorPullResult {
    pub written: usize,
    pub removed: usize,
    pub notes_dir: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorResetResult {
    pub removed_files: usize,
    pub notes_dir: String,
}

#[derive(Debug, Clone)]
pub struct MirrorNote {
    pub uuid: String,
    pub title: String,
    pub text: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocalMirrorNote {
    pub uuid: Option<String>,
    pub title: String,
    pub text: String,
    pub updated_at: Option<String>,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
struct MirrorScope {
    notes_dir: PathBuf,
    mirror_index_path: PathBuf,
    notes_relative_prefix: String,
}

pub fn notes_dir_for_profile(paths: &WorkspacePaths, profile: &str) -> PathBuf {
    mirror_scope(paths, profile).notes_dir
}

pub fn load_index(paths: &WorkspacePaths, profile: &str) -> InkResult<MirrorIndex> {
    let scope = mirror_scope(paths, profile);
    let raw = match fs::read_to_string(&scope.mirror_index_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(MirrorIndex {
                version: 1,
                entries: Vec::new(),
            });
        }
        Err(err) => {
            return Err(InkError::io(format!(
                "failed to read mirror index '{}': {}",
                scope.mirror_index_path.display(),
                err
            )));
        }
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(MirrorIndex {
            version: 1,
            entries: Vec::new(),
        });
    }

    let parsed: MirrorIndex = serde_json::from_str(trimmed).map_err(|err| {
        InkError::io(format!(
            "failed to parse mirror index '{}': {}",
            scope.mirror_index_path.display(),
            err
        ))
    })?;

    Ok(parsed)
}

pub fn save_index(paths: &WorkspacePaths, profile: &str, index: &MirrorIndex) -> InkResult<()> {
    let scope = mirror_scope(paths, profile);
    let encoded = serde_json::to_string_pretty(index)
        .map_err(|err| InkError::io(format!("failed to encode mirror index: {err}")))?;

    if let Some(parent) = scope.mirror_index_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            InkError::io(format!(
                "failed to create mirror index directory '{}': {}",
                parent.display(),
                err
            ))
        })?;
    }

    fs::write(&scope.mirror_index_path, encoded).map_err(|err| {
        InkError::io(format!(
            "failed to write mirror index '{}': {}",
            scope.mirror_index_path.display(),
            err
        ))
    })
}

pub fn pull_to_mirror(
    paths: &WorkspacePaths,
    profile: &str,
    notes: &[MirrorNote],
) -> InkResult<MirrorPullResult> {
    let scope = mirror_scope(paths, profile);
    fs::create_dir_all(&scope.notes_dir).map_err(|err| {
        InkError::io(format!(
            "failed to ensure notes dir '{}' exists: {}",
            scope.notes_dir.display(),
            err
        ))
    })?;

    let existing_index = load_index(paths, profile)?;
    let existing_map: HashMap<String, MirrorEntry> = existing_index
        .entries
        .into_iter()
        .map(|entry| (entry.uuid.clone(), entry))
        .collect();
    let local_paths_by_uuid = local_paths_by_uuid(paths, profile)?;

    let mut next_entries = Vec::with_capacity(notes.len());
    let mut written = 0;
    let mut removed = 0;
    let mut used_paths = HashSet::new();
    let mut stale_paths = HashSet::new();

    for note in notes {
        let relative_path = select_relative_path_for_note(
            note,
            &scope.notes_relative_prefix,
            &existing_map,
            &local_paths_by_uuid,
            &used_paths,
        );
        used_paths.insert(relative_path.clone());

        if let Some(existing) = existing_map.get(&note.uuid)
            && existing.path != relative_path
        {
            stale_paths.insert(existing.path.clone());
        }

        let absolute_path = paths.root.join(&relative_path);
        if let Some(parent) = absolute_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                InkError::io(format!(
                    "failed to create mirror subdirectory '{}': {}",
                    parent.display(),
                    err
                ))
            })?;
        }

        let rendered = render_note_markdown(note);
        fs::write(&absolute_path, rendered).map_err(|err| {
            InkError::io(format!(
                "failed to write mirrored note '{}': {}",
                absolute_path.display(),
                err
            ))
        })?;
        written += 1;

        next_entries.push(MirrorEntry {
            uuid: note.uuid.clone(),
            title: note.title.clone(),
            path: relative_path,
            sha256: stable_note_text_sha(&note.text),
            remote_updated_at: note.updated_at.clone(),
        });
    }

    for relative in stale_paths {
        if used_paths.contains(&relative) {
            continue;
        }

        let stale_path = paths.root.join(&relative);
        if stale_path.is_file() {
            fs::remove_file(&stale_path).map_err(|err| {
                InkError::io(format!(
                    "failed to remove stale mirrored path '{}': {}",
                    stale_path.display(),
                    err
                ))
            })?;
            removed += 1;
        }
    }

    let remote_uuids: std::collections::HashSet<&str> =
        notes.iter().map(|note| note.uuid.as_str()).collect();

    for (uuid, entry) in existing_map {
        if remote_uuids.contains(uuid.as_str()) {
            continue;
        }

        let absolute_path = paths.root.join(entry.path);
        if absolute_path.is_file() {
            let _ = fs::remove_file(absolute_path);
            removed += 1;
        }
    }

    save_index(
        paths,
        profile,
        &MirrorIndex {
            version: 1,
            entries: next_entries,
        },
    )?;

    Ok(MirrorPullResult {
        written,
        removed,
        notes_dir: scope.notes_dir.display().to_string(),
    })
}

pub fn clear_local_mirror(paths: &WorkspacePaths, profile: &str) -> InkResult<MirrorResetResult> {
    let scope = mirror_scope(paths, profile);
    let mut removed_files = 0usize;

    if scope.notes_dir.exists() {
        if !scope.notes_dir.is_dir() {
            return Err(InkError::io(format!(
                "expected notes directory '{}'",
                scope.notes_dir.display()
            )));
        }

        removed_files = WalkDir::new(&scope.notes_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .count();

        fs::remove_dir_all(&scope.notes_dir).map_err(|err| {
            InkError::io(format!(
                "failed to remove notes directory '{}': {}",
                scope.notes_dir.display(),
                err
            ))
        })?;
    }

    fs::create_dir_all(&scope.notes_dir).map_err(|err| {
        InkError::io(format!(
            "failed to recreate notes directory '{}': {}",
            scope.notes_dir.display(),
            err
        ))
    })?;

    save_index(
        paths,
        profile,
        &MirrorIndex {
            version: 1,
            entries: Vec::new(),
        },
    )?;

    Ok(MirrorResetResult {
        removed_files,
        notes_dir: scope.notes_dir.display().to_string(),
    })
}

fn local_paths_by_uuid(
    paths: &WorkspacePaths,
    profile: &str,
) -> InkResult<HashMap<String, Vec<String>>> {
    let mut by_uuid: HashMap<String, Vec<String>> = HashMap::new();
    for note in scan_local_mirror(paths, profile)? {
        let Some(uuid) = note.uuid else {
            continue;
        };
        by_uuid.entry(uuid).or_default().push(note.path);
    }

    for paths in by_uuid.values_mut() {
        paths.sort();
        paths.dedup();
    }

    Ok(by_uuid)
}

fn select_relative_path_for_note(
    note: &MirrorNote,
    notes_relative_prefix: &str,
    existing_map: &HashMap<String, MirrorEntry>,
    local_paths_by_uuid: &HashMap<String, Vec<String>>,
    used_paths: &HashSet<String>,
) -> String {
    if let Some(selected) = local_paths_by_uuid.get(&note.uuid).and_then(|paths| {
        pick_local_candidate_path(paths, existing_map.get(&note.uuid), used_paths)
    }) {
        return selected;
    }

    if let Some(existing) = existing_map.get(&note.uuid)
        && !used_paths.contains(&existing.path)
    {
        return existing.path.clone();
    }

    unique_slug_path(note, notes_relative_prefix, used_paths)
}

fn pick_local_candidate_path(
    candidates: &[String],
    existing: Option<&MirrorEntry>,
    used_paths: &HashSet<String>,
) -> Option<String> {
    if let Some(existing) = existing
        && candidates.iter().any(|path| path == &existing.path)
        && !used_paths.contains(&existing.path)
    {
        return Some(existing.path.clone());
    }

    candidates
        .iter()
        .find(|candidate| !used_paths.contains(*candidate))
        .cloned()
}

fn unique_slug_path(
    note: &MirrorNote,
    notes_relative_prefix: &str,
    used_paths: &HashSet<String>,
) -> String {
    let slug = slugify(&note.title);
    let short = short_uuid(&note.uuid);
    let base = format!("{notes_relative_prefix}/{slug}--{short}.md");
    if !used_paths.contains(&base) {
        return base;
    }

    for suffix in 2.. {
        let candidate = format!("{notes_relative_prefix}/{slug}--{short}-{suffix}.md");
        if !used_paths.contains(&candidate) {
            return candidate;
        }
    }

    unreachable!("suffix loop should always find a free path")
}

pub fn scan_local_mirror(paths: &WorkspacePaths, profile: &str) -> InkResult<Vec<LocalMirrorNote>> {
    let scope = mirror_scope(paths, profile);
    if !scope.notes_dir.exists() {
        return Ok(Vec::new());
    }

    let mut notes = Vec::new();

    for entry in WalkDir::new(&scope.notes_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }

        notes.push(parse_local_note(paths, path)?);
    }

    Ok(notes)
}

fn mirror_scope(paths: &WorkspacePaths, profile: &str) -> MirrorScope {
    if profile == DEFAULT_PROFILE {
        return MirrorScope {
            notes_dir: paths.notes_dir.clone(),
            mirror_index_path: paths.mirror_index_path.clone(),
            notes_relative_prefix: "notes".to_string(),
        };
    }

    let profile_key = profile_storage_key(profile);
    let notes_dir_name = format!("notes-{profile_key}");
    MirrorScope {
        notes_dir: paths.root.join(&notes_dir_name),
        mirror_index_path: paths
            .ink_dir
            .join(format!("mirror-index-{profile_key}.json")),
        notes_relative_prefix: notes_dir_name,
    }
}

fn profile_storage_key(profile: &str) -> String {
    let mut slug = slugify(profile);
    if slug.len() > 40 {
        slug.truncate(40);
        slug = slug.trim_matches('-').to_string();
        if slug.is_empty() {
            slug = "profile".to_string();
        }
    }
    let digest = sha256(profile);
    let suffix = &digest[..8];
    format!("{slug}-{suffix}")
}

pub fn find_entry_by_uuid<'a>(index: &'a MirrorIndex, uuid: &str) -> Option<&'a MirrorEntry> {
    index.entries.iter().find(|entry| entry.uuid == uuid)
}

fn parse_local_note(paths: &WorkspacePaths, path: &Path) -> InkResult<LocalMirrorNote> {
    let raw = fs::read_to_string(path).map_err(|err| {
        InkError::io(format!(
            "failed to read mirrored note '{}': {}",
            path.display(),
            err
        ))
    })?;

    let mut uuid = None;
    let mut title = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("Untitled")
        .to_string();
    let mut updated_at = None;
    let mut text = raw.clone();

    if let Some(stripped) = raw.strip_prefix("---\n")
        && let Some(separator_idx) = stripped.find("\n---\n")
    {
        let frontmatter = &stripped[..separator_idx];
        text = stripped[(separator_idx + 5)..].to_string();

        for line in frontmatter.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };

            match key.trim() {
                "uuid" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        uuid = Some(value.to_string());
                    }
                }
                "title" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        title = value.to_string();
                    }
                }
                "updated_at" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        updated_at = Some(value.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let relative_path = make_relative(paths, path)?;

    Ok(LocalMirrorNote {
        uuid,
        title,
        text: text.trim_start_matches('\n').to_string(),
        updated_at,
        path: relative_path,
        sha256: stable_note_text_sha(text.trim_start_matches('\n')),
    })
}

fn stable_note_text_sha(text: &str) -> String {
    // Mirror renderer always appends a trailing newline if absent; normalize that away for diffing.
    let normalized = text.trim_start_matches('\n');
    let normalized = normalized.strip_suffix('\n').unwrap_or(normalized);
    sha256(normalized)
}

fn render_note_markdown(note: &MirrorNote) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("uuid: {}\n", note.uuid));
    out.push_str(&format!("title: {}\n", note.title.replace('\n', " ")));
    out.push_str(&format!(
        "updated_at: {}\n",
        note.updated_at.clone().unwrap_or_default()
    ));
    out.push_str("---\n\n");
    out.push_str(&note.text);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

pub fn sha256(input: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(input.as_bytes());
    let hash = digest.finalize();
    format!("{hash:x}")
}

fn short_uuid(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;

    for ch in input.chars() {
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            out.push(lowered);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        return "note".to_string();
    }

    trimmed.to_string()
}

fn make_relative(paths: &WorkspacePaths, path: &Path) -> InkResult<String> {
    let relative: PathBuf = path
        .strip_prefix(&paths.root)
        .map_err(|err| {
            InkError::io(format!(
                "failed to create relative path from '{}' to '{}': {}",
                paths.root.display(),
                path.display(),
                err
            ))
        })?
        .to_path_buf();

    Ok(relative.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ink_fs::init_workspace;

    fn fixture_note(uuid: &str, title: &str, text: &str, updated_at: &str) -> MirrorNote {
        MirrorNote {
            uuid: uuid.to_string(),
            title: title.to_string(),
            text: text.to_string(),
            updated_at: Some(updated_at.to_string()),
        }
    }

    #[test]
    fn pull_to_mirror_preserves_locally_moved_path_by_uuid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some("https://example.invalid")).expect("init");
        let paths = init.paths;

        let first = fixture_note(
            "11111111-1111-4111-8111-111111111111",
            "Phase 5 Note",
            "initial body",
            "2026-02-28T00:00:00.000000Z",
        );
        let _ = pull_to_mirror(&paths, DEFAULT_PROFILE, std::slice::from_ref(&first))
            .expect("first pull");

        let first_index = load_index(&paths, DEFAULT_PROFILE).expect("first index");
        assert_eq!(first_index.entries.len(), 1);
        let original_relative = first_index.entries[0].path.clone();
        let original_abs = paths.root.join(&original_relative);
        assert!(original_abs.exists(), "original note file should exist");

        let moved_abs = paths.root.join("notes/renamed/moved-note.md");
        fs::create_dir_all(
            moved_abs
                .parent()
                .expect("moved path should have a parent directory"),
        )
        .expect("create moved parent");
        fs::rename(&original_abs, &moved_abs).expect("rename mirror note file");

        let updated = fixture_note(
            "11111111-1111-4111-8111-111111111111",
            "Phase 5 Note",
            "updated body",
            "2026-02-28T00:01:00.000000Z",
        );
        let result = pull_to_mirror(&paths, DEFAULT_PROFILE, &[updated]).expect("second pull");
        assert_eq!(result.written, 1);

        let updated_index = load_index(&paths, DEFAULT_PROFILE).expect("updated index");
        assert_eq!(updated_index.entries.len(), 1);
        assert_eq!(updated_index.entries[0].path, "notes/renamed/moved-note.md");

        let moved_contents = fs::read_to_string(&moved_abs).expect("read moved file");
        assert!(moved_contents.contains("updated body"));
        assert!(
            !original_abs.exists(),
            "old path should stay removed after move"
        );
    }

    #[test]
    fn pull_to_mirror_keeps_existing_path_when_new_write_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some("https://example.invalid")).expect("init");
        let paths = init.paths;

        let uuid = "22222222-2222-4222-8222-222222222222";
        let first = fixture_note(
            uuid,
            "Failure Guard Note",
            "initial body",
            "2026-02-28T00:00:00Z",
        );
        let _ = pull_to_mirror(&paths, DEFAULT_PROFILE, std::slice::from_ref(&first))
            .expect("first pull");

        let index = load_index(&paths, DEFAULT_PROFILE).expect("load index");
        let original_relative = index.entries[0].path.clone();
        let original_abs = paths.root.join(&original_relative);
        let original_raw = fs::read_to_string(&original_abs).expect("read original file");

        // Remove UUID from the original file so path selection prefers the alternate local file.
        let without_uuid = original_raw.replacen(&format!("uuid: {uuid}"), "uuid: ", 1);
        fs::write(&original_abs, without_uuid).expect("rewrite original file without uuid");

        let moved_abs = paths.root.join("notes/renamed/read-only.md");
        fs::create_dir_all(
            moved_abs
                .parent()
                .expect("moved path should have a parent directory"),
        )
        .expect("create moved parent");
        fs::write(&moved_abs, &original_raw).expect("write moved file");

        let mut perms = fs::metadata(&moved_abs).expect("metadata").permissions();
        perms.set_readonly(true);
        fs::set_permissions(&moved_abs, perms).expect("set read-only permissions");

        let updated = fixture_note(
            uuid,
            "Failure Guard Note",
            "updated body",
            "2026-02-28T00:01:00Z",
        );
        let result = pull_to_mirror(&paths, DEFAULT_PROFILE, &[updated]);
        assert!(
            result.is_err(),
            "expected write failure for read-only moved file"
        );

        assert!(
            original_abs.exists(),
            "original mirrored path should remain when replacement write fails"
        );
    }

    #[test]
    fn mirror_paths_and_indexes_are_isolated_by_profile() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        let init = init_workspace(Some(&root), Some("https://example.invalid")).expect("init");
        let paths = init.paths;

        let default_note = fixture_note(
            "33333333-3333-4333-8333-333333333333",
            "Default Profile Note",
            "default profile body",
            "2026-02-28T00:00:00.000000Z",
        );
        let alt_note = fixture_note(
            "44444444-4444-4444-8444-444444444444",
            "Alt Profile Note",
            "alt profile body",
            "2026-02-28T00:00:01.000000Z",
        );

        let _ = pull_to_mirror(&paths, DEFAULT_PROFILE, std::slice::from_ref(&default_note))
            .expect("default pull");
        let _ = pull_to_mirror(&paths, "mainaccount", std::slice::from_ref(&alt_note))
            .expect("mainaccount pull");

        let default_index = load_index(&paths, DEFAULT_PROFILE).expect("default index");
        let alt_index = load_index(&paths, "mainaccount").expect("alt index");
        assert_eq!(default_index.entries.len(), 1);
        assert_eq!(alt_index.entries.len(), 1);
        assert!(
            default_index.entries[0].path.starts_with("notes/"),
            "default profile should continue using notes/"
        );
        assert!(
            alt_index.entries[0].path.starts_with("notes-"),
            "non-default profile should use dedicated notes dir"
        );

        let default_local =
            scan_local_mirror(&paths, DEFAULT_PROFILE).expect("scan default local mirror");
        let alt_local = scan_local_mirror(&paths, "mainaccount").expect("scan alt local mirror");
        assert_eq!(default_local.len(), 1);
        assert_eq!(alt_local.len(), 1);

        let default_file = paths.root.join(&default_index.entries[0].path);
        assert!(default_file.exists(), "default file should exist");

        let alt_notes_dir = notes_dir_for_profile(&paths, "mainaccount");
        assert_ne!(alt_notes_dir, paths.notes_dir);
        assert!(alt_notes_dir.exists(), "alt notes dir should be created");

        let clear_alt = clear_local_mirror(&paths, "mainaccount").expect("clear alt mirror");
        assert_eq!(clear_alt.removed_files, 1);
        assert!(
            default_file.exists(),
            "clearing alt profile mirror must not remove default profile notes"
        );
    }
}
