# ink CLI Guide

`ink` is a workspace-based CLI for Standard Notes.

## Installation

### Homebrew (recommended)

```bash
brew tap ivan-loh/ink
brew install ink
ink --version
```

### From source

```bash
cargo build -p ink-cli
cargo run -q -p ink-cli -- --version
```

If `ink` is not on `PATH`, run commands as:

```bash
cargo run -q -p ink-cli -- <command> ...
```

## Usage

1. Set credentials in `.env` (project root) or shell:

```dotenv
SN_EMAIL=you@example.com
SN_PASSWORD=your-password
```

2. Initialize a workspace:

```bash
ink init --workspace sandbox/workspace --json
```

3. Authenticate and pull notes from server:

```bash
ink auth login --workspace sandbox/workspace --json
ink sync pull --workspace sandbox/workspace --json
```

4. Work with notes and tags:

```bash
ink note list --workspace sandbox/workspace
ink note new --title "Design note" --text "Initial draft" --workspace sandbox/workspace
ink tag add design --workspace sandbox/workspace
ink tag apply --note "Design note" --tag design --workspace sandbox/workspace
```

5. Push local changes back to server:

```bash
ink sync push --workspace sandbox/workspace --json
```

## Core Commands

- Health and setup:

```bash
ink doctor --workspace <path>
ink profile list --workspace <path>
ink profile set --name <profile> --server <url> --workspace <path>
ink profile use <profile> --workspace <path>
```

- Authentication:

```bash
ink auth login --workspace <path>
ink auth status --workspace <path>
ink auth refresh --workspace <path>
ink auth logout --workspace <path>
```

- Sync:

```bash
ink sync status --workspace <path>
ink sync pull --workspace <path>
ink sync push --workspace <path>
ink sync conflicts --workspace <path>
ink sync resolve <conflict_id> --use local --workspace <path>
ink sync resolve <conflict_id> --use server --workspace <path>
ink sync reset --yes --workspace <path>
```

- Notes:

```bash
ink note list --workspace <path>
ink note get <selector> --workspace <path>
ink note new --title "Title" --text "Body" --workspace <path>
ink note edit <selector> --text "Updated body" --workspace <path>
ink note delete <selector> --yes --workspace <path>
ink note search --query "keyword" --workspace <path>
```

- Tags:

```bash
ink tag list --workspace <path>
ink tag add "design" --workspace <path>
ink tag rename <selector> "new-name" --workspace <path>
ink tag delete <selector> --yes --workspace <path>
ink tag apply --note <note-selector> --tag <tag-selector> --workspace <path>
```

## Operational Notes

- Global flags: `--workspace`, `--profile`, `--server`, `--json`, `--yes`.
- If `--workspace` is omitted, the default is `sandbox/workspace`.
- Local state is stored in `.ink/state.db` (SQLite).
- Mirrored note files are under `<workspace>/notes`.

## Automation

Use `--json` for machine-readable output and stable error handling.

Exit codes:

- `0` success
- `2` usage
- `3` auth
- `4` sync
- `5` crypto
- `6` io

## Recovery

If local workspace state is corrupted:

1. Remove `<workspace>/.ink/state.db`.
2. Run `ink sync pull --workspace <path>` to rebuild local cache/state.

## Release

- CI runs on every push/PR via GitHub Actions (`fmt`, `clippy`, `test`).
- Tagged releases (`v*`) build cross-platform binaries and publish assets to GitHub Releases.
- Homebrew tap publishes to `ivan-loh/homebrew-ink` (install with `brew tap ivan-loh/ink`).
- Publishing roadmap for remaining package managers is documented in `docs/PUBLISHING_PLAN.md`.
