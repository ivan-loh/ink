# ink CLI Guide

`ink` is a workspace-based CLI for Standard Notes.

Examples below use `ink`. If `ink` is not on `PATH`, run commands as:

```bash
cargo run -q -p ink-cli -- <command> ...
```

## Quick Start

1. Build the binary:

```bash
cargo build -p ink-cli
cargo run -q -p ink-cli -- --version
```

2. Set credentials in `.env` (project root or current shell):

```dotenv
SN_EMAIL=you@example.com
SN_PASSWORD=your-password
```

3. Initialize a workspace:

```bash
cargo run -q -p ink-cli -- init --workspace sandbox/workspace --json
```

4. Authenticate and pull notes:

```bash
cargo run -q -p ink-cli -- auth login --workspace sandbox/workspace --json
cargo run -q -p ink-cli -- sync pull --workspace sandbox/workspace --json
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
- Publishing roadmap for package managers is documented in `docs/PUBLISHING_PLAN.md`.
