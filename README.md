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

## Workspace Model

A workspace is the local root directory that `ink` manages.

- `<workspace>/.ink/config.toml`: profiles and server endpoints
- `<workspace>/.ink/state.db`: local SQLite state (sessions, sync cache, app state)
- `<workspace>/notes`: mirrored note files for the `default` profile
- `<workspace>/notes-<profile-key>`: mirrored note files for non-default profiles
- `<workspace>/.ink/mirror-index.json`: mirror index for the `default` profile
- `<workspace>/.ink/mirror-index-<profile-key>.json`: mirror index for non-default profiles

`ink` enforces single-profile workspaces (`default` only).
Use one dedicated workspace per account/server.
Non-default profile usage (`--profile <non-default>`, `profile use <non-default>`, `profile set --name <non-default>`) returns a usage error.

## Session Model

- `ink auth login` exchanges credentials for session tokens (access + refresh) and stores them in `.ink/state.db`.
- Profiles are account-bound after login; switching to a different email on the same profile requires `ink --yes auth login --rebind-account`.
- Rebind is two-phase: credentials are validated first, then runtime cache/mirror cleanup is attempted; login still succeeds if cleanup partially fails, and warnings include recovery guidance.
- `ink auth status` checks auth state and auto-refreshes close-to-expiry sessions.
- `ink auth refresh` forces refresh; if refresh fails, the failure is recorded in stored session transport diagnostics (`refresh_transport_last_error`) and re-login may be required.
- Session-backed commands (`sync`, `note`, `tag`) automatically refresh near-expiry sessions before running.
- Refresh transport compatibility is persisted per profile (`token_body` or `dual_cookie_token_body`) with one-step fallback on contract mismatch.
- Refresh retries transient network/server failures with bounded backoff.
- `ink profile set --server` updates endpoint routing for the default profile without clearing bound email.

Standard Notes login payloads include an `ephemeral` flag; `ink` currently uses `ephemeral: false` (persistent session behavior).

## Core Commands

- Health and setup:

```bash
ink doctor --workspace <path>
ink profile list --workspace <path>
ink profile set --server <url> --workspace <path>
```

- Authentication:

```bash
ink auth login --workspace <path>
ink --yes auth login --rebind-account --workspace <path>
ink auth preflight --workspace <path> --json
ink auth status --workspace <path>
ink auth refresh --workspace <path>
ink auth logout --workspace <path>
ink --yes auth logout --purge --workspace <path>
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
ink note list --fields uuid,title,updated_at --limit 50 --cursor 0 --workspace <path> --json
ink note resolve "<title-or-query>" --workspace <path> --json
ink note get <selector> --workspace <path>
ink note new --title "Title" --text "Body" --workspace <path>
ink note upsert --title "Title" --text "Body" --workspace <path>
printf "Long body" | ink note upsert --title "Title" --text - --append --workspace <path>
ink note edit <selector> --text "Updated body" --workspace <path>
ink note delete <selector> --yes --workspace <path>
ink note search --query "keyword" --fields uuid,title --limit 25 --workspace <path> --json
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
- `--profile` may be omitted or set to `default`; non-default profile names are rejected.
- If `--workspace` is omitted, the default is `sandbox/workspace`.
- Local state is stored in `.ink/state.db` (SQLite).
- Mirrored note files are profile-scoped:
  - `default` profile uses `<workspace>/notes`
  - non-default profiles use `<workspace>/notes-<profile-key>`
- `--debug` enables verbose API response diagnostics (target `ink_api::http`).
- Set `INK_API_DEBUG_RAW=1` to include raw API response previews in debug logs (sensitive).
- Set `INK_API_DEBUG_MAX_CHARS=<n>` to control raw preview length (default `2000` chars).
- Session refresh uses adaptive transport compatibility (`token_body` and `dual_cookie_token_body`) and persists the last successful mode per profile.
- Set `INK_API_REFRESH_FALLBACK=0` to disable refresh-mode fallback when doing strict transport diagnostics.
- Set `INK_API_REFRESH_RETRY_ATTEMPTS=<n>` to control transient refresh retry count (default `2`, max `6`).
- Set `INK_API_REFRESH_RETRY_BASE_DELAY_MS=<ms>` to control base retry delay (default `100`, max `10000`).
- `ink auth login --rebind-account --json` includes `result.warning` when rebind cleanup had partial local failures.

## Automation

Use `--json` for machine-readable output and stable error handling.
`--json` responses include `contract_version` and `meta.timestamp` for contract-aware automation.

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

If rebind login succeeds with a cleanup warning:

1. Run `ink sync reset --yes --workspace <path>` to rebuild runtime cache/mirror for that profile.

## Release

- CI runs on every push/PR via GitHub Actions (`fmt`, `clippy`, `test`).
- Tagged releases (`v*`) build cross-platform binaries and publish assets to GitHub Releases.
- Homebrew tap publishes to `ivan-loh/homebrew-ink` (install with `brew tap ivan-loh/ink`).
- Publishing roadmap for remaining package managers is documented in `docs/PUBLISHING_PLAN.md`.
