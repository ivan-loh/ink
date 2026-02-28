# Publishing Plan

This document describes how to ship `ink` binaries from GitHub Actions and publish via package managers.

## Current Automation (Implemented)

- `CI` workflow on push/PR/manual:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all --all-features`
- `Release` workflow on version tags (`v*`) or manual trigger:
  - Builds release binaries for:
    - `x86_64-unknown-linux-gnu`
    - `x86_64-apple-darwin`
    - `aarch64-apple-darwin`
    - `x86_64-pc-windows-msvc`
  - Packages binaries as `.tar.gz` (Unix) and `.zip` (Windows)
  - Uploads release assets and `SHA256SUMS.txt` to GitHub Releases

## Release Process

1. Update version in workspace if needed.
2. Commit version changes.
3. Create and push a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

4. GitHub Actions publishes binaries to the release page.

## Package Manager Rollout

| Phase | Target | Delivery Mode | Notes |
|---|---|---|---|
| 1 | GitHub Releases | Automated now | Release artifacts are already produced by CI/CD. |
| 2 | Homebrew (custom tap) | Next | Add formula updates to a `homebrew-ink` tap repo from release assets/checksums. |
| 3 | Scoop (Windows) | Next | Add manifest updates in a scoop bucket repo using release checksums. |
| 4 | Winget | Optional | Submit manifest updates to `microsoft/winget-pkgs` on each release. |
| 5 | crates.io (`cargo install`) | Optional | Requires publish strategy for workspace crates (internal deps currently path-based). |

## One-Time Setup For Phase 2/3/4

- Create tap/bucket repos under your GitHub account:
  - `homebrew-ink`
  - `scoop-ink`
- Add a repo secret for cross-repo pushes from Actions:
  - `PACKAGE_REPO_PUSH_TOKEN` (classic PAT with `repo` scope)
- Add repo variables:
  - `HOMEBREW_TAP_REPO` (example: `ivan-loh/homebrew-ink`)
  - `SCOOP_BUCKET_REPO` (example: `ivan-loh/scoop-ink`)

## Operational Notes

- GitHub repo visibility is now `PUBLIC`.
- Release assets are suitable for direct download/install scripts today.
- Package manager publishing can be layered on top without changing core build logic.
