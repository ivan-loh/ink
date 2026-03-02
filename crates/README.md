# Crates Conventions

When adding new crates/modules:

1. Keep crate names prefixed with `ink-`.
2. Re-export only stable public API from `src/lib.rs`.
3. Put tests in `tests/` for integration behavior and `#[cfg(test)]` for local unit tests.
4. Prefer shared dependencies via `[workspace.dependencies]` in root `Cargo.toml`.
5. Keep each crate focused on one boundary (API, store, sync, CLI, etc.).
6. Prefer one shared implementation point for cross-cutting runtime behavior (for example, refresh transport/session persistence is centralized in `ink-sync` and consumed by CLI paths).
7. Preserve the single-profile workspace contract (`default` only); multi-profile behavior should fail fast with actionable usage errors.
