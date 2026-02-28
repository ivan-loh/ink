# Crates Conventions

When adding new crates/modules:

1. Keep crate names prefixed with `ink-`.
2. Re-export only stable public API from `src/lib.rs`.
3. Put tests in `tests/` for integration behavior and `#[cfg(test)]` for local unit tests.
4. Prefer shared dependencies via `[workspace.dependencies]` in root `Cargo.toml`.
5. Keep each crate focused on one boundary (API, store, sync, CLI, etc.).
