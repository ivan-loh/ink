#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <crate-name> [--bin]" >&2
  exit 1
fi

crate_name="$1"
crate_type="lib"
if [[ "${2:-}" == "--bin" ]]; then
  crate_type="bin"
fi

if [[ ! "$crate_name" =~ ^ink-[a-z0-9-]+$ ]]; then
  echo "crate name must match: ink-[a-z0-9-]+" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
crate_dir="$repo_root/crates/$crate_name"
cargo_toml="$repo_root/Cargo.toml"
member_entry="  \"crates/$crate_name\","

if [[ -e "$crate_dir" ]]; then
  echo "crate already exists: $crate_dir" >&2
  exit 1
fi

mkdir -p "$crate_dir/src"

cat > "$crate_dir/Cargo.toml" <<EOF
[package]
name = "$crate_name"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
EOF

if [[ "$crate_type" == "bin" ]]; then
  bin_name="${crate_name#ink-}"
  cat >> "$crate_dir/Cargo.toml" <<EOF

[[bin]]
name = "$bin_name"
path = "src/main.rs"
EOF

  cat > "$crate_dir/src/main.rs" <<EOF
fn main() {
    eprintln!("$crate_name scaffold: implement binary entrypoint");
}
EOF
else
  cat > "$crate_dir/src/lib.rs" <<EOF
/// $crate_name scaffold.
pub const CRATE_STATUS: &str = "scaffold";
EOF
fi

if ! grep -Fq "\"crates/$crate_name\"" "$cargo_toml"; then
  tmp_file="$(mktemp)"
  awk -v entry="$member_entry" '
    BEGIN { in_workspace = 0; in_members = 0; inserted = 0 }
    /^\[workspace\]/ { in_workspace = 1 }
    in_workspace && /^members = \[/ { in_members = 1 }
    in_members && /^\]/ && inserted == 0 {
      print entry
      inserted = 1
    }
    { print }
  ' "$cargo_toml" > "$tmp_file"
  mv "$tmp_file" "$cargo_toml"
fi

echo "Created $crate_name ($crate_type) at $crate_dir"
echo "Next: cargo check -p $crate_name"
