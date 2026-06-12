# nnn — Agent Guide

Minimal Linux sandbox using Landlock. Restricts a process to only access
whitelisted directories. Nothing else.

## Design Goals

- **Minimal surface.** One file (`src/main.rs`, ~500 lines). Six dependencies.
  No profiles, deny lists, network filtering, or any feature that isn't
  "whitelist directories for this process."
- **Config is just paths.** Global config (`~/.config/nnn/config.toml`) sets
  your baseline. Project config (`.nnn.toml` in git root) adds project-specific
  paths. Both are just `allow_read` and `allow_write` arrays.
- **CLI ergonomics.** `nnn add-ro ./src` edits `.nnn.toml` in place via
  `toml_edit` (preserving formatting). `nnn show` prints the resolved rules.
  No manual toml editing needed day-to-day.
- **Landlock only.** No seccomp, no cgroups, no containers, no capabilities.
  Landlock is the only sandboxing primitive. If Landlock can't enforce it
  (e.g. denying reads within an allowed tree), nnn won't pretend otherwise.
- **One-shot exec.** nnn sandboxes itself and replaces its process with the
  target command. No daemon, no fork, no supervision tree.

## Dependency Rationale

| Dependency | Why |
|---|---|
| `clap` | CLI parsing (derive API, subcommands) |
| `env_logger` + `log` | Diagnostic logging (warn mode) |
| `serde` | TOML deserialization (Raw struct in `load_toml_file`) |
| `toml_edit` | Reading + editing `.nnn.toml` (format-preserving) |
| `landlock` | Landlock ABI bindings |

The only non-obvious dependency is `toml_edit` — it's used for both
deserialization and programmatic editing (`add-ro`/`add-rw` insert paths
without reformatting the file). `serde` with `derive` feature is used only
for the internal `Raw` struct in `load_toml_file`.

Everything else is stdlib: `std::os::unix::process::CommandExt::exec` for
process replacement, `std::path` for path handling, `std::env` for env
sanitization.

## Quick Start

```sh
make build    # cargo build (debug)
make release  # cargo build --release
make test     # cargo test
make clean    # cargo clean
```

## Subcommands

```sh
nnn exec [OPTIONS] -- <COMMAND>  # Run sandboxed
nnn add-ro <DIR>                 # Add read-only path to .nnn.toml
nnn add-rw <DIR>                 # Add read-write path to .nnn.toml
nnn show                         # Show resolved rules for this directory
nnn init                         # Write default global config
```

### `nnn exec`

```sh
nnn exec -- cargo build
nnn exec --allow-read ./extra -- ./my-script
```

Config resolution order (each later step appends and deduplicates):

1. Global config: `$XDG_CONFIG_HOME/nnn/config.toml` (or `~/.config/nnn/config.toml`)
2. Project config: `.nnn.toml` found by walking up from cwd
3. CLI flags: `--allow-read` / `--allow-write`

Global config is optional — if it doesn't exist, only system default paths
are allowed. Project config is optional — if no `.nnn.toml` is found, only
global + system paths apply.

### `nnn add-ro` / `add-rw`

```sh
cd my-project
nnn add-ro ./src          # creates .nnn.toml in git root (or cwd)
nnn add-rw ./output       # appends to existing .nnn.toml
nnn add-ro ./src          # no-op (already present)
```

Uses `toml_edit::DocumentMut` to edit `.nnn.toml` in place — preserves
comments, formatting, and ordering. Config file is created in the nearest
git root (walked up from cwd) or cwd if no `.git` directory is found.

### `nnn show`

Prints the global config path, project config path, and the merged result:

```
Global config: /home/user/.config/nnn/config.toml
  allow-read:
    /usr
    /lib
  allow-write:
    /tmp

Project config: /home/user/project/.nnn.toml
  allow-read:
    ./src
  allow-write:
    ./output

Resolved (merged):
  allow-read:
    /usr
    /lib
    ./src
  allow-write:
    /tmp
    ./output
```

## Environment Sanitization

Before exec, nnn strips `LD_*` and `DYLD_*` environment variables
(library injection vectors). It injects `NNN=1` so the sandboxed process
can detect it's running under nnn.

## CI

Simple Rust CI — `cargo build && cargo test`. No matrix, no platforms,
no containers.

## Known Issues

- `add_rule` failure panics with no recovery (Landlock's `RulesetCreated`
  builder consumes self on `add_rule`, so there's no way to continue).
- Proc symlinks (`/dev/stdout`, `/dev/stderr` → `/proc/self/fd/*`) are
  silently skipped — Landlock rejects path references pointing into proc.
- Landlock cannot deny reads within an allowed directory tree (the kernel
  limitation, not nnn's).
