# nounours — Agent Guide

Minimal Linux sandbox using Landlock. Runs a command inside a
Landlock-restricted environment with configurable read/write directory
whitelists.

## Design Philosophy

**Minimize dependencies. Keep things simple.**

This tool has one job: restrict a process to only access specified
directories. No profiles, no command deny/allow lists, no network
filtering, no complex configuration model. Just paths.

Every dependency added is a tradeoff — prefer stdlib solutions.

## Quick Start

```sh
make build    # cargo build (debug)
make release  # cargo build --release
make test     # cargo test
make clean    # cargo clean
```

The binary is named `smolsandbox`.

## Architecture

```
main.rs        → CLI parsing (clap), config resolution, runner
├── config.rs  → Config struct (allow_read, allow_write), TOML deserialization
├── landlock.rs → Landlock ruleset application
├── paths.rs   → Path expansion (~ expansion)
└── sanitize.rs → Environment sanitization (strips LD_*/DYLD_*)
```

**Control flow:**
1. Load global config from `$XDG_CONFIG_HOME/nounours/config.toml` (or `~/.config/`)
2. Load project config from `.nounours.toml` (walked up from cwd)
3. Merge project config on top of global config
4. Apply CLI overrides (`--allow-read`, `--allow-write`)
5. Sanitize environment
6. Apply Landlock rules
7. `exec` the command (replaces process)

## Configuration

### Global config: `~/.config/nounours/config.toml`

```toml
allow_read = ["/usr", "/lib", "/lib64"]
allow_write = ["/tmp"]
```

### Project config: `.nounours.toml` (in git root)

```toml
allow_read = ["./src", "./data"]
allow_write = ["./output"]
```

Project paths are added to the global config. Relative paths are relative to
the project root (git root of the repo, or cwd).

The config is intentionally minimal: just read and write directory
whitelists. Nothing more.

## CLI

```sh
smolsandbox [OPTIONS] -- <COMMAND>

Options:
  -w, --warn              Log planned restrictions without enforcing
      --allow-read PATH   Additional read-allowed path
      --allow-write PATH  Additional write-allowed path
      --project-config PATH  Path to .nounours.toml (auto-detected from git root)
```

### Warn Mode (`--warn`)

Landlock rules are not applied — just logged. Useful for testing what would
happen without restriction.

## CI

Simple Rust CI (`cargo build && cargo test`).

## Known Issues

- `add_path_rule` panics on `add_rule` failure with no recovery path
  (Landlock's builder pattern consumes the ruleset)
- Symlinks pointing into `/proc/self/fd` are silently skipped
  (they can't be used as Landlock path references)
