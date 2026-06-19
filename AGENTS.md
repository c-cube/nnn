# nnn — Agent Guide

Minimal Linux sandbox using Landlock. Restricts a process to only access
whitelisted directories. Nothing else.

## Design Goals

- **Minimal surface.** One file (`src/main.rs`, ~680 lines). Eight dependencies.
  No profiles, deny lists, or any feature that isn't
  "restrict this process."
- **Config is just paths.** Global config (`~/.config/nnn/config.toml`) sets
  your baseline. Project config (`.nnn.toml` in git root) adds project-specific
  paths. Both are just `allow_read` and `allow_write` arrays.
- **CLI ergonomics.** `nnn add-ro ./src` edits `.nnn.toml` in place via
  `toml_edit` (preserving formatting). `nnn show` prints the resolved rules.
  No manual toml editing needed day-to-day.
- **Landlock + seccomp.** Landlock restricts filesystem access. Seccomp-bpf
  blocks dangerous syscalls (ptrace, bpf, mount, unshare, etc.) that Landlock
  doesn't cover. Network can be denied by default (TCP connect only,
  Landlock ABI V4+).
- **One-shot exec.** nnn sandboxes itself and replaces its process with the
  target command. No daemon, no fork, no supervision tree.

## Dependency Rationale

| Dependency | Why |
|---|---|
| `anyhow` | Error handling with context (no panics) |
| `clap` | CLI parsing (derive API, subcommands, external_subcommand) |
| `env_logger` + `log` | Diagnostic logging (warn mode) |
| `libc` | Syscall constants for seccomp filter |
| `serde` | TOML deserialization (Raw struct in `load_toml_file`) |
| `seccompiler` | seccomp-bpf filter compilation and application |
| `toml_edit` | Reading + editing `.nnn.toml` (format-preserving) |
| `landlock` | Landlock ABI bindings |

`toml_edit` is used for both deserialization and programmatic editing
(`add-ro`/`add-rw` insert paths without reformatting). `serde` with `derive`
is used only for the internal `Raw` struct in `load_toml_file`.

The `Config` struct is local (not serde-deserialized directly from TOML) —
a separate `Raw` struct with `#[serde(rename_all = "kebab-case")]` bridges
the kebab-case TOML keys into the code.

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

Bare `nnn <command>` (no subcommand) is **rejected** by clap to prevent
confusing mistakes like `nnn allow-read ~/`. Use `--` to run a command
without the explicit exec subcommand:

```sh
nnn -- cargo build     # equivalent to: nnn exec -- cargo build
```

### `nnn exec`

```sh
nnn exec -- cargo build
nnn exec --add-ro ./extra -- ./my-script
nnn exec --allow-port 443 -- curl https://example.com
nnn exec --no-auto-cwd -- curl example.com   # Don't auto-allow rw on cwd
nnn x -- cargo build                          # alias
```

Config resolution order (each later step appends and deduplicates):

1. Global config: `$XDG_CONFIG_HOME/nnn/config.toml` (or `~/.config/nnn/config.toml`)
2. Project config: `.nnn.toml` found by walking up from cwd
3. `NNN_CONFIG` env: path to an additional TOML file (loaded after project config)
4. `NNN_RO` / `NNN_RW` env: comma-separated paths (loaded before CLI flags)
5. CLI flags: `--add-ro` / `--add-rw`

Global config is optional — if it doesn't exist, only system default paths
are allowed. Project config is optional — if no `.nnn.toml` is found, only
global + system paths apply.

### `nnn add-ro` / `add-rw`

```sh
cd my-project
nnn add-ro ./src          # creates .nnn.toml in git root (or cwd)
nnn add-rw ./output       # appends to existing .nnn.toml
nnn add-ro ./src          # no-op (already present)
nnn add-ro -g ~/.git      # modify global config instead of project
```

Uses `toml_edit::DocumentMut` to edit `.nnn.toml` in place — preserves
comments, formatting, and ordering. Config file is created in the nearest
git root (walked up from cwd) or cwd if no `.git` directory is found.

### `nnn show`

Prints the global config path, project config path, and the merged result:

```
Global config: /home/user/.config/nnn/config.toml
  allow-read: /usr, /lib
  allow-write: /tmp

Project config: /home/user/project/.nnn.toml
  allow-read: ./src
  allow-write: ./output

Resolved (merged):
  allow-read: /usr, /lib, ./src
  allow-write: /tmp, ./output
```

### `nnn init`

Writes a default config to `~/.config/nnn/config.toml` with sensible system
paths. Refuses to overwrite an existing file. Default config includes:

- `allow-read`: `/bin/`, `/usr/bin/`, `/usr/local/bin`, `~/.cargo/bin`, `~/.config/nnn`
- `allow-write`: `/tmp/nnn/`

## Environment Sanitization

Before exec, nnn strips `LD_*` and `DYLD_*` environment variables
(library injection vectors). It injects `NNN=1` so the sandboxed process
can detect it's running under nnn.

The sandboxed environment starts from the current process env (minus
dangerous vars), then `env_clear()` + selective re-add via `exec_command`.
This means the child process only sees what nnn's own process sees.

## Default Landlock Rules

**Read-only** (`/usr`, `/lib`, `/lib64`, `/lib32`, `/bin`, `/sbin`, `/etc`,
`/proc`, `/sys`, `/run`, `/var`, `/opt`, `/dev`, `/tmp`)

**Read-write** (`/dev/null`, `/dev/tty`, `/tmp`, `/var/tmp`)

Additionally, if `--no-auto-cwd` is not set, the current working directory
gets read-write access.

Paths from config (`~` expanded) are added as read-only or read-write rules.

**Note:** `/dev/stdout` and `/dev/stderr` are symlinks to `/proc/self/fd/*`
and are silently skipped — they work through the existing `/dev` and `/proc`
read rules.

## CI

Rust CI — `cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo test`.

## Known Issues

- `add_rule` failure returns error (no panic). The `RulesetCreated`
  builder consumes self on `add_rule`, so the ruleset is lost on failure.
- Proc symlinks (`/dev/stdout`, `/dev/stderr` → `/proc/self/fd/*`) are
  silently skipped — Landlock rejects path references pointing into proc.
- Landlock cannot deny reads within an allowed directory tree (the kernel
  limitation, not nnn's).
- `ABI::V5` is hardcoded — may fail on kernels < 5.19. No runtime ABI
  detection or fallback.
- Network restriction only covers TCP connect (Landlock ABI V4+). UDP is
  unrestricted.
