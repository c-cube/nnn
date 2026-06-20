
# nnn

Minimal Linux sandbox, using Landlock to run a program with a whitelist of
allowed directories. Think `exec` but can only read or read/write from
pre-defined directories.

The goal is to make sandboxing both very low friction (have per-project config,
an easy CLI) and easy to audit (tiny codebase + dependency cone).

```sh
nnn exec -- cargo build          # Run `cargo` but sandboxed
nnn -- cargo build               # Same with `--` instead of `exec`
nnn add-ro ./src                 # Add read-only path to project config
nnn add-rw ./output              # Add read-write path to project config
nnn add-ro -g ~/.git             # Add read-only access to global config (xdg)
nnn show                         # Show resolved rules for current project
nnn init                         # Write default global config
```

Config: global (`~/.config/nnn/config.toml`, xdg config directory) + project (`.nnn.toml` in git root).
Both are just `allow-read` and `allow-write` whitelists, combined at runtime.

Additional CLI arguments `--add-ro`/`--add-rw`, as well as env variables
`NNN_RO` and `NNN_RW` can be used to add permissions in a more ad-hoc way
(so it's compatible with [direnv](https://direnv.net/)).

```env
# .envrc
export NNN_RO="$HOME/src"
export NNN_RW="$HOME/output"
```

## Syscall filtering

Seccomp is used to block some syscalls (unless `seccomp = false` is in config).

## Linux requirements

Should require Linux ≥ 5.13.

If `nnn` fails to setup landlock correctly, it will exit with an error rather
than silently run the command sandboxlessly.

## Config

Global (`~/.config/nnn/config.toml`) + project (`.nnn.toml` in closest git root, if present).
The default config is intended to be a starting point, a real workflow will need
additional entries (eg. to your package manager, some cache paths, etc.)

```toml
allow-read = ["/bin", "/usr/bin"]
allow-write = ["/tmp/"]
seccomp = true            # default, can be overridden per config

[network]
deny-default = false      # deny all outbound TCP by default, when true
allow-ports = [80, 443]   # ports allowed when deny-default = true
```

CLI: `--allow-port 80,443` appends to the config ports.

Environment variables (`NNN_RO`, `NNN_RW` — comma-separated paths) are loaded before CLI flags. `NNN_CONFIG` loads an additional TOML file after project config. Compatible with [direnv](https://direnv.net/):

```env
# .envrc
export NNN_RO="$HOME/src"
export NNN_RW="$HOME/output"
```

## Limitations

- UDP restrict requires Landlock ABI V5. Landlock ABI V4 only supports `ConnectTcp`. Setting `deny-udp = true` on kernel < 5.19 is a no-op.
- `/proc` is fully readable. Landlock cannot deny reads within an allowed directory tree. Since `/proc` is a system default path, all process information (command lines, environment variables of other processes) is visible to the sandboxed process.
- Once started, allowing more directories is impossible. Change the config and restart the sandboxed process.
- Not reviewed by security experts :-)
