
# nnn

Minimal Linux sandbox using Landlock. Restricts a process to only access whitelisted directories.

The goal is to make sandboxing both very low friction (have per-project config,
an easy CLI) and easy to audit (tiny codebase + dependency cone).

```sh
nnn exec -- cargo build          # Run sandboxed
nnn add-ro ./src                 # Add read-only path to project config
nnn add-rw ./output              # Add read-write path to project config
nnn add-ro -g ~/.git             # Add read-only access to global config
nnn show                         # Show resolved rules
nnn init                         # Write default global config
```

Config: global (`~/.config/nnn/config.toml`) + project (`.nnn.toml` in git root). Both are just `allow-read` and `allow-write` arrays. Merged at runtime. CLI `--allow-read`/`--allow-write` add on top.

Environment variables (`NNN_RO`, `NNN_RW` — comma-separated paths) are loaded before CLI flags. `NNN_CONFIG` loads an additional TOML file after project config. Compatible with [direnv](https://direnv.net/):

```env
# .envrc
export NNN_RO="$HOME/src"
export NNN_RW="$HOME/output"
```

Landlock is the primary primitive, with a seccomp-bpf deny list blocking dangerous syscalls (enabled by default, disable via `seccomp = false` in config). Requires Linux ≥ 5.13 (Landlock) and ≥ 3.5 (seccomp).

## Config

Global (`~/.config/nnn/config.toml`) + project (`.nnn.toml` in git root). Merged at runtime. CLI flags add on top.

```toml
allow-read = ["/bin", "/usr/bin"]
allow-write = ["/tmp/nnn"]
seccomp = true            # default, can be overridden per config

[network]
deny-default = false      # deny all outbound TCP when true
allow-ports = [80, 443]   # ports allowed when deny-default = true
```

CLI: `--allow-port 443 --allow-port 80` appends to the config ports.

Environment variables (`NNN_RO`, `NNN_RW` — comma-separated paths) are loaded before CLI flags. `NNN_CONFIG` loads an additional TOML file after project config. Compatible with [direnv](https://direnv.net/):

```env
# .envrc
export NNN_RO="$HOME/src"
export NNN_RW="$HOME/output"
```

## Limitations

- **UDP restrict requires ABI V5.** Landlock ABI V4 only supports `ConnectTcp`. Setting `deny-udp = true` on kernel < 5.19 is a no-op.
- **`/proc` is fully readable.** Landlock cannot deny reads within an allowed directory tree. Since `/proc` is a system default path, all process information (command lines, environment variables of other processes) is visible to the sandboxed process.
- **No kernel ABI negotiation.** `ABI::V5` is hardcoded. Kernels between 5.13 and 5.18 will fail with an error about kernel ABI, not a graceful fallback.
