
# nnn

Minimal Linux sandbox using Landlock. Restricts a process to only access whitelisted directories.

```sh
nnn exec -- cargo build          # Run sandboxed
nnn add-ro ./src                 # Add read-only path to project config
nnn add-rw ./output              # Add read-write path to project config
nnn add-ro -g ~/.git             # Add read-only access to global config
nnn show                         # Show resolved rules
nnn init                         # Write default global config
```

Config: global (`~/.config/nnn/config.toml`) + project (`.nnn.toml` in git root). Both are just `allow-read` and `allow-write` arrays. Merged at runtime. CLI `--allow-read`/`--allow-write` add on top.

Landlock is the only primitive — no seccomp, no containers, no capabilities. Requires Linux ≥ 5.13.
