use crate::config::Config;
use crate::paths;
use landlock::{
    make_bitflags, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::path::Path;

/// System paths that should always be readable.
const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/lib32",
    "/bin",
    "/sbin",
    "/etc",
    "/proc",
    "/sys",
    "/run",
    "/var/lib",
    "/var/cache",
    "/opt",
    "/dev",
    "/tmp",
    "/nix",
    "/snap",
];

/// Default writable paths needed for basic operation.
/// Note: /dev/stdout and /dev/stderr are symlinks to /proc/self/fd/* and can't
/// be added as Landlock rules. /dev is already readable, and /proc is readable,
/// so they work through the existing rules.
const SYSTEM_WRITE_PATHS: &[&str] = &["/dev/null", "/dev/tty", "/tmp", "/var/tmp"];

/// Paths readable in deny-by-default mode (tooling runtimes).
/// These version managers need read access to their full directories.
fn default_readable_home_paths() -> Vec<String> {
    vec![
        // Node.js version managers
        "~/.nvm",
        "~/.fnm",
        "~/.volta",
        "~/.n",
        // Python
        "~/.pyenv",
        "~/.local/pipx",
        // Ruby
        "~/.rbenv",
        "~/.rvm",
        // Rust
        "~/.cargo/bin",
        "~/.rustup",
        // Go
        "~/go/bin",
        "~/.go",
        // User local bins
        "~/.local/bin",
        "~/bin",
        // Bun / Deno
        "~/.bun/bin",
        "~/.deno/bin",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn access_read() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir})
}

fn access_write(abi: ABI) -> landlock::BitFlags<AccessFs> {
    let mut flags = make_bitflags!(
        AccessFs::{Execute | ReadFile | ReadDir | WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym}
    );
    if AccessFs::from_all(abi).contains(AccessFs::Refer) {
        flags |= AccessFs::Refer;
    }
    if AccessFs::from_all(abi).contains(AccessFs::Truncate) {
        flags |= AccessFs::Truncate;
    }
    flags
}

/// Apply Landlock filesystem and network restrictions based on config.
pub fn apply(config: &Config, allow_ports: &[u16], warn: bool) -> Result<(), String> {
    // Use the highest supported ABI
    let abi = ABI::V5;

    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        log::warn!("landlock: not supported on this kernel, skipping");
        return Ok(());
    }

    if warn {
        log_planned_rules(config, allow_ports);
        return Ok(());
    }

    let mut ruleset = Ruleset::default()
        .handle_access(fs_access)
        .map_err(|e| format!("creating ruleset: {e}"))?;

    // Add network handling if ABI supports it
    let net_access = AccessNet::from_all(abi);
    if !net_access.is_empty() && !allow_ports.is_empty() {
        ruleset = ruleset
            .handle_access(net_access)
            .map_err(|e| format!("handling net access: {e}"))?;
    }

    let mut ruleset = ruleset
        .create()
        .map_err(|e| format!("creating ruleset: {e}"))?;

    // 1. System read paths
    for path in SYSTEM_READ_PATHS {
        ruleset = add_path_rule(ruleset, path, access_read());
    }

    // 2. System write paths
    for path in SYSTEM_WRITE_PATHS {
        ruleset = add_path_rule(ruleset, path, access_write(abi));
    }

    // 3. CWD as read+write
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy().to_string();
        ruleset = add_path_rule(ruleset, &cwd_str, access_write(abi));
    }

    // 4. Home directory or default readable paths
    if config.filesystem.is_default_deny_read() {
        // Deny-by-default: only add specific tooling paths
        for p in &default_readable_home_paths() {
            for expanded in paths::expand(p) {
                ruleset = add_path_rule(ruleset, &expanded.to_string_lossy(), access_read());
            }
        }
    } else {
        // Allow-by-default: add $HOME as read-only
        if let Ok(home) = std::env::var("HOME") {
            ruleset = add_path_rule(ruleset, &home, access_read());
        }
        // Warn about deny_read limitations
        if !config.filesystem.deny_read.is_empty() {
            log::warn!(
                "landlock: defaultDenyRead is false but denyRead has {} entries — \
                 Landlock cannot deny files within an allowed directory",
                config.filesystem.deny_read.len()
            );
        }
    }

    // 5. Profile allow_read paths (file-level for files, dir-level for dirs)
    for p in &config.filesystem.allow_read {
        for expanded in paths::expand(p) {
            ruleset = add_path_rule(ruleset, &expanded.to_string_lossy(), access_read());
        }
    }

    // 6. Profile allow_write paths
    for p in &config.filesystem.allow_write {
        for expanded in paths::expand(p) {
            ruleset = add_path_rule(ruleset, &expanded.to_string_lossy(), access_write(abi));
        }
    }

    // 7. Network port restrictions
    if !allow_ports.is_empty() && !net_access.is_empty() {
        for &port in allow_ports {
            let rule = NetPort::new(port, AccessNet::ConnectTcp);
            match ruleset.add_rule(rule) {
                Ok(rs) => {
                    log::debug!("landlock: allow ConnectTcp port {port}");
                    ruleset = rs;
                }
                Err(e) => {
                    log::debug!("landlock: failed to add net port {port}: {e}");
                    // Can't recover the ruleset from error, so bail
                    return Err(format!("landlock: failed to add net port {port}: {e}"));
                }
            }
        }
    }

    // Apply
    ruleset
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;

    log::info!("landlock: restrictions applied");
    Ok(())
}

/// Try to add a path rule. Log and skip on failure (path may not exist).
/// Returns the ruleset (builder pattern — add_rule consumes self).
fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> landlock::RulesetCreated {
    let p = Path::new(path);
    if !p.exists() {
        log::debug!("landlock: skipping non-existent path: {path}");
        return ruleset;
    }

    // Skip symlinks that point into /proc/self/fd (e.g. /dev/stdout) —
    // these can't be used as Landlock path references.
    if p.is_symlink() {
        if let Ok(target) = std::fs::read_link(p) {
            let ts = target.to_string_lossy();
            if ts.starts_with("/proc/self/fd") || ts.starts_with("/proc/") {
                log::debug!("landlock: skipping proc symlink: {path} -> {ts}");
                return ruleset;
            }
        }
    }

    match PathFd::new(path) {
        Ok(fd) => {
            let rule = PathBeneath::new(fd, access);
            match ruleset.add_rule(rule) {
                Ok(rs) => {
                    let mode = if access.contains(AccessFs::WriteFile) {
                        "rw"
                    } else {
                        "ro"
                    };
                    log::debug!("landlock: allow {mode} {path}");
                    rs
                }
                Err(e) => {
                    // add_rule consumes the ruleset and we can't recover it from the error.
                    // This shouldn't happen for valid paths in best-effort mode.
                    log::error!("landlock: fatal: add_rule failed for {path}: {e}");
                    panic!("landlock: add_rule failed for {path}: {e}");
                }
            }
        }
        Err(e) => {
            log::debug!("landlock: failed to open {path}: {e}");
            ruleset
        }
    }
}

/// In warn mode, just log what would be restricted.
fn log_planned_rules(config: &Config, allow_ports: &[u16]) {
    log::warn!("landlock: warn mode — logging planned rules without enforcing");

    for path in SYSTEM_READ_PATHS {
        log::warn!("  would allow ro: {path}");
    }
    for path in SYSTEM_WRITE_PATHS {
        log::warn!("  would allow rw: {path}");
    }
    if let Ok(cwd) = std::env::current_dir() {
        log::warn!("  would allow rw: {} (cwd)", cwd.display());
    }

    if config.filesystem.is_default_deny_read() {
        for p in &default_readable_home_paths() {
            log::warn!("  would allow ro: {p} (default tooling)");
        }
    } else if let Ok(home) = std::env::var("HOME") {
        log::warn!("  would allow ro: {home} (entire home, allow-by-default)");
    }

    for p in &config.filesystem.allow_read {
        log::warn!("  would allow ro: {p} (profile)");
    }
    for p in &config.filesystem.allow_write {
        log::warn!("  would allow rw: {p} (profile)");
    }
    for &port in allow_ports {
        log::warn!("  would allow ConnectTcp port {port}");
    }
}
