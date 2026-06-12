use crate::config::Config;
use crate::paths;
use landlock::{
    make_bitflags, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::path::Path;

/// System paths always readable.
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
    "/var",
    "/opt",
    "/dev",
    "/tmp",
];

/// System paths always writable.
const SYSTEM_WRITE_PATHS: &[&str] = &["/dev/null", "/dev/tty", "/tmp", "/var/tmp"];

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

/// Apply Landlock filesystem restrictions based on config.
pub fn apply(config: &Config, warn: bool) -> Result<(), String> {
    let abi = ABI::V5;

    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        log::warn!("landlock: not supported on this kernel, skipping");
        return Ok(());
    }

    if warn {
        log_planned_rules(config);
        return Ok(());
    }

    let ruleset = Ruleset::default()
        .handle_access(fs_access)
        .map_err(|e| format!("creating ruleset: {e}"))?;

    let mut ruleset = ruleset
        .create()
        .map_err(|e| format!("creating ruleset: {e}"))?;

    // System read paths
    for path in SYSTEM_READ_PATHS {
        ruleset = add_path_rule(ruleset, path, access_read());
    }

    // System write paths
    for path in SYSTEM_WRITE_PATHS {
        ruleset = add_path_rule(ruleset, path, access_write(abi));
    }

    // CWD as read+write
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy().to_string();
        ruleset = add_path_rule(ruleset, &cwd_str, access_write(abi));
    }

    // Config allow_read paths
    for p in &config.allow_read {
        for expanded in paths::expand(p) {
            ruleset = add_path_rule(ruleset, &expanded.to_string_lossy(), access_read());
        }
    }

    // Config allow_write paths
    for p in &config.allow_write {
        for expanded in paths::expand(p) {
            ruleset = add_path_rule(ruleset, &expanded.to_string_lossy(), access_write(abi));
        }
    }

    // Apply
    ruleset
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;

    log::info!("landlock: restrictions applied");
    Ok(())
}

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

fn log_planned_rules(config: &Config) {
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
    for p in &config.allow_read {
        log::warn!("  would allow ro: {p} (config)");
    }
    for p in &config.allow_write {
        log::warn!("  would allow rw: {p} (config)");
    }
}
