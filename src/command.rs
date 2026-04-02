use crate::config::CommandConfig;

/// Commands blocked by default (same as greywall's DefaultDeniedCommands).
const DEFAULT_DENIED: &[&str] = &[
    // System control
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "systemctl poweroff",
    "systemctl reboot",
    "systemctl halt",
    // Kernel/module manipulation
    "insmod",
    "rmmod",
    "modprobe",
    "kexec",
    // Disk/partition manipulation
    "mkfs",
    "mkfs.ext2",
    "mkfs.ext3",
    "mkfs.ext4",
    "mkfs.xfs",
    "mkfs.btrfs",
    "mkfs.vfat",
    "mkfs.ntfs",
    "fdisk",
    "parted",
    "dd if=",
    // Container escape vectors
    "docker run -v /:/",
    "docker run --privileged",
    // Chroot/namespace escape
    "chroot",
    "unshare",
    "nsenter",
];

/// Check if a command is allowed. Returns Err with a message if blocked.
pub fn check(command: &[String], config: &CommandConfig, warn: bool) -> Result<(), String> {
    if command.is_empty() {
        return Ok(());
    }

    let normalized = normalize(&command[0]);
    let full_cmd = command.join(" ");

    // Check allow list first (takes precedence)
    for allow in &config.allow {
        if matches_prefix(&full_cmd, allow) || matches_prefix(&normalized, allow) {
            return Ok(());
        }
    }

    // Check user deny list
    for deny in &config.deny {
        if matches_prefix(&full_cmd, deny) || matches_prefix(&normalized, deny) {
            if warn {
                log::warn!("command would be blocked: {full_cmd} (matches deny: {deny:?})");
                return Ok(());
            }
            return Err(format!(
                "command blocked: {full_cmd} (matches deny rule: {deny:?})"
            ));
        }
    }

    // Check default deny list
    if config.use_default_denied_commands() {
        for &deny in DEFAULT_DENIED {
            if matches_prefix(&full_cmd, deny) || matches_prefix(&normalized, deny) {
                if warn {
                    log::warn!(
                        "command would be blocked: {full_cmd} (matches default deny: {deny:?})"
                    );
                    return Ok(());
                }
                return Err(format!(
                    "command blocked: {full_cmd} (matches default deny rule: {deny:?})"
                ));
            }
        }
    }

    Ok(())
}

/// Normalize a command: strip path prefix to get basename.
fn normalize(cmd: &str) -> String {
    std::path::Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd)
        .to_string()
}

/// Check if a command matches a deny prefix.
/// Matches if command equals the prefix, or command starts with "prefix ".
fn matches_prefix(command: &str, prefix: &str) -> bool {
    command == prefix || command.starts_with(&format!("{prefix} "))
}
