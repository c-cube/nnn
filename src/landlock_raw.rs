// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Raw Landlock syscalls to support ABI V9 features (RESOLVE_UNIX)
//! that the `landlock` crate doesn't expose yet.
//!
//! The unsafe blocks here are necessary for direct kernel syscalls
//! and are carefully bounded — each one wraps a single Linux syscall.
#![allow(unsafe_code)]

use anyhow::{bail, Context};
use std::os::unix::io::{AsRawFd, OwnedFd};

// Landlock access right constants
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
/// Added in Landlock ABI V9 (Linux ~6.8).
/// Controls connecting to pathname UNIX domain sockets.
const LANDLOCK_ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;

const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

#[repr(C)]
struct landlock_ruleset_attr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct landlock_path_beneath_attr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct landlock_net_port_attr {
    allowed_access: u64,
    port: u16,
}

// Syscall numbers for x86_64
const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
const SYS_LANDLOCK_ADD_RULE: i64 = 445;
const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

/// Build the full filesystem access bitmask for ABI V5 + RESOLVE_UNIX.
fn fs_access_all() -> u64 {
    LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE
        | LANDLOCK_ACCESS_FS_IOCTL_DEV
        | LANDLOCK_ACCESS_FS_RESOLVE_UNIX
}

/// Read-only access for directories.
fn fs_access_read() -> u64 {
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
}

/// Full write access (includes everything a process needs to write).
fn fs_access_write() -> u64 {
    fs_access_all()
}

struct Ruleset {
    fd: OwnedFd,
}

impl Ruleset {
    /// Create a new ruleset with the given handled access bits.
    fn create(fs_access: u64, net_access: u64) -> anyhow::Result<Self> {
        let attr = landlock_ruleset_attr {
            handled_access_fs: fs_access,
            handled_access_net: net_access,
            scoped: 0,
        };

        let fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<landlock_ruleset_attr>(),
                0i32,
            )
        };

        if fd < 0 {
            bail!(
                "landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        Ok(Ruleset { fd })
    }

    /// Add a path-beneath rule.
    fn add_path_beneath(&self, path: &str, allowed_access: u64) -> anyhow::Result<()> {
        let dir_fd = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("path not found, skipping: {path}");
                return Ok(());
            }
            Err(e) => {
                log::debug!("cannot open {path}: {e}, skipping");
                return Ok(());
            }
        };

        let attr = landlock_path_beneath_attr {
            allowed_access,
            parent_fd: dir_fd.as_raw_fd(),
        };

        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                self.fd.as_raw_fd() as i32,
                LANDLOCK_RULE_PATH_BENEATH as i32,
                &attr as *const _ as *const libc::c_void,
                0i32,
            )
        };

        if ret != 0 {
            bail!(
                "landlock_add_rule failed for {path}: {}",
                std::io::Error::last_os_error()
            );
        }

        let mode = if allowed_access & LANDLOCK_ACCESS_FS_WRITE_FILE != 0 {
            "rw"
        } else {
            "ro"
        };
        log::debug!("landlock: allow {mode} {path}");
        Ok(())
    }

    /// Add a net port rule.
    fn add_net_port(&self, port: u16, allowed_access: u64) -> anyhow::Result<()> {
        let attr = landlock_net_port_attr {
            allowed_access,
            port,
        };

        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                self.fd.as_raw_fd() as i32,
                LANDLOCK_RULE_NET_PORT as i32,
                &attr as *const _ as *const libc::c_void,
                0i32,
            )
        };

        if ret != 0 {
            bail!(
                "landlock_add_rule failed for port {port}: {}",
                std::io::Error::last_os_error()
            );
        }

        log::debug!("landlock: allow ConnectTcp port {port}");
        Ok(())
    }

    /// Enforce the ruleset on the current process.
    fn restrict_self(self) -> anyhow::Result<()> {
        let ret =
            unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, self.fd.as_raw_fd() as i32, 0i32) };

        if ret != 0 {
            bail!(
                "landlock_restrict_self failed: {}",
                std::io::Error::last_os_error()
            );
        }

        log::info!("landlock: restrictions applied (with RESOLVE_UNIX)");
        Ok(())
    }
}

/// Apply Landlock restrictions using raw syscalls (supports RESOLVE_UNIX).
pub fn apply(
    read_paths: &[String],
    write_paths: &[String],
    allow_ports: &[u16],
    deny_tcp: bool,
    auto_cwd: bool,
    system_read_paths: &[&str],
    system_write_paths: &[&str],
) -> anyhow::Result<()> {
    let fs_access = fs_access_all();

    let net_access = if deny_tcp || !allow_ports.is_empty() {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    let ruleset = Ruleset::create(fs_access, net_access)?;

    // System read paths
    for path in system_read_paths {
        ruleset.add_path_beneath(path, fs_access_read())?;
    }

    // System write paths
    for path in system_write_paths {
        ruleset.add_path_beneath(path, fs_access_write())?;
    }

    // Auto cwd
    if auto_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_str = cwd.to_string_lossy().to_string();
            ruleset.add_path_beneath(&cwd_str, fs_access_write())?;
        }
    }

    // Config read paths
    for path in read_paths {
        ruleset.add_path_beneath(path, fs_access_read())?;
    }

    // Config write paths
    for path in write_paths {
        ruleset.add_path_beneath(path, fs_access_write())?;
    }

    // Net port rules
    for &port in allow_ports {
        ruleset.add_net_port(port, LANDLOCK_ACCESS_NET_CONNECT_TCP)?;
    }

    ruleset.restrict_self()?;
    Ok(())
}
