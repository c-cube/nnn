//! Integration tests for nnn sandbox.
//!
//! Tests use `CARGO_BIN_EXE_nnn` to locate the built binary.
//! Tests that require unshare (--exclude) are skipped when the runtime
//! has a parent seccomp filter (common in containers and sandboxed shells).

use std::path::PathBuf;
use std::process::Command;

fn nnn_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nnn"))
}

/// Returns true if the runtime blocks `unshare` (parent seccomp filter).
fn unshare_blocked() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .any(|l| l.starts_with("Seccomp:") && l.trim() != "Seccomp:	0")
}

fn temp_dir(_prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

#[test]
fn exec_basic() {
    let bin = nnn_binary();
    let output = Command::new(&bin)
        .args(["exec", "--", "echo", "hello"])
        .output()
        .expect("run nnn exec echo");
    assert!(
        output.status.success(),
        "nnn exec echo failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn exec_with_allow_read() {
    let (_dir, tmp) = temp_dir("nnn_test_basic");
    let testfile = tmp.join("test.txt");
    std::fs::write(&testfile, "accessible").unwrap();

    let bin = nnn_binary();
    let output = Command::new(&bin)
        .args([
            "exec",
            "--allow-read",
            &tmp.to_string_lossy(),
            "--",
            "cat",
            &testfile.to_string_lossy(),
        ])
        .output()
        .expect("run nnn exec with allow-read");

    assert!(output.status.success(), "read failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "accessible");
}

#[test]
fn exec_exclude_directory() {
    if unshare_blocked() {
        eprintln!("skipping --exclude test: unshare blocked by parent seccomp");
        return;
    }

    let (_dir, tmp) = temp_dir("nnn_test_exclude_dir");

    let public = tmp.join("public");
    let confidential = tmp.join("confidential");
    std::fs::create_dir_all(&public).unwrap();
    std::fs::create_dir_all(&confidential).unwrap();
    std::fs::write(public.join("hello.txt"), "public data").unwrap();
    std::fs::write(confidential.join("secret.txt"), "SECRET").unwrap();

    let bin = nnn_binary();
    let tmp_str = tmp.to_string_lossy();

    // 1) Excluded directory should be inaccessible (tmpfs overlay hides it)
    let output = Command::new(&bin)
        .args([
            "exec",
            "--allow-read",
            &tmp_str,
            "-e",
            &confidential.to_string_lossy(),
            "--",
            "cat",
            &confidential.join("secret.txt").to_string_lossy(),
        ])
        .output()
        .expect("run nnn exec with --exclude directory");

    assert!(
        !output.status.success(),
        "expected failure reading excluded file, got success"
    );

    // 2) Non-excluded path should still be accessible
    let output = Command::new(&bin)
        .args([
            "exec",
            "--allow-read",
            &tmp_str,
            "-e",
            &confidential.to_string_lossy(),
            "--",
            "cat",
            &public.join("hello.txt").to_string_lossy(),
        ])
        .output()
        .expect("run nnn exec with --exclude but read public file");

    assert!(
        output.status.success(),
        "reading public file failed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "public data");

    // 3) Original file still exists on disk (not deleted, just hidden by overlay)
    let content = std::fs::read_to_string(confidential.join("secret.txt")).unwrap();
    assert_eq!(content.trim(), "SECRET");
}

#[test]
fn exec_exclude_file() {
    if unshare_blocked() {
        eprintln!("skipping --exclude test: unshare blocked by parent seccomp");
        return;
    }

    let (_dir, tmp) = temp_dir("nnn_test_exclude_file");

    let secrets = tmp.join("secrets.txt");
    std::fs::write(&secrets, "sensitive data").unwrap();

    let bin = nnn_binary();
    let tmp_str = tmp.to_string_lossy();
    let secrets_str = secrets.to_string_lossy();

    // Reading the excluded file should fail
    let output = Command::new(&bin)
        .args([
            "exec",
            "--allow-read",
            &tmp_str,
            "-e",
            &secrets_str,
            "--",
            "cat",
            &secrets_str,
        ])
        .output()
        .expect("run nnn exec with --exclude file");

    assert!(
        !output.status.success(),
        "expected failure reading excluded file, got success"
    );

    // Original file still exists
    let content = std::fs::read_to_string(&secrets).unwrap();
    assert_eq!(content.trim(), "sensitive data");
}

#[test]
fn exec_exclude_relative_path() {
    if unshare_blocked() {
        eprintln!("skipping --exclude test: unshare blocked by parent seccomp");
        return;
    }

    let (_dir, tmp) = temp_dir("nnn_test_exclude_rel");

    let private = tmp.join("private");
    std::fs::create_dir_all(&private).unwrap();
    std::fs::write(private.join("key.txt"), "ssh-key").unwrap();

    let bin = nnn_binary();
    let tmp_str = tmp.to_string_lossy();
    let private_rel = "./private";

    // Use a relative path for --exclude
    let output = Command::new(&bin)
        .current_dir(&tmp)
        .args([
            "exec",
            "--allow-read",
            &tmp_str,
            "-e",
            private_rel,
            "--",
            "cat",
            &private.join("key.txt").to_string_lossy(),
        ])
        .output()
        .expect("run nnn exec with relative --exclude");

    assert!(
        !output.status.success(),
        "expected failure reading relatively excluded file, got success"
    );
}
