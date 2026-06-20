use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique counter for each test invocation.
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Path to the built binary.
fn nnn_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("debug");
    p.push("nnn");
    p
}

/// Run `nnn <args>` in `dir` with `XDG_CONFIG_HOME` set to `xdg_home`.
/// Returns (stdout, stderr, status).
fn run_nnn(
    args: &[&str],
    dir: &std::path::Path,
    xdg_home: &std::path::Path,
) -> (String, String, std::process::ExitStatus) {
    let mut cmd = Command::new(nnn_bin());
    cmd.args(args);
    cmd.current_dir(dir);
    cmd.env("XDG_CONFIG_HOME", xdg_home);
    cmd.env_remove("NNN_CONFIG");
    cmd.env_remove("NNN_RO");
    cmd.env_remove("NNN_RW");
    let output = cmd.output().expect("failed to run nnn");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status,
    )
}

/// Check if nnn reports Landlock as available on this system.
fn landlock_available() -> bool {
    let mut cmd = Command::new(nnn_bin());
    cmd.args(["check-landlock"]);
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Create a temporary directory for isolated tests.
/// Each TestDir gets a unique counter to avoid parallel test conflicts.
struct TestDir {
    _base: PathBuf,
    xdg_home: PathBuf,
    project: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("nnn_test_{id}"));
        let xdg_home = base.join("xdg_config");
        let project = base.join("project");
        std::fs::create_dir_all(&xdg_home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        Self {
            _base: base,
            xdg_home,
            project,
        }
    }

    fn project(&self) -> &PathBuf {
        &self.project
    }

    fn xdg_home(&self) -> &PathBuf {
        &self.xdg_home
    }

    /// Write a project config file (.nnn.toml) in the project dir.
    fn write_project_cfg(&self, content: &str) {
        std::fs::write(self.project.join(".nnn.toml"), content).unwrap();
    }

    /// Write a global config file.
    fn write_global_cfg(&self, content: &str) {
        let cfg_dir = self.xdg_home.join("nnn");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(cfg_dir.join("config.toml"), content).unwrap();
    }

    fn create_dir(&self, rel: &str) {
        std::fs::create_dir_all(self.project.join(rel)).unwrap();
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._base);
    }
}

// ── init tests ──

#[test]
fn test_init_creates_global_config() {
    let td = TestDir::new();
    let (_, stderr, status) = run_nnn(&["init"], td.project(), td.xdg_home());
    assert!(status.success(), "init should succeed: stderr={stderr}");

    let cfg_path = td.xdg_home().join("nnn").join("config.toml");
    assert!(cfg_path.exists(), "config.toml should exist");
    let content = std::fs::read_to_string(cfg_path).unwrap();
    assert!(
        content.contains("allow-read"),
        "config should contain allow-read"
    );
}

#[test]
fn test_init_refuses_overwrite() {
    let td = TestDir::new();
    td.write_global_cfg(""); // existing config

    let (_, stderr, status) = run_nnn(&["init"], td.project(), td.xdg_home());
    assert!(!status.success(), "init should fail when config exists");
    assert!(
        stderr.contains("already exists"),
        "should say 'already exists': {stderr}"
    );
}

// ── show tests ──

#[test]
fn test_show_no_configs() {
    let td = TestDir::new();
    let (stdout, stderr, status) = run_nnn(&["show"], td.project(), td.xdg_home());
    assert!(status.success(), "show should succeed: stderr={stderr}");
    assert!(
        stdout.contains("(not found)"),
        "should say not found: {stdout}"
    );
    assert!(
        stdout.contains("Resolved (global only)"),
        "should show resolved"
    );
}

#[test]
fn test_show_with_project_config() {
    let td = TestDir::new();
    td.write_project_cfg("allow-read = [\"./src\"]\nallow-write = [\"./output\"]\n");

    let (stdout, stderr, status) = run_nnn(&["show"], td.project(), td.xdg_home());
    assert!(status.success(), "show should succeed: stderr={stderr}");
    assert!(
        stdout.contains("Project config"),
        "should mention project config: {stdout}"
    );
    assert!(stdout.contains("./src"), "should contain ./src: {stdout}");
    assert!(
        stdout.contains("./output"),
        "should contain ./output: {stdout}"
    );
    assert!(
        stdout.contains("Resolved (merged)"),
        "should show merged: {stdout}"
    );
}

#[test]
fn test_show_with_global_and_project() {
    let td = TestDir::new();
    td.write_global_cfg("allow-read = [\"/usr\", \"/lib\"]\n");
    td.write_project_cfg("allow-read = [\"./src\"]\n");

    let (stdout, stderr, status) = run_nnn(&["show"], td.project(), td.xdg_home());
    assert!(status.success(), "show should succeed: stderr={stderr}");
    assert!(
        stdout.contains("/usr"),
        "resolved should include /usr: {stdout}"
    );
    assert!(
        stdout.contains("./src"),
        "resolved should include ./src: {stdout}"
    );
}

#[test]
fn test_show_with_empty_project_config() {
    let td = TestDir::new();
    td.write_project_cfg("");

    let (stdout, stderr, status) = run_nnn(&["show"], td.project(), td.xdg_home());
    assert!(status.success(), "show should succeed: stderr={stderr}");
    assert!(
        stdout.contains("Project config"),
        "should mention project config: {stdout}"
    );
}

// ── add-ro / add-rw tests ──

#[test]
fn test_add_ro_creates_project_config() {
    let td = TestDir::new();
    td.create_dir("src");
    let (_, stderr, status) = run_nnn(&["add-ro", "./src"], td.project(), td.xdg_home());
    assert!(status.success(), "add-ro should succeed: stderr={stderr}");

    let cfg_path = td.project().join(".nnn.toml");
    assert!(cfg_path.exists(), ".nnn.toml should be created");
    let content = std::fs::read_to_string(cfg_path).unwrap();
    assert!(content.contains("allow-read"), "should have allow-read");
    assert!(content.contains("./src"), "should contain ./src");
}

#[test]
fn test_add_rw_appends_to_existing() {
    let td = TestDir::new();
    td.write_project_cfg("allow-read = [\"./src\"]\n");
    td.create_dir("output");

    let (_, stderr, status) = run_nnn(&["add-rw", "./output"], td.project(), td.xdg_home());
    assert!(status.success(), "add-rw should succeed: stderr={stderr}");

    let content = std::fs::read_to_string(td.project().join(".nnn.toml")).unwrap();
    assert!(
        content.contains("allow-read"),
        "should keep existing allow-read"
    );
    assert!(content.contains("allow-write"), "should add allow-write");
    assert!(content.contains("./output"), "should contain new path");
}

#[test]
fn test_add_ro_dedup() {
    let td = TestDir::new();
    td.create_dir("src");

    let (_, _, status) = run_nnn(&["add-ro", "./src"], td.project(), td.xdg_home());
    assert!(status.success(), "first add-ro should succeed");

    let (_, stderr, status) = run_nnn(&["add-ro", "./src"], td.project(), td.xdg_home());
    assert!(
        status.success(),
        "second add-ro should succeed: stderr={stderr}"
    );

    let content = std::fs::read_to_string(td.project().join(".nnn.toml")).unwrap();
    let count = content.matches("./src").count();
    assert_eq!(
        count, 1,
        "./src should appear exactly once, got {count}: {content}"
    );
}

#[test]
fn test_add_ro_nonexistent_path_fails() {
    let td = TestDir::new();
    let (_, stderr, status) = run_nnn(&["add-ro", "./nonexistent"], td.project(), td.xdg_home());
    assert!(!status.success(), "should fail for nonexistent path");
    assert!(
        stderr.contains("does not exist"),
        "should say path doesn't exist: {stderr}"
    );
}

#[test]
fn test_add_ro_global_flag() {
    let td = TestDir::new();
    td.create_dir("src");

    let (_, stderr, status) = run_nnn(&["add-ro", "-g", "./src"], td.project(), td.xdg_home());
    assert!(
        status.success(),
        "add-ro -g should succeed: stderr={stderr}"
    );

    let cfg_path = td.xdg_home().join("nnn").join("config.toml");
    assert!(cfg_path.exists(), "global config should be created");
    let content = std::fs::read_to_string(cfg_path).unwrap();
    assert!(
        content.contains("./src"),
        "global config should contain the path"
    );
}

// ── exec tests ──

#[test]
fn test_exec_fails_without_landlock() {
    if landlock_available() {
        return;
    }
    let td = TestDir::new();
    let (_, stderr, status) = run_nnn(
        &["exec", "--no-auto-cwd", "--", "true"],
        td.project(),
        td.xdg_home(),
    );
    assert!(!status.success(), "exec should fail without Landlock");
    assert!(
        stderr.contains("not enforced"),
        "should mention restrictions not enforced: {stderr}"
    );
}

#[test]
fn test_bare_exec_fails_without_landlock() {
    if landlock_available() {
        return;
    }
    let td = TestDir::new();
    let (_, stderr, status) = run_nnn(&["--", "true"], td.project(), td.xdg_home());
    assert!(!status.success(), "bare exec should fail");
    assert!(
        stderr.contains("not enforced"),
        "should mention not enforced: {stderr}"
    );
}

#[test]
fn test_exec_seccomp_disabled_still_fails_without_landlock() {
    if landlock_available() {
        return;
    }
    let td = TestDir::new();
    td.write_project_cfg("seccomp = false\n");
    let (_, stderr, status) = run_nnn(
        &["exec", "--no-auto-cwd", "--", "true"],
        td.project(),
        td.xdg_home(),
    );
    assert!(!status.success(), "should still fail without Landlock");
    assert!(stderr.contains("not enforced"), "{stderr}");
}

// ── CLI parsing ──

#[test]
fn test_help_works() {
    let td = TestDir::new();
    let (stdout, stderr, status) = run_nnn(&["--help"], td.project(), td.xdg_home());
    assert!(status.success(), "help should succeed: stderr={stderr}");
    assert!(stdout.contains("Usage"), "should show usage: {stdout}");
    assert!(
        stdout.contains("exec"),
        "should show exec subcommand: {stdout}"
    );
    assert!(stdout.contains("add-ro"), "should show add-ro: {stdout}");
    assert!(stdout.contains("show"), "should show show: {stdout}");
    assert!(stdout.contains("init"), "should show init: {stdout}");
}

#[test]
fn test_exec_help_works() {
    let td = TestDir::new();
    let (stdout, stderr, status) = run_nnn(&["exec", "--help"], td.project(), td.xdg_home());
    assert!(
        status.success(),
        "exec help should succeed: stderr={stderr}"
    );
    assert!(
        stdout.contains("--no-auto-cwd"),
        "should mention --no-auto-cwd: {stdout}"
    );
    assert!(
        stdout.contains("--add-ro"),
        "should mention --add-ro: {stdout}"
    );
    assert!(
        stdout.contains("--add-rw"),
        "should mention --add-rw: {stdout}"
    );
}

#[test]
fn test_add_ro_help_works() {
    let td = TestDir::new();
    let (stdout, stderr, status) = run_nnn(&["add-ro", "--help"], td.project(), td.xdg_home());
    assert!(
        status.success(),
        "add-ro help should succeed: stderr={stderr}"
    );
    assert!(
        stdout.contains("--global"),
        "should mention --global: {stdout}"
    );
}

// ── NNN_CONFIG env var ──

#[test]
fn test_nnn_config_env_loads_without_error() {
    if landlock_available() {
        return;
    }
    let td = TestDir::new();
    let extra = td.xdg_home().join("extra.toml");
    std::fs::write(&extra, "allow-read = [\"/custom\"]\n").unwrap();

    let mut cmd = Command::new(nnn_bin());
    cmd.args(["exec", "--no-auto-cwd", "--", "true"]);
    cmd.current_dir(td.project());
    cmd.env("XDG_CONFIG_HOME", td.xdg_home());
    cmd.env("NNN_CONFIG", &extra);
    let output = cmd.output().expect("failed to run nnn");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should fail due to no landlock, but NOT due to missing config file
    assert!(!output.status.success(), "should fail");
    assert!(
        !stderr.contains("not found"),
        "should not say not found: {stderr}"
    );
    assert!(
        stderr.contains("not enforced") || stderr.contains("landlock"),
        "{stderr}"
    );
}

#[test]
fn test_nnn_config_env_missing_path_warns() {
    if landlock_available() {
        return;
    }
    let td = TestDir::new();

    let mut cmd = Command::new(nnn_bin());
    cmd.args(["exec", "--no-auto-cwd", "--", "true"]);
    cmd.current_dir(td.project());
    cmd.env("XDG_CONFIG_HOME", td.xdg_home());
    cmd.env("NNN_CONFIG", "/nonexistent/nnn_extra_config.toml");
    let output = cmd.output().expect("failed to run nnn");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "should fail");
    assert!(
        stderr.contains("not found"),
        "should warn about missing config: {stderr}"
    );
}
