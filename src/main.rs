#![deny(unsafe_code)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use anyhow::{bail, Context};
use landlock::{
    make_bitflags, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use toml_edit::DocumentMut;

// ── Config ──

#[derive(Debug, Default, Clone)]
struct NetworkConfig {
    deny_tcp: Option<bool>,
    deny_udp: Option<bool>,
    allow_ports: Vec<u16>,
}

impl NetworkConfig {
    fn is_deny_tcp(&self) -> bool {
        self.deny_tcp.unwrap_or(false)
    }
    fn is_deny_udp(&self) -> bool {
        self.deny_udp.unwrap_or(false)
    }
}

#[derive(Debug, Default, Clone)]
struct Config {
    allow_read: Vec<String>,
    allow_write: Vec<String>,
    allow_env: Vec<String>,
    /// None = use built-in default (true).
    seccomp: Option<bool>,
    network: NetworkConfig,
}

fn merge_vec<T: PartialEq + Clone>(dst: &mut Vec<T>, src: &[T]) {
    for p in src {
        if !dst.contains(p) {
            dst.push(p.clone());
        }
    }
}

impl Config {
    fn seccomp_enabled(&self) -> bool {
        self.seccomp.unwrap_or(true)
    }

    fn merge(&self, overlay: &Config) -> Config {
        let mut c = self.clone();
        merge_vec(&mut c.allow_read, &overlay.allow_read);
        merge_vec(&mut c.allow_write, &overlay.allow_write);
        merge_vec(&mut c.allow_env, &overlay.allow_env);
        c.seccomp = overlay.seccomp.or(c.seccomp);
        c.network.deny_tcp = overlay.network.deny_tcp.or(c.network.deny_tcp);
        c.network.deny_udp = overlay.network.deny_udp.or(c.network.deny_udp);
        merge_vec(&mut c.network.allow_ports, &overlay.network.allow_ports);
        c
    }
}

const DEFAULT_CONFIG: &str = r#"allow-read = [
    "/bin/",
    "/usr/bin/",
    "/usr/local/bin",
    "/etc/ssl/", # for certs
    "~/.config/nnn",
]

allow-write = [
    "/tmp/nnn/",
    "~/.cargo/",
]

# Extra env vars passed into the sandbox.
# Built-in defaults are always included: HOME, USER, LOGNAME, UID, PATH, SHELL,
# TERM, COLORTERM, LANG, LC_* (locale), XDG_* (all XDG vars).
# Patterns ending with * match by prefix (e.g. "MY_APP_*").
# allow-env = ["DISPLAY", "WAYLAND_DISPLAY", "MY_TOKEN"]

# Network restrictions (Landlock ABI V4+, kernel >= 5.19)
# [network]
# deny-tcp = false
# deny-udp = false
# allow-ports = [80, 443, 22]
"#;

// ── CLI ──

#[derive(Parser)]
#[command(name = "nnn", about = "Minimal Linux sandbox using Landlock")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command inside the sandbox
    #[command(alias = "x", name = "exec")]
    Exec(ExecArgs),
    /// Add a read-only path to the project config
    #[command(name = "add-ro")]
    AddRo(AddArgs),
    /// Add a read-write path to the project config
    #[command(name = "add-rw")]
    AddRw(AddArgs),
    /// Approve the current project config, so `exec` will trust it
    Allow,
    /// Show resolved rules for the current directory
    Show,
    /// Write default global config to ~/.config/nnn/config.toml
    Init,
    /// Check if Landlock is available on this system (for testing)
    #[command(hide = true)]
    CheckLandlock,
}

#[derive(Parser)]
struct ExecArgs {
    /// Don't automatically allow read-write access to cwd
    #[arg(long)]
    no_auto_cwd: bool,

    /// Additional read-only paths (appended to config, like nnn add-ro)
    #[arg(long)]
    add_ro: Vec<String>,

    /// Additional read-write paths (appended to config, like nnn add-rw)
    #[arg(long)]
    add_rw: Vec<String>,

    /// Deny all TCP connect/bind (Landlock ABI V4+)
    #[arg(long)]
    deny_tcp: bool,

    /// Additional TCP ports allowed for outbound connect (comma-separated)
    #[arg(long, value_delimiter = ',')]
    allow_port: Vec<u16>,

    /// Path to project .nnn.toml (auto-detected from git root)
    #[arg(long)]
    project_config: Option<PathBuf>,

    /// Command to run inside the sandbox
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Parser)]
struct AddArgs {
    /// Modify the global config instead of project config
    #[arg(short, long)]
    global: bool,

    /// Directory path to add
    dir: String,
}

// ── Main ──

fn main() {
    let mut raw: Vec<String> = std::env::args().collect();

    // `nnn -- <cmd>` → `nnn exec -- <cmd>` (only way to run a command
    // without an explicit subcommand; bare `nnn <cmd>` is rejected by clap
    // to avoid confusing mistakes like `nnn allow-read ~/`)
    if raw.len() > 1 && raw[1] == "--" {
        let mut exec_args = vec![raw[0].clone(), "exec".to_string(), "--".to_string()];
        exec_args.extend(raw[2..].iter().cloned());
        raw = exec_args;
    }

    let cli = Cli::parse_from(raw);

    if let Err(e) = match cli.command {
        Command::Exec(args) => cmd_exec(args),
        Command::AddRo(args) => cmd_add_path(&args.dir, false, args.global),
        Command::AddRw(args) => cmd_add_path(&args.dir, true, args.global),
        Command::Allow => cmd_allow(),
        Command::Show => cmd_show(),
        Command::Init => cmd_init(),
        Command::CheckLandlock => {
            std::process::exit(if landlock_available() { 0 } else { 1 });
        }
    } {
        eprintln!("nnn: {e:#}");
        std::process::exit(1);
    }
}

fn cmd_exec(args: ExecArgs) -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut cfg = resolve_config(args.project_config.as_deref())?;

    // NNN_CONFIG: additional config file
    if let Ok(extra) = std::env::var("NNN_CONFIG") {
        let path = Path::new(&extra);
        if path.is_file() {
            let extra_cfg = load_toml_file(path)
                .with_context(|| format!("loading NNN_CONFIG from {}", path.display()))?;
            log::info!("loaded NNN_CONFIG from {}", path.display());
            cfg = cfg.merge(&extra_cfg);
        } else {
            log::warn!("NNN_CONFIG path not found: {}", path.display());
        }
    }

    // NNN_RO/NNN_RW: comma-separated (before CLI flags)
    cfg = cfg.merge(&env_overrides());

    // CLI deny_tcp flag overrides config / env
    if args.deny_tcp {
        cfg.network.deny_tcp = Some(true);
    }

    merge_vec(&mut cfg.allow_read, &args.add_ro);
    merge_vec(&mut cfg.allow_write, &args.add_rw);
    merge_vec(&mut cfg.network.allow_ports, &args.allow_port);

    if !cfg.network.allow_ports.is_empty() && !cfg.network.deny_tcp.unwrap_or(false) {
        log::warn!("allow-ports set without deny-tcp: deny_tcp=true implicitly");
    }

    // When the same resolved path appears in both allow-read and allow-write,
    // read-write wins. Remove it from allow_read so the write rule is authoritative.
    cfg.allow_read.retain(|p| !cfg.allow_write.contains(p));

    log::info!("resolved config: {cfg:#?}");

    let env = hardened_env(&cfg.allow_env);

    if cfg.seccomp_enabled() {
        seccomp_apply()?;
    }

    landlock_apply(&cfg, !args.no_auto_cwd)?;

    let err = exec_command(&args.command, &env);
    Err(anyhow::anyhow!("exec of {:?} failed: {err}", args.command))
}

fn cmd_add_path(dir: &str, write: bool, global: bool) -> anyhow::Result<()> {
    if !Path::new(dir).exists() {
        anyhow::bail!("path does not exist: {dir}");
    }

    let project_path = if global {
        global_config_path()
    } else {
        match find_project_config() {
            Some(p) => p,
            None => {
                let root = match find_git_root() {
                    Some(r) => r,
                    None => match std::env::current_dir() {
                        Ok(d) => d,
                        Err(_) => PathBuf::from("."),
                    },
                };
                root.join(".nnn.toml")
            }
        }
    };

    if let Some(parent) = project_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut doc: DocumentMut = if project_path.exists() {
        let data = std::fs::read_to_string(&project_path)
            .with_context(|| format!("reading {}", project_path.display()))?;
        data.parse()
            .with_context(|| format!("parsing {}", project_path.display()))?
    } else {
        DocumentMut::new()
    };

    let key = if write { "allow-write" } else { "allow-read" };

    if doc.get(key).and_then(|item| item.as_array()).is_none() {
        doc[key] = toml_edit::value(toml_edit::Array::new());
    }

    let arr = doc[key]
        .as_array_mut()
        .with_context(|| format!("{key} is not an array in config"))?;
    if !arr.iter().any(|v| v.as_str() == Some(dir)) {
        arr.push(dir);
    }

    std::fs::write(&project_path, doc.to_string())
        .with_context(|| format!("writing {}", project_path.display()))?;

    println!("added {} to {}", dir, project_path.display());
    Ok(())
}

fn cmd_show() -> anyhow::Result<()> {
    let global_path = global_config_path();
    let project_path = find_project_config();

    println!("Global config: {}", global_path.display());
    if global_path.exists() {
        print_config(&global_path);
    } else {
        println!("  (not found)");
    }

    let global_cfg = load_global_config()?;
    if let Some(ref pp) = project_path {
        println!("\nProject config: {}", pp.display());
        print_config(pp);
        match load_toml_file(pp) {
            Ok(project_cfg) => {
                let mut merged = global_cfg.merge(&project_cfg);
                merged
                    .allow_read
                    .retain(|p| !merged.allow_write.contains(p));
                println!("\nResolved (merged):");
                print_paths("allow-read", &merged.allow_read);
                print_paths("allow-write", &merged.allow_write);
                print_env_allowlist(&merged.allow_env);
                print_network(&merged.network);
            }
            Err(e) => eprintln!("  error: {e}"),
        }
    } else {
        println!("\nResolved (global only):");
        print_paths("allow-read", &global_cfg.allow_read);
        print_paths("allow-write", &global_cfg.allow_write);
        print_env_allowlist(&global_cfg.allow_env);
        print_network(&global_cfg.network);
    }
    Ok(())
}

fn print_env_allowlist(extra: &[String]) {
    let print_inline = |label: &str, items: &[&str]| {
        print!("  {label}:");
        for p in items {
            print!(" {p}");
        }
        println!();
    };
    print_inline("allow-env (built-in)", DEFAULT_ENV_ALLOWLIST);
    if !extra.is_empty() {
        let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();
        print_inline("allow-env (config)", &extra_refs);
    }
}

fn print_network(net: &NetworkConfig) {
    if net.deny_tcp.is_some() || net.deny_udp.is_some() || !net.allow_ports.is_empty() {
        println!("  network:");
        if net.deny_tcp.is_some() {
            println!("    deny-tcp: {}", net.deny_tcp.unwrap_or(false));
        }
        if net.deny_udp.is_some() {
            println!("    deny-udp: {}", net.deny_udp.unwrap_or(false));
        }
        if !net.allow_ports.is_empty() {
            println!("    allow-ports: {:?}", net.allow_ports);
        }
    } else {
        println!("  network: (unrestricted)");
    }
}

fn cmd_init() -> anyhow::Result<()> {
    let path = global_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }

    // Create /tmp/nnn as the sandbox temporary directory (used by INJECTED_ENV
    // and the default config's allow-write list). Failure is non-fatal — the
    // sandbox will still work, the user just needs to create it manually.
    let _ = std::fs::create_dir_all("/tmp/nnn");

    std::fs::write(&path, DEFAULT_CONFIG).with_context(|| format!("writing {}", path.display()))?;

    println!("wrote {}", path.display());
    Ok(())
}

fn print_config(path: &Path) {
    match load_toml_file(path) {
        Ok(cfg) => {
            print_paths("allow-read", &cfg.allow_read);
            print_paths("allow-write", &cfg.allow_write);
        }
        Err(e) => eprintln!("  error: {e}"),
    }
}

fn print_paths(label: &str, paths: &[String]) {
    if paths.is_empty() {
        println!("  {label}: (none)");
    } else {
        println!("  {label}:");
        for p in paths {
            println!("    {p}");
        }
    }
}

// ── Config resolution ──

/// Parse comma-separated env vars NNN_RO, NNN_RW, NNN_ALLOW_PORT,
/// and bool env vars NNN_DENY_TCP, NNN_DENY_UDP.
fn env_overrides() -> Config {
    let mut cfg = Config::default();
    if let Ok(val) = std::env::var("NNN_RO") {
        for p in val.split(',') {
            let p = p.trim().to_string();
            if !p.is_empty() && !cfg.allow_read.contains(&p) {
                cfg.allow_read.push(p);
            }
        }
    }
    if let Ok(val) = std::env::var("NNN_RW") {
        for p in val.split(',') {
            let p = p.trim().to_string();
            if !p.is_empty() && !cfg.allow_write.contains(&p) {
                cfg.allow_write.push(p);
            }
        }
    }
    if let Ok(val) = std::env::var("NNN_ALLOW_PORT") {
        for p in val.split(',') {
            let p = p.trim();
            if !p.is_empty() {
                if let Ok(port) = p.parse::<u16>() {
                    if !cfg.network.allow_ports.contains(&port) {
                        cfg.network.allow_ports.push(port);
                    }
                } else {
                    log::warn!("NNN_ALLOW_PORT: ignoring invalid port: {p}");
                }
            }
        }
    }
    if let Ok(val) = std::env::var("NNN_DENY_TCP") {
        if val == "true" || val == "1" {
            cfg.network.deny_tcp = Some(true);
        }
    }
    if let Ok(val) = std::env::var("NNN_DENY_UDP") {
        if val == "true" || val == "1" {
            cfg.network.deny_udp = Some(true);
        }
    }
    cfg
}

fn resolve_config(explicit_project: Option<&Path>) -> anyhow::Result<Config> {
    let global_cfg = load_global_config()?;

    // An explicit --project-config is a deliberate choice made by the caller
    // on this invocation, so it's trusted as-is. An auto-discovered
    // .nnn.toml sits inside the directory the sandbox just wrote to (auto
    // cwd), so a sandboxed command could have edited it to grant itself more
    // permissions on the *next* run — only use it if it matches an
    // explicitly `nnn allow`-ed version.
    let project_path = match explicit_project {
        Some(p) => Some(p.to_path_buf()),
        None => match find_project_config() {
            Some(p) => {
                check_project_trust(&p)?;
                Some(p)
            }
            None => None,
        },
    };

    let mut cfg = global_cfg;
    if let Some(path) = project_path {
        let project_cfg =
            load_toml_file(&path).with_context(|| format!("loading {}", path.display()))?;
        log::info!("loaded project config from {}", path.display());
        cfg = cfg.merge(&project_cfg);
    }
    Ok(cfg)
}

// ── Trust store (protects auto-discovered project config from tampering) ──

fn trust_store_path() -> PathBuf {
    config_dir().join("nnn").join("trusted.toml")
}

fn hash_file_hex(path: &Path) -> anyhow::Result<String> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(blake3::hash(&data).to_string())
}

fn trust_key(path: &Path) -> anyhow::Result<String> {
    let canon = path
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;
    Ok(canon.to_string_lossy().to_string())
}

fn load_trust_doc() -> anyhow::Result<DocumentMut> {
    let path = trust_store_path();
    if path.exists() {
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        data.parse()
            .with_context(|| format!("parsing {}", path.display()))
    } else {
        Ok(DocumentMut::new())
    }
}

fn check_project_trust(path: &Path) -> anyhow::Result<()> {
    let key = trust_key(path)?;
    let hash = hash_file_hex(path)?;
    let doc = load_trust_doc()?;
    match doc.get(key.as_str()).and_then(|v| v.as_str()) {
        Some(h) if h == hash => Ok(()),
        Some(_) => bail!(untrusted_message(path, "has changed since it was approved")),
        None => bail!(untrusted_message(path, "has not been approved yet")),
    }
}

fn untrusted_message(path: &Path, reason: &str) -> String {
    format!(
        "UNTRUSTED PROJECT CONFIG: {p}\n  This file {reason}.\n  A sandboxed command could have edited it to grant itself extra\n  permissions on your next run. Review it, then run `nnn allow` to approve.",
        p = path.display(),
    )
}

fn cmd_allow() -> anyhow::Result<()> {
    let path = find_project_config().context("no project config (.nnn.toml) found")?;
    let key = trust_key(&path)?;
    let hash = hash_file_hex(&path)?;

    let mut doc = load_trust_doc()?;
    doc[key.as_str()] = toml_edit::value(hash.clone());

    let store_path = trust_store_path();
    if let Some(parent) = store_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&store_path, doc.to_string())
        .with_context(|| format!("writing {}", store_path.display()))?;

    println!("allowed {} ({})", path.display(), &hash[..12]);
    Ok(())
}

fn load_global_config() -> anyhow::Result<Config> {
    let path = global_config_path();
    if path.exists() {
        let cfg = load_toml_file(&path)
            .with_context(|| format!("loading global config from {}", path.display()))?;
        log::info!("loaded global config from {}", path.display());
        Ok(cfg)
    } else {
        Ok(Config::default())
    }
}

fn global_config_path() -> PathBuf {
    config_dir().join("nnn").join("config.toml")
}

fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".nnn.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn find_git_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn load_toml_file(path: &Path) -> anyhow::Result<Config> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct Raw {
        #[serde(default)]
        allow_read: Vec<String>,
        #[serde(default)]
        allow_write: Vec<String>,
        #[serde(default)]
        allow_env: Vec<String>,
        #[serde(default)]
        seccomp: Option<bool>,
        #[serde(default)]
        network: Option<NetworkRaw>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct NetworkRaw {
        #[serde(default)]
        deny_tcp: Option<bool>,
        #[serde(default)]
        deny_udp: Option<bool>,
        #[serde(default)]
        allow_ports: Vec<u16>,
    }
    let raw: Raw =
        toml_edit::de::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;
    let network = match raw.network {
        Some(n) => NetworkConfig {
            deny_tcp: n.deny_tcp,
            deny_udp: n.deny_udp,
            allow_ports: n.allow_ports,
        },
        None => NetworkConfig::default(),
    };
    Ok(Config {
        allow_read: raw.allow_read,
        allow_write: raw.allow_write,
        allow_env: raw.allow_env,
        seccomp: raw.seccomp,
        network,
    })
}

fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config");
    }
    PathBuf::from("~/.config")
}

// ── Environment sanitization ──

const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "UID",
    "PATH",
    "SHELL",
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_*",  // prefix: LC_ALL, LC_CTYPE, LC_MESSAGES, etc.
    "XDG_*", // prefix: all XDG vars (XDG_RUNTIME_DIR, XDG_CONFIG_HOME, etc.)
];

// Injected into sandboxed environment. TMPDIR is a widely-used convention
// (Python tempfile, Go, GCC, cargo, etc.). Pointing it at a write-allowed
// path prevents temp-file leakage into unmonitored directories.
const INJECTED_ENV: &[(&str, &str)] = &[("NNN", "1"), ("TMPDIR", "/tmp/nnn")];

fn env_matches<S: AsRef<str>>(key: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pat| {
        let pat = pat.as_ref();
        if let Some(prefix) = pat.strip_suffix('*') {
            key.starts_with(prefix)
        } else {
            key == pat
        }
    })
}

fn hardened_env(extra_allow: &[String]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            k != "NNN"
                && !is_dangerous(k)
                && (env_matches(k, DEFAULT_ENV_ALLOWLIST) || env_matches(k, extra_allow))
        })
        .collect();
    for (k, v) in INJECTED_ENV {
        env.push((k.to_string(), v.to_string()));
    }
    env
}

fn is_dangerous(key: &str) -> bool {
    key.starts_with("LD_") || key.starts_with("DYLD_")
}

// ── Execution ──

fn exec_command(command: &[String], env: &[(String, String)]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.exec()
}

// ── Path expansion ──

/// Expand leading `~/` or `~` to `$HOME`.
fn expand_tilde(s: &str) -> String {
    if s == "~" {
        std::env::var("HOME").unwrap_or_else(|_| s.to_string())
    } else if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            Path::new(&home).join(rest).to_string_lossy().to_string()
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    }
}

// ── Seccomp ──

/// Apply a seccomp-bpf deny list: block dangerous syscalls Landlock doesn't cover.
fn seccomp_apply() -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

    let blocked: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_pivot_root,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
    ];

    for &syscall in blocked {
        rules.insert(syscall, vec![]);
    }

    let target_arch: seccompiler::TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| anyhow::anyhow!("unsupported arch: {}", std::env::consts::ARCH))?;

    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::KillProcess,
        target_arch,
    )
    .context("seccomp: failed to build seccomp-bpf filter (check syscall numbers)")?;

    let bpf: seccompiler::BpfProgram = filter
        .try_into()
        .context("seccomp: filter compilation failed (try disabling with `seccomp = false`)")?;

    seccompiler::apply_filter(&bpf)
        .context("seccomp: failed to apply filter — kernel needs SECCOMP_FILTER (Linux >= 3.5, CONFIG_SECCOMP=y)")?;

    log::info!("seccomp: restrictions applied");
    Ok(())
}

const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys", "/run", "/var",
    "/opt", "/dev",
];

const SYSTEM_WRITE_PATHS: &[&str] = &["/dev/null", "/dev/tty"];

fn landlock_access_read() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir})
}

fn landlock_access_write(abi: ABI) -> landlock::BitFlags<AccessFs> {
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

fn landlock_available() -> bool {
    let abi = ABI::V5;
    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        return false;
    }
    let ruleset = match Ruleset::default()
        .handle_access(fs_access)
        .and_then(|r| r.create())
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    match ruleset.restrict_self() {
        Ok(status) => status.ruleset == RulesetStatus::FullyEnforced,
        Err(_) => false,
    }
}

fn landlock_apply(config: &Config, auto_cwd: bool) -> anyhow::Result<()> {
    let abi = ABI::V5;

    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        log::error!(
            "landlock: not supported on this kernel (ABI {abi:?} returned empty access set)"
        );
        anyhow::bail!("landlock not supported on this kernel (need Linux >= 5.19 for ABI V5, or check CONFIG_SECCOMP_FILTER in kernel)");
    }

    let deny_tcp = config.network.is_deny_tcp();
    let deny_udp = config.network.is_deny_udp();
    let net_restricted = deny_tcp || deny_udp || !config.network.allow_ports.is_empty();

    if deny_udp {
        log::warn!("landlock: deny-udp requires AccessNet::ConnectUdp which is not available in landlock 0.4 — ignored");
    }

    let mut ruleset = Ruleset::default().handle_access(fs_access).map_err(|e| {
        anyhow::anyhow!("landlock: kernel rejected access rights (need Linux >= 5.19, ABI V5): {e}")
    })?;

    if net_restricted {
        let net_access = AccessNet::from_all(abi);
        let handle = make_bitflags!(AccessNet::{BindTcp | ConnectTcp});
        if !net_access.intersects(handle) {
            anyhow::bail!(
                "landlock: network restrictions require Landlock ABI V4+ (kernel >= 5.19)"
            );
        }
        ruleset = ruleset.handle_access(handle).map_err(|e| {
            anyhow::anyhow!(
                "landlock: kernel rejected net access rights (need Linux >= 5.19, ABI V4+): {e}"
            )
        })?;
    }

    let mut ruleset = ruleset.create().map_err(|e| {
        anyhow::anyhow!(
            "landlock: ruleset creation failed (check Landlock ABI support in kernel config): {e}"
        )
    })?;

    for path in SYSTEM_READ_PATHS {
        ruleset = landlock_add_rule(ruleset, path, landlock_access_read())
            .with_context(|| format!("adding read rule for {path}"))?;
    }

    for path in SYSTEM_WRITE_PATHS {
        ruleset = landlock_add_rule(ruleset, path, landlock_access_write(abi))
            .with_context(|| format!("adding write rule for {path}"))?;
    }

    if auto_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_str = cwd.to_string_lossy().to_string();
            ruleset = landlock_add_rule(ruleset, &cwd_str, landlock_access_write(abi))
                .context("adding cwd rule")?;
        }
    }

    for p in &config.allow_read {
        let expanded = expand_tilde(p);
        ruleset = landlock_add_rule(ruleset, &expanded, landlock_access_read())
            .with_context(|| format!("adding read rule for {p}"))?;
    }

    for p in &config.allow_write {
        let expanded = expand_tilde(p);
        ruleset = landlock_add_rule(ruleset, &expanded, landlock_access_write(abi))
            .with_context(|| format!("adding write rule for {p}"))?;
    }

    if net_restricted {
        for &port in &config.network.allow_ports {
            let rule = NetPort::new(port, AccessNet::ConnectTcp);
            match ruleset.add_rule(rule) {
                Ok(rs) => {
                    log::debug!("landlock: allow ConnectTcp port {port}");
                    ruleset = rs;
                }
                Err(e) => {
                    bail!("landlock: failed to add net port {port}: {e}")
                }
            }
        }
    }

    let status = ruleset
        .restrict_self()
        .context("landlock: restrict_self failed (process lacks CAP_SYS_ADMIN or Landlock not enabled in kernel)")?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        anyhow::bail!(
            "Landlock restrictions not enforced: ruleset={:?}, landlock={:?} \
             (kernel too old or Landlock not enabled in kernel)",
            status.ruleset,
            status.landlock,
        );
    }

    log::info!("landlock: restrictions applied");
    Ok(())
}

// Access bits that are valid only for file FDs, not dirs
const FILE_ACCESS: landlock::BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | WriteFile | Execute | Truncate | IoctlDev
});

fn landlock_add_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> anyhow::Result<landlock::RulesetCreated> {
    // PathFd::new resolves symlinks atomically — no TOCTOU window.
    let fd = match PathFd::new(path) {
        Ok(fd) => fd,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("No such file") || msg.contains("entity not found") {
                log::debug!("landlock: skipping non-existent path: {path}");
            } else {
                log::debug!("landlock: skipping {path}: {e}");
            }
            return Ok(ruleset);
        }
    };

    // decide exactly what access to get, depending on file vs dir
    let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(true);
    let effective_access = if is_dir { access } else { access & FILE_ACCESS };
    if effective_access.is_empty() {
        log::debug!("landlock: no applicable access bits for {path}, skipping");
        return Ok(ruleset);
    }

    let rule = PathBeneath::new(fd, effective_access);

    match ruleset.add_rule(rule) {
        Ok(rs) => {
            let mode = if effective_access.contains(AccessFs::WriteFile) {
                "rw"
            } else {
                "ro"
            };
            log::debug!("landlock: allow {mode} {path}");
            Ok(rs)
        }
        Err(e) => {
            bail!("landlock: add_rule failed for {path}: {e}")
        }
    }
}

#[cfg(test)]
mod tests;
