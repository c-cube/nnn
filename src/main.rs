#![deny(unsafe_code)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use anyhow::{bail, Context};
use landlock::{
    make_bitflags, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
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
    /// None = use built-in default (true).
    seccomp: Option<bool>,
    network: NetworkConfig,
}

impl Config {
    fn seccomp_enabled(&self) -> bool {
        self.seccomp.unwrap_or(true)
    }

    fn merge(&self, overlay: &Config) -> Config {
        let mut c = self.clone();
        for p in &overlay.allow_read {
            if !c.allow_read.contains(p) {
                c.allow_read.push(p.clone());
            }
        }
        for p in &overlay.allow_write {
            if !c.allow_write.contains(p) {
                c.allow_write.push(p.clone());
            }
        }
        c.seccomp = overlay.seccomp.or(c.seccomp);
        c.network.deny_tcp = overlay.network.deny_tcp.or(c.network.deny_tcp);
        c.network.deny_udp = overlay.network.deny_udp.or(c.network.deny_udp);
        for p in &overlay.network.allow_ports {
            if !c.network.allow_ports.contains(p) {
                c.network.allow_ports.push(*p);
            }
        }
        c
    }
}

const DEFAULT_CONFIG: &str = concat!(
    "allow-read = [\n",
    "    \"/bin/\",\n",
    "    \"/usr/bin/\",\n",
    "    \"/usr/local/bin\",\n",
    "    \"~/.cargo/bin\",\n",
    "    \"~/.config/nnn\",\n",
    "]\n",
    "\n",
    "allow-write = [\n",
    "    \"/tmp/nnn/\",\n",
    "]\n",
    "\n",
    "# Network restrictions (Landlock ABI V4+, kernel >= 5.19)\n",
    "# [network]\n",
    "# deny-tcp = false\n",
    "# deny-udp = false\n",
    "# allow-ports = [80, 443, 22]\n",
);

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
    /// Show resolved rules for the current directory
    Show,
    /// Write default global config to ~/.config/nnn/config.toml
    Init,
    #[command(external_subcommand)]
    Other(Vec<String>),
}

#[derive(Parser)]
struct ExecArgs {
    /// Don't automatically allow read-write access to cwd
    #[arg(long)]
    no_auto_cwd: bool,

    /// Additional read-allowed paths (appended to config)
    #[arg(long)]
    allow_read: Vec<String>,

    /// Additional write-allowed paths (appended to config)
    #[arg(long)]
    allow_write: Vec<String>,

    /// Additional TCP ports allowed for outbound connect
    #[arg(long)]
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
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Exec(args) => cmd_exec(args),
        Command::AddRo(args) => {
            cmd_add_path(&args.dir, false, args.global);
            Ok(())
        }
        Command::AddRw(args) => {
            cmd_add_path(&args.dir, true, args.global);
            Ok(())
        }
        Command::Show => {
            cmd_show();
            Ok(())
        }
        Command::Other(args) if args.is_empty() => {
            eprintln!("nnn: expected a command to run");
            std::process::exit(1);
        }
        Command::Other(args) => cmd_exec(ExecArgs {
            no_auto_cwd: false,
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_port: Vec::new(),
            project_config: None,
            command: args,
        }),
        Command::Init => {
            cmd_init();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("nnn: {e:#}");
        std::process::exit(1);
    }
}

fn cmd_exec(args: ExecArgs) -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut cfg = resolve_config(args.project_config.as_deref());

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

    for p in &args.allow_read {
        if !cfg.allow_read.contains(p) {
            cfg.allow_read.push(p.clone());
        }
    }
    for p in &args.allow_write {
        if !cfg.allow_write.contains(p) {
            cfg.allow_write.push(p.clone());
        }
    }
    for &p in &args.allow_port {
        if !cfg.network.allow_ports.contains(&p) {
            cfg.network.allow_ports.push(p);
        }
    }

    log::info!("resolved config: {cfg:#?}");

    let env = hardened_env();

    if cfg.seccomp_enabled() {
        seccomp_apply()?;
    }

    landlock_apply(&cfg, !args.no_auto_cwd)?;

    let err = exec_command(&args.command, &env);
    Err(anyhow::anyhow!("exec of {:?} failed: {err}", args.command))
}

fn cmd_add_path(dir: &str, write: bool, global: bool) {
    let project_path = if global {
        global_config_path()
    } else {
        find_project_config().unwrap_or_else(|| {
            let root = find_git_root().unwrap_or_else(|| match std::env::current_dir() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("nnn: no cwd: {e}");
                    std::process::exit(1);
                }
            });
            root.join(".nnn.toml")
        })
    };

    if let Some(parent) = project_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut doc: DocumentMut = if project_path.exists() {
        let data = std::fs::read_to_string(&project_path).unwrap_or_default();
        data.parse().unwrap_or_default()
    } else {
        DocumentMut::new()
    };

    let key = if write { "allow-write" } else { "allow-read" };

    if doc.get(key).and_then(|item| item.as_array()).is_none() {
        doc[key] = toml_edit::value(toml_edit::Array::new());
    }

    let arr = doc[key].as_array_mut().unwrap_or_else(|| {
        eprintln!("nnn: {} is not an array in config", key);
        std::process::exit(1);
    });
    if !arr.iter().any(|v| v.as_str() == Some(dir)) {
        arr.push(dir);
    }

    std::fs::write(&project_path, doc.to_string()).unwrap_or_else(|e| {
        eprintln!("nnn: write {}: {e}", project_path.display());
        std::process::exit(1);
    });

    println!("added {} to {}", dir, project_path.display());
}

fn cmd_show() {
    let global_path = global_config_path();
    let project_path = find_project_config();

    println!("Global config: {}", global_path.display());
    if global_path.exists() {
        print_config(&global_path);
    } else {
        println!("  (not found)");
    }

    let global_cfg = load_global_config();
    if let Some(ref pp) = project_path {
        println!("\nProject config: {}", pp.display());
        print_config(pp);
        match load_toml_file(pp) {
            Ok(project_cfg) => {
                let merged = global_cfg.merge(&project_cfg);
                println!("\nResolved (merged):");
                print_paths("allow-read", &merged.allow_read);
                print_paths("allow-write", &merged.allow_write);
                print_network(&merged.network);
            }
            Err(e) => eprintln!("  error: {e}"),
        }
    } else {
        println!("\nResolved (global only):");
        print_paths("allow-read", &global_cfg.allow_read);
        print_paths("allow-write", &global_cfg.allow_write);
        print_network(&global_cfg.network);
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

fn cmd_init() {
    let path = global_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("nnn: create {}: {e}", parent.display());
            std::process::exit(1);
        });
    }

    if path.exists() {
        eprintln!("nnn: {} already exists", path.display());
        std::process::exit(1);
    }

    std::fs::write(&path, DEFAULT_CONFIG).unwrap_or_else(|e| {
        eprintln!("nnn: write {}: {e}", path.display());
        std::process::exit(1);
    });

    println!("wrote {}", path.display());
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

fn resolve_config(explicit_project: Option<&Path>) -> Config {
    let global_cfg = load_global_config();
    let project_path = explicit_project
        .map(|p| p.to_path_buf())
        .or_else(find_project_config);

    let mut cfg = global_cfg;
    if let Some(path) = project_path {
        match load_toml_file(&path) {
            Ok(project_cfg) => {
                log::info!("loaded project config from {}", path.display());
                cfg = cfg.merge(&project_cfg);
            }
            Err(e) => {
                eprintln!("nnn: {e}");
                std::process::exit(1);
            }
        }
    }
    cfg
}

fn load_global_config() -> Config {
    let path = global_config_path();
    if path.exists() {
        match load_toml_file(&path) {
            Ok(cfg) => {
                log::info!("loaded global config from {}", path.display());
                return cfg;
            }
            Err(e) => {
                eprintln!("nnn: {e}");
                std::process::exit(1);
            }
        }
    }
    Config::default()
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

fn hardened_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> =
        std::env::vars().filter(|(k, _)| !is_dangerous(k)).collect();
    env.push(("NNN".to_string(), "1".to_string()));
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
        std::env::var("HOME").unwrap_or_default()
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
    .context("building seccomp filter")?;

    let bpf: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|_| anyhow::anyhow!("seccomp filter compilation failed"))?;

    seccompiler::apply_filter(&bpf).context("applying seccomp filter (need Linux >= 3.5)")?;

    log::info!("seccomp: restrictions applied");
    Ok(())
}

const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys", "/run", "/var",
    "/opt", "/dev", "/tmp",
];

const SYSTEM_WRITE_PATHS: &[&str] = &["/dev/null", "/dev/tty", "/tmp", "/var/tmp"];

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

fn landlock_apply(config: &Config, auto_cwd: bool) -> anyhow::Result<()> {
    let abi = ABI::V5;

    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        log::error!("landlock: not supported on this kernel (need Linux >= 5.13)");
        anyhow::bail!("landlock not supported on this kernel (need Linux >= 5.13)");
    }

    let deny_tcp = config.network.is_deny_tcp();
    let deny_udp = config.network.is_deny_udp();
    let net_restricted = deny_tcp || deny_udp || !config.network.allow_ports.is_empty();

    if deny_udp {
        log::warn!("landlock: deny-udp requires AccessNet::ConnectUdp which is not available in landlock 0.4 — ignored");
    }

    let mut ruleset = Ruleset::default().handle_access(fs_access).map_err(|e| {
        anyhow::anyhow!("landlock: kernel rejected access rights (kernel too old?): {e}")
    })?;

    if net_restricted {
        let net_access = AccessNet::from_all(abi);
        let handle = make_bitflags!(AccessNet::{BindTcp | ConnectTcp});
        if !net_access.intersects(handle) {
            anyhow::bail!(
                "landlock: network restrictions require Landlock ABI V4+ (kernel >= 5.19)"
            );
        }
        ruleset = ruleset
            .handle_access(handle)
            .map_err(|e| anyhow::anyhow!("landlock: kernel rejected net access rights: {e}"))?;
    }

    let mut ruleset = ruleset
        .create()
        .map_err(|e| anyhow::anyhow!("landlock: ruleset creation failed: {e}"))?;

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

    ruleset.restrict_self().context("restrict_self")?;

    log::info!("landlock: restrictions applied");
    Ok(())
}

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
    let rule = PathBeneath::new(fd, access);

    match ruleset.add_rule(rule) {
        Ok(rs) => {
            let mode = if access.contains(AccessFs::WriteFile) {
                "rw"
            } else {
                "ro"
            };
            log::debug!("landlock: allow {mode} {path}");
            Ok(rs)
        }
        Err(e) => {
            bail!("add_rule failed for {path}: {e}")
        }
    }
}
