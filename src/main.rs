use landlock::{
    make_bitflags, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use toml_edit::DocumentMut;

// ── Config ──

#[derive(Debug, Default, Clone)]
struct Config {
    allow_read: Vec<String>,
    allow_write: Vec<String>,
}

impl Config {
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

    match cli.command {
        Command::Exec(args) => cmd_exec(args),
        Command::AddRo(args) => cmd_add_path(&args.dir, false, args.global),
        Command::AddRw(args) => cmd_add_path(&args.dir, true, args.global),
        Command::Show => cmd_show(),
        Command::Other(args) if args.is_empty() => {
            eprintln!("nnn: expected a command to run");
            std::process::exit(1);
        }
        Command::Other(args) => {
            let exec_args = ExecArgs {
                no_auto_cwd: false,
                allow_read: Vec::new(),
                allow_write: Vec::new(),
                project_config: None,
                command: args,
            };
            cmd_exec(exec_args);
        }
        Command::Init => cmd_init(),
    }
}

fn cmd_exec(args: ExecArgs) {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .init();

    let mut cfg = resolve_config(args.project_config.as_deref());

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

    log::info!("resolved config: {cfg:#?}");

    let env = hardened_env();

    if let Err(e) = landlock_apply(&cfg, !args.no_auto_cwd) {
        eprintln!("nnn: landlock: {e}");
        std::process::exit(1);
    }

    let err = exec_command(&args.command, &env);
    eprintln!("nnn: exec failed: {err}");
    std::process::exit(1);
}

fn cmd_add_path(dir: &str, write: bool, global: bool) {
    let project_path = if global {
        global_config_path()
    } else {
        find_project_config().unwrap_or_else(|| {
            let root = find_git_root().unwrap_or_else(|| {
                std::env::current_dir().expect("cwd available")
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

    if !doc.contains_table(key) {
        doc[key] = toml_edit::value(toml_edit::Array::new());
    }

    let arr = doc[key].as_array_mut().expect("expected array");
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
            }
            Err(e) => eprintln!("  error: {e}"),
        }
    } else {
        println!("\nResolved (global only):");
        print_paths("allow-read", &global_cfg.allow_read);
        print_paths("allow-write", &global_cfg.allow_write);
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

fn load_toml_file(path: &Path) -> Result<Config, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct Raw {
        #[serde(default)]
        allow_read: Vec<String>,
        #[serde(default)]
        allow_write: Vec<String>,
    }
    let raw: Raw =
        toml_edit::de::from_str(&data).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    Ok(Config {
        allow_read: raw.allow_read,
        allow_write: raw.allow_write,
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

// ── Landlock ──

const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc",
    "/sys", "/run", "/var", "/opt", "/dev", "/tmp",
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

fn landlock_apply(config: &Config, auto_cwd: bool) -> Result<(), String> {
    let abi = ABI::V5;

    let fs_access = AccessFs::from_all(abi);
    if fs_access.is_empty() {
        log::warn!("landlock: not supported on this kernel, skipping");
        return Ok(());
    }

    let ruleset = Ruleset::default()
        .handle_access(fs_access)
        .map_err(|e| format!("creating ruleset: {e}"))?;

    let mut ruleset = ruleset
        .create()
        .map_err(|e| format!("creating ruleset: {e}"))?;

    for path in SYSTEM_READ_PATHS {
        ruleset = landlock_add_rule(ruleset, path, landlock_access_read());
    }

    for path in SYSTEM_WRITE_PATHS {
        ruleset = landlock_add_rule(ruleset, path, landlock_access_write(abi));
    }

    if auto_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_str = cwd.to_string_lossy().to_string();
            ruleset = landlock_add_rule(ruleset, &cwd_str, landlock_access_write(abi));
        }
    }

    for p in &config.allow_read {
        let expanded = expand_tilde(p);
        ruleset = landlock_add_rule(ruleset, &expanded, landlock_access_read());
    }

    for p in &config.allow_write {
        let expanded = expand_tilde(p);
        ruleset = landlock_add_rule(ruleset, &expanded, landlock_access_write(abi));
    }

    ruleset
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;

    log::info!("landlock: restrictions applied");
    Ok(())
}

fn landlock_add_rule(
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
