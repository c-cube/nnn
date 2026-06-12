mod config;
mod landlock;
mod paths;
mod sanitize;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "smolsandbox", about = "Minimal Linux sandbox using Landlock")]
struct Cli {
    /// Log violations as warnings instead of blocking
    #[arg(short, long)]
    warn: bool,

    /// Additional read-allowed paths (appended to config)
    #[arg(long)]
    allow_read: Vec<String>,

    /// Additional write-allowed paths (appended to config)
    #[arg(long)]
    allow_write: Vec<String>,

    /// Path to project .nounours.toml (auto-detected from git root)
    #[arg(long)]
    project_config: Option<PathBuf>,

    /// Command to run inside the sandbox
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    // Resolve config: global (xdg) + project (.nounours.toml) + CLI
    let mut cfg = resolve_config(&cli);

    // Merge CLI overrides into allow_read / allow_write
    for p in &cli.allow_read {
        if !cfg.allow_read.contains(p) {
            cfg.allow_read.push(p.clone());
        }
    }
    for p in &cli.allow_write {
        if !cfg.allow_write.contains(p) {
            cfg.allow_write.push(p.clone());
        }
    }

    log::info!("resolved config: {cfg:#?}");

    // Sanitize environment
    let env = sanitize::hardened_env();

    // Apply Landlock
    if let Err(e) = landlock::apply(&cfg, cli.warn) {
        eprintln!("smolsandbox: landlock: {e}");
        std::process::exit(1);
    }

    // Exec the command
    let err = exec_command(&cli.command, &env);
    eprintln!("smolsandbox: exec failed: {err}");
    std::process::exit(1);
}

fn resolve_config(cli: &Cli) -> config::Config {
    // 1. Global config from XDG
    let global_cfg = load_global_config();

    // 2. Project config from cli arg or git root
    let project_path = cli
        .project_config
        .clone()
        .or_else(find_project_config);

    let mut cfg = global_cfg;
    if let Some(path) = project_path {
        match load_toml_file(&path) {
            Ok(project_cfg) => {
                log::info!("loaded project config from {}", path.display());
                cfg = cfg.merge(&project_cfg);
            }
            Err(e) => {
                eprintln!("smolsandbox: {e}");
                std::process::exit(1);
            }
        }
    }

    cfg
}

fn load_global_config() -> config::Config {
    let config_dir = dirs_config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
    let path = config_dir.join("nounours").join("config.toml");
    if path.exists() {
        match load_toml_file(&path) {
            Ok(cfg) => {
                log::info!("loaded global config from {}", path.display());
                return cfg;
            }
            Err(e) => {
                eprintln!("smolsandbox: {e}");
                std::process::exit(1);
            }
        }
    }
    config::Config::default()
}

fn find_project_config() -> Option<PathBuf> {
    // Walk up from cwd looking for .nounours.toml
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".nounours.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn load_toml_file(path: &std::path::Path) -> Result<config::Config, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    toml_edit::de::from_str(&data)
        .map_err(|e| format!("parsing {}: {e}", path.display()))
}

fn dirs_config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config"))
}

fn exec_command(command: &[String], env: &[(String, String)]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Replace current process (sandbox one-shot)
    cmd.exec()
}
