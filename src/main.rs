mod command;
mod config;
mod landlock;
mod paths;
mod profile;
mod sanitize;

use clap::Parser;
use std::convert::Infallible;
use std::ffi::CString;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "smolsandbox", about = "Minimal Linux sandbox using Landlock")]
struct Cli {
    /// Path to JSON profile file (overrides auto-detection)
    #[arg(short, long)]
    profile: Option<PathBuf>,

    /// Don't auto-detect profile from command name
    #[arg(long)]
    no_default_profile: bool,

    /// Log violations as warnings instead of blocking
    #[arg(short, long)]
    warn: bool,

    /// Additional read-allowed paths
    #[arg(long)]
    allow_read: Vec<String>,

    /// Additional write-allowed paths
    #[arg(long)]
    allow_write: Vec<String>,

    /// Additional read-denied paths
    #[arg(long)]
    deny_read: Vec<String>,

    /// Additional denied commands
    #[arg(long)]
    deny_cmd: Vec<String>,

    /// TCP ports allowed for outbound connect (Landlock ABI V4+)
    #[arg(long)]
    allow_port: Vec<u16>,

    /// List available built-in profiles and exit
    #[arg(long)]
    list_profiles: bool,

    /// Command to run inside the sandbox
    #[arg(last = true, required_unless_present = "list_profiles")]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if cli.list_profiles {
        profile::list_profiles();
        return;
    }

    // Resolve profile
    let mut cfg = resolve_config(&cli);

    // Merge CLI overrides
    let cli_overlay = config::Config {
        filesystem: config::FilesystemConfig {
            allow_read: cli.allow_read,
            allow_write: cli.allow_write,
            deny_read: cli.deny_read,
            ..Default::default()
        },
        command: config::CommandConfig {
            deny: cli.deny_cmd,
            ..Default::default()
        },
    };
    cfg = config::merge(&cfg, &cli_overlay);

    log::info!("resolved config: {cfg:#?}");

    // Check command against deny list
    if let Err(msg) = command::check(&cli.command, &cfg.command, cli.warn) {
        eprintln!("smolsandbox: {msg}");
        std::process::exit(1);
    }

    // Sanitize environment
    let env = sanitize::hardened_env();

    // Apply Landlock
    if let Err(e) = landlock::apply(&cfg, &cli.allow_port, cli.warn) {
        eprintln!("smolsandbox: landlock: {e}");
        std::process::exit(1);
    }

    // Exec the command
    let _ = exec_command(&cli.command, &env);
}

fn resolve_config(cli: &Cli) -> config::Config {
    if let Some(ref path) = cli.profile {
        match config::load_file(path) {
            Ok(cfg) => return cfg,
            Err(e) => {
                eprintln!("smolsandbox: {e}");
                std::process::exit(1);
            }
        }
    }

    if cli.no_default_profile {
        return config::Config::default();
    }

    // Auto-detect from command basename
    if let Some(cmd) = cli.command.first() {
        let basename = std::path::Path::new(cmd)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(cmd);
        if let Some(cfg) = profile::find(basename) {
            log::info!("auto-detected profile for {basename:?}");
            return cfg;
        }
    }

    config::Config::default()
}

fn exec_command(command: &[String], env: &[(String, String)]) -> Infallible {
    let program = CString::new(command[0].as_str()).expect("invalid command name");
    let args: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_str()).expect("invalid argument"))
        .collect();
    let env_cstrings: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
        .collect();

    log::debug!("exec: {:?}", command);
    nix::unistd::execvpe(&program, &args, &env_cstrings).expect("execvpe failed")
}
