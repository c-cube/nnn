use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Main configuration — JSON-compatible with greywall's format.
/// Unknown fields (network, ssh, credentials) are silently ignored.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub command: CommandConfig,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemConfig {
    /// None or Some(true) = deny reads by default (only system paths + allow_read accessible).
    pub default_deny_read: Option<bool>,
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub deny_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub deny_write: Vec<String>,
}

impl FilesystemConfig {
    pub fn is_default_deny_read(&self) -> bool {
        self.default_deny_read.unwrap_or(true)
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandConfig {
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    /// None or Some(true) = use default dangerous command deny list.
    pub use_defaults: Option<bool>,
}

impl CommandConfig {
    pub fn use_default_denied_commands(&self) -> bool {
        self.use_defaults.unwrap_or(true)
    }
}

/// A named profile as produced by sync-profiles and baked into the binary.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDef {
    pub names: Vec<String>,
    #[serde(default)]
    pub toolchain: bool,
    #[serde(flatten)]
    pub config: Config,
}

/// Merge two configs: append vecs (dedup), override wins for Option fields.
pub fn merge(base: &Config, overlay: &Config) -> Config {
    Config {
        filesystem: FilesystemConfig {
            default_deny_read: overlay
                .filesystem
                .default_deny_read
                .or(base.filesystem.default_deny_read),
            allow_read: merge_vecs(&base.filesystem.allow_read, &overlay.filesystem.allow_read),
            deny_read: merge_vecs(&base.filesystem.deny_read, &overlay.filesystem.deny_read),
            allow_write: merge_vecs(
                &base.filesystem.allow_write,
                &overlay.filesystem.allow_write,
            ),
            deny_write: merge_vecs(&base.filesystem.deny_write, &overlay.filesystem.deny_write),
        },
        command: CommandConfig {
            deny: merge_vecs(&base.command.deny, &overlay.command.deny),
            allow: merge_vecs(&base.command.allow, &overlay.command.allow),
            use_defaults: overlay.command.use_defaults.or(base.command.use_defaults),
        },
    }
}

fn merge_vecs(base: &[String], overlay: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(base.len() + overlay.len());
    for s in base.iter().chain(overlay.iter()) {
        if seen.insert(s.as_str()) {
            result.push(s.clone());
        }
    }
    result
}

/// Load a config from a JSON file. Unknown fields are ignored.
pub fn load_file(path: &std::path::Path) -> Result<Config, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("parsing {}: {e}", path.display()))
}
