use serde::Deserialize;

/// Filesystem paths to allow — loaded from TOML config.
/// Config is just allow_read + allow_write, nothing more.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
}

impl Config {
    /// Merge another config on top (project overrides global).
    pub fn merge(&self, overlay: &Config) -> Config {
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
