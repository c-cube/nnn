use std::path::PathBuf;

/// Expand leading `~` to $HOME. No glob support — keep it simple.
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let expanded = if let Some(rest) = pattern.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(rest)
        } else {
            PathBuf::from(pattern)
        }
    } else if pattern == "~" {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
        } else {
            PathBuf::from(pattern)
        }
    } else {
        PathBuf::from(pattern)
    };
    vec![expanded]
}
