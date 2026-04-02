use std::path::PathBuf;

/// Expand leading `~` to $HOME.
pub fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if p == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(p)
}

/// Expand a path pattern: tilde expansion, then glob expansion if it contains glob chars.
/// For patterns without glob chars, returns the single normalized path.
/// Patterns with `**` are collapsed to their parent directory (Landlock PATH_BENEATH covers descendants).
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let expanded = expand_tilde(pattern);
    let s = expanded.to_string_lossy();

    // If pattern contains **, strip it — Landlock covers the subtree
    if s.contains("**") {
        let base = s.split("**").next().unwrap_or(&s);
        let base = base.trim_end_matches('/');
        if !base.is_empty() {
            return vec![PathBuf::from(base)];
        }
        return vec![];
    }

    // If pattern contains glob chars, expand
    if s.contains('*') || s.contains('?') || s.contains('[') {
        match glob::glob(&s) {
            Ok(paths) => {
                let result: Vec<PathBuf> = paths.filter_map(|p| p.ok()).collect();
                if result.is_empty() {
                    log::debug!("glob pattern matched nothing: {pattern}");
                }
                return result;
            }
            Err(e) => {
                log::debug!("invalid glob pattern {pattern}: {e}");
                return vec![];
            }
        }
    }

    vec![expanded]
}
