/// Return the current environment with dangerous variables stripped.
pub fn hardened_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> =
        std::env::vars().filter(|(k, _)| !is_dangerous(k)).collect();
    env.push(("NOUNOURS".to_string(), "1".to_string()));
    env
}

fn is_dangerous(key: &str) -> bool {
    // Strip LD_* and DYLD_* prefixes (library injection vectors)
    key.starts_with("LD_") || key.starts_with("DYLD_")
}
