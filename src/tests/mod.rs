use super::*;

#[test]
fn test_env_matches_exact() {
    assert!(env_matches("HOME", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("PATH", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("LANG", DEFAULT_ENV_ALLOWLIST));
    assert!(!env_matches("AWS_SECRET_KEY", DEFAULT_ENV_ALLOWLIST));
    assert!(!env_matches("GITHUB_TOKEN", DEFAULT_ENV_ALLOWLIST));
    assert!(!env_matches("LD_PRELOAD", DEFAULT_ENV_ALLOWLIST));
}

#[test]
fn test_env_matches_prefix() {
    assert!(env_matches("LC_ALL", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("LC_CTYPE", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("XDG_RUNTIME_DIR", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("XDG_CONFIG_HOME", DEFAULT_ENV_ALLOWLIST));
    assert!(env_matches("XDG_DATA_HOME", DEFAULT_ENV_ALLOWLIST));
    // "LC" without underscore should not match "LC_*" prefix
    assert!(!env_matches("LC", DEFAULT_ENV_ALLOWLIST));
}

#[test]
fn test_is_dangerous() {
    assert!(is_dangerous("LD_PRELOAD"));
    assert!(is_dangerous("LD_LIBRARY_PATH"));
    assert!(is_dangerous("DYLD_INSERT_LIBRARIES"));
    assert!(!is_dangerous("HOME"));
    assert!(!is_dangerous("PATH"));
}

#[test]
fn test_hardened_env_extra_allow() {
    let extra = vec!["DISPLAY".to_string(), "MY_APP_*".to_string()];
    assert!(env_matches("DISPLAY", &extra));
    assert!(env_matches("MY_APP_TOKEN", &extra));
    assert!(!env_matches("OTHER_TOKEN", &extra));
}
