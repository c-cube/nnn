use crate::config::{self, Config, ProfileDef};

const PROFILES_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/profiles.bin.zz"));

fn load_all() -> Vec<ProfileDef> {
    let json = miniz_oxide::inflate::decompress_to_vec_zlib(PROFILES_BLOB)
        .expect("failed to decompress built-in profiles");
    serde_json::from_slice(&json).expect("failed to parse built-in profiles")
}

/// Find a built-in profile by command name.
/// For agents: merges base profile + agent overlay.
/// For toolchains: returns the toolchain config as-is.
pub fn find(name: &str) -> Option<Config> {
    let profiles = load_all();
    let name_lower = name.to_lowercase();

    // Find base profile
    let base = profiles
        .iter()
        .find(|p| p.names.contains(&"_base".to_string()));

    // Find matching profile
    let matched = profiles
        .iter()
        .find(|p| p.names.iter().any(|n| n.to_lowercase() == name_lower))?;

    if matched.toolchain {
        Some(matched.config.clone())
    } else if let Some(base) = base {
        Some(config::merge(&base.config, &matched.config))
    } else {
        Some(matched.config.clone())
    }
}

/// Print all available built-in profiles.
pub fn list_profiles() {
    let profiles = load_all();
    println!("{:<20} {:<10} {}", "NAME", "TYPE", "ALIASES");
    println!("{:<20} {:<10} {}", "----", "----", "-------");
    for p in &profiles {
        if p.names.first().map(|s| s.as_str()) == Some("_base") {
            continue;
        }
        let kind = if p.toolchain { "toolchain" } else { "agent" };
        let name = p.names.first().map(|s| s.as_str()).unwrap_or("?");
        let aliases = if p.names.len() > 1 {
            p.names[1..].join(", ")
        } else {
            String::new()
        };
        println!("{name:<20} {kind:<10} {aliases}");
    }
}
