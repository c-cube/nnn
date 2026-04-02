use miniz_oxide::deflate::compress_to_vec_zlib;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let profiles_dir = Path::new("profiles");

    println!("cargo:rerun-if-changed=profiles/");

    let mut all_profiles: Vec<serde_json::Value> = Vec::new();

    if profiles_dir.exists() {
        // Load base profile
        let base_path = profiles_dir.join("base.json");
        if base_path.exists() {
            let data = fs::read_to_string(&base_path).expect("reading base.json");
            let val: serde_json::Value = serde_json::from_str(&data).expect("parsing base.json");
            all_profiles.push(val);
        }

        // Load agent profiles
        let agents_dir = profiles_dir.join("agents");
        if agents_dir.exists() {
            load_profiles_from_dir(&agents_dir, &mut all_profiles);
        }

        // Load toolchain profiles
        let toolchains_dir = profiles_dir.join("toolchains");
        if toolchains_dir.exists() {
            load_profiles_from_dir(&toolchains_dir, &mut all_profiles);
        }
    }

    let json = serde_json::to_vec(&all_profiles).expect("serializing profiles");
    let compressed = compress_to_vec_zlib(&json, 6);

    let out_path = Path::new(&out_dir).join("profiles.bin.zz");
    fs::write(&out_path, &compressed).expect("writing compressed profiles");
}

fn load_profiles_from_dir(dir: &Path, out: &mut Vec<serde_json::Value>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("reading profiles directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let data = fs::read_to_string(entry.path()).expect("reading profile json");
        let val: serde_json::Value = serde_json::from_str(&data).expect("parsing profile json");
        out.push(val);
    }
}
