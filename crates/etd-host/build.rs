use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=cores.lock");
    let target = env::var("TARGET").expect("Cargo target");
    let mut table = BTreeMap::new();
    let input = fs::read_to_string("cores.lock").expect("checked-in release hash table");
    for (line_no, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            3,
            "cores.lock line {}: expected target version sha256",
            line_no + 1
        );
        let (platform, version, hash) = (fields[0], fields[1], fields[2]);
        assert!(
            !version.is_empty()
                && version != "."
                && version != ".."
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
            "invalid core version"
        );
        assert!(
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid core hash"
        );
        if platform == target {
            assert!(
                table.insert(version, hash).is_none(),
                "duplicate version for build target"
            );
        }
    }
    let entries = table
        .iter()
        .map(|(version, hash)| format!("    ({version:?}, {hash:?}),\n"))
        .collect::<String>();
    let output = format!("pub const TRUSTED_CORES: &[(&str, &str)] = &[\n{entries}];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"))
            .join("trusted_cores.rs"),
        output,
    )
    .expect("write embedded core table");
}
