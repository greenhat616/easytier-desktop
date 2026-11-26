use std::{env, fs, path::PathBuf};

mod core_lock;

fn main() {
    println!("cargo:rerun-if-changed=cores.lock");
    println!("cargo:rerun-if-changed=core_lock.rs");
    let target = env::var("TARGET").expect("Cargo target");
    let input = fs::read_to_string("cores.lock").expect("checked-in release hash table");
    let table = core_lock::parse(&input).expect("valid release hash table");
    let entries = table
        .iter()
        .filter(|((platform, _), _)| *platform == target)
        .map(|((_, version), bundle)| {
            let hash = bundle.exe.expect("validated executable hash");
            let companions = bundle
                .files
                .iter()
                .map(|(name, digest)| format!("({name:?}, {digest:?}),"))
                .collect::<String>();
            format!("    ({version:?}, {hash:?}, &[{companions}]),\n")
        })
        .collect::<String>();
    let output = format!(
        "pub type TrustedCoreRow = (&'static str, &'static str, &'static [(&'static str, &'static str)]);\npub const TRUSTED_CORES: &[TrustedCoreRow] = &[\n{entries}];\n"
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"))
            .join("trusted_cores.rs"),
        output,
    )
    .expect("write embedded core table");
}
