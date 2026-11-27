use std::{env, fs, path::PathBuf};

mod core_lock;

fn main() {
    println!("cargo:rerun-if-changed=cores.lock");
    println!("cargo:rerun-if-changed=core_lock.rs");
    // DLL hardening (doc#13): the loader resolves etd-host.exe's own
    // imported DLLs from System32 only (LOAD_LIBRARY_SEARCH_SYSTEM32),
    // never from the possibly user-writable image directory.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bin=etd-host=/DEPENDENTLOADFLAG:0x800");
    }
    let target = env::var("TARGET").expect("Cargo target");
    if !core_lock::supported_target(&target) {
        println!("cargo:warning=no trusted release kernels for unsupported build target {target}");
    }
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
