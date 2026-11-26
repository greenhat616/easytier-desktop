#[path = "../core_lock.rs"]
mod core_lock;

const A: &str = "x86_64-pc-windows-msvc";
const B: &str = "aarch64-apple-darwin";
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn valid_legacy_and_companion_rows_in_either_order() {
    let input = format!("# comment\n{A} 1 file:Packet.dll {HASH}\n{A} 1 {HASH}\n{B} 2 {HASH}\n");
    let table = core_lock::parse(&input).unwrap();
    assert_eq!(table[&(A, "1")].exe, Some(HASH));
    assert_eq!(table[&(A, "1")].files["Packet.dll"], HASH);
    assert!(table[&(B, "2")].files.is_empty());
    assert!(core_lock::parse("").unwrap().is_empty());
}

#[test]
fn invalid_rows_and_duplicates_are_rejected_for_any_target() {
    for input in [
        format!("{A} 1 file:x.dll {HASH}"),
        format!("{A} 1 {HASH}\n{A} 1 {HASH}"),
        format!("{A} 1 {HASH}\n{A} 2 {HASH}"),
        format!("{A} 1 {HASH}\n{A} 1 file:X.dll {HASH}\n{A} 1 file:x.DLL {HASH}"),
        format!("{A} .. {HASH}"),
        format!("{A} 1 {}", HASH.to_ascii_uppercase()),
        format!("{A} 1 other:x {HASH}"),
        format!("{A} 1 {HASH} extra field"),
        format!("{A} 1 short"),
    ] {
        assert!(core_lock::parse(&input).is_err(), "{input}");
    }
}

#[test]
fn invalid_companion_names() {
    for name in [
        "",
        ".",
        "..",
        "../x",
        "a/b",
        "a\\b",
        "C:x",
        "x:stream",
        "x..dll",
        "x.",
        "x y",
        "NUL.dll",
        "com1.sys",
        "easytier-core",
        "EASYTIER-CORE.EXE",
        "*.dll",
    ] {
        let input = format!("{A} 1 {HASH}\n{A} 1 file:{name} {HASH}");
        assert!(core_lock::parse(&input).is_err(), "{name}");
    }
}

#[test]
fn rejects_unsupported_targets_and_windows_reserved_versions() {
    for target in ["x86_64-pc-windows-gnu", "typo", "i686-pc-windows-msvc"] {
        assert!(core_lock::parse(&format!("{target} 1 {HASH}")).is_err());
    }
    for version in ["NUL", "COM1.2", "lpt9", "1.", "1 2"] {
        assert!(core_lock::parse(&format!("{A} {version} {HASH}")).is_err());
    }
}
