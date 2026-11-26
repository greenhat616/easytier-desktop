#[path = "../core_lock.rs"]
mod core_lock;

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn valid_legacy_and_companion_rows_in_either_order() {
    let input = format!("# comment\na 1 file:Packet.dll {HASH}\na 1 {HASH}\nb 2 {HASH}\n");
    let table = core_lock::parse(&input).unwrap();
    assert_eq!(table[&("a", "1")].exe, Some(HASH));
    assert_eq!(table[&("a", "1")].files["Packet.dll"], HASH);
    assert!(table[&("b", "2")].files.is_empty());
    assert!(core_lock::parse("").unwrap().is_empty());
}

#[test]
fn invalid_rows_and_duplicates_are_rejected_for_any_target() {
    for input in [
        format!("a 1 file:x.dll {HASH}"),
        format!("a 1 {HASH}\na 1 {HASH}"),
        format!("a 1 {HASH}\na 2 {HASH}"),
        format!("a 1 {HASH}\na 1 file:X.dll {HASH}\na 1 file:x.DLL {HASH}"),
        format!("a .. {HASH}"),
        format!("a 1 {}", HASH.to_ascii_uppercase()),
        format!("a 1 other:x {HASH}"),
        format!("a 1 {HASH} extra field"),
        "a 1 short".into(),
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
        let input = format!("a 1 {HASH}\na 1 file:{name} {HASH}");
        assert!(core_lock::parse(&input).is_err(), "{name}");
    }
}
