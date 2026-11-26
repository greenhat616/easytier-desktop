use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub exe: Option<&'a str>,
    pub files: BTreeMap<&'a str, &'a str>,
}

pub fn supported_target(target: &str) -> bool {
    matches!(
        target,
        "x86_64-pc-windows-msvc"
            | "aarch64-pc-windows-msvc"
            | "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "x86_64-apple-darwin"
            | "aarch64-apple-darwin"
    )
}

pub type LockTable<'a> = BTreeMap<(&'a str, &'a str), Bundle<'a>>;

pub fn parse(input: &str) -> Result<LockTable<'_>, String> {
    let mut table = BTreeMap::<_, Bundle<'_>>::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        let fail = |why: &str| format!("cores.lock line {}: {why}", index + 1);
        let (target, version, file, hash) = match fields.as_slice() {
            [target, version, hash] => (*target, *version, None, *hash),
            [target, version, file, hash] => {
                let name = file
                    .strip_prefix("file:")
                    .ok_or_else(|| fail("expected file:<name>"))?;
                if !valid_name(name) {
                    return Err(fail("invalid companion name"));
                }
                (*target, *version, Some(name), *hash)
            }
            _ => return Err(fail("expected target version [file:<name>] sha256")),
        };
        if !supported_target(target) {
            return Err(fail("unsupported core target"));
        }
        if version == "."
            || version == ".."
            || version.ends_with('.')
            || reserved_device_name(version)
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(fail("invalid core version"));
        }
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(fail("invalid core hash"));
        }
        let bundle = table.entry((target, version)).or_default();
        if let Some(name) = file {
            if bundle
                .files
                .keys()
                .any(|other| other.eq_ignore_ascii_case(name))
            {
                return Err(fail("duplicate companion name"));
            }
            bundle.files.insert(name, hash);
        } else if bundle.exe.replace(hash).is_some() {
            return Err(fail("duplicate executable row"));
        }
    }
    let mut hashes = BTreeSet::new();
    for (&(target, version), bundle) in &table {
        let hash = bundle
            .exe
            .ok_or_else(|| format!("cores.lock: missing executable row for {target} {version}"))?;
        if !hashes.insert((target, hash)) {
            return Err(format!(
                "cores.lock: duplicate executable hash for {target}"
            ));
        }
    }
    Ok(table)
}

// A portable subset of ordinary filenames; Windows aliasing and device
// names must not allow a companion to overwrite another bundle member.
fn valid_name(name: &str) -> bool {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        || ["easytier-core", "easytier-core.exe"]
            .iter()
            .any(|exe| exe.eq_ignore_ascii_case(name))
    {
        return false;
    }
    !reserved_device_name(name)
}

fn reserved_device_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}
