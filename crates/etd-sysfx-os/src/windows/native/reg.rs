//! The registry operations: NRPT rules, network profiles, adapter interface
//! values and the Magic DNS record, read and reclaimed through the 64-bit
//! HKLM view. Rows have the shape the PowerShell worker produced.
use super::super::{
    WinError,
    registry::{Key, RawValue, delete_key, utf16},
};
use super::Sweep;
use ::windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ,
};
use etd_sysfx::SettingValue;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) const NRPT: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
pub(super) const PROFILES: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles";
const SIGNATURES: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged";
pub(super) const MAGIC: &str = r"SOFTWARE\EasyTier\MagicDNS";
const INTERFACES: [&str; 3] = [
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
    r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces",
];

fn open(path: &str) -> Result<Option<Key>, WinError> {
    Key::open(HKEY_LOCAL_MACHINE, path, KEY_READ)
}

fn children(path: &str) -> Result<Vec<String>, WinError> {
    open(path)?.map_or(Ok(Vec::new()), |k| k.children())
}

/// A string value as .NET's `RegistryKey.GetValue` reads it: one
/// terminating NUL removed, embedded NULs kept.
fn text(value: &RawValue) -> Result<String, WinError> {
    let mut buf = utf16(value)?;
    if buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf16(&buf).map_err(|_| WinError::invalid("invalid registry text"))
}

/// The strings of a REG_MULTI_SZ as .NET's `RegistryKey.GetValue` splits
/// them: an empty string inside the list is kept, the final terminator is
/// not.
fn strings(value: &RawValue) -> Result<Vec<String>, WinError> {
    let mut buf = utf16(value)?;
    if buf.last().is_some_and(|&c| c != 0) {
        buf.push(0);
    }
    let len = buf.len();
    let mut out = Vec::new();
    let mut cur = 0;
    while cur < len {
        let next = cur + buf[cur..].iter().position(|&c| c == 0).expect("terminated");
        if next > cur {
            out.push(
                String::from_utf16(&buf[cur..next])
                    .map_err(|_| WinError::invalid("invalid registry text"))?,
            );
        } else if next != len - 1 {
            out.push(String::new());
        }
        cur = next + 1;
    }
    Ok(out)
}

fn fixed<const N: usize>(value: &RawValue) -> Option<[u8; N]> {
    value.bytes.get(..N)?.try_into().ok()
}

/// A value as the worker printed it in descriptions: what .NET's
/// `RegistryKey.GetValue` returns, joined with `,`. REG_EXPAND_SZ is
/// expanded against the fixed machine environment only ([`expand`]), never
/// this process's.
pub(super) fn shown(value: &RawValue) -> Result<String, WinError> {
    Ok(match value.ty {
        REG_SZ => text(value)?,
        REG_EXPAND_SZ => expand(&text(value)?)?,
        REG_MULTI_SZ => strings(value)?.join(","),
        REG_DWORD if value.bytes.len() == 4 => {
            i32::from_le_bytes(fixed(value).expect("four bytes")).to_string()
        }
        REG_QWORD if value.bytes.len() == 8 => {
            i64::from_le_bytes(fixed(value).expect("eight bytes")).to_string()
        }
        _ => value
            .bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(","),
    })
}

/// A value as `[string]` of `GetValue`: like [`shown`], but a multi-string
/// joined with a space, and absent as "".
fn as_string(value: Option<&RawValue>) -> Result<String, WinError> {
    match value {
        None => Ok(String::new()),
        Some(v) if v.ty == REG_MULTI_SZ => Ok(strings(v)?.join(" ")),
        Some(v) => shown(v),
    }
}

/// The machine's own values for the variables a system registry value can
/// reference, from the system directory and HKLM: never this process's
/// environment, which HKCU\Environment can set in an elevated session.
fn machine_variables() -> Result<Vec<(&'static str, String)>, WinError> {
    let windows = super::super::driver_refs::windows_dir()?
        .to_string_lossy()
        .into_owned();
    let drive: String = windows.chars().take(2).collect();
    let current = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        KEY_READ,
    )?;
    let value = |name: &str| -> Result<Option<String>, WinError> {
        match current
            .as_ref()
            .map(|k| k.read(name))
            .transpose()?
            .flatten()
        {
            Some(v) if v.ty == REG_SZ => Ok(Some(text(&v)?)),
            _ => Ok(None),
        }
    };
    let mut out = vec![
        ("SystemRoot", windows.clone()),
        ("windir", windows),
        ("SystemDrive", drive.clone()),
        ("ProgramData", format!(r"{drive}\ProgramData")),
        ("ALLUSERSPROFILE", format!(r"{drive}\ProgramData")),
    ];
    if let Some(p) = value("ProgramFilesDir")? {
        out.push(("ProgramFiles", p));
    }
    if let Some(p) = value("ProgramFilesDir (x86)")? {
        out.push(("ProgramFiles(x86)", p));
    }
    Ok(out)
}

/// `%NAME%` references replaced by the machine values of
/// [`machine_variables`] (names compared case-insensitively); any other
/// reference is left as written, as ExpandEnvironmentStrings leaves an
/// undefined one.
pub(super) fn expand(raw: &str) -> Result<String, WinError> {
    if !raw.contains('%') {
        return Ok(raw.to_owned());
    }
    Ok(expand_with(raw, &machine_variables()?))
}

fn expand_with(raw: &str, variables: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match variables
                    .iter()
                    .find(|(n, _)| !name.is_empty() && n.eq_ignore_ascii_case(name))
                {
                    Some((_, value)) => {
                        out.push_str(value);
                        rest = &after[end + 1..];
                    }
                    None => {
                        out.push('%');
                        rest = after;
                    }
                }
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `name=value` for every value of `key`, sorted by name (ordinal,
/// case-insensitive; the worker's culture order is a declared difference),
/// joined with `;`.
fn description(key: &Key) -> Result<String, WinError> {
    let mut names = key.value_names()?;
    names.sort_by(|a, b| {
        a.to_lowercase()
            .cmp(&b.to_lowercase())
            .then_with(|| a.cmp(b))
    });
    let mut parts = Vec::with_capacity(names.len());
    for name in names {
        let value = match key.read(&name)? {
            Some(v) => shown(&v)?,
            None => String::new(),
        };
        parts.push(format!("{name}={value}"));
    }
    Ok(parts.join(";"))
}

/// One row per subkey of `root`, built by `row`; in sweep mode a subkey that
/// fails becomes a `{warning, object}` row instead of failing all.
fn rows(
    root: &str,
    sweep: Sweep,
    row: impl Fn(&str, &Key) -> Result<Value, WinError>,
) -> Result<Vec<Value>, WinError> {
    let mut out = Vec::new();
    for id in children(root)? {
        let built = (|| match open(&format!(r"{root}\{id}"))? {
            Some(key) => row(&id, &key).map(Some),
            None => Ok(None),
        })();
        match built {
            Ok(Some(v)) => out.push(v),
            Ok(None) => {}
            Err(e) if sweep.0 => out.push(json!({"warning": e.message, "object": id})),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

pub(super) fn nrpt(sweep: Sweep) -> Result<Vec<Value>, WinError> {
    rows(NRPT, sweep, |id, key| {
        Ok(json!({
            "name": id,
            "group": as_string(key.read("Comment")?.as_ref())?,
            "id": id,
            "description": description(key)?,
        }))
    })
}

pub(super) fn profiles(sweep: Sweep) -> Result<Vec<Value>, WinError> {
    rows(PROFILES, sweep, |id, key| {
        Ok(json!({
            "name": as_string(key.read("ProfileName")?.as_ref())?,
            "id": id,
            "description": description(key)?,
        }))
    })
}

/// Every value under the Tcpip, Tcpip6 and NetBT interface keys.
pub(super) fn interface_values(sweep: Sweep) -> Result<Vec<Value>, WinError> {
    let mut out = Vec::new();
    for prefix in INTERFACES {
        for name in children(prefix)? {
            let path = format!(r"{prefix}\{name}");
            let key = match open(&path) {
                Ok(Some(k)) => k,
                Ok(None) => continue,
                Err(e) if sweep.0 => {
                    out.push(json!({"warning": e.message, "object": path}));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let values = match key.value_names() {
                Ok(v) => v,
                Err(e) if sweep.0 => {
                    out.push(json!({"warning": e.message, "object": path}));
                    continue;
                }
                Err(e) => return Err(e),
            };
            for value in values {
                let shown = key
                    .read(&value)
                    .and_then(|v| v.map_or(Ok(String::new()), |v| shown(&v)));
                match shown {
                    Ok(description) => out.push(json!({
                        "key": format!(r"HKLM\{path}"),
                        "value": value,
                        "description": description,
                    })),
                    Err(e) if sweep.0 => out
                        .push(json!({"warning": e.message, "object": format!(r"{path}\{value}")})),
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(out)
}

/// A value as a [`SettingValue`]; types other than the five are refused, as
/// the worker refused them (REG_EXPAND_SZ included: it is never compared
/// expanded).
fn typed(value: Option<RawValue>) -> Result<SettingValue, WinError> {
    let Some(value) = value else {
        return Ok(SettingValue::Absent);
    };
    Ok(match value.ty {
        REG_SZ => SettingValue::String(text(&value)?),
        REG_MULTI_SZ => SettingValue::MultiString(strings(&value)?),
        REG_DWORD if value.bytes.len() == 4 => {
            SettingValue::U32(u32::from_le_bytes(fixed(&value).expect("four bytes")))
        }
        REG_QWORD if value.bytes.len() == 8 => {
            SettingValue::U64(u64::from_le_bytes(fixed(&value).expect("eight bytes")))
        }
        REG_BINARY => SettingValue::Bytes(value.bytes),
        _ => return Err(WinError::invalid("Unsupported registry value type")),
    })
}

fn raw(value: &SettingValue) -> Result<Option<RawValue>, WinError> {
    let wide = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    Ok(Some(match value {
        SettingValue::Absent => return Ok(None),
        SettingValue::String(s) => RawValue {
            ty: REG_SZ,
            bytes: wide(s),
        },
        SettingValue::MultiString(items) => RawValue {
            ty: REG_MULTI_SZ,
            bytes: items
                .iter()
                .flat_map(|s| s.encode_utf16().chain([0]))
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        },
        SettingValue::U32(n) => RawValue {
            ty: REG_DWORD,
            bytes: n.to_le_bytes().to_vec(),
        },
        SettingValue::U64(n) => RawValue {
            ty: REG_QWORD,
            bytes: n.to_le_bytes().to_vec(),
        },
        SettingValue::Bytes(b) => RawValue {
            ty: REG_BINARY,
            bytes: b.clone(),
        },
        _ => return Err(WinError::invalid("Unsupported restore type")),
    }))
}

/// `HKLM\<path>` without the hive, or an error for any other hive.
fn machine_path(key: &str) -> Result<&str, WinError> {
    match key.get(..5) {
        Some(hive) if hive.eq_ignore_ascii_case(r"HKLM\") => Ok(&key[5..]),
        _ => Err(WinError::invalid("Not HKLM")),
    }
}

pub(super) fn read(key: &str, value: &str) -> Result<Value, WinError> {
    let current = match open(machine_path(key)?)? {
        Some(k) => typed(k.read(value)?)?,
        None => SettingValue::Absent,
    };
    serde_json::to_value(current).map_err(|e| WinError::invalid(e.to_string()))
}

/// Put back `original` if the value is still `ours`: `absent` if it is
/// already the original (or the key is gone), `modified` if someone else
/// changed it, else `restored`.
pub(super) fn restore(
    key: &str,
    value: &str,
    ours: &SettingValue,
    original: &SettingValue,
) -> Result<&'static str, WinError> {
    let Some(k) = Key::open(HKEY_LOCAL_MACHINE, machine_path(key)?, KEY_READ | KEY_WRITE)? else {
        return Ok("absent");
    };
    let current = typed(k.read(value)?)?;
    if &current == original {
        return Ok("absent");
    }
    if &current != ours {
        return Ok("modified");
    }
    match raw(original)? {
        None => k.delete_value(value)?,
        Some(v) => k.set(value, &v)?,
    }
    Ok("restored")
}

pub(super) fn magic() -> Result<bool, WinError> {
    Ok(open(MAGIC)?.is_some())
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` of a GUID in any form the
/// worker's `[guid]` accepted that `uuid` parses.
fn guid_text(s: &str) -> Result<String, WinError> {
    let u = Uuid::parse_str(s).map_err(|_| WinError::invalid(format!("not a GUID: {s}")))?;
    Ok(format!("{{{}}}", u.hyphenated()).to_uppercase())
}

pub(super) fn delete_nrpt(
    id: &str,
    name: &str,
    group: Option<&str>,
) -> Result<&'static str, WinError> {
    if !guid_text(id)?.eq_ignore_ascii_case(name) {
        return Err(WinError::invalid("NRPT credential mismatch"));
    }
    let path = format!(r"{NRPT}\{id}");
    let Some(key) = open(&path)? else {
        return Ok("absent");
    };
    if let Some(group) = group.filter(|g| !g.is_empty())
        && !as_string(key.read("Comment")?.as_ref())?.eq_ignore_ascii_case(group)
    {
        return Err(WinError::invalid("NRPT group mismatch"));
    }
    drop(key);
    // Non-recursive: a rule key that grew subkeys is not ours to remove.
    delete_key(HKEY_LOCAL_MACHINE, &path, false)?;
    Ok("removed")
}

/// Delete the signatures that point at the verified profile GUID (parsed,
/// never matched by name), re-verify the profile, then delete it.
pub(super) fn delete_profile(id: &str, name: &str) -> Result<&'static str, WinError> {
    if !guid_text(id)?.eq_ignore_ascii_case(id) {
        return Err(WinError::invalid("Invalid profile GUID"));
    }
    let profile = Uuid::parse_str(id).expect("checked above");
    let path = format!(r"{PROFILES}\{id}");
    let named = |what: &str| -> Result<bool, WinError> {
        let Some(key) = open(&path)? else {
            return Ok(false);
        };
        if !as_string(key.read("ProfileName")?.as_ref())?.eq_ignore_ascii_case(name) {
            return Err(WinError::invalid(what.to_owned()));
        }
        Ok(true)
    };
    if !named("Profile credential mismatch")? {
        return Ok("absent");
    }
    for signature in children(SIGNATURES)? {
        let signature_path = format!(r"{SIGNATURES}\{signature}");
        let matching = match open(&signature_path)? {
            Some(key) => match key.read("ProfileGuid")? {
                Some(v) if v.ty == REG_SZ || v.ty == REG_EXPAND_SZ => {
                    Uuid::parse_str(text(&v)?.trim()).is_ok_and(|g| g == profile)
                }
                _ => false,
            },
            None => false,
        };
        if matching {
            delete_key(HKEY_LOCAL_MACHINE, &signature_path, true)?;
        }
    }
    if !named("Profile credential changed during signature cleanup")? {
        return Err(WinError::invalid(
            "Profile disappeared during signature cleanup",
        ));
    }
    delete_key(HKEY_LOCAL_MACHINE, &path, true)?;
    Ok("removed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(ty: ::windows::Win32::System::Registry::REG_VALUE_TYPE, bytes: &[u8]) -> RawValue {
        RawValue {
            ty,
            bytes: bytes.to_vec(),
        }
    }
    fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn values_are_shown_as_the_worker_printed_them() {
        assert_eq!(shown(&value(REG_SZ, &wide("a\0"))).unwrap(), "a");
        assert_eq!(
            shown(&value(REG_MULTI_SZ, &wide("a\0b\0\0"))).unwrap(),
            "a,b"
        );
        assert_eq!(
            strings(&value(REG_MULTI_SZ, &wide("a\0\0\0"))).unwrap(),
            ["a", ""]
        );
        assert_eq!(
            strings(&value(REG_MULTI_SZ, &wide("a\0b"))).unwrap(),
            ["a", "b"]
        );
        assert!(
            strings(&value(REG_MULTI_SZ, &wide("\0")))
                .unwrap()
                .is_empty()
        );
        assert_eq!(text(&value(REG_SZ, &wide("a\0b\0"))).unwrap(), "a\0b");
        assert_eq!(
            shown(&value(REG_DWORD, &0xFFFF_FFFFu32.to_le_bytes())).unwrap(),
            "-1"
        );
        assert_eq!(
            shown(&value(REG_QWORD, &u64::MAX.to_le_bytes())).unwrap(),
            "-1"
        );
        assert_eq!(shown(&value(REG_BINARY, &[1, 255])).unwrap(), "1,255");
        assert_eq!(shown(&value(REG_BINARY, &[])).unwrap(), "");
        assert_eq!(
            as_string(Some(&value(REG_MULTI_SZ, &wide("a\0b\0\0")))).unwrap(),
            "a b"
        );
        assert_eq!(as_string(None).unwrap(), "");
    }

    #[test]
    fn expansion_uses_only_the_given_machine_values() {
        let vars = [("SystemRoot", r"C:\Windows".to_owned())];
        assert_eq!(
            expand_with(r"%systemroot%\x;%USERPROFILE%\y;%;50%", &vars),
            r"C:\Windows\x;%USERPROFILE%\y;%;50%"
        );
        assert_eq!(expand_with("%%SystemRoot%", &vars), r"%C:\Windows");
    }

    #[test]
    fn a_user_variable_changes_no_expansion() {
        // SAFETY: test-only; no other thread of this test reads the
        // variable concurrently.
        unsafe { std::env::set_var("SystemRoot", r"C:\attacker") };
        let expanded = expand("%SystemRoot%").unwrap();
        assert!(!expanded.contains("attacker"), "{expanded}");
        let windows = super::super::super::driver_refs::windows_dir().unwrap();
        // SAFETY: as above.
        unsafe { std::env::set_var("SystemRoot", windows) };
    }

    #[test]
    fn typed_values_refuse_what_the_worker_refused() {
        assert_eq!(typed(None).unwrap(), SettingValue::Absent);
        assert!(typed(Some(value(REG_EXPAND_SZ, &wide("%x%\0")))).is_err());
        let all = [
            SettingValue::String("a".into()),
            SettingValue::MultiString(vec!["a".into(), "b".into()]),
            SettingValue::U32(u32::MAX),
            SettingValue::U64(u64::MAX),
            SettingValue::Bytes(vec![1, 2]),
        ];
        for v in all {
            assert_eq!(typed(raw(&v).unwrap()).unwrap(), v);
        }
        assert_eq!(raw(&SettingValue::Absent).unwrap(), None);
    }

    #[test]
    fn only_machine_paths_and_guids_are_accepted() {
        assert_eq!(machine_path(r"hklm\SYSTEM\x").unwrap(), r"SYSTEM\x");
        assert!(machine_path(r"HKCU\x").is_err());
        assert_eq!(
            guid_text("12345678-1234-1234-1234-1234567890ab").unwrap(),
            "{12345678-1234-1234-1234-1234567890AB}"
        );
        assert!(guid_text("x").is_err());
        // A profile id that is not its own braced form is refused before
        // anything is opened.
        assert!(delete_profile("12345678-1234-1234-1234-1234567890ab", "x").is_err());
    }
}
