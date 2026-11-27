//! Replay the exact upstream WindowsDNSRecovery record. The machine-wide
//! record is shared with official EasyTier installs; no other writer may be
//! present during any mutation stage. Own core-store processes are excluded
//! by opened-file and directory identity, not a textual path prefix.
use super::{
    WinError,
    registry::{Handle, Key, RawValue, delete_key, utf16},
};
use ::windows::{
    Win32::{
        Foundation::ERROR_NO_MORE_FILES,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FileBasicInfo, FileIdInfo,
            GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OPEN_EXISTING,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Registry::{
                HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
            },
            Threading::{
                OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    },
    core::{HSTRING, PWSTR},
};
use etd_sysfx::{ReclaimError, Reclaimed};
use std::{
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAGIC: &str = r"SOFTWARE\EasyTier\MagicDNS";
const NRPT: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
fn busy(message: impl std::fmt::Display) -> WinError {
    WinError::invalid(format!("BUSY: {message}"))
}
/// Why a replay did not finish.
pub(super) enum ReplayError {
    /// Proven held by another EasyTier (named), with nothing replayed yet.
    HeldBy(String),
    Win(WinError),
}
impl From<WinError> for ReplayError {
    fn from(e: WinError) -> Self {
        Self::Win(e)
    }
}
impl ReplayError {
    pub(super) fn reclaim(self) -> ReclaimError {
        match self {
            Self::HeldBy(holder) => ReclaimError::HeldBy(holder),
            Self::Win(e) => e.reclaim(),
        }
    }
}

/// What the process gate found.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// No EasyTier process outside the kernel store runs.
    Clear,
    /// Every candidate was proven, and this one runs outside the store.
    External(String),
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    index: [u8; 16],
}
fn open_identity(path: &Path) -> Result<(Handle, FileIdentity, PathBuf, bool), WinError> {
    let handle = Handle(unsafe {
        CreateFileW(
            &HSTRING::from(path.as_os_str()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        .map_err(WinError::windows)?
    });
    let mut id = FILE_ID_INFO::default();
    let mut info = FILE_BASIC_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
        .map_err(WinError::windows)?;
        GetFileInformationByHandleEx(
            handle.0,
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
        .map_err(WinError::windows)?;
    }
    let mut buf = vec![0u16; 32768];
    let n = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(WinError::invalid(
            "cannot canonicalize opened image/directory",
        ));
    }
    let canonical = PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]));
    Ok((
        handle,
        FileIdentity {
            volume: id.VolumeSerialNumber,
            index: id.FileId.Identifier,
        },
        canonical,
        info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
    ))
}

fn inside_store(root: &FileIdentity, image: &Path) -> Result<bool, WinError> {
    // Accepted boundary: this proves the identity of an opened image path,
    // not the kernel's already mapped executable image object. The gate
    // re-enumerates and verifies these handles immediately before each stage.
    let (_file, _, canonical, is_dir) = open_identity(image)?;
    if is_dir {
        return Err(WinError::invalid("process image is not a file"));
    }
    let parent = canonical
        .parent()
        .ok_or_else(|| WinError::invalid("image has no parent"))?;
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let (_handle, id, _, is_dir) = open_identity(ancestor)?;
        if !is_dir {
            return Err(WinError::invalid("image ancestor is not a directory"));
        }
        if &id == root {
            return Ok(true);
        }
    }
    Ok(false)
}

fn candidate(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("easytier")
}
fn image_path(pid: u32) -> Result<PathBuf, WinError> {
    let handle = Handle(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(WinError::windows)?
    });
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .map_err(WinError::windows)?;
    }
    if len == 0 || len as usize >= buf.len() {
        return Err(WinError::invalid("process image path is missing"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buf[..len as usize],
    )))
}

type CandidateImage = (String, Result<PathBuf, WinError>);
fn candidates() -> Result<Vec<CandidateImage>, WinError> {
    let snapshot = Handle(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(WinError::windows)?
    });
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe {
        Process32FirstW(snapshot.0, &mut entry).map_err(WinError::windows)?;
    }
    let mut out = Vec::new();
    loop {
        let name = String::from_utf16_lossy(
            &entry.szExeFile[..entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len())],
        );
        // Accepted limitation: a renamed external EasyTier image is outside
        // the candidate gate. Non-candidates such as Idle/System/protected
        // OS processes do not need readable executable paths.
        if candidate(&name) {
            out.push((
                format!("{name} pid={}", entry.th32ProcessID),
                image_path(entry.th32ProcessID),
            ));
        }
        match unsafe { Process32NextW(snapshot.0, &mut entry) } {
            Ok(()) => {}
            Err(e) if e.code().0 as u32 == (0x80070000 | ERROR_NO_MORE_FILES.0) => break,
            Err(e) => return Err(WinError::windows(e)),
        }
    }
    Ok(out)
}

fn gate_candidates(root: &Path, items: Vec<CandidateImage>) -> Result<Gate, WinError> {
    let (_root_handle, root_id, _, is_dir) =
        open_identity(root).map_err(|e| busy(format!("core store identity unavailable: {e}")))?;
    if !is_dir {
        return Err(busy("core store is not a directory"));
    }
    // An external process is a proven holder only once every candidate is
    // proven: any candidate that cannot be read or placed stays Busy, even
    // beside a proven external one.
    let mut external = None;
    for (name, path) in items {
        let path = path.map_err(|e| busy(format!("cannot read candidate {name}: {e}")))?;
        if !inside_store(&root_id, &path).map_err(|e| {
            busy(format!(
                "cannot prove candidate {name} is in core store: {e}"
            ))
        })? {
            external.get_or_insert_with(|| format!("{name} image {}", path.display()));
        }
    }
    Ok(match external {
        Some(holder) => Gate::External(format!("external EasyTier process {holder}")),
        None => Gate::Clear,
    })
}
fn gate(root: &Path) -> Result<Gate, WinError> {
    gate_candidates(
        root,
        candidates().map_err(|e| busy(format!("cannot enumerate processes: {e}")))?,
    )
}

#[derive(PartialEq, Eq)]
struct Saved {
    path: String,
    original: Option<RawValue>,
}
#[derive(PartialEq, Eq)]
struct Recovery {
    ids: Vec<String>,
    saved: Vec<Saved>,
}
fn guid(s: &str) -> Result<(), WinError> {
    let id = Uuid::parse_str(s).map_err(|_| WinError::invalid("invalid upstream recovery GUID"))?;
    if !format!("{{{id}}}").eq_ignore_ascii_case(s) {
        return Err(WinError::invalid("noncanonical upstream recovery GUID"));
    }
    Ok(())
}
fn multisz(value: RawValue) -> Result<Vec<String>, WinError> {
    if value.ty != REG_MULTI_SZ {
        return Err(WinError::invalid("NRPTRuleIDs is not REG_MULTI_SZ"));
    }
    let buf = utf16(&value)?;
    if !buf.ends_with(&[0, 0]) && buf != [0] {
        return Err(WinError::invalid("unterminated NRPTRuleIDs"));
    }
    let mut ids = Vec::new();
    let mut ended = false;
    for s in buf.split(|c| *c == 0) {
        if s.is_empty() {
            ended = true;
            continue;
        }
        if ended {
            return Err(WinError::invalid("data after NRPTRuleIDs terminator"));
        }
        let id = String::from_utf16(s).map_err(|_| WinError::invalid("invalid NRPT id"))?;
        guid(&id)?;
        ids.push(id);
    }
    Ok(ids)
}
fn load() -> Result<Option<Recovery>, WinError> {
    let Some(key) = Key::open(HKEY_LOCAL_MACHINE, MAGIC, KEY_READ)? else {
        return Ok(None);
    };
    let mut ids = key
        .read("NRPTRuleIDs")?
        .map(multisz)
        .transpose()?
        .unwrap_or_default();
    ids.sort();
    let mut saved = Vec::new();
    let Some(searches) = Key::open(key.0, "SearchLists", KEY_READ)? else {
        return Ok(Some(Recovery { ids, saved }));
    };
    for id in searches.children()? {
        guid(&id)?;
        for (protocol, service) in [("IPv4", "Tcpip"), ("IPv6", "Tcpip6")] {
            let Some(entry) = Key::open(searches.0, &format!(r"{id}\{protocol}"), KEY_READ)? else {
                continue;
            };
            let ready = entry.read("Ready")?;
            if let Some(v) = ready {
                if v.ty != REG_DWORD || v.bytes.len() != 4 {
                    return Err(WinError::invalid("invalid SearchList Ready marker"));
                }
                if v.bytes != 1u32.to_le_bytes() {
                    continue;
                }
                let path = format!(
                    r"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{id}"
                );
                saved.push(Saved {
                    path,
                    original: entry.read("OriginalSearchList")?,
                });
            }
        }
    }
    saved.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Some(Recovery { ids, saved }))
}
fn confirm(root: &Path, expected: &Recovery) -> Result<Gate, WinError> {
    let gate = gate(root)?;
    if load()?.as_ref() != Some(expected) {
        return Err(busy("Magic DNS recovery record changed during replay"));
    }
    Ok(gate)
}
/// A gate after this replay changed something: an external holder does not
/// make the rest someone else's, so retry (Busy) to finish it.
fn confirm_clear(root: &Path, expected: &Recovery) -> Result<(), WinError> {
    match confirm(root, expected)? {
        Gate::Clear => Ok(()),
        Gate::External(holder) => Err(busy(format!("{holder} started during the replay"))),
    }
}
/// The verdict of the first gate. An external holder is `HeldBy` only with
/// durable proof that no replay, in this call or an earlier one, changed
/// anything yet: the system still holds every entry the record says was
/// applied. Anything else, or anything uncertain, is Busy.
fn first_gate(
    gate: Gate,
    untouched: impl FnOnce() -> Result<bool, WinError>,
) -> Result<(), ReplayError> {
    match gate {
        Gate::Clear => Ok(()),
        Gate::External(holder) => match untouched() {
            Ok(true) => Err(ReplayError::HeldBy(holder)),
            Ok(false) => Err(busy(format!(
                "{holder}; an earlier replay may have changed this record's state"
            ))
            .into()),
            Err(e) => Err(busy(format!("{holder}; cannot read this record's state: {e}")).into()),
        },
    }
}
/// Whether the system still holds every entry the record says was applied:
/// each listed NRPT rule present, and each saved `SearchList` different from
/// its original (the replay writes exactly the original). `nrpt_rule`:
/// whether the rule's key exists. `search_list`: `None` if the interface
/// key is gone, else its `SearchList` value.
fn untouched_by(
    recovery: &Recovery,
    nrpt_rule: impl Fn(&str) -> Result<bool, WinError>,
    search_list: impl Fn(&str) -> Result<Option<Option<RawValue>>, WinError>,
) -> Result<bool, WinError> {
    for id in &recovery.ids {
        if !nrpt_rule(id)? {
            return Ok(false);
        }
    }
    for saved in &recovery.saved {
        match search_list(&saved.path)? {
            Some(now) if now != saved.original => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}
fn untouched(recovery: &Recovery) -> Result<bool, WinError> {
    untouched_by(
        recovery,
        |id| Ok(Key::open(HKEY_LOCAL_MACHINE, &format!(r"{NRPT}\{id}"), KEY_READ)?.is_some()),
        |path| {
            Key::open(HKEY_LOCAL_MACHINE, path, KEY_READ)?
                .map(|key| key.read("SearchList"))
                .transpose()
        },
    )
}
pub(super) fn replay(root: &Path) -> Result<Reclaimed, ReplayError> {
    let Some(recovery) = load()? else {
        return Ok(Reclaimed::AlreadyAbsent);
    };
    // Gate and re-read the record directly before EACH mutating stage. Only
    // the first gate, before any change, may answer HeldBy.
    first_gate(confirm(root, &recovery)?, || untouched(&recovery))?;
    if let Some(nrpt) = Key::open(HKEY_LOCAL_MACHINE, NRPT, KEY_READ | KEY_WRITE)? {
        for id in &recovery.ids {
            nrpt.delete_child(id)?;
        }
    }
    confirm_clear(root, &recovery)?;
    for saved in &recovery.saved {
        if let Some(target) = Key::open(HKEY_LOCAL_MACHINE, &saved.path, KEY_READ | KEY_SET_VALUE)?
        {
            match &saved.original {
                Some(raw) => target.set("SearchList", raw)?,
                None => target.delete_value("SearchList")?,
            }
        }
    }
    confirm_clear(root, &recovery)?;
    delete_key(HKEY_LOCAL_MACHINE, MAGIC, true)?;
    Ok(Reclaimed::Removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_rejects_unreadable_and_outside_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("core");
        std::fs::create_dir(&root).unwrap();
        let own = root.join("easytier-core.exe");
        std::fs::write(&own, b"fixture").unwrap();
        let alias = root.join("..").join("core").join("easytier-core.exe");
        assert_eq!(
            gate_candidates(&root, vec![("own".into(), Ok(alias))]).unwrap(),
            Gate::Clear
        );
        let external = dir.path().join("core-other");
        std::fs::create_dir(&external).unwrap();
        let image = external.join("easytier-core.exe");
        std::fs::write(&image, b"fixture").unwrap();
        let held = gate_candidates(&root, vec![("external".into(), Ok(image.clone()))]).unwrap();
        assert!(
            matches!(&held, Gate::External(h) if h.contains("external") && h.contains("core-other")),
            "{held:?}"
        );
        // Beside an unprovable candidate, in either order, it stays Busy.
        let unreadable = || ("unreadable".into(), Err(WinError::invalid("missing path")));
        for items in [
            vec![("external".into(), Ok(image.clone())), unreadable()],
            vec![unreadable(), ("external".into(), Ok(image.clone()))],
        ] {
            assert!(matches!(
                gate_candidates(&root, items).unwrap_err().reclaim(),
                ReclaimError::Busy(_)
            ));
        }
        assert!(
            gate_candidates(
                &root,
                vec![("unreadable".into(), Err(WinError::invalid("missing path")))]
            )
            .unwrap_err()
            .message
            .contains("BUSY:")
        );
        assert!(
            gate_candidates(&root.join("missing"), vec![("own".into(), Ok(own))])
                .unwrap_err()
                .message
                .contains("BUSY:")
        );
    }
    fn raw(text: &str) -> RawValue {
        RawValue {
            ty: ::windows::Win32::System::Registry::REG_SZ,
            bytes: text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        }
    }

    /// A replay interrupted in an earlier call leaves the system short of
    /// what the record lists; a later call that finds an external holder
    /// must then retry (Busy), never answer HeldBy.
    #[test]
    fn held_by_needs_every_applied_entry_still_in_place() {
        let recovery = Recovery {
            ids: vec!["{a}".into(), "{b}".into()],
            saved: vec![
                Saved {
                    path: "if-1".into(),
                    original: Some(raw("corp.example")),
                },
                Saved {
                    path: "if-2".into(),
                    original: None,
                },
            ],
        };
        let applied = Some(raw("corp.example,et.net"));
        // Rules present, then the SearchList of if-1 and of if-2.
        let state =
            |rules: &[&str], one: Option<Option<RawValue>>, two: Option<Option<RawValue>>| {
                untouched_by(
                    &recovery,
                    |id| Ok(rules.contains(&id)),
                    |path| {
                        Ok(if path == "if-1" {
                            one.clone()
                        } else {
                            two.clone()
                        })
                    },
                )
            };
        let all: &[&str] = &["{a}", "{b}"];
        let verdict = |untouched: Result<bool, WinError>| match first_gate(
            Gate::External("external EasyTier process x".into()),
            || untouched,
        ) {
            Err(ReplayError::HeldBy(h)) => Ok(h),
            Err(ReplayError::Win(e)) => Err(e.reclaim()),
            Ok(()) => panic!("an external holder never clears the gate"),
        };
        // Nothing replayed yet: HeldBy.
        let fresh = state(all, Some(applied.clone()), Some(applied.clone()));
        assert_eq!(verdict(fresh).unwrap(), "external EasyTier process x");
        for (what, partial) in [
            // Stage 1 interrupted: one rule already deleted.
            (
                "one rule gone",
                state(&["{b}"], Some(applied.clone()), Some(applied.clone())),
            ),
            // Stage 1 done, stage 2 not started.
            (
                "rules gone",
                state(&[], Some(applied.clone()), Some(applied.clone())),
            ),
            // Stage 2 interrupted: one SearchList restored or deleted.
            (
                "list restored",
                state(all, Some(Some(raw("corp.example"))), Some(applied.clone())),
            ),
            (
                "list deleted",
                state(all, Some(applied.clone()), Some(None)),
            ),
            // An interface key gone: cannot tell.
            ("interface gone", state(all, None, Some(applied.clone()))),
        ] {
            assert!(
                matches!(verdict(partial), Err(ReclaimError::Busy(_))),
                "{what}"
            );
        }
        // The state cannot be read: Busy.
        assert!(matches!(
            verdict(Err(WinError::invalid("access denied"))),
            Err(ReclaimError::Busy(m)) if m.contains("cannot read")
        ));
        // No external holder: the replay goes on, whatever the state.
        assert!(first_gate(Gate::Clear, || Ok(false)).is_ok());
    }

    #[test]
    fn candidate_names() {
        assert!(candidate("EasyTier-core.exe"));
        assert!(candidate("easytier-other.exe"));
        assert!(!candidate("System"));
    }
}
