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
use etd_sysfx::Reclaimed;
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
/// Proven held by another EasyTier: `ReclaimError::HeldBy(holder)`.
fn held(holder: impl std::fmt::Display) -> WinError {
    WinError::invalid(format!("{}{holder}", super::HELD_BY))
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

fn gate_candidates(root: &Path, items: Vec<CandidateImage>) -> Result<(), WinError> {
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
    match external {
        Some(holder) => Err(held(format!("external EasyTier process {holder}"))),
        None => Ok(()),
    }
}
fn gate(root: &Path) -> Result<(), WinError> {
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
fn confirm(root: &Path, expected: &Recovery) -> Result<(), WinError> {
    gate(root)?;
    if load()?.as_ref() != Some(expected) {
        return Err(busy("Magic DNS recovery record changed during replay"));
    }
    Ok(())
}
/// A holder that appears once the replay has changed something does not make
/// the rest someone else's: retry (Busy), so the replay can finish.
fn mid_replay(e: WinError) -> WinError {
    match e.message.strip_prefix(super::HELD_BY) {
        Some(holder) => busy(format!("{holder} started during the replay")),
        None => e,
    }
}
pub(super) fn replay(root: &Path) -> Result<Reclaimed, WinError> {
    let Some(recovery) = load()? else {
        return Ok(Reclaimed::AlreadyAbsent);
    };
    // Gate and re-read the record directly before EACH mutating stage. Only
    // the first gate, before any change, may answer HeldBy.
    confirm(root, &recovery)?;
    if let Some(nrpt) = Key::open(HKEY_LOCAL_MACHINE, NRPT, KEY_READ | KEY_WRITE)? {
        for id in &recovery.ids {
            nrpt.delete_child(id)?;
        }
    }
    confirm(root, &recovery).map_err(mid_replay)?;
    for saved in &recovery.saved {
        if let Some(target) = Key::open(HKEY_LOCAL_MACHINE, &saved.path, KEY_READ | KEY_SET_VALUE)?
        {
            match &saved.original {
                Some(raw) => target.set("SearchList", raw)?,
                None => target.delete_value("SearchList")?,
            }
        }
    }
    confirm(root, &recovery).map_err(mid_replay)?;
    delete_key(HKEY_LOCAL_MACHINE, MAGIC, true)?;
    Ok(Reclaimed::Removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etd_sysfx::ReclaimError;
    #[test]
    fn gate_rejects_unreadable_and_outside_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("core");
        std::fs::create_dir(&root).unwrap();
        let own = root.join("easytier-core.exe");
        std::fs::write(&own, b"fixture").unwrap();
        let alias = root.join("..").join("core").join("easytier-core.exe");
        assert!(gate_candidates(&root, vec![("own".into(), Ok(alias))]).is_ok());
        let external = dir.path().join("core-other");
        std::fs::create_dir(&external).unwrap();
        let image = external.join("easytier-core.exe");
        std::fs::write(&image, b"fixture").unwrap();
        let held = gate_candidates(&root, vec![("external".into(), Ok(image.clone()))])
            .unwrap_err()
            .reclaim();
        assert!(
            matches!(&held, ReclaimError::HeldBy(h) if h.contains("external") && h.contains("core-other")),
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
        // Found only once the replay changed something: Busy, to finish it.
        assert!(matches!(
            mid_replay(held_error(&root, image)).reclaim(),
            ReclaimError::Busy(m) if m.contains("started during the replay")
        ));
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
    fn held_error(root: &Path, image: PathBuf) -> WinError {
        gate_candidates(root, vec![("external".into(), Ok(image))]).unwrap_err()
    }
    #[test]
    fn candidate_names() {
        assert!(candidate("EasyTier-core.exe"));
        assert!(candidate("easytier-other.exe"));
        assert!(!candidate("System"));
    }
}
