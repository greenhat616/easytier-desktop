use super::*;
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    ptr,
};

type AclPtr = *mut c_void;

// Darwin Libc sys/acl.h, membership.h and libproc.h.
unsafe extern "C" {
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> c_int;
    fn mbr_gid_to_uuid(gid: u32, uuid: *mut u8) -> c_int;
    fn acl_init(count: c_int) -> AclPtr;
    fn acl_free(acl: AclPtr) -> c_int;
    fn acl_create_entry(acl: *mut AclPtr, entry: *mut AclPtr) -> c_int;
    fn acl_set_tag_type(entry: AclPtr, tag: c_int) -> c_int;
    fn acl_set_qualifier(entry: AclPtr, qualifier: *const c_void) -> c_int;
    fn acl_set_permset_mask_np(entry: AclPtr, mask: u64) -> c_int;
    fn acl_set_file(path: *const c_char, kind: c_int, acl: AclPtr) -> c_int;
    fn proc_pidpath_audittoken(token: *mut [u32; 8], buf: *mut c_void, size: u32) -> c_int;
}

struct Acl(AclPtr);
impl Drop for Acl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}
fn check(rc: c_int) -> io::Result<()> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn set_acl(
    path: &CStr,
    _: Option<Gid>,
    users: Vec<u32>,
    groups: Vec<u32>,
) -> io::Result<()> {
    let count = (users.len() + groups.len())
        .try_into()
        .map_err(|_| invalid("too many ACL entries"))?;
    let ptr = unsafe { acl_init(count) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut acl = Acl(ptr);
    for (id, is_group) in users
        .into_iter()
        .map(|id| (id, false))
        .chain(groups.into_iter().map(|id| (id, true)))
    {
        let mut guid = [0u8; 16];
        let err = unsafe {
            if is_group {
                mbr_gid_to_uuid(id, guid.as_mut_ptr())
            } else {
                mbr_uid_to_uuid(id, guid.as_mut_ptr())
            }
        };
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }
        let mut entry = ptr::null_mut();
        unsafe {
            check(acl_create_entry(&mut acl.0, &mut entry))?;
            check(acl_set_tag_type(entry, 1))?; // ACL_EXTENDED_ALLOW
            check(acl_set_qualifier(entry, guid.as_ptr().cast()))?;
            check(acl_set_permset_mask_np(entry, (1 << 1) | (1 << 2)))?; // READ_DATA | WRITE_DATA
        }
    }
    unsafe { check(acl_set_file(path.as_ptr(), 0x100, acl.0)) } // ACL_TYPE_EXTENDED
}

// Only called with the matching fixed-size ABI structure for the option.
unsafe fn opt<T>(stream: &UnixStream, option: i32) -> io::Result<T> {
    let mut val = MaybeUninit::<T>::zeroed();
    let mut len = size_of::<T>() as libc::socklen_t;
    check(unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            option,
            val.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    if len as usize != size_of::<T>() {
        return Err(denied("unexpected peer credential length"));
    }
    Ok(unsafe { val.assume_init() })
}

pub(super) fn peer(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let cred: libc::xucred = unsafe { opt(stream, libc::LOCAL_PEERCRED)? };
    let pid: i32 = unsafe { opt(stream, libc::LOCAL_PEERPID)? };
    let n = usize::try_from(cred.cr_ngroups)
        .ok()
        .filter(|&n| n > 0 && n <= cred.cr_groups.len())
        .ok_or_else(|| denied("invalid peer groups"))?;
    if cred.cr_version != 0 || pid <= 0 {
        return Err(denied("invalid peer credentials"));
    }
    let groups = cred.cr_groups;
    Ok(PeerIdentity {
        user: OsUserId::UnixUid(cred.cr_uid),
        groups: groups[..n]
            .iter()
            .copied()
            .map(OsGroupId::UnixGid)
            .collect(),
        pid: pid as u32,
        session: None,
        elevated: cred.cr_uid == 0,
    })
}

pub(super) fn image(stream: &UnixStream, _: u32) -> io::Result<PathBuf> {
    let mut token: [u32; 8] = unsafe { opt(stream, libc::LOCAL_PEERTOKEN)? };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    if unsafe { proc_pidpath_audittoken(&mut token, buf.as_mut_ptr().cast(), buf.len() as u32) }
        <= 0
    {
        return Err(io::Error::last_os_error());
    }
    let path = CStr::from_bytes_until_nul(&buf).map_err(denied)?;
    Ok(std::ffi::OsString::from_vec(path.to_bytes().into()).into())
}
