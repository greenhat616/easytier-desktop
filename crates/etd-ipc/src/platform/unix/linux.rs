use super::*;
use std::{
    ffi::CStr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(super) fn peer(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let cred = stream.peer_cred()?;
    let pid = cred
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| denied("peer PID unavailable in this namespace"))?;
    // SO_PEERGROUPS is the supplementary group snapshot captured by the
    // kernel at connect/listen time, including groups changed by setgroups.
    let mut gids = vec![0u32; 16];
    loop {
        let mut len = (gids.len() * size_of::<u32>()) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                gids.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc == 0 {
            gids.truncate(len as usize / size_of::<u32>());
            break;
        }
        let e = io::Error::last_os_error();
        let needed = len as usize / size_of::<u32>();
        if e.raw_os_error() != Some(libc::ERANGE) || needed <= gids.len() || needed > 65536 {
            return Err(e);
        }
        gids.resize(needed, 0);
    }
    gids.push(cred.gid());
    gids.sort_unstable();
    gids.dedup();
    Ok(PeerIdentity {
        user: OsUserId::UnixUid(cred.uid()),
        groups: gids.into_iter().map(OsGroupId::UnixGid).collect(),
        pid,
        session: None,
        elevated: cred.uid() == 0,
    })
}

pub(super) fn root_socket(path: &Path) -> io::Result<(u64, u64)> {
    directory_chain(path, 0, true)?;
    let m = fs::symlink_metadata(path)?;
    if m.uid() != 0 || !m.file_type().is_socket() {
        return Err(denied("expected root-owned service socket"));
    }
    Ok(inode(&m))
}

pub(super) fn image(stream: &UnixStream, pid: u32) -> io::Result<PathBuf> {
    let image = fs::read_link(format!("/proc/{pid}/exe"))?;
    // Check liveness through the socket's own pidfd *after* looking up the
    // numeric PID. A dead/recycled peer cannot authorize another image.
    let mut fd = -1i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut probe = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    match unsafe { libc::poll(&mut probe, 1, 0) } {
        0 => Ok(image),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(denied("server process exited")),
    }
}

pub(super) fn set_acl(
    path: &CStr,
    group: Option<Gid>,
    mut users: Vec<u32>,
    mut groups: Vec<u32>,
) -> io::Result<()> {
    // Linux POSIX ACL xattr ABI (linux/posix_acl_xattr.h). Always replace
    // the entire ACL, including any ACL inherited from a default directory ACL.
    const NO_ID: u32 = u32::MAX;
    let mut acl = 2u32.to_le_bytes().to_vec();
    let mut entry = |tag: u16, perm: u16, id: u32| {
        acl.extend(tag.to_le_bytes());
        acl.extend(perm.to_le_bytes());
        acl.extend(id.to_le_bytes());
    };
    users.sort_unstable();
    users.dedup();
    groups.sort_unstable();
    groups.dedup();
    let extended = !users.is_empty() || !groups.is_empty();
    entry(1, 6, NO_ID); // ACL_USER_OBJ
    for id in users {
        entry(2, 6, id);
    }
    entry(4, if group.is_some() { 6 } else { 0 }, NO_ID); // ACL_GROUP_OBJ
    for id in groups {
        entry(8, 6, id);
    }
    if extended {
        entry(16, 6, NO_ID);
    } // ACL_MASK
    entry(32, 0, NO_ID); // ACL_OTHER
    if unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        if extended || e.raw_os_error() != Some(libc::EOPNOTSUPP) {
            return Err(e);
        }
    }
    Ok(())
}
