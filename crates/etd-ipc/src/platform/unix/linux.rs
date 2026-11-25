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

/// Directory for the per-user endpoint. The launcher creates it mode 0700.
/// Machines without a login-session runtime directory use a per-uid directory
/// under /tmp, validated with the same ownership and mode requirements.
pub fn user_runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/easytier-desk-{}", Uid::effective())))
}

pub(super) fn pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
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
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// The primary service proof is uid 0 on a root-owned socket whose entire
// directory chain is root-owned and protected. The user form requires the
// current uid and its private runtime directory. Never substitute an expected
// filename for an unavailable process image in ServerIdentity.
pub(super) fn verified_image(
    expect: &ServerExpectation,
    pid: u32,
    pidfd: io::Result<OwnedFd>,
) -> io::Result<PathBuf> {
    let fd = match pidfd {
        Ok(fd) => Some(fd),
        Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            tracing::debug!(
                "SO_PEERPIDFD unavailable; verified the socket owner, path and peer uid"
            );
            if !expect.privileged {
                return Ok(PathBuf::new());
            }
            None
        }
        Err(e) => return Err(denied(e)),
    };
    let image = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => verify_image(&expect.exe_dir, &path)?,
        Err(e)
            if expect.privileged
                && matches!(
                    e.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
        {
            PathBuf::new()
        }
        Err(e) => return Err(denied(e)),
    };
    if let Some(fd) = fd {
        let mut probe = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut probe, 1, 0) } {
            0 => (),
            -1 => return Err(denied(io::Error::last_os_error())),
            _ => return Err(denied("server process exited")),
        }
    }
    Ok(image)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_missing_peer_pidfd_uses_legacy_user_host_evidence() {
        let expect = ServerExpectation {
            exe_dir: PathBuf::new(),
            user: None,
            privileged: false,
        };
        let old_kernel = io::Error::from_raw_os_error(libc::ENOPROTOOPT);
        assert!(
            verified_image(&expect, std::process::id(), Err(old_kernel))
                .unwrap()
                .as_os_str()
                .is_empty()
        );
        assert!(
            verified_image(
                &expect,
                std::process::id(),
                Err(io::Error::from_raw_os_error(libc::EBADF))
            )
            .is_err()
        );
    }
}
