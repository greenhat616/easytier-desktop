use super::*;
use nix::sys::socket::{UnixAddr, connect};
use std::os::fd::AsRawFd;
use tokio::net::UnixSocket;

// The caller holds HR's singleton lock and has checked the directory chain.
// Use a nonblocking connect: a full backlog is a live endpoint, too.
fn remove_refused(path: &Path, uid: u32) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket() || m.uid() != uid {
        return Err(denied("refusing to remove a foreign or non-socket object"));
    }
    let socket = UnixSocket::new_stream()?;
    match connect(socket.as_raw_fd(), &UnixAddr::new(path)?) {
        Err(nix::errno::Errno::ECONNREFUSED) => (),
        Ok(()) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket listener is live",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let now = fs::symlink_metadata(path)?;
    if inode(&now) != inode(&m) || !now.file_type().is_socket() || now.uid() != uid {
        return Err(denied("socket changed during stale endpoint recovery"));
    }
    fs::remove_file(path)
}

fn stage_pid(name: &str) -> Option<i32> {
    let (pid, seq) = name.strip_prefix(".i")?.split_once('.')?;
    let pid_num = i32::from_str_radix(pid, 16).ok()?;
    let seq_num = u64::from_str_radix(seq, 16).ok()?;
    (pid_num > 0 && format!(".i{pid_num:x}.{seq_num:x}") == name).then_some(pid_num)
}

fn clean_stages(parent: &Path, uid: u32) -> io::Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(stage_pid) else {
            continue;
        };
        // Signal zero checks liveness only. A reused PID or EPERM preserves
        // the directory, as does any object outside our exact staging layout.
        if unsafe { libc::kill(pid, 0) } == 0
            || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            continue;
        }
        let dir = entry.path();
        let metadata = fs::symlink_metadata(&dir)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            continue;
        }
        let mut entries = fs::read_dir(&dir)?;
        if let Some(first) = entries.next().transpose()? {
            if first.file_name() != "s" || entries.next().is_some() {
                continue;
            }
            let candidate = first.path();
            let m = fs::symlink_metadata(&candidate)?;
            if !m.file_type().is_socket() || m.uid() != uid {
                continue;
            }
            if remove_refused(&candidate, uid).is_err() {
                continue;
            }
        }
        fs::remove_dir(&dir)?;
    }
    Ok(())
}

pub(super) fn recover(path: &Path, uid: u32) -> io::Result<()> {
    match remove_refused(path, uid) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    clean_stages(path.parent().unwrap(), uid)
}
