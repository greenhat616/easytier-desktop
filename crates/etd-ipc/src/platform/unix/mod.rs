use super::*;
use crate::{Listener, OsGroupId, PeerIdentity, SERVICE_SOCKET_PATH};
use futures_util::future::{Either, select};
use nix::unistd::{Gid, Group, Uid};
use std::{
    ffi::CString,
    fs::{self, DirBuilder, Metadata},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::Component,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
};

pub(super) fn current_user() -> io::Result<OsUserId> {
    Ok(OsUserId::UnixUid(Uid::effective().as_raw()))
}

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod os;

#[cfg(target_os = "linux")]
pub use os::user_runtime_dir;

fn path(endpoint: &Endpoint) -> io::Result<&Path> {
    let Endpoint::UnixSocket(path) = endpoint else {
        return Err(invalid("expected a Unix domain socket"));
    };
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid(
            "expected an absolute socket path without parent traversal",
        ));
    }
    Ok(path)
}

/// Check from the filesystem root down, before relying on a child. A user
/// host may live below a sticky temporary directory, but its immediate
/// parent must be its own unwritable-by-others directory. For a service
/// even sticky ancestors are excluded.
fn directory_chain(path: &Path, uid: u32, service: bool) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| invalid("missing socket parent"))?;
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component);
        let m = fs::symlink_metadata(&current)?;
        let sticky_ancestor = !service && current != dir && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || (m.uid() != 0 && m.uid() != uid)
            || (m.mode() & 0o022 != 0 && !sticky_ancestor)
        {
            return Err(denied("untrusted socket directory"));
        }
        if current == dir && m.uid() != uid {
            return Err(denied("unexpected socket directory owner"));
        }
    }
    Ok(())
}

fn inode(m: &Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}

struct Published {
    path: PathBuf,
    id: (u64, u64),
}
impl Published {
    fn still_owned(&self) -> bool {
        fs::symlink_metadata(&self.path)
            .is_ok_and(|m| inode(&m) == self.id && m.file_type().is_socket())
    }
}
impl Drop for Published {
    fn drop(&mut self) {
        if self.still_owned() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// A socket bound directly at the public name would initially have the
// process umask and possibly an inherited ACL. Stage it in a private
// directory, apply the complete policy, then publish in one filesystem op.
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("s"));
        let _ = fs::remove_dir(&self.0);
    }
}
fn stage(path: &Path, policy: &ListenerPolicy) -> io::Result<(Stage, UnixListener, (u64, u64))> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().unwrap();
    let stage = loop {
        let temp = dir.join(format!(
            ".i{:x}.{:x}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        match DirBuilder::new().mode(0o700).create(&temp) {
            Ok(()) => break Stage(temp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let temp = stage.0.join("s");
    let listener = UnixListener::bind(&temp)?;
    let group = match policy.unix_group.as_ref() {
        None => None,
        Some(name) => Some(
            Group::from_name(name)?
                .ok_or_else(|| invalid("unknown socket group"))?
                .gid,
        ),
    };
    let mut users = Vec::new();
    for id in &policy.allow_users {
        let OsUserId::UnixUid(id) = id else {
            return Err(invalid("expected Unix uid"));
        };
        users.push(*id);
    }
    let mut groups = Vec::new();
    for id in &policy.allow_groups {
        let OsGroupId::UnixGid(id) = id else {
            return Err(invalid("expected Unix gid"));
        };
        groups.push(*id);
    }
    if let Some(group) = group {
        nix::unistd::chown(&temp, None, Some(group))?;
    }
    fs::set_permissions(
        &temp,
        fs::Permissions::from_mode(if group.is_some() { 0o660 } else { 0o600 }),
    )?;
    os::set_acl(
        &CString::new(temp.as_os_str().as_bytes())?,
        group,
        users,
        groups,
    )?;
    Ok((stage, listener, inode(&fs::symlink_metadata(temp)?)))
}

struct State {
    endpoint: Published,
    change: watch::Sender<Arc<UnixListener>>,
}

#[derive(Clone)]
pub struct PolicyHandle(Weak<Mutex<State>>);
impl PolicyHandle {
    /// Atomically publish the new mode, owning group and named ACLs and
    /// wake accept even when it is waiting on the previous socket.
    pub fn update(&self, policy: &ListenerPolicy) -> io::Result<()> {
        let state = self.0.upgrade().ok_or(io::ErrorKind::NotConnected)?;
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("socket policy lock poisoned"))?;
        let (staged, listener, id) = stage(&state.endpoint.path, policy)?;
        if !state.endpoint.still_owned() {
            return Err(denied("socket endpoint was replaced"));
        }
        fs::rename(staged.0.join("s"), &state.endpoint.path)?;
        state.endpoint.id = id;
        state.change.send_replace(Arc::new(listener));
        Ok(())
    }
}

pub struct LocalListener {
    state: Arc<Mutex<State>>,
    change: watch::Receiver<Arc<UnixListener>>,
}

impl LocalListener {
    pub(super) fn bind_native(endpoint: &Endpoint, policy: &ListenerPolicy) -> io::Result<Self> {
        let path = path(endpoint)?;
        let uid = Uid::effective().as_raw();
        let service = path == Path::new(SERVICE_SOCKET_PATH);
        if service && uid != 0 {
            return Err(denied("service socket requires root"));
        }
        directory_chain(path, uid, service)?;
        let (staged, listener, id) = stage(path, policy)?;
        fs::hard_link(staged.0.join("s"), path)?;
        let endpoint = Published {
            path: path.to_owned(),
            id,
        };
        let (sender, change) = watch::channel(Arc::new(listener));
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                endpoint,
                change: sender,
            })),
            change,
        })
    }
    pub fn policy_handle(&self) -> PolicyHandle {
        PolicyHandle(Arc::downgrade(&self.state))
    }
}

#[async_trait::async_trait]
impl Listener for LocalListener {
    async fn accept(&mut self) -> io::Result<(BoxConn, PeerIdentity)> {
        loop {
            let socket = self.change.borrow_and_update().clone();
            if let Either::Right((result, _)) =
                select(Box::pin(self.change.changed()), Box::pin(socket.accept())).await
            {
                let (stream, _) = result?;
                let peer = os::peer(&stream)?;
                return Ok((Box::new(stream), peer));
            }
        }
    }
}

pub(super) async fn connect(
    endpoint: &Endpoint,
    expect: &ServerExpectation,
) -> io::Result<(BoxConn, ServerIdentity)> {
    let path = path(endpoint)?;
    #[cfg(target_os = "linux")]
    let id = os::socket_identity(path, expect.privileged).map_err(denied)?;
    let stream = UnixStream::connect(path).await?;
    let peer = os::peer(&stream).map_err(denied)?;
    verify_user(expect, &peer.user, current_user()?, OsUserId::UnixUid(0))?;
    #[cfg(target_os = "linux")]
    let exe = {
        if id != os::socket_identity(path, expect.privileged).map_err(denied)? {
            return Err(denied("socket changed during connect"));
        }
        if !expect.privileged && peer.user != current_user()? {
            return Err(denied("user host must run as the current user"));
        }
        os::verified_image(expect, peer.pid, os::pidfd(&stream))?
    };
    #[cfg(target_os = "macos")]
    let exe = verify_image(
        &expect.exe_dir,
        &os::image(&stream, peer.pid).map_err(denied)?,
    )?;
    Ok((Box::new(stream), ServerIdentity { peer, exe }))
}
