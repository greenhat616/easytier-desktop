use super::*;
use crate::{Listener, OsGroupId, PeerIdentity};
use futures_util::{
    future::{BoxFuture, Either, select},
    stream::{FuturesUnordered, StreamExt},
};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    },
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            SetKernelObjectSecurity,
        },
        Storage::FileSystem::{
            FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA,
            READ_CONTROL, SECURITY_IDENTIFICATION, SYNCHRONIZE,
        },
        System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
    },
    core::HSTRING,
};
mod identity;

pub(super) fn current_user() -> io::Result<OsUserId> {
    identity::current_user()
}

fn pipe_name(endpoint: &Endpoint) -> io::Result<&str> {
    let Endpoint::NamedPipe(name) = endpoint else {
        return Err(invalid("expected a Windows named pipe"));
    };
    let leaf = name
        .strip_prefix(r"\\.\pipe\")
        .ok_or_else(|| invalid("expected a local pipe name"))?;
    if leaf.is_empty() || leaf.contains(['\\', '/', '\0', ':']) {
        return Err(invalid("invalid local pipe name"));
    }
    Ok(name)
}

fn client_mask() -> u32 {
    (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE).0
}

fn descriptor(policy: &ListenerPolicy) -> io::Result<identity::Allocation> {
    if policy.unix_group.is_some() {
        return Err(invalid("Unix group on a Windows pipe"));
    }
    let OsUserId::WindowsSid(host) = identity::current_user()? else {
        unreachable!()
    };
    // Subsequent server instances need FILE_CREATE_PIPE_INSTANCE. Only the
    // host account needs that bit and WRITE_DAC for live policy updates.
    let host_mask = 0x0012019f | 0x00040000; // FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC
    let rw = client_mask();
    let mut acl =
        format!("O:{host}D:P(A;;0x{host_mask:x};;;{host})(A;;0x{rw:x};;;SY)(A;;0x{rw:x};;;BA)");
    let mut add = |sid: &str| -> io::Result<()> {
        // Only numeric SIDs may be interpolated into SDDL. The OS parser
        // validates their structure and bounds.
        if !sid.starts_with("S-1-") || !sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return Err(invalid("expected a numeric Windows SID"));
        }
        acl.push_str(&format!("(A;;0x{rw:x};;;{sid})"));
        Ok(())
    };
    for user in &policy.allow_users {
        let OsUserId::WindowsSid(s) = user else {
            return Err(invalid("expected Windows user SID"));
        };
        add(s)?;
    }
    for group in &policy.allow_groups {
        let OsGroupId::WindowsSid(s) = group else {
            return Err(invalid("expected Windows group SID"));
        };
        add(s)?;
    }
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(acl),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(win_error)?;
    }
    Ok(identity::Allocation(HLOCAL(sd.0)))
}

fn options() -> ServerOptions {
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true).write_dac(true);
    opts
}

fn duplicate(pipe: &NamedPipeServer) -> io::Result<OwnedHandle> {
    unsafe { BorrowedHandle::borrow_raw(pipe.as_raw_handle()) }.try_clone_to_owned()
}

#[derive(Clone)]
pub struct PolicyHandle(Weak<Mutex<OwnedHandle>>);
impl PolicyHandle {
    /// Replace the DACL of the live pipe. Existing connections retain their
    /// handles; per-RPC role checks observe the host's current allow list.
    pub fn update(&self, policy: &ListenerPolicy) -> io::Result<()> {
        let state = self.0.upgrade().ok_or(io::ErrorKind::NotConnected)?;
        let sd = descriptor(policy)?;
        let handle = state
            .lock()
            .map_err(|_| io::Error::other("pipe policy lock poisoned"))?;
        unsafe {
            SetKernelObjectSecurity(
                HANDLE(handle.as_raw_handle()),
                DACL_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR(sd.0.0),
            )
            .map_err(win_error)?;
        }
        Ok(())
    }
}

type Accepted = io::Result<(BoxConn, PeerIdentity)>;
const MAX_PENDING_PER_SID: usize = 8;
const MAX_PENDING: usize = 64;
const MARKER_TIMEOUT: Duration = Duration::from_secs(2);

type Authentication = (OsUserId, Accepted);

#[derive(Default)]
struct PendingAccounts(HashMap<OsUserId, usize>);

impl PendingAccounts {
    fn reserve(&mut self, user: &OsUserId) -> io::Result<()> {
        let count = self.0.entry(user.clone()).or_default();
        if *count >= MAX_PENDING_PER_SID {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many pending pipes for account",
            ));
        }
        *count += 1;
        Ok(())
    }

    fn release(&mut self, user: &OsUserId) {
        let count = self.0.get_mut(user).expect("pending authentication");
        *count -= 1;
        if *count == 0 {
            self.0.remove(user);
        }
    }
}

pub struct LocalListener {
    name: String,
    pipe: NamedPipeServer,
    policy: Arc<Mutex<OwnedHandle>>,
    authenticating: FuturesUnordered<BoxFuture<'static, Authentication>>,
    pending: PendingAccounts,
}

impl LocalListener {
    pub(super) fn bind_native(
        _form: HostForm,
        endpoint: &Endpoint,
        policy: &ListenerPolicy,
    ) -> io::Result<Self> {
        let name = pipe_name(endpoint)?;
        let sd = descriptor(policy)?;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0.0,
            bInheritHandle: false.into(),
        };
        let pipe = unsafe {
            options()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(name, (&raw mut attrs).cast())?
        };
        let policy = Arc::new(Mutex::new(duplicate(&pipe)?));
        Ok(Self {
            name: name.to_owned(),
            pipe,
            policy,
            authenticating: FuturesUnordered::new(),
            pending: PendingAccounts::default(),
        })
    }
    pub fn policy_handle(&self) -> PolicyHandle {
        PolicyHandle(Arc::downgrade(&self.policy))
    }

    fn start_authentication(&mut self) -> io::Result<()> {
        let mut handle = self
            .policy
            .lock()
            .map_err(|_| io::Error::other("pipe policy lock poisoned"))?;
        // Hold the old instance until its successor owns the name. Additional
        // instances inherit the pipe object's current DACL.
        let next = options().create(&self.name)?;
        *handle = duplicate(&next)?;
        let mut pipe = mem::replace(&mut self.pipe, next);
        drop(handle);
        let user = identity::admission_user(&pipe)?;
        self.pending.reserve(&user)?;
        let deadline = tokio::time::Instant::now() + MARKER_TIMEOUT;
        self.authenticating.push(Box::pin(async move {
            let outcome = async {
                let byte = tokio::time::timeout_at(deadline, pipe.read_u8()).await??;
                if byte != 1 {
                    return Err(denied("invalid IPC identification marker"));
                }
                let peer = identity::client_peer(&pipe)?;
                if peer.user != user {
                    return Err(denied("pipe user changed during identification"));
                }
                Ok((Box::new(pipe) as BoxConn, peer))
            }
            .await;
            (user, outcome)
        }));
        Ok(())
    }
}

#[async_trait::async_trait]
impl Listener for LocalListener {
    async fn accept(&mut self) -> Accepted {
        loop {
            if self.authenticating.is_empty() {
                self.pipe.connect().await?;
            } else if self.authenticating.len() >= MAX_PENDING {
                let (user, outcome) = self.authenticating.next().await.unwrap();
                self.pending.release(&user);
                return outcome;
            } else {
                match select(self.authenticating.next(), Box::pin(self.pipe.connect())).await {
                    Either::Left((Some((user, outcome)), _)) => {
                        self.pending.release(&user);
                        return outcome;
                    }
                    Either::Left((None, _)) => unreachable!(),
                    Either::Right((result, _)) => result?,
                }
            }
            self.start_authentication()?;
        }
    }
}

pub(super) async fn connect(
    endpoint: &Endpoint,
    expect: &ServerExpectation,
) -> io::Result<(BoxConn, ServerIdentity)> {
    let name = pipe_name(endpoint)?;
    let before = SystemTime::now();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(client_mask())
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .security_qos_flags(SECURITY_IDENTIFICATION.0)
        .open(name)?;
    let mut pipe = unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle())? };
    let server = identity::server_identity(&pipe, expect, before).map_err(denied)?;
    pipe.write_u8(1).await?;
    Ok((Box::new(pipe), server))
}

fn win_error(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(error.code().0 & 0xffff)
}

/// Expand 8.3 names reported by QueryFullProcessImageNameW (for example
/// RUNNER~1 in a temp path). Expanding a name does not follow junctions.
/// Require both the resulting spelling and the final filesystem path to match.
pub(super) fn image_matches(image: &Path, host: &Path) -> io::Result<bool> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;
    let mut wide = vec![0u16; 32768];
    let len =
        unsafe { GetLongPathNameW(&HSTRING::from(image.as_os_str()), Some(&mut wide)) } as usize;
    if len == 0 || len >= wide.len() {
        return Err(denied("could not expand host image path"));
    }
    wide.truncate(len);
    let expanded = OsString::from_wide(&wide);
    let expected = host.as_os_str().as_encoded_bytes();
    let actual = expanded.as_encoded_bytes();
    let prefix = br"\\?\";
    Ok(actual
        .strip_prefix(prefix)
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected.strip_prefix(prefix).unwrap_or(expected))
        && image.canonicalize().map_err(denied)? == host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_slots_are_counted_and_released_per_account() {
        let first = OsUserId::WindowsSid("S-1-5-18".into());
        let second = OsUserId::WindowsSid("S-1-5-19".into());
        let mut accounts = PendingAccounts::default();
        for _ in 0..8 {
            accounts.reserve(&first).unwrap();
        }
        assert_eq!(
            accounts.reserve(&first).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        accounts.reserve(&second).unwrap();
        accounts.release(&second);
        accounts.release(&first);
        accounts.reserve(&first).unwrap();
        for _ in 0..8 {
            accounts.release(&first);
        }
        assert!(accounts.0.is_empty());
    }
}
