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
        System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, WaitNamedPipeW},
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

/// FILE_GENERIC_READ | FILE_GENERIC_WRITE minus [`client_mask`]:
/// FILE_CREATE_PIPE_INSTANCE, FILE_READ_EA, FILE_WRITE_EA and
/// FILE_WRITE_ATTRIBUTES. No data access and no WRITE_DAC.
const SESSION_HOST_EXTRA: u32 = 0x0000011c;

fn descriptor(form: HostForm, policy: &ListenerPolicy) -> io::Result<identity::Allocation> {
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
    let owner_only = policy.allow_users.is_empty() && policy.allow_groups.is_empty();
    let mut acl = format!("O:{host}D:P");
    match form {
        HostForm::Service => acl.push_str(&format!(
            "(A;;0x{host_mask:x};;;{host})(A;;0x{rw:x};;;SY)(A;;0x{rw:x};;;BA)"
        )),
        HostForm::User => {
            if !owner_only {
                return Err(invalid("user host pipe policy must be owner-only"));
            }
            acl.push_str(&format!("(A;;0x{host_mask:x};;;{host})"));
        }
        HostForm::ElevatedSession => {
            if !owner_only {
                return Err(invalid("elevated session pipe policy must be owner-only"));
            }
            // The host and its non-elevated clients share the user SID, so
            // that SID gets client access only. OWNER RIGHTS replaces the
            // owner's implicit READ_CONTROL | WRITE_DAC. The remaining bits
            // the host needs to add instances go to Administrators, which is
            // enabled only in elevated tokens (deny-only in a filtered one).
            acl.push_str(&format!(
                "(A;;0x{rw:x};;;{host})(A;;0x{rw:x};;;OW)(A;;0x{SESSION_HOST_EXTRA:x};;;BA)"
            ));
        }
    }
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
    if form == HostForm::ElevatedSession {
        // Medium, no-write-up and no-read-up: a non-elevated UI may open it,
        // Low and AppContainer processes may not open it at all. No-read-up
        // matters because a client open is not checked for FILE_APPEND_DATA
        // yet is granted it, which makes the handle writable. A label at or
        // below the creator's own integrity level needs no privilege.
        acl.push_str("S:(ML;;NWNR;;;ME)");
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

fn options(form: HostForm) -> ServerOptions {
    let mut opts = ServerOptions::new();
    // The session DACL is fixed and grants nobody WRITE_DAC.
    opts.reject_remote_clients(true)
        .write_dac(form != HostForm::ElevatedSession);
    opts
}

fn duplicate(pipe: &NamedPipeServer) -> io::Result<OwnedHandle> {
    unsafe { BorrowedHandle::borrow_raw(pipe.as_raw_handle()) }.try_clone_to_owned()
}

#[derive(Clone)]
pub struct PolicyHandle(Weak<Mutex<OwnedHandle>>, HostForm);
impl PolicyHandle {
    /// Replace the DACL of the live pipe. Existing connections retain their
    /// handles; per-RPC role checks observe the host's current allow list.
    pub fn update(&self, policy: &ListenerPolicy) -> io::Result<()> {
        let state = self.0.upgrade().ok_or(io::ErrorKind::NotConnected)?;
        let sd = descriptor(self.1, policy)?;
        if self.1 == HostForm::ElevatedSession {
            // Only the empty policy passes `descriptor`; the DACL is fixed.
            return Ok(());
        }
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
    form: HostForm,
    name: String,
    pipe: NamedPipeServer,
    policy: Arc<Mutex<OwnedHandle>>,
    authenticating: FuturesUnordered<BoxFuture<'static, Authentication>>,
    pending: PendingAccounts,
    /// The elevated session host's own account and Windows session.
    session_owner: Option<identity::SessionOwner>,
}

impl LocalListener {
    pub(super) fn bind_native(
        form: HostForm,
        endpoint: &Endpoint,
        policy: &ListenerPolicy,
    ) -> io::Result<Self> {
        let name = pipe_name(endpoint)?;
        let sd = descriptor(form, policy)?;
        let session_owner = match form {
            HostForm::ElevatedSession => Some(identity::session_owner()?),
            HostForm::Service | HostForm::User => None,
        };
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0.0,
            bInheritHandle: false.into(),
        };
        let pipe = unsafe {
            options(form)
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(name, (&raw mut attrs).cast())?
        };
        let policy = Arc::new(Mutex::new(duplicate(&pipe)?));
        Ok(Self {
            form,
            name: name.to_owned(),
            pipe,
            policy,
            authenticating: FuturesUnordered::new(),
            pending: PendingAccounts::default(),
            session_owner,
        })
    }
    pub fn policy_handle(&self) -> PolicyHandle {
        PolicyHandle(Arc::downgrade(&self.policy), self.form)
    }

    fn start_authentication(&mut self) -> io::Result<()> {
        let mut handle = self
            .policy
            .lock()
            .map_err(|_| io::Error::other("pipe policy lock poisoned"))?;
        // Hold the old instance until its successor owns the name. Additional
        // instances inherit the pipe object's current DACL.
        let next = options(self.form).create(&self.name)?;
        *handle = duplicate(&next)?;
        let mut pipe = mem::replace(&mut self.pipe, next);
        drop(handle);
        let user = identity::admission_user(&pipe)?;
        self.pending.reserve(&user)?;
        let deadline = tokio::time::Instant::now() + MARKER_TIMEOUT;
        let session_owner = self.session_owner.clone();
        self.authenticating.push(Box::pin(async move {
            let outcome = async {
                let byte = tokio::time::timeout_at(deadline, pipe.read_u8()).await??;
                if byte != 1 {
                    return Err(denied("invalid IPC identification marker"));
                }
                let peer = match &session_owner {
                    Some(owner) => identity::session_client_peer(&pipe, owner)?,
                    None => identity::client_peer(&pipe)?,
                };
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
    let proof = proof(expect)?;
    let name = pipe_name(endpoint)?;
    let before = SystemTime::now();
    let file = open_client(name).await?;
    let mut pipe = unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle())? };
    let server =
        identity::server_identity(&pipe, &expect.exe_dir, proof, before).map_err(denied)?;
    pipe.write_u8(1).await?;
    Ok((Box::new(pipe), server))
}

/// `ERROR_PIPE_BUSY`: every instance of the pipe is connected.
const ERROR_PIPE_BUSY: i32 = 231;
/// How long [`open_client`] waits for a busy pipe to offer an instance.
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// Opens the client end once.
fn open_once(name: &str) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(client_mask())
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .security_qos_flags(SECURITY_IDENTIFICATION.0)
        .open(name)
}

/// Opens the client end. A busy pipe (the server is between accepting one
/// client and offering its next instance) is waited for with
/// `WaitNamedPipeW`, for up to [`BUSY_WAIT`]; any other error is returned at
/// once, so callers can still tell "no such pipe" from the rest.
///
/// `BUSY_WAIT` bounds every open. Callers that wrap `connect` in their own
/// timeout (the desktop launcher's probes) cut it shorter; the others (the
/// host waiting for the service after install, the client's reconnect and
/// tonic connect) wait up to `BUSY_WAIT`. A `WaitNamedPipeW` already running
/// when an outer timeout fires cannot be cancelled and keeps its blocking
/// thread until it returns, at most `BUSY_WAIT` later.
async fn open_client(name: &str) -> io::Result<std::fs::File> {
    let deadline = std::time::Instant::now() + BUSY_WAIT;
    loop {
        let error = match open_once(name) {
            Ok(file) => return Ok(file),
            Err(error) => error,
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY) || remaining.is_zero() {
            return Err(error);
        }
        let wide = HSTRING::from(name);
        let millis = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        // WaitNamedPipeW blocks, so not on the async worker. Its result does
        // not matter: the next open decides.
        let _ = tokio::task::spawn_blocking(move || {
            // SAFETY: `wide` is a NUL-terminated name that outlives the call.
            let _ = unsafe { WaitNamedPipeW(&wide, millis) };
        })
        .await;
    }
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

    /// In-process pipe only: no second process, no network.
    #[tokio::test]
    async fn a_busy_pipe_is_waited_for_and_other_errors_are_not() {
        let name = format!(r"\\.\pipe\etd-ipc-busy-test-{}", std::process::id());
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        // Takes the only instance: every instance is now connected.
        let _held = open_client(&name).await.unwrap();
        assert_eq!(
            open_once(&name).unwrap_err().raw_os_error(),
            Some(ERROR_PIPE_BUSY)
        );
        let offer = tokio::spawn({
            let name = name.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                ServerOptions::new().create(&name).unwrap()
            }
        });
        let started = std::time::Instant::now();
        open_client(&name).await.unwrap();
        assert!(started.elapsed() < BUSY_WAIT);
        drop((offer.await.unwrap(), first));

        // No such pipe: reported at once, not waited for.
        let started = std::time::Instant::now();
        let missing = open_client(r"\\.\pipe\etd-ipc-busy-test-missing")
            .await
            .unwrap_err();
        assert_eq!(missing.raw_os_error(), Some(2));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

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
