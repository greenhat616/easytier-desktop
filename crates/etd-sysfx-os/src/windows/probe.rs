//! Probe a live listener from an identity the fence must refuse. No saved
//! account password, child process, or script: a dedicated host thread
//! impersonates the identity, checks that its effective token really is
//! that identity, and connects once. Only an explicit refusal (the
//! connect's own WSAEACCES) counts.
//!
//! - System service: the built-in LocalService logon (not SYSTEM, no
//!   enabled Administrators, System integrity).
//! - Elevated session: a restricted Medium copy of the host token
//!   (Administrators deny-only). A child process of the same user could be
//!   ended by any of the user's processes with the "refused" exit code;
//!   that does not apply to a thread of the host.
use super::{
    FenceForm, WinError,
    registry::Handle,
    token::{self, ProbeIdentity},
};
use ::windows::Win32::{Security::RevertToSelf, System::Threading::SetThreadToken};
use etd_sysfx::{DirectionResult, FenceError};
use std::net::SocketAddr;

/// WSAEACCES: the connection was refused by a filter, not by the listener.
const ACCESS_DENIED: i32 = 10013;
/// TCP_MAXRT for the probe socket, in seconds: bounds the connect.
const CONNECT_SECONDS: u32 = 5;

pub fn unprivileged_connect(
    address: SocketAddr,
    form: FenceForm,
) -> Result<DirectionResult, FenceError> {
    // A transient local socket/resource error is not evidence of denial.
    // Retry it once, but never retry a successful unauthorized connection.
    let first = connect_once(address, form)?;
    if let DirectionResult::Error(first_error) = first {
        tracing::warn!(error=%first_error,%address,"unprivileged probe first attempt failed; retrying once");
        std::thread::sleep(std::time::Duration::from_millis(100));
        match connect_once(address, form)? {
            DirectionResult::Error(second_error) => Ok(DirectionResult::Error(format!(
                "initial probe: {first_error}; retry: {second_error}"
            ))),
            verdict => Ok(verdict),
        }
    } else {
        Ok(first)
    }
}

fn connect_once(address: SocketAddr, form: FenceForm) -> Result<DirectionResult, FenceError> {
    match form {
        FenceForm::Service => service_probe(address),
        FenceForm::Session => session_probe(address),
    }
}

fn service_probe(address: SocketAddr) -> Result<DirectionResult, FenceError> {
    on_probe_thread(address, || {
        Ok((
            token::local_service_impersonation()?,
            Box::new(ProbeIdentity::is_local_service) as Check,
        ))
    })
}

fn session_probe(address: SocketAddr) -> Result<DirectionResult, FenceError> {
    on_probe_thread(address, || {
        let token = token::restricted_impersonation()?;
        let user = token::host_user()?;
        Ok((
            token,
            Box::new(move |identity: &ProbeIdentity| identity.is_non_elevated(&user)) as Check,
        ))
    })
}

/// Whether the probe thread's effective identity is the expected one.
type Check = Box<dyn Fn(&ProbeIdentity) -> bool>;

/// On a fresh thread (impersonation never leaks into a pooled one, and the
/// token is made on it, so no handle crosses threads): make the token,
/// impersonate, check, connect, revert. The connect is bounded by
/// TCP_MAXRT, so the join is too.
fn on_probe_thread(
    address: SocketAddr,
    make: impl FnOnce() -> Result<(Handle, Check), WinError> + Send + 'static,
) -> Result<DirectionResult, FenceError> {
    std::thread::Builder::new()
        .name("etd-fence-probe".into())
        .spawn(move || {
            let (token, check) = make().map_err(|e| FenceError::Probe(e.to_string()))?;
            impersonated_connect(address, &token, &*check)
        })
        .map_err(|e| FenceError::Probe(e.to_string()))?
        .join()
        .map_err(|_| FenceError::Probe("probe thread panicked".into()))?
}

/// On the calling thread: impersonate `token`, confirm the effective
/// identity, connect once, revert.
fn impersonated_connect(
    address: SocketAddr,
    token: &Handle,
    check: &dyn Fn(&ProbeIdentity) -> bool,
) -> Result<DirectionResult, FenceError> {
    // SAFETY: `token` is an impersonation token with TOKEN_IMPERSONATE.
    unsafe { SetThreadToken(None, Some(token.0)) }
        .map_err(|e| FenceError::Probe(format!("impersonate the probe identity: {e}")))?;
    let verdict = match token::thread_identity() {
        Ok(identity) if check(&identity) => connect_verdict(address),
        Ok(identity) => DirectionResult::Error(format!(
            "probe thread is not the expected identity: {identity:?}"
        )),
        Err(e) => DirectionResult::Error(format!("probe thread identity: {e}")),
    };
    // SAFETY: ends this thread's impersonation.
    if let Err(e) = unsafe { RevertToSelf() } {
        // The thread ends right after; still, never report a verdict from a
        // thread whose identity is unknown.
        return Err(FenceError::Probe(format!("revert the probe identity: {e}")));
    }
    Ok(verdict)
}

/// A socket of the probe's identity, closed on drop.
struct Socket(::windows::Win32::Networking::WinSock::SOCKET);
impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: the socket was opened by `connect_verdict` and is closed once.
        let _ = unsafe { ::windows::Win32::Networking::WinSock::closesocket(self.0) };
    }
}

/// One connection attempt in steps, so that only the connect's own
/// WSAEACCES is a refusal: a socket that cannot be created, configured or
/// bound (a denied \Device\Afd open, a resource-assignment filter) is an
/// error, never evidence of the fence.
fn connect_verdict(address: SocketAddr) -> DirectionResult {
    use ::windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IPPROTO_TCP, SOCK_STREAM,
        SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, TCP_MAXRT, WSA_FLAG_NO_HANDLE_INHERIT, WSACleanup,
        WSADATA, WSAGetLastError, WSASocketW, WSAStartup, bind, connect, setsockopt,
    };
    let mut data = WSADATA::default();
    // SAFETY: `data` is writable; balanced by WSACleanup below.
    let started = unsafe { WSAStartup(0x0202, &mut data) };
    if started != 0 {
        return DirectionResult::Error(format!("probe WSAStartup: {started}"));
    }
    let verdict = (|| {
        let error = |step: &str| {
            // SAFETY: reads this thread's last Winsock error.
            let code = unsafe { WSAGetLastError() }.0;
            DirectionResult::Error(format!("probe {step}: WSA error {code}"))
        };
        // The address as a sockaddr; the local end is the same loopback
        // address with port 0.
        let (remote, local, length) = match address {
            SocketAddr::V4(v4) => {
                let at = |port: u16| SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: port.to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v4.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                let mut remote = [0u8; size_of::<SOCKADDR_IN6>()];
                let mut local = remote;
                // SAFETY: SOCKADDR_IN fits the buffer; written unaligned.
                unsafe {
                    remote
                        .as_mut_ptr()
                        .cast::<SOCKADDR_IN>()
                        .write_unaligned(at(v4.port()));
                    local
                        .as_mut_ptr()
                        .cast::<SOCKADDR_IN>()
                        .write_unaligned(at(0));
                }
                (remote, local, size_of::<SOCKADDR_IN>())
            }
            SocketAddr::V6(v6) => {
                let at = |port: u16| SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: port.to_be(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: v6.ip().octets(),
                        },
                    },
                    ..Default::default()
                };
                let mut remote = [0u8; size_of::<SOCKADDR_IN6>()];
                let mut local = remote;
                // SAFETY: SOCKADDR_IN6 is the buffer's size; written unaligned.
                unsafe {
                    remote
                        .as_mut_ptr()
                        .cast::<SOCKADDR_IN6>()
                        .write_unaligned(at(v6.port()));
                    local
                        .as_mut_ptr()
                        .cast::<SOCKADDR_IN6>()
                        .write_unaligned(at(0));
                }
                (remote, local, size_of::<SOCKADDR_IN6>())
            }
        };
        let family = if address.is_ipv6() { AF_INET6 } else { AF_INET };
        // SAFETY: plain socket creation; the handle is owned by `Socket`.
        let socket = match unsafe {
            WSASocketW(
                i32::from(family.0),
                SOCK_STREAM.0,
                IPPROTO_TCP.0,
                None,
                0,
                WSA_FLAG_NO_HANDLE_INHERIT,
            )
        } {
            Ok(socket) => Socket(socket),
            Err(e) => return DirectionResult::Error(format!("probe socket: {e}")),
        };
        let seconds = CONNECT_SECONDS.to_ne_bytes();
        // SAFETY: TCP_MAXRT takes a DWORD of seconds.
        if unsafe { setsockopt(socket.0, IPPROTO_TCP.0, TCP_MAXRT, Some(&seconds)) } != 0 {
            return error("TCP_MAXRT");
        }
        // SAFETY: `local` holds a sockaddr of `length` bytes.
        if unsafe { bind(socket.0, local.as_ptr().cast::<SOCKADDR>(), length as i32) } != 0 {
            return error("bind");
        }
        // SAFETY: `remote` holds a sockaddr of `length` bytes; a blocking
        // connect bounded by TCP_MAXRT.
        if unsafe { connect(socket.0, remote.as_ptr().cast::<SOCKADDR>(), length as i32) } == 0 {
            return DirectionResult::Connected;
        }
        // SAFETY: reads this thread's last Winsock error.
        let code = unsafe { WSAGetLastError() }.0;
        if code == ACCESS_DENIED {
            DirectionResult::Refused
        } else {
            DirectionResult::Error(format!("probe connect: WSA error {code}"))
        }
    })();
    // SAFETY: balances the successful WSAStartup above.
    unsafe { WSACleanup() };
    verdict
}
