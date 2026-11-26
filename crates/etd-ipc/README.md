# etd-ipc

Local IPC between the desktop clients and the host. This library provides Windows named
pipes and Unix domain sockets (Linux, macOS), and both sides use it. The host binds a
`LocalListener`, which applies an access policy and reports every peer's identity as
the OS sees it. Clients connect through `LocalConnector`, which verifies the server
process before sending a byte. The crate also adapts both ends to tonic. It makes no
business authorisation decisions: roles are decided in `etd-host-core` from the
`PeerIdentity` this crate attaches.

## Public surface

Frozen (`src/lib.rs`, `src/transport.rs`):

| Item | Purpose |
| --- | --- |
| `SERVICE_PIPE_NAME`, `SERVICE_SOCKET_PATH`, `SERVICE_SOCKET_GROUP` | Service host endpoint and optional socket group name |
| `HostForm` (`Service`, `User`, `ElevatedSession`) | Which host owns a listener and its singleton lock; `ElevatedSession` is not implemented yet and binding it fails with `Unsupported` |
| `Endpoint` (`NamedPipe`, `UnixSocket`) | Where a host listens |
| `OsUserId`, `OsGroupId` | Windows SID strings or Unix uid/gid |
| `PeerIdentity` | `user`, enabled `groups`, `pid`, Windows `session`, `elevated`; never taken from client data |
| `ServerIdentity` | Verified server `peer` plus its image path `exe` |
| `ListenerPolicy` | `allow_users`, `allow_groups`, `unix_group` granted besides the built-in owners |
| `ServerExpectation` | `exe_dir` and a `ServerRequirement` |
| `ServerRequirement` | `Service` (SYSTEM / root), `CurrentUser`, `CurrentUserElevated` (Windows only, not implemented yet), and `ServiceAccount(user)` / `UserAccount(user)`, the same proofs for a named account |
| `Listener`, `Connector`, `Connection`, `BoxConn` | Transport traits |

Implementation (`platform`, `tonic_io`):

- `platform::LocalListener::bind(form, endpoint, policy)` creates the endpoint, and
  never takes over an existing one. `bind_replacing_stale(claim, policy)` recovers an
  abandoned endpoint while the caller holds the host lock (`HeldHostLock`, borrowed as
  a `ListenerClaim`). `policy_handle()` returns a `PolicyHandle` whose `update(policy)`
  changes access on the live endpoint.
- `platform::LocalConnector { expectation }` implements `Connector`.
- `platform::current_user()`; on Unix also `platform::user_runtime_dir()`, which
  returns `PathBuf` on Linux and `io::Result<PathBuf>` on macOS.
- `tonic_io::incoming(listener)` gives a stream for `serve_with_incoming`. Its
  `connect_info` is the `PeerIdentity`. `tonic_io::ClientIo` is a tower connector for
  `connect_with_connector`; every reconnect is verified again.

## Endpoints

| Host form | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Service | `\\.\pipe\easytier-desk-host` | `/run/easytier-desk/host.sock` | `/Library/Application Support/easytier-desk/run/host.sock` |
| User | `\\.\pipe\easytier-desk-user-<SID>` | `$XDG_RUNTIME_DIR/host.sock`, or `/tmp/easytier-desk-<uid>/host.sock` if the variable is unset or empty | `<per-user temp dir>/easytier-desk/host.sock` (`_CS_DARWIN_USER_TEMP_DIR`, canonicalized) |
| Elevated session | `\\.\pipe\easytier-desk-session-<SID>` | — | — |

This crate defines the service names and `user_runtime_dir()`. `etd-host`, `etd-app`
and `etd-ctl` each compose the user-host names in the same way. A pipe name must be
`\\.\pipe\<leaf>`, where the leaf is non-empty and contains no `\`, `/`, `:` or NUL. A
socket path must be absolute, name a file and contain no `..`.

## Access policy (listener side)

**Windows.** The pipe is created as the first instance, so binding fails if the name
is taken. Remote clients are rejected. The security descriptor has the host account as
owner and a protected DACL (`D:P`, nothing inherited):

- Service and user forms: the host account gets read/write, `WRITE_DAC` and the right
  to create instances.
- Service form: `SYSTEM` and `BUILTIN\Administrators` get client access (read/write
  data, read attributes, `READ_CONTROL`, `SYNCHRONIZE`), and so does every allow-listed
  user or group SID. Only numeric `S-1-...` SIDs are accepted.
- User form: owner only. A policy with allow entries is refused (`InvalidInput`), as
  is `unix_group` on any Windows pipe.
- Elevated session form (Windows only): the host and its non-elevated clients share
  the user SID, so that SID gets client access only, and an `OWNER RIGHTS` entry with
  client access replaces the owner's implicit `READ_CONTROL | WRITE_DAC`.
  `BUILTIN\Administrators`, enabled only in elevated tokens, gets the remaining rights
  the host needs to add instances (`FILE_CREATE_PIPE_INSTANCE`, read/write EA, write
  attributes) and no data access. Nobody gets `WRITE_DAC` or `WRITE_OWNER`, and
  instances are created without `WRITE_DAC`. The SACL holds an explicit Medium,
  no-write-up mandatory label (`S:(ML;;NW;;;ME)`): a Medium UI can write, Low and
  AppContainer processes cannot. Allow entries are refused (`InvalidInput`).

`PolicyHandle::update` replaces the DACL of the live pipe object. Existing connections
keep their handles, and new instances inherit the current DACL. On the elevated session
pipe it only accepts the empty policy and leaves the fixed DACL as it is.

Before a connection is handed out, the client must send the marker byte `0x01` within
2 s. The listener identifies the client account by impersonating it, and after the
marker reads the full identity again; the account must not have changed. At most 8
connections per account and 64 in total may be pending this step. On the elevated
session pipe that token must also be the host's own account in the host's Windows
session, at least Medium integrity and not an AppContainer; otherwise the connection
is refused. It reports `elevated` only for an elevated token at High integrity or
above. The host decides the role afterwards from `PeerIdentity`.

**Unix.** The service form requires euid 0. The socket's directory chain must pass the
checks described under server verification. The socket is first bound inside a fresh
private staging directory (`.i<pid>.<seq>`, mode 0700) next to the endpoint. There it
gets `unix_group` (if set), mode 0660 with a group or 0600 without one, and the ACL.
Only then is it hard-linked to the public name, which fails if anything already exists
there. On drop the listener removes the socket if it is still the same inode.

- Linux: the whole POSIX access ACL is replaced. Owner, named users and named groups
  get `rw`; the owning group gets `rw` only with `unix_group`; others get nothing. A
  filesystem without ACL support is tolerated only when there are no named entries.
- macOS: an extended ACL allows `READ_DATA | WRITE_DATA` to each listed uid and gid.

`PolicyHandle::update` stages a new socket with the new policy and renames it over the
public name. `accept` drains the old backlog, then switches to the new socket. Clients
may see `ECONNRESET` or `ECONNREFUSED` during the swap and must reconnect.

`bind_replacing_stale` removes an existing socket only if it is a socket owned by the
host's uid and a non-blocking connect is refused. A live listener gives `AddrInUse`;
a foreign or non-socket object gives `PermissionDenied`. The inode is checked again
before the unlink, and abandoned staging directories of dead PIDs are cleaned. On
Windows it is a plain `bind`, because the kernel releases pipe names itself.

`etd-host` builds the policy from its allow list (service form) or uses the empty
policy (user form). It does not set `unix_group`.

## Peer identity

| Field | Windows | Linux | macOS |
| --- | --- | --- | --- |
| `user` | Client token user SID | `SO_PEERCRED` uid | `LOCAL_PEERCRED` uid |
| `groups` | Enabled token groups, deny-only excluded | `SO_PEERGROUPS` plus primary gid | `xucred` groups |
| `pid` | `GetNamedPipeClientProcessId` | `SO_PEERCRED` pid; refused if 0 (other namespace) | `LOCAL_PEERPID` |
| `session` | Token logon session | `None` | `None` |
| `elevated` | `TokenElevation`; on the elevated session pipe also integrity High or above | uid 0 | uid 0 |

## Server verification (connector side)

The server image must be exactly `<canonical exe_dir>/etd-host` (`etd-host.exe` on
Windows): an existing file whose canonical path is itself. The expected account comes
from `expectation.requirement`: SYSTEM (`S-1-5-18`) or uid 0 for `Service`, the current
user for `CurrentUser`, or the named account. `Service` and `ServiceAccount` use the
service-host proof below ("privileged"), the others the user-host proof. Until the
elevated session proof exists, `CurrentUserElevated` fails before the endpoint is
opened: `PermissionDenied` on Windows, `Unsupported` on Unix.

- **Windows:** the client opens the pipe with `SECURITY_IDENTIFICATION`, so the server
  can identify the client but not impersonate it. The server process must have been
  created before the open started, which defeats PID reuse. Its image path is matched
  after 8.3 expansion, case-insensitively. Privileged: the pipe owner SID must be the
  expected SID. If the server token is readable, its user or one of its groups must
  contain that SID; if `TOKEN_QUERY` is denied, the owner proof is enough (no groups,
  `elevated: false`). User form: the token user must match. Elevated session
  (`CurrentUserElevated`): the server token must be readable, be the current user's, be
  elevated and have integrity High or above (a restricted or lowered copy of an
  elevated token still reports `TokenElevation`); there is no owner fallback, so a
  token that cannot be queried is refused.
  Finally the server PID must be unchanged and the process still running. Only then
  does the client send the marker byte.
- **Linux:** checks run before connecting. Every directory from `/` to the socket's
  parent must be a real directory (not a symlink), owned by root or the expected uid,
  and not group- or world-writable. The user form allows sticky ancestors, but not as
  the parent. The parent must be owned by the expected uid; in the user form it must be
  mode 0700 and lie under `user_runtime_dir()`, which must itself be owned by the user
  and mode 0700. The socket must be a socket owned by the expected uid. After
  connecting: peer credentials, account check, inode unchanged, and the image from
  `/proc/<pid>/exe`, with an `SO_PEERPIDFD` pidfd proving the process did not exit
  meanwhile.
  - Without `SO_PEERPIDFD` (kernels before 6.5): a user host is accepted on directory
    and uid evidence, with an empty `exe`.
  - Service form: if `/proc/<pid>/exe` is unreadable, root ownership of the chain and
    the peer is the proof, with an empty `exe`.
- **macOS:** the same filesystem checks without the runtime-directory rule. The image
  comes from the `LOCAL_PEERTOKEN` audit token (`proc_pidpath_audittoken`). The service
  form tolerates an unreadable image.

A missing endpoint is reported as `NotFound`. A failed verification is
`PermissionDenied` without an OS error code, which `etd-client` reports as
`HostNotVerified`. An OS access denial keeps its OS code.

## Dependencies and boundaries

- **Used by:** `etd-client`, `etd-app`, `etd-ui`, `etd-ctl`, `etd-host`,
  `etd-host-core`, `etd-testkit` (normal).
- **Depends on:** no workspace crate at runtime; `etd-contract` and `etd-testkit` as
  dev-dependencies. System crates: `windows` (Windows), `libc` and `nix` (Unix).
- **Boundaries:** one of only three crates allowed to depend directly on system
  binding crates (with `etd-sysfx-os` and `etd-proc`).

## Key modules

| Module | Responsibility |
| --- | --- |
| `transport.rs` | Frozen types, traits and service endpoint constants |
| `platform/mod.rs` | `LocalConnector`, `HeldHostLock`, account and image verification |
| `platform/windows/` | Pipe DACL, admission, client and server token identity |
| `platform/unix/mod.rs` | Directory chain, staged publication, policy swap, connect checks |
| `platform/unix/{linux,macos}.rs` | Peer credentials, image lookup, ACLs, `user_runtime_dir` |
| `platform/unix/recovery.rs` | Stale socket and staging directory recovery |
| `tonic_io.rs` | `incoming` and `ClientIo` |

## Testing

```sh
cargo nextest run -p etd-ipc
cargo test --doc -p etd-ipc
```

Several tests copy the test binary to a temporary directory under the name `etd-host`
and re-run themselves there, so that real image verification applies. On Linux they
point `XDG_RUNTIME_DIR` at that directory.

| Test file | Covers |
| --- | --- |
| `peer_cred.rs` | Reported identity matches the process; Unix policy swap and exclusive name |
| `server_verify.rs` | Impostor rejected before any write; Windows service owner and image proof |
| `tonic_roundtrip.rs` | Handshake through tonic with native `connect_info` |
| `stale_endpoint.rs` (Unix) | Recovery under the session lock; files and symlinks preserved |
| `pipe_acl.rs` (Windows) | First instance, remote rejection, live DACL, owner-only user pipe |
| `session_pipe_acl.rs` (Windows) | Session pipe DACL and label, first instance; no `WRITE_DAC`, `WRITE_OWNER` or new instance for a non-elevated copy |
| `session_clients.rs` (Windows) | Restricted Medium copy admitted as not elevated; Low, AppContainer and second account refused |
| `session_server_verify.rs` (Windows) | Elevated host accepted, tonic handshake; a non-elevated squatter running the trusted image refused before any write |
| `unix_service.rs` (Unix) | Linux: user runtime path rules, writable service ancestor refused |
| `macos_service_path.rs` | Protected directory chain of the macOS service path |

These tests are privileged and `#[ignore]`d:
`stale_endpoint::foreign_owned_stale_socket_is_preserved` and the three `privileged_*`
tests in `unix_service.rs`. They need root, and some also need a second local account.
The `session_*.rs` tests are also ignored; `ci.yml` (`privileged-install`, Windows)
runs them on the administrator runner with restricted and low-box copies of the
runner's token. Run the Unix ones only as root in a disposable VM, with
`--profile privileged --run-ignored only`; no CI workflow runs those yet.

`pipe_acl::second_account_denied_allowed_and_revoked_on_real_pipe` creates a temporary
local Windows account. It runs only with `ETD_IPC_CI_ACCOUNTS=1` and an elevated token,
and CI sets that variable on Windows runners. Never set it on a developer machine.
