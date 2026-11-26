# etd-client

The host-facing client library shared by the UI (`etd-app` / `etd-ui`) and the CLI
(`etd-ctl`). It defines the `HostClient` trait, which is everything a client sees of a
host, and implements it as `GrpcHostClient`: tonic over an authenticated
[`etd-ipc`](../etd-ipc/README.md) connection. The implementation handles the
`etd.v1` handshake, capability gating, reconnect with backoff, gap-free event
resumption and lost-reply recovery. It is on the UI side and never depends on EasyTier.

## Public surface

| Item | Purpose |
| --- | --- |
| `HostClient` (frozen, `host_client.rs`) | Async trait: `snapshot`, `subscribe`, `apply`, `set_desired`, `remove_instance`, `receipt`, `query`, `logs`, `reclaim_report`, `retry_reclaim`, `retry_start`, `resolve_candidates`, `release_lease`, `allow_list`, `set_allow_list`, `cores`, `select_core`, `purge_all_data`, plus `negotiated()` and `connection()` |
| `CallError` (frozen) | `VersionMismatch`, `Unsupported`, `Unavailable`, `HostNotVerified`, `PermissionDenied`, `ElevationRequired`, `Conflict`, `RequestIdReused`, `Rejected(ErrorDetail)`, `Cancelled`, `Transport` |
| `ConnectionState` (frozen) | `Connecting`, `Connected(Negotiated)`, `Reconnecting { attempt }`, `UpgradeRequired { .. }`, `Closed` |
| `new_request_id()` (frozen) | Fresh UUID v4 `RequestId` for a `MutationHeader` |
| `grpc::GrpcHostClient` | `new(connector, endpoint, options)`, `close()`; closes on drop |
| `grpc::ClientOptions` | Client kind, build string, backoff and timeouts |
| `stub` | tonic client stubs for `etd.v1`, reusing `etd_contract::v1` messages |

Mutations take the contract request messages unchanged. The caller fills the
`MutationHeader`: a fresh request id per logical request, reused verbatim on retry, and
the revision it last saw. See
[the contract versioning notes](../etd-contract/docs/versioning.md#idempotent-mutations).

## Behaviour of `GrpcHostClient`

- **Connecting.** `new` spawns a supervisor task (it panics outside a Tokio runtime).
  Each connection is one session: native server verification through the
  `Connector`, then `Handshake`. A session's channel never dials twice, so the
  capabilities, role and stream id are renegotiated after every reconnect.
- **Backoff.** Exponential backoff with jitter from `backoff_min` to `backoff_max`,
  never giving up. A connection that lasted `stable_after` resets the backoff.
- **No waiting calls.** Without a live session a call fails at once with the reason of
  the last attempt. Watch `connection()` to wait instead.
- **Version.** Every call carries `etd-contract-version: 1.0`. A host with another
  major version leads to `UpgradeRequired`; the minor version is never compared.
- **Capabilities.** A call whose capability is missing from the `Welcome` fails
  locally with `Unsupported` and is never sent. `Query` checks the capability of the
  query kind it is asked for.
- **Events.** `subscribe(after)` survives reconnects. It resumes from the last
  delivered cursor and drops duplicates, so each event arrives once. Subscribing "from
  now" takes a snapshot first so that it has a cursor. The stream ends after yielding
  `ResyncRequired`, or after yielding an error such as a host rejection, `Unsupported`,
  `VersionMismatch` or `Cancelled`. Losing the connection is not an error.
- **Logs.** `logs` has no cursor; a broken log stream is reported, not resumed.
- **Lost replies.** A status that carries an `ErrorDetail` is a definite answer.
  `Unavailable`, `Unknown`, `Internal`, `Cancelled`, `Aborted` and `DeadlineExceeded`
  without one, and the request timeout, leave the outcome unknown. In that case the
  client looks the receipt up with `GetReceipt` for up to `recovery_timeout`. It never
  re-sends the mutation. If nothing is found, the original error is returned, and the
  caller may retry with the same request.
- **Verification failures.** A connector's refusal (`PermissionDenied` without an OS
  error code) becomes `HostNotVerified`. An OS access denial, a refused connection or a
  reset becomes `Unavailable`.

`ClientOptions::default()`: `ClientKind::Desktop`, backoff 200 ms to 5 s, stable after
5 s, connect (verification plus handshake) 10 s, request 30 s, recovery 15 s.

## Capability per call

| Capability | Calls |
| --- | --- |
| `instances` | `snapshot`, `subscribe`, `apply`, `set_desired`, `remove_instance`, `receipt`, `retry_start` |
| `query.nodes` / `query.routes` / `query.traffic` | `query` by kind |
| `logs` | `logs` |
| `reclaim` | `reclaim_report`, `retry_reclaim` |
| `reclaim.candidates` | `resolve_candidates` |
| `lease` | `release_lease` |
| `admin.allow_list` | `allow_list`, `set_allow_list` |
| `admin.cores` | `cores`, `select_core` |
| `admin.purge` | `purge_all_data` |

## Dependencies and boundaries

- **Used by:** `etd-app`, `etd-ui`, `etd-ctl`, `etd-testkit` (normal); `etd-host` (dev).
- **Depends on:** `etd-contract`, `etd-ipc`; `etd-testkit` as a dev-dependency.
- **Must not depend on:** `etd-core-easytier` or any `easytier*` crate anywhere in its
  dependency closure, dev-dependencies included (rule 1 of
  `cargo xtask check-boundaries`); no system binding crates directly (rule 2).

## Key modules

| Module | Responsibility |
| --- | --- |
| `host_client.rs` | Frozen `HostClient`, `CallError`, `ConnectionState`, `new_request_id` |
| `grpc.rs` | `GrpcHostClient`, `ClientOptions`, version metadata interceptor, error mapping |
| `negotiate.rs` | Handshake, major check, capability gating |
| `reconnect.rs` | Supervisor and backoff, single-dial sessions, resumable subscription, receipt recovery |
| `build.rs` | Client-only tonic stubs from `../etd-contract/proto` |

## Testing

```sh
cargo nextest run -p etd-client
cargo test --doc -p etd-client
```

The tests run against `etd-testkit`'s in-memory transport, so nothing here is
privileged and no real process or socket is involved.

| Test file | Covers |
| --- | --- |
| `negotiate.rs` | Upgrade flow, capability gating and renegotiation, metadata on every call, typed rejections, impostor never spoken to |
| `reconnect.rs` | Resume from cursor, duplicates, resync, backoff growth and reset, hung handshake, close and drop, broken log stream; property test for exactly-once in-order delivery |
| `receipt_retry.rs` | Lost replies recovered by `GetReceipt` and never re-sent; outcome left open when the host stays away |
| `contract_service.rs` | Against the real `etd-host-core` contract service (`ContractHost`): handshake per host form, mutation and receipt semantics, event resume and resync |
