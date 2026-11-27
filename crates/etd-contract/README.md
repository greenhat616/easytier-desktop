# etd-contract

The public desktop contract `etd.v1`. This crate holds the Protobuf definitions that
the UI, the CLI and the host speak, the Rust messages generated from them, the
contract version and capability constants, and the method-to-role table. It is a
library on the boundary between the UI side (`etd-client`, `etd-app`, `etd-ui`,
`etd-ctl`) and the host side (`etd-host-core`, `etd-host`). It never exposes kernel
or transport types and its only runtime dependency is `prost`.

The `.proto` files under `proto/etd/v1/` are the source of truth. To learn how the
contract changes and how client and host agree on a version, read
[docs/versioning.md](docs/versioning.md).

## Public surface

The whole crate (`crates/etd-contract/**`) is frozen at tag `freeze-v1`. Additive
changes follow the minor-version rules in [docs/versioning.md](docs/versioning.md).

| Item | Purpose |
| --- | --- |
| `proto/etd/v1/host.proto` | `service HostService` and all request, event and error messages |
| `proto/etd/v1/options.proto` | `enum Role` and the `(etd.v1.required_role)` method option (field 50000) |
| `v1` | prost-generated messages and enums |
| crate-root re-exports | `Hello`, `Welcome`, `HostSnapshot`, `Event`, `EventCursor`, `Receipt`, `ErrorCode`, `ErrorDetail`, `Role`, `HostMode`, `HostPhase`, `NetworkSpec`, ... |
| `VERSION_MAJOR`, `VERSION_MINOR` | `1` and `0` |
| `VERSION_METADATA_KEY` | `etd-contract-version`; `version_metadata_value()` builds `"1.0"`, `parse_version_metadata()` reads it |
| `SERVICE_NAME` | `etd.v1.HostService` |
| `capability::*` | Feature names a host lists in `Welcome.capabilities` |
| `method_roles()`, `required_role(path)`, `MethodRole` | Role table read from the embedded descriptor |
| `REQUIRED_ROLE_OPTION`, `FILE_DESCRIPTOR_SET` | Option field number; encoded descriptor set of both files |
| `Revision`, `InstanceId`, `RequestId` | Rust-side identifiers (`model.rs`) |
| `Negotiated` | Handshake result as seen by a client, built `From<Welcome>` |

`HostService` methods (server-streaming ones marked):

- Handshake and state: `Handshake`, `Snapshot`, `Subscribe` (stream), `GetReceipt`.
- Instances: `Apply`, `SetDesired`, `RemoveInstance`, `RetryStart`.
- Kernel queries and logs: `Query` (nodes, routes, traffic), `StreamLogs` (stream).
- Reclaim: `GetReclaimReport`, `RetryReclaim`, `ResolveCandidates`.
- Session hosts: `ReleaseLease`.
- Administration: `GetAllowList`, `SetAllowList`, `ListCores`, `SelectCore`,
  `PurgeAllData`.

Rejected calls carry an encoded `ErrorDetail` (with an `ErrorCode`) in the gRPC status
details. The user host's "remote" mode (attach to another machine's kernel without
starting one) is not part of contract 1.0.

## Code generation

`build.rs` compiles both files with `prost-build` and writes the descriptor set into
`OUT_DIR`; a `protoc` with the well-known types (`google/protobuf/descriptor.proto`)
must be installed (CI pins protoc 36.2). This crate generates messages only. The tonic
stubs are generated from the same files elsewhere, with
`extern_path(".etd.v1", "::etd_contract::v1")` so they reuse these message types:
client stubs in [`etd-client`](../etd-client/README.md) (`etd_client::stub`) and server
stubs in `etd-host-core` (`etd_host_core::stub`).

Role lookups never use a hand-written table: `roles.rs` decodes `FILE_DESCRIPTOR_SET`
with a minimal descriptor mirror that keeps the custom option (which `prost-types`
would drop as an unknown field).

## Dependencies and boundaries

- **Used by:** `etd-client`, `etd-app`, `etd-ui`, `etd-ctl`, `etd-host`,
  `etd-host-core`, `etd-core-api`, `etd-core-easytier`, `etd-sysfx`, `etd-sysfx-os`,
  `etd-testkit` (normal); `etd-ipc` (dev).
- **Depends on:** no workspace crate. `prost` (normal), `prost-build` (build),
  `prost-types` (dev).
- **Must not depend on:** anything except `prost` / `prost-build` as normal or build
  dependencies ("contract isolation" in `cargo xtask check-boundaries`).

## Key modules

| Module | Responsibility |
| --- | --- |
| `src/lib.rs` | Generated `v1` module, re-exports, version constants, `capability` names |
| `src/model.rs` | `Revision`, `InstanceId`, `RequestId`, `Negotiated` |
| `src/roles.rs` | Method-to-role table decoded from the descriptor set |
| `build.rs` | `prost-build` invocation and descriptor set output |

## Testing

```sh
cargo nextest run -p etd-contract
cargo test --doc -p etd-contract
```

| Test file | Covers |
| --- | --- |
| `tests/descriptor.rs` | Compiled descriptor equals `tests/baseline/etd.v1.txt` (fields, enum values, methods, option, role table) |
| `tests/roles.rs` | Every method has a role; the table matches the read / control / admin split; only `Subscribe` and `StreamLogs` stream |
| `tests/wire_compat.rs` | Every message decodes from empty input, round-trips, skips unknown fields; unknown enum values survive |

An additive change fails `descriptor_matches_baseline` until the baseline is
regenerated and reviewed:

```sh
ETD_UPDATE_BASELINE=1 cargo nextest run -p etd-contract
```

A removed or changed line is reported as `BREAKING` and needs a new major version.
`buf lint` and `buf breaking` (configured in the root `buf.yaml`) run in CI's
`contract` job; see [docs/versioning.md](docs/versioning.md). Nothing in
this crate is privileged.
