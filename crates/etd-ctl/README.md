# etd-ctl

The command-line client of an EasyTier Desktop host (binary `etd-ctl`). It speaks only
the local `etd.v1` contract, through [`etd-client`](../etd-client/README.md)'s
`GrpcHostClient` (as `CLIENT_KIND_CLI`) over a verified
[`etd-ipc`](../etd-ipc/README.md) connection. It never talks to a kernel. Results go to
standard output and errors to standard error. Tracing is off unless `RUST_LOG` is set,
and then it goes to standard error.

## Usage

```text
etd-ctl [GLOBAL OPTIONS] <COMMAND>
```

Global options, accepted before or after the subcommand:

| Option | Default | Meaning |
| --- | --- | --- |
| `--json` | off | Machine-readable JSON on stdout; errors as JSON on stderr |
| `--host <service\|user>` | `service` | Which host form to talk to |
| `--endpoint <ENDPOINT>` | per host form | Pipe name (Windows) or socket path (Unix) to use instead |
| `--host-dir <DIR>` | see below | Directory the host executable must run from |
| `--timeout <SECONDS>` | `10` | 1 to 3600: wait for the connection, and for each reply |
| `-h`, `--help` / `-V`, `--version` | | Help (lists the exit codes) / version |

| Command | Contract calls (capability, role) | Effect |
| --- | --- | --- |
| `status [INSTANCE]` | `Snapshot` (`instances`, viewer) | Host mode, phase, build, contract, your role, revision, instances |
| `apply -f <FILE> [--instance <ID>] [--start \| --stop] [REPLAY]` | `Apply` (`instances`, control) | Create or replace an instance configuration |
| `start <INSTANCE> [REPLAY]` | `SetDesired` RUNNING (`instances`, control) | Desired state running |
| `start <INSTANCE> --retry [REPLAY]` | `RetryStart` (`instances`, control) | Restart an instance in state `gave_up` |
| `stop <INSTANCE> [REPLAY]` | `SetDesired` STOPPED (`instances`, control) | Desired state stopped |
| `logs [INSTANCE] [--tail <LINES>] [-f\|--follow]` | `StreamLogs` (`logs`, viewer) | Instance log, or the host's own log when omitted; `--tail` defaults to 100 |
| `reclaim-report` | `GetReclaimReport` (`reclaim`, viewer) | Open residues, candidates, conflicts, notes |

`REPLAY` is `--request-id <ID>` and `--expected-revision <REVISION>`. `--request-id`
requires `--expected-revision`; `--expected-revision` alone is allowed. Without
`--expected-revision`, the command reads the current revision with an extra
`Snapshot`. Without `--request-id`, it generates a UUID v4.

- `apply`: `-f -` reads standard input, and a leading UTF-8 BOM is ignored. The file is
  read and checked before any connection is made. Without `--instance` a new UUID v4
  instance id is generated and printed. `--start` and `--stop` conflict. Without
  either, the desired state is left unchanged; a new instance starts stopped.
  `--request-id` on `apply` also needs `--instance` (otherwise exit 2).
- `start` without `--retry`: if the instance is in `gave_up` afterwards, a warning on
  stderr suggests `etd-ctl start --retry <INSTANCE>`. The change is still accepted.
- `status <INSTANCE>` with an id the host does not know exits with 8
  (`unknown_instance`).
- `logs` without `--follow` ends when the host closes the stream. If the reader of
  stdout goes away (for example `| head`), it ends quietly with 0.

## Finding the host

Endpoint: `--endpoint` wins for either host form. On Windows it is taken as a pipe
name, on Unix as a socket path. Otherwise:

| `--host` | Windows | Linux | macOS |
| --- | --- | --- | --- |
| `service` | `\\.\pipe\easytier-desk-host` | `/run/easytier-desk/host.sock` | `/Library/Application Support/easytier-desk/run/host.sock` |
| `user` | `\\.\pipe\easytier-desk-user-<current user SID>` | `$XDG_RUNTIME_DIR/host.sock`, else `/tmp/easytier-desk-<uid>/host.sock` | `<per-user temp dir>/easytier-desk/host.sock` |

Verification: before sending anything, the connection must prove that the server is
`<DIR>/etd-host` (`etd-host.exe` on Windows). `--host service` also requires a
SYSTEM / root server on a protected endpoint. `--host user` requires a server running
as the current user. `DIR` is `--host-dir`, or by default:

- `--host service`: the installed service directory, from
  `etd_sysfx_os::service::installed_host_dir()`: `%ProgramFiles%\EasyTierDesk`,
  `/usr/local/lib/easytier-desk` or `/Library/Application Support/easytier-desk`;
- `--host user`: the directory containing the `etd-ctl` executable.

The per-platform checks are described in the [etd-ipc README](../etd-ipc/README.md).

## Connecting, retries and replay

`etd-ctl` waits up to `--timeout` for the handshake. It fails at once on a host that
fails verification (4) or speaks another major version (5). Otherwise it gives up
after the timeout and reports the latest reason. A peer the host refuses (exit 6)
therefore also fails only after the timeout.

For `apply`, `start` and `stop`, a reply that is lost is first recovered by
`etd-client` through `GetReceipt`. If the outcome is still unknown (`unavailable`,
`transport`), `etd-ctl` sends the identical request (same request id, revision and
content) up to two more times, after 300 ms and then 600 ms, waiting for a
reconnection in between. A host refusal settles the request at once. If the outcome
is still unknown after the retries, the command fails with the code of the last error
(normally 3). Its `hint:` line, or the JSON fields, give the flags that replay the
request by hand: `[--instance <ID>] --request-id <ID> --expected-revision <N>`. The
host answers a replay of an accepted request with the original receipt.

## Exit codes

| Code | Meaning | JSON `kind` |
| --- | --- | --- |
| 0 | Success; for `apply`, `start`, `stop`: the host durably accepted the request | |
| 1 | Internal or local I/O error, or cancelled | `internal`, `cancelled` |
| 2 | Invalid arguments or configuration file | `invalid_input` (clap errors print plain text) |
| 3 | Host unavailable; a state change may or may not have been accepted | `unavailable`, `transport` |
| 4 | Endpoint served by a process that failed host verification | `host_not_verified` |
| 5 | Contract major version mismatch: upgrade the service | `upgrade_required` |
| 6 | Permission denied or elevation required | `permission_denied`, `elevation_required` |
| 7 | Revision conflict, or request id reused with different content | `revision_conflict`, `request_id_reused` |
| 8 | Rejected by the host, or `status` named an unknown instance | `rejected`, `unknown_instance` |
| 9 | The host does not offer the needed capability | `unsupported` |

## Output

Text mode prints `error: <message>` and an optional `hint: <hint>` (an unknown outcome,
or a revision conflict) on stderr. Control characters in host-supplied text are
replaced with spaces.

With `--json`, stdout carries one JSON value per command, or one object per line for
`logs`. Enum values are lower-case without their prefix (`ready_full`, `running`,
`service`, `core_stderr`).

- Receipt (`apply`, `start`, `stop`): `instance_id`, `request_id`, `revision`,
  `ticket`, `accepted_unix_ms`.
- `status`: `host` (`mode`, `phase`, `role`, `build`, `contract`, `capabilities`),
  `revision`, `default_core_version`, `reclaim` (`candidates`, `conflicts` counts), and
  `instances[]` with `instance_id`, `desired`, `display_name`, `network_name`,
  `network_secret_set`, `status`. `status` holds `state`, `state_since_unix_ms`,
  `epoch`, `management`, `message`, `interface_name`, `addresses`, `core_version`,
  `restart_attempt`, `next_restart_unix_ms`, `last_exit`, `open_residues`.
- `logs`: `at_unix_ms`, `source` (`host`, `core_stdout`, `core_stderr`),
  `instance_id`, `epoch`, `text`.
- `reclaim-report`: `generated_unix_ms`, `instances[]` (with `residues[]`),
  `candidates[]`, `conflicts[]`, `notes[]`.
- Errors on stderr: `{"error": {"kind", "message", "exit_code", ...}}`, plus
  `current_revision` for a revision conflict; `error_code` (for example
  `instance_busy`), `features` and `instance_id` for a rejection; and `request_id`,
  `expected_revision` and `instance_id` for an unknown outcome.

Secrets: configurations are shown only as `network_secret_set`. Text that follows
`network_secret` / `network-secret` in host messages and log lines is replaced with
`<redacted>`, and `apply` errors are scrubbed of the secret it sent.

## The `apply` file

A JSON object whose keys are `NetworkSpec` field names; `null` counts as absent.
Unknown keys are refused, and error messages name keys, never values.

- Strings: `display_name`, `network_name`, `hostname`, `network_secret` (absent keeps
  the stored secret, `""` clears it).
- Addressing: `ipv4_cidr` (`"a.b.c.d/len"`) or `dhcp` (bool), not both.
- String arrays: `peers`, `listeners`, `proxy_cidrs`, `exit_nodes`.
- Booleans: `no_listener`, `enable_exit_node`, `no_tun`, `magic_dns`,
  `public_ipv6_provider`.
- Integers: `mtu` (0 = kernel default), `socks5_port` (0 to 65535, 0 = off).
- `port_forwards`: an array of `{"protocol": "tcp" | "udp", "bind", "destination"}`;
  `protocol` is required.
- `flags`: booleans `latency_first`, `disable_encryption`, `enable_kcp_proxy`,
  `enable_quic_proxy`, `disable_p2p`, `disable_udp_hole_punching`,
  `relay_all_peer_rpc`, `private_mode`, `disable_ipv6`, `use_smoltcp`; `multi_thread`
  and `bind_device` (absent keeps the upstream default); `compression` (string).
- `network_secret_set` is output only and refused.

## Dependencies and boundaries

- **Depends on:** `etd-client`, `etd-contract`, `etd-ipc`, `etd-sysfx-os` (only for
  the installed service directory); `etd-testkit` as a dev-dependency.
- **Used by:** none (binary).
- **Must not:** talk to a kernel or bypass `HostClient`; no direct system binding
  crates (rule 2 of `cargo xtask check-boundaries`).

## Key modules

| Module | Responsibility |
| --- | --- |
| `cli.rs` | clap grammar and exit code help text |
| `target.rs` | Endpoint and `ServerExpectation` per host form |
| `commands.rs` | Connection wait, one function per subcommand, retry loop |
| `spec.rs` | `apply` file parser |
| `output.rs` | Text and JSON rendering, redaction |
| `error.rs` | `CtlError`, exit codes, JSON kinds, hints |

## Testing

```sh
cargo nextest run -p etd-ctl
```

`tests/cli.rs` runs the real binary against `etd-testkit`'s `ScriptedHost` on a real
local listener. Each such test re-runs itself from a copy named `etd-host`, so host
verification is real. The tests cover every subcommand's text and JSON output and
exit codes, automatic resend and manual replay, refusals, version mismatch, timeout,
an untrusted host executable, input errors before connecting, and `--help`. Unit tests
in `spec.rs` and `output.rs` cover parsing and redaction. Nothing here is privileged.
