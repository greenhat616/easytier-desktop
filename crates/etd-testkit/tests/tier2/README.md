# Tier 2 integration tests

Run the unprivileged suite with `cargo nextest run -p etd-testkit --test tier2`.
The two `fixture_*` test entries are subprocess entrypoints only (they return
without the corresponding fixture environment). The named scenarios are the
actual assertions.

The suite re-executes its own test binary under the `etd-host` image name,
not the shipped executable, and uses the same `serve_with_deps` implementation
as the product. No test CLI flag, dependency injection, or fake is compiled
into the shipped host. Real components: isolated native pipe/socket and peer
verification, gRPC contract, authorizer, orchestrator, ProcessKit, fake-core
**process**, runtime directory reclamation, SQLite commits, host/UI process
termination, and wall clock. The fake components are the kernel planner/session,
core store, OS observations/boot ID, and repair index. A ready-file from the
actual core process drives the simulated listener observation. The helper UI
uses the native client stub; it is not the GPUI frontend.

| Scenario | Observations |
|---|---|
| Kill host while child is live | Verified core identity is gone immediately on Windows/Linux; on macOS the restarted host must sweep it. Old-generation records and directories disappear after self-check. |
| Kill host after intent, before spawn | Deterministic fixture-only barrier before the real ProcessKit launch; committed intent without PID; independent process inventory empty; restart closes old records and creates a fresh generation. |
| Kill UI after intent | UI subprocess has submitted the request; host remains alive and completes the launch after barrier release. |
| Kill UI with running instance | Real user host and core survive the disconnect; after the 30-second lease grace the user host exits and cleans up the core and open effects. |
| Lost response | Client response is deliberately discarded (not packet-level loss injection); compare recovered request-ID receipt and identical retry with the SQLite receipt; no duplicate revision or instance. |
| Abnormal core exit | The scriptable fake-core exits with code 37 after its runtime-directory trigger; real lifecycle reclaims old generation and starts a new live identity. |
| Kill host mid-reclaim | Barrier after delegated runtime-directory removal but before ledger closure; restart handles already-absent directory and closes every old record. |
| Log redaction | Synthetic secret equals a real fake-core stderr line; the native log stream must contain a redacted stderr line and no plaintext. |

These scenarios run against the product's serving code, not the shipped `etd-host`
binary with real OS adapters; that binary also needs a trusted kernel from a populated
`cores.lock`. Repeating them against the shipped binary belongs to the planned tier-3
suite. Native TUN, firewall/router/DNS
and foreign-object preservation, system power cuts, and actual OS-side kernel
writes are not simulated as proof of clean native system state in this suite.

## Privileged and real-kernel follow-up

- `cargo nextest run --profile privileged -p etd-testkit --test tier2 --run-ignored only`
  exercises crash of a UI connected to the **service-form** test host. Requires
  root on Unix or LocalSystem on Windows and `ETD_G1_SERVICE_RUNTIME` pointing
  to an existing private, protected directory (not `/tmp` on Unix). It does not
  install a system service. The service host and core must survive past lease
  grace. This case is ignored by the default suite.
- `cargo nextest run --profile privileged -p etd-core-easytier --test session_real --run-ignored only`
  is the ignored native-kernel smoke test of `etd-core-easytier`; supply `ETD_EASYTIER_CORE`
  as the absolute path to the pinned c97f36b native executable.
- The `etd-host --test install_roundtrip` privileged CI test (`ci.yml`)
  verifies actual installed image/LocalSystem peer, standard versus elevated
  role, durable SetAllowList, and native revocation. The existing
  `etd-ipc --test pipe_acl` Windows second-account test runs with
  `ETD_IPC_CI_ACCOUNTS=1` in Windows CI. The existing
  `etd-ipc --test unix_service` ignored second-account tests require a root
  runner; use the privileged nextest profile. `etd-host-core`'s `service_allow_list_sink`
  covers injected ACL-update failures; actual native ACL failure injection is
  not covered by this fixture.
