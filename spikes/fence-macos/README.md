# S1 macOS management-port fence

Standalone Cargo spike; build with `cargo build --locked --bins`. Run
`sudo bash run-check /absolute/path/to/fixture` only in a disposable privileged
runner. The check creates a distinct local account and loads an isolated PF
anchor, without replacing the main ruleset or modifying other anchors.

O3 can lift the `block return out quick ... user != 0` rules in `run-check`.
The spike uses the active Apple wildcard anchor hook for testing. Production
must arrange a dedicated product-owned anchor hook, ensure loopback isn't
skipped, and manage its own PF enable reference; do not overwrite the main
ruleset or silently depend on an inactive anchor. If the required hook or the
identity-enforcement proof is missing, the test fails closed.

The separate privileged listener and host process permit verification after
host death. Both IPv4 and IPv6 use challenge reads, an unfenced control port,
and positive-negative-positive probes; PF rule counters and independent
post-cleanup enumeration are evidence.
