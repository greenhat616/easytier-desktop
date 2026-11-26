# S1 macOS management-port fence

Standalone Cargo spike; build with `cargo build --locked --bins`. Run
`sudo bash run-check /absolute/path/to/fixture` only in a disposable privileged
runner. The check creates a distinct local account and loads an isolated PF
anchor, without replacing the main ruleset or modifying other anchors.

O3 can lift the `block return out quick ... user != 0` rules in `run-check`.
Per topic#32 msg#892, use one fixed install-level product-owned child anchor
under the existing active `com.apple/*` hook; the name is not per generation.
Ensure loopback isn't skipped, verify the hook is active, and manage the PF
enable reference owned by the installation/host; do not overwrite the main
ruleset or silently depend on an inactive anchor. If the required hook or the
identity-enforcement proof is missing, the test fails closed.

The separate privileged listener and host process permit verification after
host death. Both IPv4 and IPv6 use challenge reads, an unfenced control port,
and positive-negative-positive probes; PF rule counters and independent
post-cleanup enumeration are evidence. The check reuses the fixed anchor for
two generations with different ports and releases/reacquires its own PF
enable reference between them. Reclamation means no instance rules remain;
the kernel may retain the empty install-level anchor name. On uninstall,
atomically empty our anchor and release only our enable reference. Never
flush other PF policy to remove an otherwise empty kernel name.

The fixture has one live generation at a time. Production must serialize
updates and atomically compose rules for all live instances in the shared
anchor (e.g. generation-specific labels), not replace it with an empty
ruleset while other listeners are alive.

No on-disk PF configuration is written by this spike. An in-memory anchor
without a persistent configuration is not a reboot-persistent policy; the
host must check/recreate the anchor and reinstall its rules before launching
any privileged listener. Global PF reload and reboot were not performed on
the hosted runner. A global policy reload may affect dynamic rules; recheck
both identity probes before granting management access and fail closed if
the active hook or rules aren't present.
