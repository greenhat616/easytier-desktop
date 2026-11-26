# S1 Windows management-port fence

Standalone Cargo spike, intended for an elevated disposable CI runner only.
Build with `cargo build --locked --bins`; the workflow invokes
`run-check.ps1` with the resulting fixture and WFP executables.

The liftable O1 implementation is in `src/bin/wfp.rs`: create a persistent
provider and sublayer using an ordinary (not dynamic) BFE session. At each
ALE_AUTH_CONNECT layer, install a high-weight soft permit for the LocalSystem
security descriptor followed by a lower-weight block scoped to the same TCP
loopback address and target port. Use a transaction for the four filters.
Never grant a hard permit overriding unrelated firewall policy.

The check uses LocalSystem scheduled tasks for the installer, both listeners
and positive probes; secondary logon launches a distinct non-admin account
for negative probes. The
control endpoint must be reachable from that account, and every failed
connection to the fenced endpoint is bracketed by successful challenge reads
from the same listener. The installer alone is killed, then the probes and
persistent-object enumeration are repeated. After listener death, delete
filters before sublayer/provider, enumerate independently, and assert zero.

Fixed GUIDs here are spike-only: production should use a protected product
namespace and per-instance filter keys, verify container identity before
reclamation, and repeat both probes at startup. Passing this test establishes
the specific fixture's endpoint on the hosted runner, not arbitrary policy.
