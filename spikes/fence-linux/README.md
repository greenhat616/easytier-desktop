# S1 Linux management-port fence

Standalone Cargo spike; build with `cargo build --locked --bins`. Run
`sudo bash run-check /absolute/path/to/fixture` only in a disposable privileged
runner. The check creates a distinct local account and an isolated nftables
inet table; no changes to unrelated tables.

O2 can lift the atomic nftables transaction in `run-check`: an inet output
base chain matches TCP destination 127.0.0.1 or ::1 and the exact port, rejecting
connections whose socket uid is not root. The base chain does not change the
verdict for other traffic. The table survives the installing process being
killed. Production should use its own exclusive table, per-instance rules and
stable ownership/identity checks, not this fixed test name.

The control port proves the second user can connect to a real listener.
Successful challenge reads before and after each denied probe establish that
the fenced listener is still present. Rule counters and the independent
post-delete global table enumeration are printed to CI evidence.
