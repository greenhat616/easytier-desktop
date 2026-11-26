---
name: etd-ctl
description: Inspect and control a running EasyTier Desktop host from the terminal with etd-ctl. Use it to check the host and its network instances, read instance or host logs, read the reclaim report, create or replace an instance configuration, and start or stop instances.
---

# Controlling EasyTier Desktop with `etd-ctl`

`etd-ctl` talks to one EasyTier Desktop host (`etd-host`, the installed system service
or the current user's host) over its local, authenticated endpoint. It never starts a
host, never talks to a kernel, and verifies the host executable before sending
anything.

## Ground rules

- Always pass `--json`. Output is one JSON value per command (one object per line for
  `logs`); errors are JSON on stderr. Never parse the text output.
- Start with `etd-ctl --json status`. It shows the host form, your role, the
  capabilities and the current revision. Do not attempt a command whose capability or
  role is missing.
- Treat `status`, `logs` and `reclaim-report` as safe. Before `apply`, `start` or
  `stop`, say what will change and ask the user to confirm: stopping or reconfiguring
  an instance drops that network.
- Never put a network secret on a command line or in a reply. Pass configurations
  through a file or standard input (`apply -f -`), and do not echo them back. Output
  only ever shows `network_secret_set`.
- Run one mutation at a time and read its result before the next.
- Never run `etd-host install`, `uninstall` or `reclaim --all --purge` on the user's
  behalf unless they ask for exactly that.

## Choosing the host

- Default: `--host service`, the installed system service.
- `--host user`: the current user's host. `etd-ctl` must sit in the same directory as
  `etd-host`, or pass `--host-dir <DIR>`.
- `--endpoint <PIPE_OR_SOCKET>` overrides the endpoint; host verification still
  applies.
- `--timeout <SECONDS>` (default 10) bounds the connection and each reply.

## Commands

| Command | Does |
| --- | --- |
| `status [INSTANCE]` | Host and instances: desired state, actual state, epoch, management availability, addresses, restart info, open residues |
| `logs [INSTANCE] [--tail N] [-f]` | Instance log, or the host's own log without an instance |
| `reclaim-report` | Open residues, candidates and conflicts that need attention |
| `apply -f <FILE\|-> [--instance ID] [--start\|--stop]` | Create (new id printed) or replace an instance configuration |
| `start <INSTANCE>` | Desired state running |
| `start <INSTANCE> --retry` | Restart an instance in state `gave_up` |
| `stop <INSTANCE>` | Desired state stopped |

The `apply` file is a JSON object of `NetworkSpec` fields (`network_name`,
`network_secret`, `peers`, `listeners`, `ipv4_cidr` or `dhcp`, `no_tun`, `magic_dns`,
`port_forwards`, `flags`, ...). Unknown keys are refused. See
[`crates/etd-ctl/README.md`](../../crates/etd-ctl/README.md#the-apply-file) for the full
list.

## Reading results

- Exit 0 for a mutation means the host durably accepted it; progress shows in later
  `status` calls (`starting`, `ready_basic`, `ready_full`, `backoff`, `gave_up`,
  `quarantined`, `cut_unconfirmed`, ...).
- `cut_unconfirmed` means traffic stopped but the stop is not durable yet; tell the
  user and do not report the instance as stopped.
- `quarantined` or entries in `reclaim-report` need a human decision; report them, do
  not try to work around them.

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | Success | |
| 2 | Invalid arguments or file | Fix the input |
| 3 | Host unavailable; outcome unknown | Use the `request_id` and `expected_revision` from the error to replay the same request with `--request-id` and `--expected-revision`; never send a different request instead |
| 4 | Endpoint served by an unverified process | Stop and tell the user |
| 5 | Contract major mismatch | The service needs an upgrade |
| 6 | Permission denied or elevation required | Tell the user; do not retry |
| 7 | Revision conflict or reused request id | Read `status` again, then decide |
| 8 | Rejected by the host, or unknown instance | Report the `error_code` |
| 9 | Capability not offered by this host | Do not retry |
