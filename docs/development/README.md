# Development standards

These are the current development rules for human contributors and coding agents.
Read them before changing code. They are the single source of the detailed rules;
[`AGENTS.md`](../../AGENTS.md) adds agent behaviour guidelines, routes to these guides,
and restates only the rules that are broken most often.

## Choose a guide

| When you are working on | Read |
| --- | --- |
| Processes, crates, the contract, host forms, state machines | [Architecture overview](../architecture/README.md) |
| Host lifecycle, self-check, port fence, host forms | [Host](../architecture/host.md) |
| Ledger records, reclaim, ownership proofs, candidates | [Side effects](../architecture/side-effects.md) |
| Rust style, errors, async, unsafe, platform code | [Rust code guide](rust.md) |
| Building, checks, worktrees, frozen interfaces, commits | [Development workflow](workflow.md) |
| Test tiers, CI jobs, privileged runners | [Testing](../testing/README.md) |
| One crate's surface, boundaries and tests | That crate's `README.md` under `crates/` |

Start with the [root README](../../README.md#build-from-source) for building and
[CONTRIBUTING.md](../../CONTRIBUTING.md) for the contribution flow.

## Rules to keep in mind

- The UI and CLI talk only to the host, only through `etd.v1`. Nothing on the UI side
  depends on EasyTier.
- `etd-host-core` sees traits only; real implementations are injected by `etd-host`.
- Record before acting: a side effect is in the ledger before the kernel can create it.
- Never delete an operating-system object by name alone; prove ownership or report a
  candidate. When in doubt, fail closed.
- Frozen interfaces change only through a reviewed change request.
- Every Windows child process starts with `CREATE_NO_WINDOW`.
- Privileged tests run in CI or disposable VMs, never on a developer desktop.
- One commit does one thing; Conventional Commits with the crate name as scope.

## Maintaining these rules

Update the relevant guide when a shared rule changes, and update `AGENTS.md` in the
same change only if it restates that rule. `CLAUDE.md` imports `AGENTS.md`, so the same
instructions apply to every agent. Do not add a tool-specific or agent-specific
exception to an architectural rule.
