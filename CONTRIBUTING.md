# Contributing to EasyTier Desktop

Thank you for helping. This guide covers the environment, the development loop and how
to submit a change. The detailed rules live in the
[development standards](docs/development/README.md); read them before changing code.

## 1. Before you start

- For a new feature or a larger refactor, open an issue first so the design can be
  discussed. Several interfaces are frozen ([why and how to change
  them](docs/development/workflow.md#frozen-interfaces)).
- Keep discussions on GitHub, in issues and pull requests.
- Never post secrets, network keys or full configurations in issues or logs.

## 2. Environment

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.100.0 | Install `rustup`; `rust-toolchain.toml` selects the version, rustfmt and Clippy. Use the MSVC toolchain on Windows. |
| protoc | 36.2 | Must be on `PATH`. |
| cargo-nextest | 0.9.x | `cargo install cargo-nextest --locked` or a prebuilt binary. |
| cargo-deny | 0.22.x | Dependency policy check. |
| git | recent | |

Platform toolchains:

- **Windows:** Visual Studio C++ build tools and the Windows SDK.
- **macOS:** Xcode Command Line Tools.
- **Linux:** the native build, graphics and windowing libraries GPUI needs. On
  Debian/Ubuntu, the `check` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
  installs the full list (`build-essential clang cmake pkg-config libssl-dev
  libfontconfig1-dev libfreetype6-dev libx11-dev libxcb*-dev libxkbcommon-dev
  libwayland-dev libvulkan-dev libdbus-1-dev`, among others).

## 3. Development loop

```sh
cargo build --workspace --locked
cargo run -p etd-ui                        # desktop app
cargo run -p etd-host -- run --mode user   # user host in the foreground
cargo run -p etd-ctl -- --host user status
```

Before you push:

```sh
cargo fmt --all -- --check
cargo xtask check-boundaries
cargo clippy --locked --workspace -- -D warnings
cargo nextest run --locked -p <crate-you-changed>
```

CI runs the whole suite on Windows, macOS and Linux. Read its result rather than
trying to reproduce every platform locally.

> [!WARNING]
> Do not run privileged tests (`--profile privileged --run-ignored only`) or
> `etd-host install`, `uninstall` or `reclaim --all --purge` on your everyday machine.
> They change networking, firewall rules and services and create local accounts. They
> are meant for disposable CI runners and VMs.

## 4. Submitting a change

1. Branch from the latest `main`; do not work on `main` directly.
2. Keep each commit to one change that builds, and follow
   [Conventional Commits](docs/development/workflow.md#git-commits) with the crate name
   as scope, for example `fix(etd-proc): verify start time before kill`.
3. Stage explicit paths (`git add <paths>`), never `git add .`.
4. If you changed dependencies, include `Cargo.lock`.
5. Open a pull request against `main`, describe what changed and why, and link the
   issue. CI must be green on all three platforms.

Coding agents follow [AGENTS.md](AGENTS.md), which applies the same rules.
