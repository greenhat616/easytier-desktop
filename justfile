[windows]
set shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

check:
    cargo check --locked --workspace

test:
    cargo nextest run --locked --workspace --profile ci

lint:
    cargo fmt --all -- --check
    cargo clippy --locked --workspace -- -D warnings

deny:
    cargo deny --locked check

proto-lint:
    buf lint

boundaries:
    cargo xtask check-boundaries

fetch-cores:
    cargo xtask fetch-cores --target host --bundle target/debug/cores
