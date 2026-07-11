# ADR-0006: Private GitHub Release Distribution

## Status

Accepted

## Date

2026-07-11

## Context

`lgtm` needs reproducible single-binary installation while the repository remains private. Cargo-only installation would require source access and a Rust toolchain on every consumer machine.

## Decision

Publish tag-triggered GitHub Releases for `v*` tags. Each release contains tested x86_64 Linux and Intel macOS tarballs plus SHA-256 files. The workflow uses hosted stable Rust and immutable commits from official GitHub actions only. Release write permission exists only on the release job.

Install through `scripts/install.sh`, which uses an authenticated GitHub CLI session to access the private repository, verifies the checksum, and atomically installs without sudo. Repository visibility remains private.

## Consequences

- Consumers need `gh` authenticated with repository access.
- Supported release platforms are Linux x86_64 and macOS x86_64.
- Tags must match the Cargo package version. The failed cross-platform `v0.1.0` attempt remains immutable; the corrected first release is `v0.1.1`.
- No `rust-toolchain.toml` is added: hosted stable Rust is selected explicitly in CI, avoiding repository-wide toolchain pin churn.
