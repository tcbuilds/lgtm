# ADR-0006: Public GitHub Release Distribution

## Status

Accepted

## Date

2026-07-11

## Context

`lgtm` needs reproducible single-binary installation without requiring a Rust toolchain on every consumer machine. Public release assets should install without a GitHub account or authentication.

## Decision

Publish tag-triggered GitHub Releases for `v*` tags. Each release contains tested x86_64 Linux and Intel macOS tarballs plus SHA-256 files. The workflow uses hosted stable Rust and immutable commits from official GitHub actions only. Release write permission exists only on the release job.

Install through `scripts/install.sh`, which downloads public release assets with `curl`, verifies the checksum, and atomically installs without sudo.

## Consequences

- Consumers need `curl` and either `sha256sum` or `shasum`.
- Supported release platforms are Linux x86_64 and macOS x86_64.
- Tags must match the Cargo package version. Failed cross-platform attempts remain immutable; the corrected first release is the first tag whose full release workflow passes.
- No `rust-toolchain.toml` is added: hosted stable Rust is selected explicitly in CI, avoiding repository-wide toolchain pin churn.
