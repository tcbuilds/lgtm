---
paths:
  - "**/*.rs"
---

# Rust

- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` must pass.
- Forbid `unsafe` unless approved by architecture review and documented with invariants.
- Avoid `unwrap()` and `expect()` in production paths. Use `?`, typed errors, or explicit handling.
- Use `thiserror` for libraries and domain errors; use `anyhow` at binary boundaries when appropriate.
- Prefer owned domain types at boundaries and borrowed values inside hot paths.
- Use `tracing` with structured fields.
- Use `tokio::time::timeout` around external async work.
- Keep `async` tasks cancellable and joinable.
- Use newtypes for IDs, units, and validated strings.
- Use property tests or fuzzing for parsers and codecs.
