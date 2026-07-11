//! lgtm library surface: the agent-neutral policy model and compiler.
//!
//! The binary (`src/main.rs`) is a thin CLI over this crate. Exposing the
//! policy registry and compiler here lets integration tests exercise the same
//! code paths the binary runs.

pub mod compile;
pub mod policy;
