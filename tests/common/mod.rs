//! Shared test-support fixtures for the integration test binaries.
//!
//! [`TempRepo`] is a process- and counter-unique temporary directory removed on
//! drop, used by the `init` and `session-start` integration tests as a throwaway
//! repo root so filesystem effects and config presence are exercised end to end
//! without touching the real repo. Centralizing it here keeps the two test
//! binaries from carrying divergent copies of the same fixture.
//!
//! Each integration test binary compiles this module independently and uses a
//! subset of its methods, so unused-method warnings here are expected and
//! silenced: a helper unused by one binary is still used by another.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

/// Monotonic counter making concurrent temp directory names unique.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A uniquely named temporary directory that is removed when dropped.
pub struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    /// Create an empty temporary directory unique to this process and call.
    pub fn new() -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("lgtm-it-{}-{unique}", std::process::id());
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).expect("temp dir should be creatable");
        Self { path }
    }

    /// The root path a command runs against.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a file relative to the temp root, creating parent directories.
    pub fn write(&self, relative: &str, contents: &str) {
        let target = self.path.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("parent dir should be creatable");
        }
        std::fs::write(target, contents).expect("fixture file should be writable");
    }

    /// Read a file relative to the temp root as a string.
    pub fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.path.join(relative)).expect("file should be readable")
    }

    /// Read and parse a JSON file relative to the temp root.
    pub fn read_json(&self, relative: &str) -> Value {
        serde_json::from_str(&self.read(relative)).expect("file should be valid JSON")
    }

    /// True when a path relative to the temp root exists.
    pub fn exists(&self, relative: &str) -> bool {
        self.path.join(relative).exists()
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
