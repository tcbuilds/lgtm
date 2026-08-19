//! Bounded sibling-file locking for shared evidence ledgers.

use std::path::Path;
use std::time::Instant;

/// An exclusive advisory lock with a bounded acquisition wait.
pub(crate) struct EvidenceLock {
    #[cfg(unix)]
    file: std::fs::File,
}

#[cfg(unix)]
const LOCK_RETRY_ATTEMPTS: u32 = 20;
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

impl EvidenceLock {
    /// Lock the sibling path without allowing a wedged writer to block forever.
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        Self::acquire_until(path, None)
    }

    /// Lock the sibling path, respecting an optional caller deadline.
    #[cfg(unix)]
    pub(crate) fn acquire_until(path: &Path, deadline: Option<Instant>) -> Result<Self, String> {
        use std::os::unix::io::AsRawFd;

        use std::os::unix::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| format!("lock open ({error})"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("lock inspect ({error})"))?;
        if !metadata.is_file() {
            return Err("lock path is not a regular file".to_string());
        }
        for attempt in 0..LOCK_RETRY_ATTEMPTS {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err("lock deadline expired".to_string());
            }
            // SAFETY: the descriptor is open for the duration of this call and
            // LOCK_EX|LOCK_NB only changes the kernel lock state for that file.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            let contended = matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            );
            if !contended {
                return Err(format!("lock acquire ({error})"));
            }
            if attempt + 1 < LOCK_RETRY_ATTEMPTS {
                let sleep = deadline.map_or(LOCK_RETRY_INTERVAL, |deadline| {
                    std::cmp::min(
                        LOCK_RETRY_INTERVAL,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                });
                if sleep.is_zero() {
                    return Err("lock deadline expired".to_string());
                }
                std::thread::sleep(sleep);
            }
        }
        Err(format!(
            "lock contended for {LOCK_RETRY_ATTEMPTS} attempts (~{}ms)",
            LOCK_RETRY_ATTEMPTS as u128 * LOCK_RETRY_INTERVAL.as_millis()
        ))
    }

    #[cfg(not(unix))]
    pub(crate) fn acquire_until(_path: &Path, _deadline: Option<Instant>) -> Result<Self, String> {
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for EvidenceLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: this guard owns a valid descriptor until Drop completes.
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EvidenceLock;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "lgtm-evidence-lock-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn rejects_a_symlinked_lock_before_following_it() {
        let path = temp_path("symlink");
        let target = temp_path("target");
        std::fs::write(&target, b"target").expect("target");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert!(EvidenceLock::acquire(&path).is_err());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(target);
    }

    #[test]
    fn rejects_a_fifo_lock_without_blocking() {
        let path = temp_path("fifo");
        let path_string = path.to_string_lossy().into_owned();
        let path_c = std::ffi::CString::new(path_string).expect("temporary path has no NUL");
        // SAFETY: this creates only the unique test fixture path with a bounded mode.
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(result, 0);
        assert!(EvidenceLock::acquire(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
