//! Small filesystem helpers shared across commands.
//!
//! These are generic, best-effort helpers that are not specific to any one
//! command's domain (detection, init, or a hook), so they live here rather than
//! being tied to a single module.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Atomically open `path` for reading, requiring it to be a regular file.
///
/// Repo-controlled paths (e.g. `pyproject.toml`, `.lgtm/config.json`) may be
/// planted as FIFOs, devices, sockets, or symlinks. A prior "stat the path, then
/// open it" sequence is a TOCTOU hole: a concurrent swap to a FIFO or symlink
/// between the check and the open can hang the reader forever or follow the
/// symlink out of the repo. This helper closes both holes atomically.
///
/// On unix the open uses `O_NOFOLLOW` (a final-component symlink fails the open
/// with `ELOOP` rather than being followed) and `O_NONBLOCK` (opening a FIFO with
/// no writer returns immediately instead of blocking). The type is then verified
/// by `fstat`-ing the *open* descriptor via [`File::metadata`] — the same object
/// that will be read — so no window exists between the type check and the read.
/// A regular file never blocks on a normal `read`, so `O_NONBLOCK` on the open
/// descriptor is harmless once the type is confirmed. A non-regular open target
/// (FIFO, device, socket) is closed and reported as absent (`Ok(None)`).
///
/// On non-unix targets those open flags do not exist, so the symlink rejection is
/// best-effort: a pre-open `symlink_metadata` check rejects a final-component
/// symlink and the post-open [`File::metadata`] check still rejects non-regular
/// targets, but a residual TOCTOU window remains between the pre-open check and
/// the open. This is atomic only on unix; non-unix is not a supported deployment
/// target for hooks in the MVP.
///
/// Returns `Ok(Some(file))` for a regular file, `Ok(None)` when the path is
/// absent or is not a regular file, and `Err` for any other I/O failure (e.g. a
/// permission error) so callers can distinguish "nothing to read" from a real
/// fault.
pub fn open_regular_file(path: &Path) -> io::Result<Option<File>> {
    let open_result = open_no_follow_nonblock(path);
    let file = match open_result {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if is_symlink_open_rejection(&error) => return Ok(None),
        Err(error) => return Err(error),
    };

    match file.metadata() {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(file)),
        Ok(_) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Open `path` without following a final-component symlink and without blocking
/// on a FIFO.
///
/// On unix both properties are enforced atomically by the open itself via
/// `O_NOFOLLOW` and `O_NONBLOCK`.
///
/// On non-unix targets neither flag exists. The symlink defense is best-effort:
/// a pre-open `symlink_metadata` check rejects a final-component symlink (mapped
/// to [`io::ErrorKind::NotFound`] so [`open_regular_file`] treats it as absent),
/// and the post-open [`File::metadata`] check in [`open_regular_file`] still
/// rejects non-regular targets. A residual TOCTOU window remains between the
/// pre-open check and the open, and a FIFO can still block the open. Both are
/// accepted because non-unix is not a supported deployment target for hooks in
/// the MVP; the guarantee is atomic only on unix.
#[cfg(unix)]
fn open_no_follow_nonblock(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow_nonblock(path: &Path) -> io::Result<File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "refusing to open symlink",
        ));
    }
    File::open(path)
}

/// True when an open error is the kernel refusing to follow a final-component
/// symlink under `O_NOFOLLOW`. Linux reports this as `ELOOP` and some BSDs as
/// `EMLINK`; either way the target is a symlink, which callers treat as absent.
#[cfg(unix)]
fn is_symlink_open_rejection(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::EMLINK)
}

#[cfg(not(unix))]
fn is_symlink_open_rejection(_error: &io::Error) -> bool {
    false
}

/// Read a file to a string, bounding the read at `max` bytes and treating any
/// failure (absence, unreadable, or oversized) as empty content.
///
/// Reads at most `max + 1` bytes so an oversized file is detected without
/// pulling its whole contents into memory: when more than `max` bytes are
/// present the file is treated as absent (empty string), so unbounded
/// repo-controlled content cannot force an arbitrarily large allocation. A path
/// that is not a regular file (FIFO, device, socket, or symlink) is treated as
/// empty rather than blocking: the open is atomic and refuses to follow symlinks
/// or hang on FIFOs (see [`open_regular_file`]). Used for best-effort probing of
/// repo metadata where a missing, unreadable, or implausibly large file simply
/// means "no content found".
pub fn read_optional_bounded(path: &Path, max: u64) -> String {
    let Ok(Some(file)) = open_regular_file(path) else {
        return String::new();
    };
    let mut contents = String::new();
    if file.take(max + 1).read_to_string(&mut contents).is_err() {
        return String::new();
    }
    if contents.len() as u64 > max {
        return String::new();
    }
    contents
}
