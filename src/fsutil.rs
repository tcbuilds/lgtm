//! Small filesystem helpers shared across commands.
//!
//! These are generic, best-effort helpers that are not specific to any one
//! command's domain (detection, init, or a hook), so they live here rather than
//! being tied to a single module.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const MAX_DIRECTORY_COMPONENTS: usize = 128;

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

/// Open a configured repository-relative directory without following any
/// symlink component. The returned descriptor is a directory capability that
/// callers can retain through process creation.
#[cfg(unix)]
pub fn open_directory_capability(
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
) -> io::Result<File> {
    let workspace = safe_relative_components(workspace_root)?;
    let cwd_components = safe_relative_components(cwd)?;
    if !cwd_components.starts_with(&workspace) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cwd is outside the workspace root",
        ));
    }

    let mut directory = open_repository_directory(repository_root)?;
    for component in cwd_components {
        directory = open_directory_component(&directory, &component)?;
    }
    #[cfg(target_os = "linux")]
    prove_directory_search_access(&directory)?;
    Ok(directory)
}

#[cfg(not(unix))]
pub fn open_directory_capability(
    _repository_root: &Path,
    _workspace_root: &Path,
    _cwd: &Path,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory containment is unavailable on this platform",
    ))
}

#[cfg(unix)]
pub fn directory_identity(directory: &File) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata()?;
    Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
pub fn directory_identity(_directory: &File) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory identity is unavailable on this platform",
    ))
}

/// Resolve an opened directory capability through its stable descriptor path.
/// Linux's proc descriptor link identifies the directory that was opened,
/// rather than re-resolving a mutable pathname. Other targets fail closed so
/// callers retain obligations when this snapshot cannot be proven.
#[cfg(target_os = "linux")]
pub fn opened_directory_path(directory: &File) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn opened_directory_path(_directory: &File) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "opened directory paths are unavailable on this platform",
    ))
}

#[cfg(not(unix))]
pub fn opened_directory_path(_directory: &File) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "opened directory paths are unavailable on this platform",
    ))
}

#[cfg(unix)]
pub fn directory_contains_executable(directory: &File, path: &Path) -> io::Result<bool> {
    if path.is_absolute() {
        return Ok(false);
    }
    metadata_and_execute_access(directory.as_raw_fd(), path)
}

#[cfg(not(unix))]
pub fn directory_contains_executable(_directory: &File, _path: &Path) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative file lookup is unavailable on this platform",
    ))
}

#[cfg(unix)]
pub fn absolute_file_is_executable(path: &Path) -> io::Result<bool> {
    metadata_and_execute_access(libc::AT_FDCWD, path)
}

#[cfg(not(unix))]
pub fn absolute_file_is_executable(path: &Path) -> io::Result<bool> {
    Ok(path.is_file())
}

#[cfg(unix)]
fn metadata_and_execute_access(directory_fd: libc::c_int, path: &Path) -> io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is live and path is NUL-free. fstatat follows
    // executable-path symlinks like runtime exec while inspecting metadata;
    // it never opens the final target, so devices and FIFOs are not opened.
    let result = unsafe { libc::fstatat(directory_fd, path.as_ptr(), metadata.as_mut_ptr(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized metadata when it returned success.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(false);
    }
    // SAFETY: path is NUL-free and the descriptor/path pair is the same one
    // used for the metadata probe. AT_EACCESS checks effective credentials.
    let accessible =
        unsafe { libc::faccessat(directory_fd, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) };
    if accessible == 0 {
        Ok(true)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn safe_relative_components(path: &Path) -> io::Result<Vec<CString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => {
                components.push(CString::new(value.as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte")
                })?)
            }
            std::path::Component::RootDir
            | std::path::Component::Prefix(_)
            | std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path must be repository-relative without parent components",
                ));
            }
        }
    }
    if components.len() > MAX_DIRECTORY_COMPONENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path has too many directory components",
        ));
    }
    Ok(components)
}

#[cfg(target_os = "linux")]
fn directory_open_flags() -> libc::c_int {
    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
}

#[cfg(all(unix, not(target_os = "linux")))]
fn directory_open_flags() -> libc::c_int {
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
}

#[cfg(target_os = "linux")]
fn prove_directory_search_access(directory: &File) -> io::Result<()> {
    let current_directory = b".\0";
    // SAFETY: the descriptor is borrowed for this call and the path is a
    // static NUL-terminated string. AT_EACCESS checks effective credentials.
    let result = unsafe {
        libc::faccessat(
            directory.as_raw_fd(),
            current_directory.as_ptr().cast(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    (result == 0)
        .then_some(())
        .ok_or_else(io::Error::last_os_error)
}

#[cfg(unix)]
fn open_repository_directory(path: &Path) -> io::Result<File> {
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(directory_open_flags())
        .open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
    for component in path.components() {
        match component {
            std::path::Component::CurDir | std::path::Component::RootDir => {}
            std::path::Component::Normal(value) => {
                let component = CString::new(value.as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte")
                })?;
                directory = open_directory_component(&directory, &component)?;
            }
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository root must not contain parent or prefix components",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_component(parent: &File, component: &CStr) -> io::Result<File> {
    // SAFETY: the component is NUL-free and the descriptor is borrowed only
    // for this call. O_NOFOLLOW rejects symlink components atomically, while
    // O_CLOEXEC keeps the capability out of children.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            directory_open_flags(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly opened descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
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

/// Ensure one repository-controlled directory exists without following a symlink.
///
/// Callers create each required directory from the trusted root downward so a
/// symlinked `.lgtm` or `evidence` component cannot redirect writes elsewhere.
pub fn ensure_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => std::fs::create_dir(path),
        Err(error) => Err(error),
    }
}

/// Return whether any bounded filesystem component is a symlink or cannot be
/// inspected. The check walks each prefix with `symlink_metadata`, so it does
/// not follow the component it is checking. An unavailable prefix is treated
/// as uncertain so callers fail closed rather than canonicalizing an unchecked
/// path.
pub(crate) fn path_contains_symlink(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        if index >= MAX_DIRECTORY_COMPONENTS {
            return true;
        }
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return true,
        }
    }
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Descriptor-relative containment is the Linux production path; non-Linux
    // command execution deliberately reports containment unavailable.
    #[cfg(target_os = "linux")]
    #[test]
    fn directory_capability_rejects_escape_and_symlink_components() {
        let root = std::env::temp_dir().join(format!("lgtm-fsutil-{}", std::process::id()));
        let outside = root.join("outside");
        std::fs::create_dir_all(root.join("workspace/src")).expect("workspace fixture");
        std::fs::create_dir(&outside).expect("outside fixture");
        std::os::unix::fs::symlink(&outside, root.join("workspace/link")).expect("symlink fixture");

        assert!(
            open_directory_capability(&root, Path::new("workspace"), Path::new("workspace/src"))
                .is_ok()
        );
        assert!(
            open_directory_capability(&root, Path::new("workspace"), Path::new("workspace/link"))
                .is_err()
        );
        assert!(
            open_directory_capability(
                &root,
                Path::new("workspace"),
                Path::new("workspace/../outside")
            )
            .is_err()
        );
        assert!(
            open_directory_capability(&root, Path::new("workspace"), Path::new("workspace2"))
                .is_err()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_bounded_reader_accepts_exact_limit_and_rejects_one_byte_over() {
        const MAX: u64 = 256 * 1024;
        let root = std::env::temp_dir().join(format!(
            "lgtm-fsutil-required-boundary-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("boundary fixture");
        let root = std::fs::canonicalize(root).expect("canonical boundary fixture");
        let path = root.join("source.rs");
        let exact = "x".repeat(MAX as usize);
        std::fs::write(&path, exact.as_bytes()).expect("exact-size source");
        assert_eq!(
            read_required_bounded(&path, MAX).as_deref(),
            Some(exact.as_str()),
            "an exact-size valid UTF-8 file is accepted"
        );

        let mut oversized = exact.into_bytes();
        oversized.push(b'x');
        std::fs::write(&path, oversized).expect("oversized source");
        assert!(
            read_required_bounded(&path, MAX).is_none(),
            "one byte over the limit is uncertain"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_component_limit_accepts_exact_depth_and_rejects_one_over() {
        let root = std::env::temp_dir().join(format!(
            "lgtm-fsutil-component-boundary-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("component-boundary fixture");
        let root = std::fs::canonicalize(root).expect("canonical component-boundary fixture");
        let root_components = root.components().count();
        let exact_directory_count = MAX_DIRECTORY_COMPONENTS
            .checked_sub(root_components + 1)
            .expect("temporary root leaves room for an exact-depth file");
        let mut exact_directory = root.clone();
        for index in 0..exact_directory_count {
            exact_directory.push(format!("d{index}"));
        }
        std::fs::create_dir_all(&exact_directory).expect("exact-depth directories");
        let exact_file = exact_directory.join("source.rs");
        std::fs::write(&exact_file, "fn exact() {}\n").expect("exact-depth source");
        assert!(
            !path_contains_symlink(&exact_file),
            "a regular path at the component limit is inspected successfully"
        );

        let over_directory = exact_directory.join("over");
        std::fs::create_dir(&over_directory).expect("one-over directory");
        let over_file = over_directory.join("source.rs");
        std::fs::write(&over_file, "fn over() {}\n").expect("one-over source");
        assert!(
            path_contains_symlink(&over_file),
            "a path one component over the limit is uncertain"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_bounded_reader_rejects_final_component_symlink() {
        let root = std::env::temp_dir().join(format!(
            "lgtm-fsutil-required-symlink-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("symlink fixture");
        let root = std::fs::canonicalize(root).expect("canonical symlink fixture");
        let target = root.join("target.rs");
        let link = root.join("source.rs");
        std::fs::write(&target, "fn target() {}\n").expect("symlink target source");
        std::os::unix::fs::symlink(&target, &link).expect("final-component symlink fixture");
        assert!(
            read_required_bounded(&link, 256 * 1024).is_none(),
            "a final-component symlink is uncertain"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_bounded_reader_rejects_symlinked_ancestor() {
        let root = std::env::temp_dir().join(format!(
            "lgtm-fsutil-required-ancestor-symlink-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("real")).expect("ancestor fixture");
        let root = std::fs::canonicalize(root).expect("canonical ancestor fixture");
        let target = root.join("real/source.rs");
        let link = root.join("alias");
        let descendant = link.join("source.rs");
        std::fs::write(&target, "fn target() {}\n").expect("regular supported descendant");
        std::os::unix::fs::symlink("real", &link).expect("symlinked ancestor directory");
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("descendant metadata")
                .is_file(),
            "the descendant target is a regular file"
        );
        assert!(
            read_required_bounded(&descendant, 256 * 1024).is_none(),
            "a symlinked ancestor is uncertain"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn required_bounded_reader_rejects_read_error_from_regular_proc_path() {
        let path = Path::new("/proc/self/mem");
        let metadata = std::fs::symlink_metadata(path).expect("proc memory metadata");
        assert!(
            metadata.file_type().is_file(),
            "/proc/self/mem must remain a regular proc path for this fixture"
        );
        let file = open_regular_file(path)
            .expect("opening proc memory should report the descriptor")
            .expect("proc memory should open as a regular file");
        let opened_metadata = file.metadata().expect("opened proc memory metadata");
        assert!(
            opened_metadata.file_type().is_file(),
            "open_regular_file must verify the opened descriptor is regular"
        );
        let mut contents = Vec::new();
        assert!(
            file.take(256 * 1024 + 1)
                .read_to_end(&mut contents)
                .is_err(),
            "a bounded read on the opened proc descriptor must fail"
        );
        assert!(
            read_required_bounded(path, 256 * 1024).is_none(),
            "a read error from a regular proc path is uncertain"
        );
    }
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

/// Read a regular UTF-8 file completely when it fits within `max` bytes.
///
/// Unlike [`read_optional_bounded`], this helper preserves the distinction
/// between a successfully read file and an unavailable or incomplete one.
/// Callers that use the bytes as authorization material can therefore reject
/// absence, non-regular paths, invalid UTF-8, read failures, and oversized
/// files instead of treating them as an empty file. A bounded component walk
/// rejects a path containing a symlink before opening it; the final open still
/// enforces no-follow and regular-file checks. The `max + 1` read window keeps
/// both the read and its allocation bounded while detecting an exact one-byte
/// overflow.
pub(crate) fn read_required_bounded(path: &Path, max: u64) -> Option<String> {
    if path_contains_symlink(path) {
        return None;
    }
    let file = match open_regular_file(path) {
        Ok(Some(file)) => file,
        Ok(None) | Err(_) => return None,
    };
    let limit = max.checked_add(1)?;
    let mut contents = String::new();
    file.take(limit).read_to_string(&mut contents).ok()?;
    (contents.len() as u64 <= max).then_some(contents)
}
