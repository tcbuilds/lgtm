use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::path_injection::{MAX_SESSION_ID_BYTES, MAX_SOURCE_DOCUMENTS, MAX_SOURCE_PATH_BYTES};

/// The stable repository-relative location used by future adapters for shared
/// path-injection session state.
pub const SESSION_DEDUP_STATE_RELATIVE_PATH: &str = ".lgtm/evidence/path-injection-sessions.json";
pub const MAX_SESSION_DEDUP_STATE_BYTES: usize = 256 * 1_024;
pub const MAX_SESSION_DEDUP_SESSIONS: usize = 64;

#[cfg(unix)]
const MAX_LOCK_ATTEMPTS: u32 = 100;
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Opaque failure returned by a deduplication store. Callers must fail open
/// without exposing filesystem or state contents to a hook consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDedupStoreError;

/// Failure beginning a persistent selection transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDedupBeginError {
    Contended,
    Unavailable,
}

/// A held session transaction used to make the preliminary snapshot and
/// atomic record operation cover one selection call.
pub trait SessionDedupTransaction {
    fn seen(&self) -> Result<BTreeSet<String>, SessionDedupStoreError>;

    fn filter_and_record(
        &mut self,
        source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError>;
}

/// Persistent store seam for session-scoped source identities.
pub trait SessionDedupStore {
    /// Begin a transaction that remains held through one selection call.
    fn begin(
        &self,
        session_id: &str,
    ) -> Result<Box<dyn SessionDedupTransaction + '_>, SessionDedupBeginError> {
        let previously_seen = self
            .seen(session_id)
            .map_err(|_| SessionDedupBeginError::Unavailable)?;
        Ok(Box::new(CompatibilitySessionDedupTransaction {
            store: self,
            session_id: session_id.to_string(),
            previously_seen,
        }))
    }

    /// Return identities already recorded for `session_id`.
    fn seen(&self, session_id: &str) -> Result<BTreeSet<String>, SessionDedupStoreError>;

    /// Atomically return identities already recorded and record the selected
    /// identities. A failure leaves the caller free to emit all selected bodies.
    fn filter_and_record(
        &self,
        session_id: &str,
        source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError>;
}

struct CompatibilitySessionDedupTransaction<'a, S: SessionDedupStore + ?Sized> {
    store: &'a S,
    session_id: String,
    previously_seen: BTreeSet<String>,
}

impl<S: SessionDedupStore + ?Sized> SessionDedupTransaction
    for CompatibilitySessionDedupTransaction<'_, S>
{
    fn seen(&self) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        Ok(self.previously_seen.clone())
    }

    fn filter_and_record(
        &mut self,
        source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        self.store.filter_and_record(&self.session_id, source_paths)
    }
}

/// Compatibility store used by the original service APIs. Without an explicit
/// persistent store, requests retain their prior non-deduplicated behavior.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSessionDedupStore;

impl SessionDedupStore for NoopSessionDedupStore {
    fn seen(&self, _session_id: &str) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        Ok(BTreeSet::new())
    }

    fn filter_and_record(
        &self,
        _session_id: &str,
        _source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        Ok(BTreeSet::new())
    }
}

/// File-backed session store. Use [`Self::for_root`] so all adapters share the
/// same repository-relative state file rather than maintaining adapter-local
/// deduplication. On non-Unix targets, persistent deduplication is intentionally
/// unavailable and operations fail open without filesystem access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSessionDedupStore {
    path: PathBuf,
}

impl FileSessionDedupStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn for_root(root: impl AsRef<Path>) -> Self {
        Self::new(root.as_ref().join(SESSION_DEDUP_STATE_RELATIVE_PATH))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SessionDedupStore for FileSessionDedupStore {
    fn begin(
        &self,
        session_id: &str,
    ) -> Result<Box<dyn SessionDedupTransaction + '_>, SessionDedupBeginError> {
        if !valid_session_id(session_id) {
            return Err(SessionDedupBeginError::Unavailable);
        }
        let location =
            prepare_parent(&self.path).map_err(|_| SessionDedupBeginError::Unavailable)?;
        let lock = StateLock::acquire(&location).map_err(|error| match error {
            StateLockError::Contended => SessionDedupBeginError::Contended,
            StateLockError::Unavailable => SessionDedupBeginError::Unavailable,
        })?;
        let state = load_state(&location).map_err(|_| SessionDedupBeginError::Unavailable)?;
        Ok(Box::new(FileSessionDedupTransaction {
            location,
            _lock: lock,
            session_id: session_id.to_string(),
            state,
        }))
    }

    fn seen(&self, session_id: &str) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        let transaction = self.begin(session_id).map_err(|_| SessionDedupStoreError)?;
        transaction.seen()
    }

    fn filter_and_record(
        &self,
        session_id: &str,
        source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        if source_paths.len() > MAX_SOURCE_DOCUMENTS
            || source_paths.iter().any(|path| !valid_source_path(path))
        {
            return Err(SessionDedupStoreError);
        }
        let mut transaction = self.begin(session_id).map_err(|_| SessionDedupStoreError)?;
        transaction.filter_and_record(source_paths)
    }
}

struct FileSessionDedupTransaction {
    location: StateLocation,
    _lock: StateLock,
    session_id: String,
    state: SessionDedupState,
}

impl SessionDedupTransaction for FileSessionDedupTransaction {
    fn seen(&self) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        Ok(self
            .state
            .sessions
            .get(&self.session_id)
            .cloned()
            .unwrap_or_default())
    }

    fn filter_and_record(
        &mut self,
        source_paths: &[String],
    ) -> Result<BTreeSet<String>, SessionDedupStoreError> {
        if source_paths.len() > MAX_SOURCE_DOCUMENTS
            || source_paths.iter().any(|path| !valid_source_path(path))
        {
            return Err(SessionDedupStoreError);
        }
        if !self.state.sessions.contains_key(&self.session_id)
            && self.state.sessions.len() >= MAX_SESSION_DEDUP_SESSIONS
            && let Some(oldest) = self.state.sessions.keys().next().cloned()
        {
            self.state.sessions.remove(&oldest);
        }
        let session = self
            .state
            .sessions
            .entry(self.session_id.clone())
            .or_default();
        let previously_seen = session.clone();
        let incoming = source_paths.iter().cloned().collect::<BTreeSet<_>>();
        let already_seen = incoming
            .intersection(&previously_seen)
            .cloned()
            .collect::<BTreeSet<_>>();
        let new_paths = incoming
            .difference(&previously_seen)
            .cloned()
            .collect::<Vec<_>>();
        let evictions = session
            .len()
            .saturating_add(new_paths.len())
            .saturating_sub(MAX_SOURCE_DOCUMENTS);
        for _ in 0..evictions {
            if let Some(oldest) = session.iter().next().cloned() {
                session.remove(&oldest);
            }
        }
        session.extend(new_paths);
        validate_state(&self.state)?;
        persist_state(&self.location, &self.state)?;
        Ok(already_seen)
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionDedupState {
    sessions: BTreeMap<String, BTreeSet<String>>,
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SESSION_ID_BYTES && !value.chars().any(char::is_control)
}

fn valid_source_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_PATH_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(unix)]
struct StateLocation {
    directory: std::fs::File,
    state_name: CString,
    lock_name: CString,
}

#[cfg(not(unix))]
struct StateLocation;

#[cfg(unix)]
fn prepare_parent(path: &Path) -> Result<StateLocation, SessionDedupStoreError> {
    let parent = path.parent().ok_or(SessionDedupStoreError)?;
    let directory = open_directory_path(parent)?;
    validate_directory(&directory)?;
    let state_name = file_name(path)?;
    let lock_name = file_name(&path.with_extension("lock"))?;
    Ok(StateLocation {
        directory,
        state_name,
        lock_name,
    })
}

#[cfg(not(unix))]
fn prepare_parent(_path: &Path) -> Result<StateLocation, SessionDedupStoreError> {
    // Persistent deduplication is intentionally unavailable where the Unix
    // descriptor-relative implementation is not available.
    Err(SessionDedupStoreError)
}

#[cfg(unix)]
fn file_name(path: &Path) -> Result<CString, SessionDedupStoreError> {
    let name = path.file_name().ok_or(SessionDedupStoreError)?;
    CString::new(name.as_bytes()).map_err(|_| SessionDedupStoreError)
}

#[cfg(unix)]
fn open_directory_path(path: &Path) -> Result<std::fs::File, SessionDedupStoreError> {
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = open_directory_pathname(start)?;
    validate_traversal_directory(&directory)?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            if matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            ) {
                return Err(SessionDedupStoreError);
            }
            continue;
        };
        let name = CString::new(name.as_bytes()).map_err(|_| SessionDedupStoreError)?;
        directory = open_or_create_directory(&directory, &name)?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_pathname(path: &Path) -> Result<std::fs::File, SessionDedupStoreError> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| SessionDedupStoreError)?;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is owned by
    // the File created below. The flags open only a directory without following
    // its final symlink.
    let descriptor = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(SessionDedupStoreError);
    }
    // SAFETY: `descriptor` is a newly-owned valid descriptor from `open`.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_or_create_directory(
    parent: &std::fs::File,
    name: &CString,
) -> Result<std::fs::File, SessionDedupStoreError> {
    match open_directory_at(parent, name) {
        Ok(directory) => {
            sync_directory(parent)?;
            validate_traversal_directory(&directory)?;
            Ok(directory)
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            // SAFETY: `parent` is a live directory descriptor and `name` is a
            // validated NUL-terminated single path component.
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(SessionDedupStoreError);
            }
            sync_directory(parent)?;
            let directory = open_directory_at(parent, name).map_err(|_| SessionDedupStoreError)?;
            sync_directory(parent)?;
            validate_traversal_directory(&directory)?;
            Ok(directory)
        }
        Err(_) => Err(SessionDedupStoreError),
    }
}

#[cfg(unix)]
fn open_directory_at(parent: &std::fs::File, name: &CString) -> std::io::Result<std::fs::File> {
    // SAFETY: `parent` remains alive for the call and `name` is NUL-terminated.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `descriptor` is a newly-owned valid descriptor from `openat`.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn validate_traversal_directory(directory: &std::fs::File) -> Result<(), SessionDedupStoreError> {
    let metadata = directory.metadata().map_err(|_| SessionDedupStoreError)?;
    let effective_uid = unsafe { libc::geteuid() };
    let root_owned_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let untrusted_write = metadata.mode() & 0o022 != 0 && !root_owned_sticky;
    if !metadata.is_dir() || !trusted_owner || untrusted_write {
        return Err(SessionDedupStoreError);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_directory(directory: &std::fs::File) -> Result<(), SessionDedupStoreError> {
    validate_traversal_directory(directory)?;
    let metadata = directory.metadata().map_err(|_| SessionDedupStoreError)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(SessionDedupStoreError);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn sync_directory(_directory: &std::fs::File) -> Result<(), SessionDedupStoreError> {
    // macOS does not expose a reliable directory-fsync result through
    // `File::sync_all`; file contents are synced before the atomic rename.
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn sync_directory(directory: &std::fs::File) -> Result<(), SessionDedupStoreError> {
    directory.sync_all().map_err(|_| SessionDedupStoreError)
}

#[cfg(unix)]
fn load_state(location: &StateLocation) -> Result<SessionDedupState, SessionDedupStoreError> {
    match regular_entry_status(location.directory.as_raw_fd(), &location.state_name) {
        Ok(false) => return Ok(SessionDedupState::default()),
        Ok(true) => {}
        Err(_) => return Err(SessionDedupStoreError),
    }
    let file = match openat_file(
        location.directory.as_raw_fd(),
        &location.state_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(_) => return Err(SessionDedupStoreError),
    };
    if !secure_file_metadata(&file).map_err(|_| SessionDedupStoreError)? {
        return Err(SessionDedupStoreError);
    }
    parse_state(file)
}

#[cfg(not(unix))]
fn load_state(_location: &StateLocation) -> Result<SessionDedupState, SessionDedupStoreError> {
    Err(SessionDedupStoreError)
}

fn parse_state(mut file: std::fs::File) -> Result<SessionDedupState, SessionDedupStoreError> {
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_SESSION_DEDUP_STATE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SessionDedupStoreError)?;
    if bytes.len() > MAX_SESSION_DEDUP_STATE_BYTES {
        return Err(SessionDedupStoreError);
    }
    let state = serde_json::from_slice(&bytes).map_err(|_| SessionDedupStoreError)?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &SessionDedupState) -> Result<(), SessionDedupStoreError> {
    if state.sessions.len() > MAX_SESSION_DEDUP_SESSIONS {
        return Err(SessionDedupStoreError);
    }
    for (session_id, source_paths) in &state.sessions {
        if !valid_session_id(session_id) || source_paths.len() > MAX_SOURCE_DOCUMENTS {
            return Err(SessionDedupStoreError);
        }
        if source_paths.iter().any(|path| !valid_source_path(path)) {
            return Err(SessionDedupStoreError);
        }
    }
    let bytes = serde_json::to_vec(state).map_err(|_| SessionDedupStoreError)?;
    if bytes.len() > MAX_SESSION_DEDUP_STATE_BYTES {
        return Err(SessionDedupStoreError);
    }
    Ok(())
}

#[cfg(unix)]
fn persist_state(
    location: &StateLocation,
    state: &SessionDedupState,
) -> Result<(), SessionDedupStoreError> {
    let bytes = serde_json::to_vec(state).map_err(|_| SessionDedupStoreError)?;
    if bytes.len() > MAX_SESSION_DEDUP_STATE_BYTES {
        return Err(SessionDedupStoreError);
    }
    let temp_name = temp_name()?;
    let mut file = openat_file(
        location.directory.as_raw_fd(),
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .map_err(|_| SessionDedupStoreError)?;
    let result = file.write_all(&bytes).and_then(|_| file.sync_all());
    if result.is_ok() {
        drop(file);
        // SAFETY: both descriptors are the verified evidence directory handle;
        // names are bounded NUL-terminated single components.
        let result = unsafe {
            libc::renameat(
                location.directory.as_raw_fd(),
                temp_name.as_ptr(),
                location.directory.as_raw_fd(),
                location.state_name.as_ptr(),
            )
        };
        if result < 0 {
            let _ = unlinkat(location, &temp_name);
            return Err(SessionDedupStoreError);
        }
        sync_directory(&location.directory)?;
        return Ok(());
    }
    let _ = unlinkat(location, &temp_name);
    Err(SessionDedupStoreError)
}

#[cfg(not(unix))]
fn persist_state(
    _location: &StateLocation,
    _state: &SessionDedupState,
) -> Result<(), SessionDedupStoreError> {
    Err(SessionDedupStoreError)
}

#[cfg(unix)]
fn regular_entry_status(directory: i32, name: &CString) -> std::io::Result<bool> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` is a live directory descriptor, `name` is one
    // NUL-terminated component, and `metadata` points to writable storage.
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(error);
    }
    // SAFETY: `fstatat` initialized `metadata` on success.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_mode & 0o022 != 0
        || metadata.st_nlink != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "state entry is not a private regular file",
        ));
    }
    Ok(true)
}

#[cfg(unix)]
fn same_regular_entry(location: &StateLocation, file: &std::fs::File) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Ok(false);
    }
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the directory descriptor and name are valid and `entry` is writable.
    let result = unsafe {
        libc::fstatat(
            location.directory.as_raw_fd(),
            location.lock_name.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return Ok(false);
    }
    let entry = unsafe { entry.assume_init() };
    #[cfg(target_os = "macos")]
    let same_device = u64::try_from(entry.st_dev).ok() == Some(metadata.dev());
    #[cfg(not(target_os = "macos"))]
    let same_device = entry.st_dev == metadata.dev();
    let same_inode = entry.st_ino == metadata.ino();
    Ok(same_device && same_inode)
}

#[cfg(unix)]
fn secure_file_metadata(file: &std::fs::File) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Ok(false);
    }
    if metadata.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

#[cfg(unix)]
fn openat_file(
    directory: i32,
    name: &CString,
    flags: i32,
    mode: u32,
) -> std::io::Result<std::fs::File> {
    // SAFETY: `directory` is a live directory descriptor and `name` is
    // NUL-terminated. The caller owns the returned descriptor on success.
    let descriptor = unsafe { libc::openat(directory, name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `descriptor` is a newly-owned valid descriptor from `openat`.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn temp_name() -> Result<CString, SessionDedupStoreError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionDedupStoreError)?
        .as_nanos();
    CString::new(format!(
        ".path-injection-sessions.tmp-{}-{nanos}-{counter}",
        std::process::id()
    ))
    .map_err(|_| SessionDedupStoreError)
}

#[derive(Debug)]
enum StateLockError {
    Contended,
    Unavailable,
}

struct StateLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl StateLock {
    #[cfg(unix)]
    fn acquire(location: &StateLocation) -> Result<Self, StateLockError> {
        Self::acquire_with_hook(location, || {})
    }

    #[cfg(unix)]
    fn acquire_with_hook<F>(
        location: &StateLocation,
        mut on_contention: F,
    ) -> Result<Self, StateLockError>
    where
        F: FnMut(),
    {
        regular_entry_status(location.directory.as_raw_fd(), &location.lock_name)
            .map_err(|_| StateLockError::Unavailable)?;
        let file = openat_file(
            location.directory.as_raw_fd(),
            &location.lock_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|_| StateLockError::Unavailable)?;
        if !same_regular_entry(location, &file).map_err(|_| StateLockError::Unavailable)?
            || !secure_file_metadata(&file).map_err(|_| StateLockError::Unavailable)?
        {
            return Err(StateLockError::Unavailable);
        }
        for attempt in 0..MAX_LOCK_ATTEMPTS {
            // SAFETY: the descriptor is owned by `file` and remains valid for
            // the duration of this call. All failure paths are handled below.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                if !same_regular_entry(location, &file).map_err(|_| StateLockError::Unavailable)? {
                    return Err(StateLockError::Unavailable);
                }
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            let contended = matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            );
            if !contended {
                return Err(StateLockError::Unavailable);
            }
            on_contention();
            if attempt + 1 < MAX_LOCK_ATTEMPTS {
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
        }
        Err(StateLockError::Contended)
    }

    #[cfg(not(unix))]
    fn acquire(_location: &StateLocation) -> Result<Self, StateLockError> {
        Err(StateLockError::Unavailable)
    }
}

#[cfg(unix)]
fn unlinkat(location: &StateLocation, name: &CString) -> std::io::Result<()> {
    // SAFETY: `location.directory` is a live directory descriptor and `name`
    // is a NUL-terminated single component.
    let result = unsafe { libc::unlinkat(location.directory.as_raw_fd(), name.as_ptr(), 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until this guard is dropped.
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;

    struct RemoveDirectory(std::path::PathBuf);

    impl Drop for RemoveDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lock_retry_observes_contention_before_release() {
        let root = std::env::temp_dir().join(format!(
            "lgtm-path-injection-lock-retry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("lock retry directory");
        let _cleanup = RemoveDirectory(root.clone());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private lock retry directory");
        let path = root.join("sessions.json");
        let first_location = prepare_parent(&path).expect("first location");
        let held = StateLock::acquire(&first_location).expect("held lock");
        let second_location = prepare_parent(&path).expect("second location");
        let (contended_sender, contended_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (result_sender, result_receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let acquired = StateLock::acquire_with_hook(&second_location, || {
                contended_sender
                    .send(())
                    .expect("contention receiver remains active");
                release_receiver
                    .recv()
                    .expect("release acknowledgment remains active");
            })
            .is_ok();
            result_sender
                .send(acquired)
                .expect("result receiver remains active");
        });

        contended_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("lock retry must observe contention");
        drop(held);
        release_sender
            .send(())
            .expect("release acknowledgment receiver remains active");
        assert!(
            result_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("lock retry must finish after release")
        );
        assert!(handle.join().is_ok());
    }
}
