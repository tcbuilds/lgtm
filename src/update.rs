//! Safe self-update from checksum-protected public GitHub release assets.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const RELEASES: &str = "https://github.com/tcbuilds/lgtm/releases";
const MAX_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(120);

pub fn run(check: bool, requested: Option<&str>) -> Result<String, String> {
    let target = platform_target()?;
    let pinned = requested.is_some();
    let version = match requested {
        Some(version) => validate_version(version)?.to_string(),
        None => latest_version()?,
    };
    let current = env!("CARGO_PKG_VERSION");
    let ordering = parse_version(&version)?.cmp(&parse_version(&format!("v{current}"))?);
    if check {
        return Ok(match ordering {
            std::cmp::Ordering::Greater => format!("update available: {current} -> {version}"),
            std::cmp::Ordering::Equal => format!("lgtm {current} is current"),
            std::cmp::Ordering::Less => {
                format!("lgtm {current} is newer than available {version}")
            }
        });
    }
    if ordering == std::cmp::Ordering::Equal {
        return Ok(format!("lgtm {current} is already current"));
    }
    if !pinned && ordering == std::cmp::Ordering::Less {
        return Ok(format!("lgtm {current} is newer than available {version}"));
    }

    let executable =
        std::env::current_exe().map_err(|error| format!("resolve current executable ({error})"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?;
    let temporary = TemporaryDirectory::create()?;
    let archive_name = format!("lgtm-{version}-{target}.tar.gz");
    let archive = temporary.path.join(&archive_name);
    let checksum = temporary.path.join(format!("{archive_name}.sha256"));
    let asset_base = format!("{RELEASES}/download/{version}");
    download(&format!("{asset_base}/{archive_name}"), &archive)?;
    download(&format!("{asset_base}/{archive_name}.sha256"), &checksum)?;
    verify_checksum(&archive, &checksum)?;
    extract(&archive, &temporary.path)?;
    let binary = temporary.path.join("lgtm");
    require_regular_file(&binary, MAX_DOWNLOAD_BYTES)?;
    install(&binary, &executable, parent)?;
    Ok(format!(
        "updated lgtm {current} -> {} at {}",
        version.trim_start_matches('v'),
        executable.display()
    ))
}

fn platform_target() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        (os, arch) => Err(format!("unsupported platform: {os}/{arch}")),
    }
}

fn validate_version(version: &str) -> Result<&str, String> {
    parse_version(version).map(|_| version)
}

fn parse_version(version: &str) -> Result<(u64, u64, u64), String> {
    let valid = version.strip_prefix('v').is_some_and(|rest| {
        let components: Vec<_> = rest.split('.').collect();
        components.len() == 3
            && components
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    });
    if valid {
        let mut parts = version[1..].split('.').map(|part| {
            part.parse::<u64>()
                .map_err(|_| "version component is too large".to_string())
        });
        let major = parts.next().expect("validated major")?;
        let minor = parts.next().expect("validated minor")?;
        let patch = parts.next().expect("validated patch")?;
        Ok((major, minor, patch))
    } else {
        Err("version must look like v1.2.3".to_string())
    }
}

fn latest_version() -> Result<String, String> {
    let output = run_bounded(
        Command::new("curl")
            .args(["-fsSL", "-o", "/dev/null", "-w", "%{url_effective}"])
            .arg(format!("{RELEASES}/latest")),
        NETWORK_TIMEOUT,
    )?;
    if output.status != Some(0) {
        return Err("resolve latest release with curl".to_string());
    }
    let url = String::from_utf8(output.stdout)
        .map_err(|_| "latest release URL was not UTF-8".to_string())?;
    let version = url
        .trim()
        .rsplit('/')
        .next()
        .ok_or_else(|| "latest release URL had no tag".to_string())?;
    Ok(validate_version(version)?.to_string())
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let mut command = Command::new("curl");
    command.args(["-fsSL", url, "-o", "-"]);
    download_with_command(&mut command, destination, MAX_DOWNLOAD_BYTES)
        .map_err(|error| format!("download release asset from {url} ({error})"))
}

fn download_with_command(
    command: &mut Command,
    destination: &Path,
    max_bytes: u64,
) -> Result<(), String> {
    let (staging, output) = create_download_staging(destination)?;
    let mut output = Some(output);

    let result = (|| {
        // Drain into a bounded buffer before touching the filesystem so storage latency cannot
        // prevent the child from being observed, terminated, and reaped by run_bounded.
        let transfer = run_bounded_to_file(
            command,
            NETWORK_TIMEOUT,
            output.as_mut().expect("staging output is open"),
            max_bytes,
        )?;
        if transfer.status != Some(0) {
            return Err("download command failed".to_string());
        }
        // `sync_all` has no portable cancellation point; the child group is already reaped and
        // proven gone before this storage-only step.
        output
            .as_ref()
            .expect("staging output is open")
            .sync_all()
            .map_err(|error| format!("sync downloaded asset ({error})"))?;
        drop(output.take());
        require_regular_file(&staging, max_bytes)?;
        fs::rename(&staging, destination).map_err(|error| {
            format!(
                "install downloaded asset at {} ({error})",
                destination.display()
            )
        })?;
        Ok(())
    })();

    if let Err(primary_error) = result {
        drop(output.take());
        return match fs::remove_file(&staging) {
            Ok(()) => Err(primary_error),
            Err(cleanup_error) => Err(format!(
                "{primary_error}; failed to remove staging file {} ({cleanup_error})",
                staging.display()
            )),
        };
    }
    Ok(())
}

fn download_staging_path(destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset");
    destination.with_file_name(format!(".{name}.part-{}", std::process::id()))
}

fn create_download_staging(destination: &Path) -> Result<(PathBuf, File), String> {
    let base = download_staging_path(destination);
    let base_name = base
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(".asset.part");
    for attempt in 0..32_u32 {
        let staging = if attempt == 0 {
            base.clone()
        } else {
            base.with_file_name(format!("{base_name}-{attempt}"))
        };
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
        {
            Ok(file) => return Ok((staging, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "stage download beside {} ({error})",
                    destination.display()
                ));
            }
        }
    }
    Err(format!(
        "stage download beside {} (too many staging files)",
        destination.display()
    ))
}

fn require_regular_file(path: &Path, max_bytes: u64) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {} ({error})", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!("{} has an invalid size", path.display()));
    }
    Ok(())
}

fn verify_checksum(archive: &Path, checksum: &Path) -> Result<(), String> {
    require_regular_file(checksum, 4 * 1024)?;
    let expected_raw =
        fs::read_to_string(checksum).map_err(|error| format!("read checksum ({error})"))?;
    let expected = expected_raw
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| "release checksum is malformed".to_string())?;
    let mut file = File::open(archive).map_err(|error| format!("open archive ({error})"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read archive ({error})"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err("release checksum verification failed".to_string())
    }
}

fn extract(archive: &Path, directory: &Path) -> Result<(), String> {
    let output = run_bounded(
        Command::new("tar")
            .args(["-xzf"])
            .arg(archive)
            .args(["-C"])
            .arg(directory)
            .arg("lgtm"),
        Duration::from_secs(30),
    )?;
    if output.status == Some(0) {
        Ok(())
    } else {
        Err("extract release archive".to_string())
    }
}

fn install(source: &Path, executable: &Path, parent: &Path) -> Result<(), String> {
    let stage = parent.join(format!(".lgtm-update-{}", std::process::id()));
    let mut input = File::open(source).map_err(|error| format!("open new binary ({error})"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|error| format!("stage update beside executable ({error})"))?;
    std::io::copy(&mut input, &mut output).map_err(|error| format!("copy new binary ({error})"))?;
    output
        .sync_all()
        .map_err(|error| format!("sync new binary ({error})"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("mark new binary executable ({error})"))?;
    }
    if let Err(error) = fs::rename(&stage, executable) {
        let _ = fs::remove_file(&stage);
        return Err(format!("replace {} ({error})", executable.display()));
    }
    Ok(())
}

const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_PIPE_READS_PER_TURN: usize = 16;
const CLEANUP_RESERVE: Duration = Duration::from_millis(50);

struct Captured {
    status: Option<i32>,
    stdout: Vec<u8>,
}

fn run_bounded(command: &mut Command, timeout: Duration) -> Result<Captured, String> {
    let mut stdout = Vec::new();
    let status = run_bounded_with_sink(command, timeout, |chunk| {
        if stdout.len().saturating_add(chunk.len()) > MAX_COMMAND_OUTPUT_BYTES {
            return Err(format!(
                "external command output exceeded {MAX_COMMAND_OUTPUT_BYTES} bytes"
            ));
        }
        stdout.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(Captured { status, stdout })
}

struct Transfer {
    status: Option<i32>,
}

fn run_bounded_to_file<W: Write>(
    command: &mut Command,
    timeout: Duration,
    output: &mut W,
    max_bytes: u64,
) -> Result<Transfer, String> {
    let mut downloaded = Vec::new();
    let mut bytes_written = 0_u64;
    let transfer = run_bounded_with_sink(command, timeout, |chunk| {
        let remaining = max_bytes.saturating_sub(bytes_written);
        let writable = chunk
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if writable != 0 {
            downloaded
                .try_reserve(writable)
                .map_err(|_| "buffer downloaded asset (out of memory)".to_string())?;
            downloaded.extend_from_slice(&chunk[..writable]);
            bytes_written += writable as u64;
        }
        if writable < chunk.len() {
            Err(format!(
                "download exceeded {max_bytes} bytes after writing {bytes_written} bytes"
            ))
        } else {
            Ok(())
        }
    });
    output
        .write_all(&downloaded)
        .map_err(|error| format!("write downloaded asset ({error})"))?;
    let status = transfer?;
    Ok(Transfer { status })
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn run_bounded_with_sink<F>(
    command: &mut Command,
    timeout: Duration,
    mut sink: F,
) -> Result<Option<i32>, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    use std::os::unix::process::CommandExt;

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let observation_deadline = deadline.checked_sub(CLEANUP_RESERVE).unwrap_or(deadline);
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("start external command ({error})"))?;
    let process_group = child.id() as libc::pid_t;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = cleanup_child(&mut child, process_group, deadline);
            return Err(match cleanup {
                Ok(_) => "external command had no stdout pipe".to_string(),
                Err(cleanup) => {
                    format!("external command had no stdout pipe; {cleanup}")
                }
            });
        }
    };
    if let Err(error) = set_stdout_nonblocking(&stdout) {
        let cleanup = cleanup_child(&mut child, process_group, deadline);
        return Err(match cleanup {
            Ok(_) => error,
            Err(cleanup) => format!("{error}; failed to clean up external command ({cleanup})"),
        });
    }

    let mut completed = false;
    let mut stdout_closed = false;
    let mut failure = None;
    loop {
        if !completed && failure.is_none() {
            match observe_child(&child) {
                Ok(done) => completed = done,
                Err(error) => failure = Some(error),
            }
        }

        if !stdout_closed && failure.is_none() {
            match drain_stdout(&mut stdout, &mut sink, observation_deadline) {
                Ok(closed) => stdout_closed = closed,
                Err(error) => failure = Some(error),
            }
        }

        if failure.is_none() && completed && stdout_closed {
            if Instant::now() >= observation_deadline {
                failure = Some("external command timed out".to_string());
            } else {
                let cleanup = cleanup_child(&mut child, process_group, deadline);
                drop(stdout);
                return cleanup.map_err(|cleanup_error| {
                    format!("failed to clean up external command ({cleanup_error})")
                });
            }
        }
        if failure.is_none() && Instant::now() >= observation_deadline {
            failure = Some("external command timed out".to_string());
        }

        if let Some(error) = failure.take() {
            let cleanup = cleanup_child(&mut child, process_group, deadline);
            drop(stdout);
            return match cleanup {
                Ok(_) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; failed to clean up external command ({cleanup_error})"
                )),
            };
        }

        let remaining = observation_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(not(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos"))))]
fn run_bounded_with_sink<F>(
    _command: &mut Command,
    _timeout: Duration,
    _sink: F,
) -> Result<Option<i32>, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    Err("bounded external commands require a Unix process group".to_string())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn set_stdout_nonblocking(stdout: &std::process::ChildStdout) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    let descriptor = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(format!(
            "configure external command output ({})",
            std::io::Error::last_os_error()
        ));
    }
    if flags & libc::O_NONBLOCK == 0
        && unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(format!(
            "configure external command output ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn drain_stdout<F>(
    stdout: &mut std::process::ChildStdout,
    sink: &mut F,
    deadline: Instant,
) -> Result<bool, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut attempted_read = false;
    for _ in 0..MAX_PIPE_READS_PER_TURN {
        if attempted_read && Instant::now() >= deadline {
            return Ok(false);
        }
        attempted_read = true;
        match stdout.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => sink(&buffer[..read])?,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("read command output ({error})")),
        }
    }
    Ok(false)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn observe_child(child: &std::process::Child) -> Result<bool, String> {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(format!(
            "observe command completion ({})",
            std::io::Error::last_os_error()
        ));
    }
    let observed_pid = unsafe { info.si_pid() };
    if observed_pid == 0 {
        return Ok(false);
    }
    if observed_pid != child.id() as libc::pid_t {
        return Err("observe command completion (unexpected child)".to_string());
    }
    match info.si_code {
        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => Ok(true),
        code => Err(format!(
            "observe command completion (unexpected child status {code})"
        )),
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn cleanup_child(
    child: &mut std::process::Child,
    process_group: libc::pid_t,
    deadline: Instant,
) -> Result<Option<i32>, String> {
    let terminate_error = terminate_process_group(child, process_group).err();
    let reap_result = reap_child_before_deadline(child, deadline);
    let gone_result = prove_process_group_gone(process_group, deadline);
    match (reap_result, gone_result) {
        (Ok(status), Ok(())) if terminate_error.is_none() => Ok(status),
        (reap_result, gone_result) => {
            let mut cleanup_errors = terminate_error.into_iter().collect::<Vec<_>>();
            if let Err(reap_error) = reap_result {
                cleanup_errors.push(reap_error);
            }
            if let Err(gone_error) = gone_result {
                cleanup_errors.push(gone_error);
            }
            Err(cleanup_errors.join("; "))
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn reap_child_before_deadline(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<Option<i32>, String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code()),
            Ok(None) => {}
            Err(error) => return Err(format!("wait for command ({error})")),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("command did not finish reaping before deadline".to_string());
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn prove_process_group_gone(process_group: libc::pid_t, deadline: Instant) -> Result<(), String> {
    loop {
        let result = unsafe { libc::kill(-process_group, 0) };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            if error.raw_os_error() != Some(libc::EPERM) {
                return Err(format!("check command group cleanup ({error})"));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(
                "could not prove external command group cleanup before deadline".to_string(),
            );
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn terminate_process_group(
    child: &std::process::Child,
    process_group: libc::pid_t,
) -> Result<(), String> {
    let group_result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if group_result == -1 {
        let group_error = std::io::Error::last_os_error();
        if group_error.raw_os_error() != Some(libc::ESRCH) {
            let direct_error = kill_direct_child(child).err();
            return Err(match direct_error {
                Some(direct_error) => format!("kill command group ({group_error}); {direct_error}"),
                None => format!("kill command group ({group_error})"),
            });
        }
    }
    kill_direct_child(child)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn kill_direct_child(child: &std::process::Child) -> Result<(), String> {
    let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!("kill command ({error})"));
        }
    }
    Ok(())
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn create() -> Result<Self, String> {
        for attempt in 0..32_u32 {
            let path =
                std::env::temp_dir().join(format!("lgtm-update-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("create update directory ({error})")),
            }
        }
        Err("could not allocate update directory".to_string())
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_ROLE_ENV: &str = "LGTM_UPDATE_FIXTURE_ROLE";
    const RETAINED_PIPE_TIMEOUT: Duration = Duration::from_millis(150);
    const CLOSING_PIPE_TIMEOUT: Duration = Duration::from_millis(500);
    // This margin covers scheduler jitter; each fixture also has a one-second outer watchdog.
    const FIXTURE_SCHEDULER_MARGIN: Duration = Duration::from_millis(100);

    fn fixture_is_active(role: &str, directory_env: &str) -> bool {
        std::env::var(FIXTURE_ROLE_ENV).ok().as_deref() == Some(role)
            && std::env::var_os(directory_env).is_some()
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes: Vec<u8>,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn versions_are_strictly_validated() {
        assert_eq!(validate_version("v1.2.3"), Ok("v1.2.3"));
        for invalid in [
            "1.2.3", "v", "v1/2", "v1..2", "v1.2.", "vlatest", "v.1.2", "v1.2", "v1.2.3.4",
        ] {
            assert!(validate_version(invalid).is_err(), "accepted {invalid}");
        }
        assert!(parse_version("v2.0.0").unwrap() > parse_version("v1.99.99").unwrap());
    }

    #[test]
    fn checksum_accepts_matching_file_and_rejects_mismatch() {
        let directory = TemporaryDirectory::create().unwrap();
        let archive = directory.path.join("archive");
        let checksum = directory.path.join("archive.sha256");
        fs::write(&archive, b"portable binary").unwrap();
        let digest = Sha256::digest(b"portable binary");
        fs::write(&checksum, format!("{digest:x}  archive\n")).unwrap();
        assert!(verify_checksum(&archive, &checksum).is_ok());
        fs::write(&archive, b"tampered").unwrap();
        assert!(verify_checksum(&archive, &checksum).is_err());
    }

    #[test]
    fn install_atomically_replaces_existing_binary() {
        let directory = TemporaryDirectory::create().unwrap();
        let source = directory.path.join("new-lgtm");
        let executable = directory.path.join("installed-lgtm");
        fs::write(&source, b"new binary").unwrap();
        fs::write(&executable, b"old binary").unwrap();

        install(&source, &executable, &directory.path).unwrap();

        assert_eq!(fs::read(&executable).unwrap(), b"new binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn bounded_command_cleans_descendant_retaining_stdout() {
        const FIXTURE_ENV: &str = "LGTM_RETAINED_PIPE_FIXTURE";
        const FIXTURE_ROLE: &str = "retained-pipe";
        if fixture_is_active(FIXTURE_ROLE, FIXTURE_ENV) {
            run_retained_pipe_fixture();
            return;
        }

        let directory = TemporaryDirectory::create().unwrap();
        let started = Instant::now();
        let completed = run_isolated_fixture(
            "bounded_command_cleans_descendant_retaining_stdout",
            FIXTURE_ENV,
            FIXTURE_ROLE,
            &directory.path,
            &directory.path.join("command.pid"),
            Duration::from_secs(1),
        );
        assert!(
            completed,
            "retained-pipe fixture did not finish within its watchdog"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "retained-pipe fixture exceeded its watchdog"
        );

        let result = fs::read_to_string(directory.path.join("result"))
            .expect("retained-pipe fixture did not publish a result");
        let mut fields = result.split(':');
        assert_eq!(fields.next(), Some("failure"));
        let elapsed_ms: u64 = fields
            .next()
            .expect("retained-pipe fixture omitted elapsed time")
            .parse()
            .expect("retained-pipe fixture elapsed time was not numeric");
        assert!(
            elapsed_ms < (RETAINED_PIPE_TIMEOUT + FIXTURE_SCHEDULER_MARGIN).as_millis() as u64,
            "bounded command exceeded its retained-pipe deadline tolerance"
        );

        let pid = wait_for_pid_file(
            &directory.path.join("descendant.pid"),
            Duration::from_secs(1),
        )
        .expect("descendant did not publish its pid");
        let cleaned = wait_for_pid_exit(pid, Duration::from_secs(1));
        if !cleaned {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(cleaned, "descendant process survived bounded cleanup");
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn bounded_command_cleans_descendant_after_successful_pipe_closure() {
        const FIXTURE_ENV: &str = "LGTM_CLOSING_PIPE_FIXTURE";
        const FIXTURE_ROLE: &str = "closing-pipe";
        if fixture_is_active(FIXTURE_ROLE, FIXTURE_ENV) {
            run_closing_pipe_fixture();
            return;
        }

        let directory = TemporaryDirectory::create().unwrap();
        let started = Instant::now();
        let completed = run_isolated_fixture(
            "bounded_command_cleans_descendant_after_successful_pipe_closure",
            FIXTURE_ENV,
            FIXTURE_ROLE,
            &directory.path,
            &directory.path.join("command.pid"),
            Duration::from_secs(1),
        );
        assert!(
            completed,
            "closing-pipe fixture did not finish within its watchdog"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "closing-pipe fixture exceeded its watchdog"
        );

        let result = fs::read_to_string(directory.path.join("result"))
            .expect("closing-pipe fixture did not publish a result");
        let mut fields = result.split(':');
        assert_eq!(fields.next(), Some("success"));
        assert_eq!(fields.next(), Some("0"));
        let elapsed_ms: u64 = fields
            .next()
            .expect("closing-pipe fixture omitted elapsed time")
            .parse()
            .expect("closing-pipe fixture elapsed time was not numeric");
        assert!(
            elapsed_ms < (CLOSING_PIPE_TIMEOUT + FIXTURE_SCHEDULER_MARGIN).as_millis() as u64,
            "bounded command exceeded its closing-pipe deadline tolerance"
        );

        let pid = wait_for_pid_file(
            &directory.path.join("descendant.pid"),
            Duration::from_secs(1),
        )
        .expect("descendant did not publish its pid");
        let cleaned = wait_for_pid_exit(pid, Duration::from_secs(1));
        if !cleaned {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(cleaned, "descendant process survived successful cleanup");
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn complete_download_replaces_destination_after_bounded_transfer() {
        let directory = TemporaryDirectory::create().unwrap();
        let destination = directory.path.join("asset");
        fs::write(&destination, b"old asset").unwrap();

        let mut command = Command::new("sh");
        command.args(["-c", "printf 'new asset'"]);
        download_with_command(&mut command, &destination, 4 * 1024).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new asset");
        assert!(!download_staging_path(&destination).exists());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn download_rejects_nonzero_command_and_preserves_destination() {
        let directory = TemporaryDirectory::create().unwrap();
        let destination = directory.path.join("asset");
        fs::write(&destination, b"old asset").unwrap();

        let mut command = Command::new("sh");
        command.args(["-c", "printf 'partial asset'; exit 7"]);
        let error = download_with_command(&mut command, &destination, 4 * 1024)
            .expect_err("nonzero download unexpectedly succeeded");

        assert!(
            error.contains("download command failed"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"old asset");
        assert!(!download_staging_path(&destination).exists());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn bounded_command_rejects_output_over_max_command_output_bytes() {
        let mut command = Command::new("sh");
        command.args(["-c", "dd if=/dev/zero bs=1024 count=65 2>/dev/null"]);

        let error = match run_bounded(&mut command, Duration::from_secs(1)) {
            Ok(_) => panic!("oversized command output unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            error.contains("external command output exceeded 65536 bytes"),
            "unexpected output-limit error: {error}"
        );
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn bounded_command_accepts_exact_max_command_output_bytes() {
        let mut command = Command::new("sh");
        command.args(["-c", "dd if=/dev/zero bs=1024 count=64 2>/dev/null"]);

        let captured = run_bounded(&mut command, Duration::from_secs(1)).unwrap();
        assert_eq!(captured.status, Some(0));
        assert_eq!(captured.stdout.len(), MAX_COMMAND_OUTPUT_BYTES);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn run_bounded_to_file_never_writes_more_than_cap() {
        let mut command = Command::new("sh");
        command.args(["-c", "dd if=/dev/zero bs=1024 count=8 2>/dev/null"]);
        let mut output = CountingWriter::default();

        let result =
            run_bounded_to_file(&mut command, Duration::from_secs(1), &mut output, 4 * 1024);
        let error = match result {
            Ok(_) => panic!("over-limit transfer unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.contains("after writing 4096 bytes"));
        assert_eq!(output.bytes.len(), 4 * 1024);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn exact_limit_download_succeeds_and_cleans_staging() {
        let directory = TemporaryDirectory::create().unwrap();
        let destination = directory.path.join("asset-at-limit");
        fs::write(&destination, b"old asset").unwrap();

        let mut command = Command::new("sh");
        command.args(["-c", "printf 1234"]);
        download_with_command(&mut command, &destination, 4).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"1234");
        assert!(!download_staging_path(&destination).exists());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn download_retries_after_stale_pid_staging_file() {
        let directory = TemporaryDirectory::create().unwrap();
        let destination = directory.path.join("asset-after-retry");
        let stale = download_staging_path(&destination);
        fs::write(&stale, b"stale partial asset").unwrap();
        fs::write(&destination, b"old asset").unwrap();

        let mut command = Command::new("sh");
        command.args(["-c", "printf 'new asset'"]);
        download_with_command(&mut command, &destination, 4 * 1024).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new asset");
        assert_eq!(fs::read(&stale).unwrap(), b"stale partial asset");
        let stale_name = stale.file_name().unwrap().to_str().unwrap();
        let suffix_prefix = format!("{stale_name}-");
        let suffixes = fs::read_dir(&directory.path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&suffix_prefix))
            })
            .count();
        assert_eq!(suffixes, 0, "generated staging suffix was not cleaned");
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn over_limit_download_stops_at_cap_and_preserves_existing_destination() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TemporaryDirectory::create().unwrap();
        let destination = directory.path.join("existing-executable");
        let marker = directory.path.join("completed");
        fs::write(&destination, b"existing executable").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
        let original_mode = fs::metadata(&destination).unwrap().permissions().mode() & 0o777;

        let mut command = Command::new("sh");
        command.env("LGTM_DOWNLOAD_MARKER", &marker).args([
            "-c",
            "set -e; dd if=/dev/zero bs=1024 count=1024; printf done > \"$LGTM_DOWNLOAD_MARKER\"",
        ]);
        let result = download_with_command(&mut command, &destination, 4 * 1024);

        let error = result.expect_err("over-limit transfer unexpectedly succeeded");
        assert!(
            error.contains("after writing 4096 bytes"),
            "transfer was not stopped at the cap: {error}"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"existing executable");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            original_mode
        );
        assert!(
            !marker.exists(),
            "producer completed after the transfer cap instead of being stopped"
        );
        assert!(!download_staging_path(&destination).exists());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn run_retained_pipe_fixture() {
        let directory = PathBuf::from(
            std::env::var_os("LGTM_RETAINED_PIPE_FIXTURE").expect("fixture directory missing"),
        );
        let pid_file = directory.join("descendant.pid");
        let command_pid_file = directory.join("command.pid");
        let result_file = directory.join("result");
        let mut command = Command::new("sh");
        command
            .env("LGTM_DESCENDANT_PID_FILE", &pid_file)
            .env("LGTM_COMMAND_PID_FILE", &command_pid_file)
            .args([
                "-c",
                "printf '%s' \"$$\" > \"$LGTM_COMMAND_PID_FILE\"; sleep 30 & descendant=$!; printf '%s' \"$descendant\" > \"$LGTM_DESCENDANT_PID_FILE\"; wait \"$descendant\"",
            ]);
        let started = Instant::now();
        let result = run_bounded(&mut command, RETAINED_PIPE_TIMEOUT);
        let elapsed_ms = started.elapsed().as_millis();
        let outcome = if result.is_err() {
            format!("failure:{elapsed_ms}")
        } else {
            format!("success:{elapsed_ms}")
        };
        fs::write(result_file, outcome).expect("publish retained-pipe fixture result");
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn run_closing_pipe_fixture() {
        let directory = PathBuf::from(
            std::env::var_os("LGTM_CLOSING_PIPE_FIXTURE").expect("fixture directory missing"),
        );
        let pid_file = directory.join("descendant.pid");
        let command_pid_file = directory.join("command.pid");
        let result_file = directory.join("result");
        let mut command = Command::new("sh");
        command
            .env("LGTM_DESCENDANT_PID_FILE", &pid_file)
            .env("LGTM_COMMAND_PID_FILE", &command_pid_file)
            .args([
                "-c",
                "printf '%s' \"$$\" > \"$LGTM_COMMAND_PID_FILE\"; sleep 30 >/dev/null 2>&1 & descendant=$!; printf '%s' \"$descendant\" > \"$LGTM_DESCENDANT_PID_FILE\"; printf 'ready:%s\\n' \"$descendant\"; exit 0",
            ]);
        let mut readiness = Vec::new();
        let mut ready_pid = None;
        let started = Instant::now();
        let result = run_bounded_with_sink(&mut command, CLOSING_PIPE_TIMEOUT, |chunk| {
            readiness.extend_from_slice(chunk);
            if let Some(pid) = readiness
                .strip_prefix(b"ready:")
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.trim().parse().ok())
                && process_is_alive(pid)
            {
                ready_pid = Some(pid);
            }
            Ok(())
        });
        let elapsed_ms = started.elapsed().as_millis();
        let outcome = match result {
            Ok(status) if ready_pid.is_some() => {
                format!("success:{}:{elapsed_ms}", status.unwrap_or(-1))
            }
            Ok(_) => format!("not-ready:{elapsed_ms}"),
            Err(_) => format!("failure:{elapsed_ms}"),
        };
        fs::write(result_file, outcome).expect("publish closing-pipe fixture result");
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn run_isolated_fixture(
        test_filter: &str,
        fixture_env: &str,
        fixture_role: &str,
        fixture_directory: &Path,
        command_pid_file: &Path,
        timeout: Duration,
    ) -> bool {
        use std::os::unix::process::CommandExt;

        let mut fixture = Command::new(std::env::current_exe().expect("resolve test executable"));
        fixture
            .arg(test_filter)
            .env(fixture_env, fixture_directory)
            .env(FIXTURE_ROLE_ENV, fixture_role)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            fixture.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut fixture = match fixture.spawn() {
            Ok(fixture) => fixture,
            Err(_) => return false,
        };
        let fixture_pid = fixture.id() as libc::pid_t;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            match fixture.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(_) => return false,
            }
            if Instant::now() >= deadline {
                if let Some(command_pid) = read_pid_file(command_pid_file) {
                    kill_pid_group(command_pid);
                }
                kill_pid_group(fixture_pid);
                let cleanup_deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match fixture.try_wait() {
                        Ok(Some(_)) => return false,
                        Ok(None) => {}
                        Err(_) => return false,
                    }
                    if Instant::now() >= cleanup_deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn read_pid_file(path: &Path) -> Option<libc::pid_t> {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn kill_pid_group(pid: libc::pid_t) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn wait_for_pid_file(path: &Path, timeout: Duration) -> Option<libc::pid_t> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = fs::read_to_string(path)
                && let Ok(pid) = contents.trim().parse()
            {
                return Some(pid);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn process_is_alive(pid: libc::pid_t) -> bool {
        (unsafe { libc::kill(pid, 0) == 0 })
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn wait_for_pid_exit(pid: libc::pid_t, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if !process_is_alive(pid) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
