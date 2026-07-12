//! Safe self-update from checksum-protected public GitHub release assets.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
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
    let output = run_bounded(
        Command::new("curl")
            .args(["-fsSL", url, "-o"])
            .arg(destination),
        NETWORK_TIMEOUT,
    )?;
    if output.status != Some(0) {
        return Err(format!("download release asset from {url}"));
    }
    require_regular_file(destination, MAX_DOWNLOAD_BYTES)
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

struct Captured {
    status: Option<i32>,
    stdout: Vec<u8>,
}

fn run_bounded(command: &mut Command, timeout: Duration) -> Result<Captured, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("start external command ({error})"))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait for command ({error})"))?
        {
            let mut stdout = Vec::new();
            if let Some(pipe) = child.stdout.take() {
                pipe.take(64 * 1024)
                    .read_to_end(&mut stdout)
                    .map_err(|error| format!("read command output ({error})"))?;
            }
            return Ok(Captured {
                status: status.code(),
                stdout,
            });
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err("external command timed out".to_string());
        }
        thread::sleep(Duration::from_millis(25));
    }
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
}
