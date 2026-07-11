use std::path::{Path, PathBuf};

use serde::Deserialize;

pub(super) const MAX_CAPTURE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Deserialize)]
pub(super) struct Finding {
    #[serde(rename = "RuleID")]
    pub(super) rule_id: String,
    #[serde(rename = "Description")]
    pub(super) description: String,
    #[serde(rename = "File")]
    pub(super) file: String,
    #[serde(rename = "StartLine")]
    pub(super) start_line: u64,
}

pub(super) enum ScanOutcome {
    Findings(Vec<Finding>),
    Unverified(String),
}

pub(super) fn classify_exit(code: Option<i32>, report_path: &Path) -> ScanOutcome {
    match code {
        Some(2) => parse_report(report_path),
        Some(0) => ScanOutcome::Findings(Vec::new()),
        Some(other) => ScanOutcome::Unverified(format!("gitleaks exited with status {other}")),
        None => ScanOutcome::Unverified("gitleaks was terminated by a signal".to_string()),
    }
}

fn parse_report(report_path: &Path) -> ScanOutcome {
    let contents = crate::fsutil::read_optional_bounded(report_path, MAX_CAPTURE_BYTES);
    if contents.trim().is_empty() {
        return ScanOutcome::Unverified(
            "gitleaks reported leaks but its report was empty or unreadable".to_string(),
        );
    }
    serde_json::from_str::<Vec<Finding>>(&contents)
        .map(ScanOutcome::Findings)
        .unwrap_or_else(|error| {
            ScanOutcome::Unverified(format!("could not parse gitleaks report ({error})"))
        })
}

pub(crate) struct ReportDir {
    dir: PathBuf,
}

impl ReportDir {
    pub(crate) fn create() -> Result<Self, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("lgtm-gitleaks-{}-{nanos}-{counter}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        create_private_dir(&dir)
            .map_err(|error| format!("could not create a private report directory ({error})"))?;
        Ok(Self { dir })
    }

    pub(crate) fn report_path(&self) -> PathBuf {
        self.dir.join("report.json")
    }
}

impl Drop for ReportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_report_is_unverified() {
        let path =
            std::env::temp_dir().join(format!("lgtm-gitleaks-bad-{}.json", std::process::id()));
        std::fs::write(&path, "{ not an array").expect("fixture writable");
        let outcome = parse_report(&path);
        std::fs::remove_file(path).ok();
        assert!(matches!(outcome, ScanOutcome::Unverified(_)));
    }

    #[test]
    fn empty_report_array_is_clean_findings() {
        let path =
            std::env::temp_dir().join(format!("lgtm-gitleaks-empty-{}.json", std::process::id()));
        std::fs::write(&path, "[]").expect("fixture writable");
        let outcome = parse_report(&path);
        std::fs::remove_file(path).ok();
        assert!(matches!(outcome, ScanOutcome::Findings(findings) if findings.is_empty()));
    }

    #[cfg(unix)]
    #[test]
    fn report_directory_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let path;
        {
            let directory = ReportDir::create().expect("directory created");
            path = directory.dir.clone();
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
            assert!(directory.report_path().starts_with(&path));
        }
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_refuses_preexisting_path() {
        let path =
            std::env::temp_dir().join(format!("lgtm-gitleaks-existing-{}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture directory created");
        let result = create_private_dir(&path);
        std::fs::remove_dir(path).ok();
        assert!(result.is_err());
    }
}
