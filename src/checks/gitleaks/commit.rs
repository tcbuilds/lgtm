use std::fs::Metadata;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::report::{Finding, MAX_CAPTURE_BYTES, ReportDir, ScanOutcome};
use super::{GITLEAKS_BIN, result, runner};

const CONFIG_FILE: &str = ".gitleaks.toml";
const IGNORE_FILE: &str = ".gitleaksignore";
const POLICY_CONFIG_FILE: &str = ".lgtm/config.json";
const WAIVERS_FILE: &str = ".lgtm/waivers.json";
const EXECUTION_POLICY_FILE: &str = ".lgtm/execpolicy.json";
const GENERIC_RULE_ID: &str = "generic-api-key";
const MAX_FINDINGS: usize = 1_024;
const COMMIT_SCANNER_MODE: &str = "gitleaks protect --staged";
const COMMIT_REMEDIATION: &str = "Stage the intended files separately, remove or rotate the detected credential, then retry the direct commit.";

#[path = "commit/identity.rs"]
mod identity;

use identity::{BoundFile, GitCapture, IdentityContext, RepositoryState, build_identity};
pub(crate) use identity::{CommitAssessment, CommitFinding};

pub(crate) fn assess_commit(
    root: &Path,
    commit_argv: &[String],
    session_id: Option<&str>,
    harness: &str,
    deadline: Instant,
) -> CommitAssessment {
    match assess_commit_inner(root, commit_argv, session_id, harness, deadline) {
        Ok(assessment) => assessment,
        Err(reason) => CommitAssessment::Deny {
            identity: None,
            reason: format!(
                "staged commit secret assessment is unverified ({reason}); {COMMIT_REMEDIATION}"
            ),
        },
    }
}

fn assess_commit_inner(
    root: &Path,
    commit_argv: &[String],
    session_id: Option<&str>,
    harness: &str,
    deadline: Instant,
) -> Result<CommitAssessment, String> {
    reject_selector_environment()?;
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| format!("repository root is unavailable ({error})"))?;
    let config = read_bound_file(&canonical_root.join(CONFIG_FILE), CONFIG_FILE)?;
    let ignore = read_bound_file(&canonical_root.join(IGNORE_FILE), IGNORE_FILE)?;
    let policy_config =
        read_bound_file(&canonical_root.join(POLICY_CONFIG_FILE), POLICY_CONFIG_FILE)?;
    let waivers = read_bound_file(&canonical_root.join(WAIVERS_FILE), WAIVERS_FILE)?;
    let execution_policy = read_bound_file(
        &canonical_root.join(EXECUTION_POLICY_FILE),
        EXECUTION_POLICY_FILE,
    )?;
    let git_binary = resolve_binary("git")?;
    let git_binary_identity = binary_identity(&git_binary)?;
    let scanner_binary = resolve_binary(GITLEAKS_BIN)?;
    let scanner_binary_identity = binary_identity(&scanner_binary)?;
    let initial =
        capture_repository_state(&canonical_root, &git_binary, &git_binary_identity, deadline)?;
    let scanner_name = scanner_binary.to_string_lossy();
    let version = super::tool_version_until(&scanner_name, deadline)
        .ok_or_else(|| "gitleaks version could not be verified".to_string())?;
    let outcome = run_staged_scanner(&canonical_root, &scanner_binary, &config, &ignore, deadline)?;
    let final_config = read_bound_file(&canonical_root.join(CONFIG_FILE), CONFIG_FILE)?;
    let final_ignore = read_bound_file(&canonical_root.join(IGNORE_FILE), IGNORE_FILE)?;
    let final_policy_config =
        read_bound_file(&canonical_root.join(POLICY_CONFIG_FILE), POLICY_CONFIG_FILE)?;
    let final_waivers = read_bound_file(&canonical_root.join(WAIVERS_FILE), WAIVERS_FILE)?;
    let final_execution_policy = read_bound_file(
        &canonical_root.join(EXECUTION_POLICY_FILE),
        EXECUTION_POLICY_FILE,
    )?;
    let final_git_binary = resolve_binary("git")?;
    let final_git_binary_identity = binary_identity(&final_git_binary)?;
    let final_scanner_binary = resolve_binary(GITLEAKS_BIN)?;
    let final_scanner_binary_identity = binary_identity(&final_scanner_binary)?;
    let final_state = capture_repository_state(
        &canonical_root,
        &final_git_binary,
        &final_git_binary_identity,
        deadline,
    )?;
    if initial != final_state
        || config != final_config
        || ignore != final_ignore
        || policy_config != final_policy_config
        || waivers != final_waivers
        || execution_policy != final_execution_policy
        || scanner_binary_identity != final_scanner_binary_identity
    {
        return Err(
            "repository index, HEAD, or scanner configuration changed while scanning".to_string(),
        );
    }
    let raw_findings = match outcome {
        ScanOutcome::Findings(findings) => findings,
        ScanOutcome::Unverified(reason) => return Err(reason),
    };
    let findings = materialize_findings(
        &canonical_root,
        &initial,
        &git_binary,
        raw_findings,
        deadline,
    )?;
    if binary_identity(&git_binary)? != git_binary_identity {
        return Err("Git executable changed while materializing staged findings".to_string());
    }
    let identity = build_identity(
        &initial,
        IdentityContext {
            config: &config,
            ignore: &ignore,
            policy_config: &policy_config,
            waivers: &waivers,
            execution_policy: &execution_policy,
            scanner_version: &version,
            scanner_binary_identity: &scanner_binary_identity,
            commit_argv,
            session_id,
            harness,
            findings: &findings,
        },
    );
    if findings.is_empty() {
        return Ok(CommitAssessment::Pass { identity });
    }
    if findings
        .iter()
        .all(|finding| is_heuristic_eligible(finding, &config))
    {
        return Ok(CommitAssessment::PendingHeuristicApproval { identity, findings });
    }
    let result = result::commit_failed(&findings, Some(version));
    Ok(CommitAssessment::Deny {
        identity: Some(identity),
        reason: format!("{} {}", result.message, COMMIT_REMEDIATION),
    })
}

fn reject_selector_environment() -> Result<(), String> {
    const SELECTORS: [&str; 7] = [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
        "GITLEAKS_CONFIG",
        "GITLEAKS_CONFIG_TOML",
    ];
    for name in SELECTORS {
        if std::env::var_os(name).is_some() {
            return Err(format!("environment selector {name} is unsupported"));
        }
    }
    Ok(())
}

fn run_staged_scanner(
    root: &Path,
    binary: &Path,
    config: &BoundFile,
    ignore: &BoundFile,
    deadline: Instant,
) -> Result<ScanOutcome, String> {
    let report_dir = ReportDir::create()?;
    let report_path = report_dir.report_path();
    let mut command = Command::new(binary);
    command
        .current_dir(root)
        .arg("protect")
        .arg("--staged")
        .arg("--report-format")
        .arg("json")
        .arg("--report-path")
        .arg(&report_path)
        .arg("--exit-code")
        .arg("2")
        .arg("--redact")
        .arg("--no-banner")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if config.present {
        command.arg("--config").arg(&config.path);
    }
    if ignore.present {
        command.arg("--gitleaks-ignore-path").arg(&ignore.path);
    }
    Ok(runner::run_scan_with_deadline(
        command,
        &report_path,
        deadline,
    ))
}

fn capture_repository_state(
    root: &Path,
    git_binary: &Path,
    git_binary_identity: &str,
    deadline: Instant,
) -> Result<RepositoryState, String> {
    let reported_root = git_output(
        root,
        git_binary,
        &["rev-parse", "--show-toplevel"],
        deadline,
    )?;
    let reported_root = std::fs::canonicalize(reported_root.trim())
        .map_err(|error| format!("git repository root is invalid ({error})"))?;
    if reported_root != root {
        return Err("git repository root does not match the resolved hook root".to_string());
    }
    let git_dir_raw = git_output(root, git_binary, &["rev-parse", "--git-dir"], deadline)?;
    let git_dir_path = resolve_git_path(root, git_dir_raw.trim());
    let git_dir = std::fs::canonicalize(&git_dir_path)
        .map_err(|error| format!("git directory is unavailable ({error})"))?;
    let head = head_identity(root, git_binary, deadline)?;
    let tree = git_output(root, git_binary, &["write-tree"], deadline)?;
    validate_object_id(tree.trim())?;
    let index_path = resolve_git_path(
        root,
        git_output(
            root,
            git_binary,
            &["rev-parse", "--git-path", "index"],
            deadline,
        )?
        .trim(),
    );
    let head_path = resolve_git_path(
        root,
        git_output(
            root,
            git_binary,
            &["rev-parse", "--git-path", "HEAD"],
            deadline,
        )?
        .trim(),
    );
    Ok(RepositoryState {
        root: root.to_string_lossy().into_owned(),
        git_dir: git_dir.to_string_lossy().into_owned(),
        head,
        tree: tree.trim().to_string(),
        index_identity: file_identity(&index_path)?,
        head_identity: file_identity(&head_path)?,
        git_binary_identity: git_binary_identity.to_string(),
    })
}

fn head_identity(root: &Path, git_binary: &Path, deadline: Instant) -> Result<String, String> {
    let head = run_git(
        root,
        git_binary,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        deadline,
    )?;
    if head.code == Some(0) {
        let oid = clean_stdout(&head.stdout)?;
        validate_object_id(&oid)?;
        return Ok(format!("commit:{oid}"));
    }
    let symbolic = git_output(
        root,
        git_binary,
        &["symbolic-ref", "--quiet", "HEAD"],
        deadline,
    )?;
    let symbolic = symbolic.trim();
    if symbolic.is_empty() || symbolic.chars().any(|character| character.is_control()) {
        return Err("HEAD is neither a verified commit nor an unborn symbolic ref".to_string());
    }
    Ok(format!("unborn:{symbolic}"))
}

fn resolve_git_path(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn materialize_findings(
    root: &Path,
    state: &RepositoryState,
    git_binary: &Path,
    findings: Vec<Finding>,
    deadline: Instant,
) -> Result<Vec<CommitFinding>, String> {
    if findings.len() > MAX_FINDINGS {
        return Err(format!(
            "gitleaks report exceeded the {MAX_FINDINGS}-finding limit"
        ));
    }
    let mut materialized = Vec::with_capacity(findings.len());
    for finding in findings {
        let file = normalize_finding_path(root, &finding.file)?;
        let spec = format!("{}:{file}", state.tree);
        let blob_identity = git_output(
            root,
            git_binary,
            &["rev-parse", "--verify", &spec],
            deadline,
        )?;
        validate_object_id(blob_identity.trim())?;
        let fingerprint = if finding.fingerprint.trim().is_empty() {
            format!(
                "{file}:{}:{}:{}:{}",
                finding.rule_id, finding.start_line, finding.start_column, finding.end_line,
            )
        } else {
            finding.fingerprint.clone()
        };
        materialized.push(CommitFinding {
            rule_id: finding.rule_id,
            file,
            start_line: finding.start_line,
            start_column: finding.start_column,
            end_line: finding.end_line,
            end_column: finding.end_column,
            fingerprint,
            blob_identity: blob_identity.trim().to_string(),
        });
    }
    materialized.sort_by(|left, right| {
        (
            &left.rule_id,
            &left.file,
            left.start_line,
            left.start_column,
            left.end_line,
            left.end_column,
            &left.fingerprint,
            &left.blob_identity,
        )
            .cmp(&(
                &right.rule_id,
                &right.file,
                right.start_line,
                right.start_column,
                right.end_line,
                right.end_column,
                &right.fingerprint,
                &right.blob_identity,
            ))
    });
    Ok(materialized)
}

fn normalize_finding_path(root: &Path, raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.chars().any(|character| character.is_control()) {
        return Err("gitleaks returned an invalid finding path".to_string());
    }
    let path = Path::new(raw);
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .map_err(|_| "gitleaks returned a finding outside the repository root".to_string())?
    } else {
        path
    };
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("gitleaks returned a finding path with traversal".to_string());
            }
        }
    }
    if components.is_empty() {
        return Err("gitleaks returned an empty finding path".to_string());
    }
    Ok(components.join("/"))
}

// A custom config can redefine built-in rule IDs, so only the default rule set
// is trusted for the narrow heuristic-approval candidate path.
fn is_heuristic_eligible(finding: &CommitFinding, config: &BoundFile) -> bool {
    finding.rule_id == GENERIC_RULE_ID && !config.present
}

fn read_bound_file(path: &Path, label: &str) -> Result<BoundFile, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BoundFile {
                path: path.to_path_buf(),
                contents: Vec::new(),
                digest: format!("absent:{label}"),
                metadata_identity: "absent".to_string(),
                present: false,
            });
        }
        Err(error) => return Err(format!("could not inspect {label} ({error})")),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    let expected_identity = metadata_identity(&metadata);
    let file = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("could not open {label} ({error})"))?
        .ok_or_else(|| format!("{label} changed before it could be opened"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect opened {label} ({error})"))?;
    if !opened_metadata.file_type().is_file() {
        return Err(format!("{label} changed to a non-regular file"));
    }
    let opened_identity = metadata_identity(&opened_metadata);
    if opened_identity != expected_identity {
        return Err(format!("{label} changed before it could be opened"));
    }
    let mut contents = Vec::new();
    file.take(MAX_CAPTURE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|error| format!("could not read {label} ({error})"))?;
    if contents.len() as u64 > MAX_CAPTURE_BYTES {
        return Err(format!(
            "{label} exceeds the bounded {MAX_CAPTURE_BYTES}-byte limit"
        ));
    }
    let digest = format!("{:x}", Sha256::digest(&contents));
    Ok(BoundFile {
        path: path.to_path_buf(),
        contents,
        digest,
        metadata_identity: opened_identity,
        present: true,
    })
}

fn file_identity(path: &Path) -> Result<String, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("absent".to_string());
        }
        Err(error) => return Err(format!("could not inspect repository state ({error})")),
    };
    if metadata.file_type().is_symlink() {
        return Err("repository state path must not be a symlink".to_string());
    }
    Ok(metadata_identity(&metadata))
}

fn metadata_identity(metadata: &Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            metadata.len(),
            metadata.mtime(),
            metadata.ctime(),
        )
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        format!("{}:{modified}", metadata.len())
    }
}

pub(crate) fn resolve_binary(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is unavailable".to_string())?;
    for directory in std::env::split_paths(&path) {
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory.as_path()
        };
        let candidate = directory.join(name);
        let metadata = match std::fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.file_type().is_file() || !is_executable(&metadata) {
            continue;
        }
        return std::fs::canonicalize(&candidate)
            .map_err(|error| format!("could not resolve {name} binary ({error})"));
    }
    Err(format!("{name} binary was not found on PATH"))
}

fn is_executable(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn binary_identity(path: &Path) -> Result<String, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("could not canonicalize binary ({error})"))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("could not inspect binary ({error})"))?;
    if !metadata.file_type().is_file() || !is_executable(&metadata) {
        return Err("resolved binary is not executable regular file".to_string());
    }
    Ok(format!(
        "{}:{}",
        canonical.display(),
        metadata_identity(&metadata)
    ))
}

fn git_output(
    root: &Path,
    git_binary: &Path,
    arguments: &[&str],
    deadline: Instant,
) -> Result<String, String> {
    let capture = run_git(root, git_binary, arguments, deadline)?;
    if capture.code != Some(0) {
        return Err(format!(
            "git {} failed",
            arguments.first().copied().unwrap_or("command")
        ));
    }
    clean_stdout(&capture.stdout)
}

fn run_git(
    root: &Path,
    git_binary: &Path,
    arguments: &[&str],
    deadline: Instant,
) -> Result<GitCapture, String> {
    let mut command = Command::new(git_binary);
    command
        .current_dir(root)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let capture = runner::run_details_with_deadline(command, deadline).ok_or_else(|| {
        format!(
            "git {} could not be completed before the deadline",
            arguments.first().copied().unwrap_or("command")
        )
    })?;
    if capture.process_group_survived {
        return Err("git process-group cleanup could not be verified".to_string());
    }
    Ok(GitCapture {
        code: capture.code,
        stdout: capture.stdout,
    })
}

fn clean_stdout(stdout: &[u8]) -> Result<String, String> {
    let text = String::from_utf8(stdout.to_vec())
        .map_err(|_| "git returned non-UTF-8 output".to_string())?;
    let text = text.trim_end_matches(['\r', '\n']).to_string();
    if text.is_empty() || text.chars().any(|character| character.is_control()) {
        return Err("git returned empty or unsafe output".to_string());
    }
    Ok(text)
}

fn validate_object_id(value: &str) -> Result<(), String> {
    let length = value.len();
    if !matches!(length, 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("git returned a non-canonical object identity".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "commit/tests.rs"]
mod tests;
