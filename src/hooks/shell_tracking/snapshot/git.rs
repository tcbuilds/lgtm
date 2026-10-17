//! Bounded, names-only Git queries for shell snapshots.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use super::{
    MAX_PATHS, check_deadline, is_evidence_path, validate_head_identity, validate_relative_path,
};

const MAX_GIT_OUTPUT_BYTES: u64 = 1024 * 1024;
const GIT_CAPTURE_LIMIT: u64 = MAX_GIT_OUTPUT_BYTES + 1;

struct GitOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
}

pub(super) fn head_identity(root: &Path, deadline: Instant) -> Result<String, String> {
    let work_tree = run_git(root, &["rev-parse", "--is-inside-work-tree"], deadline)?;
    if work_tree.code != Some(0) || work_tree.stdout != b"true\n" {
        return Err("path is not a Git work tree".to_string());
    }

    let prefix = run_git(root, &["rev-parse", "--show-prefix"], deadline)?;
    if prefix.code != Some(0) || prefix.stdout != b"\n" {
        return Err("repository root must be the Git work-tree root".to_string());
    }

    let head = run_git(
        root,
        &["rev-parse", "--verify", "--quiet", "HEAD"],
        deadline,
    )?;
    match head.code {
        Some(0) => {
            let identity = git_line(&head.stdout, "HEAD identity")?;
            validate_head_identity(identity)?;
            Ok(identity.to_string())
        }
        Some(1) => {
            let symbolic = run_git(root, &["symbolic-ref", "-q", "HEAD"], deadline)?;
            if symbolic.code != Some(0) {
                return Err("HEAD is unresolved outside an unborn branch".to_string());
            }
            let reference = git_line(&symbolic.stdout, "unborn HEAD reference")?;
            if !reference.starts_with("refs/heads/") || reference.contains('\0') {
                return Err("Git returned an invalid unborn HEAD reference".to_string());
            }
            Ok(format!("unborn:{reference}"))
        }
        _ => Err("could not resolve Git HEAD".to_string()),
    }
}

fn run_git(root: &Path, arguments: &[&str], deadline: Instant) -> Result<GitOutput, String> {
    check_deadline(deadline)?;
    let mut command = Command::new("git");
    command
        .args(["--no-pager", "-c", "core.fsmonitor=false"])
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let capture = crate::checks::gitleaks::runner::run_details_with_deadline_and_limit(
        command,
        deadline,
        GIT_CAPTURE_LIMIT,
    )
    .ok_or_else(|| {
        format!(
            "git {} did not complete before the snapshot deadline",
            arguments.first().copied().unwrap_or("command")
        )
    })?;
    if capture.process_group_survived {
        return Err("Git process-group cleanup could not be verified".to_string());
    }
    if capture.stdout.len() as u64 + capture.stderr.len() as u64 > MAX_GIT_OUTPUT_BYTES {
        return Err(format!(
            "git {} output exceeds the {MAX_GIT_OUTPUT_BYTES}-byte limit",
            arguments.first().copied().unwrap_or("command")
        ));
    }
    check_deadline(deadline)?;
    Ok(GitOutput {
        code: capture.code,
        stdout: capture.stdout,
    })
}

fn git_line<'a>(output: &'a [u8], label: &str) -> Result<&'a str, String> {
    let output = output
        .strip_suffix(b"\n")
        .ok_or_else(|| format!("Git returned an unterminated {label}"))?;
    let line =
        std::str::from_utf8(output).map_err(|_| format!("Git returned a non-UTF-8 {label}"))?;
    if line.is_empty() || line.chars().any(char::is_control) {
        return Err(format!("Git returned an invalid {label}"));
    }
    Ok(line)
}

pub(super) fn collect_dirty_paths(
    root: &Path,
    deadline: Instant,
) -> Result<BTreeSet<String>, String> {
    let commands: [&[&str]; 3] = [
        &["diff", "--no-ext-diff", "--no-renames", "--name-only", "-z"],
        &[
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-renames",
            "--name-only",
            "-z",
        ],
        &["ls-files", "--others", "--exclude-standard", "-z"],
    ];
    let mut paths = BTreeSet::new();
    let mut output_bytes = 0_u64;

    for arguments in commands {
        let output = run_git(root, arguments, deadline)?;
        if output.code != Some(0) {
            return Err(format!(
                "git {} failed while collecting dirty paths",
                arguments.first().copied().unwrap_or("command")
            ));
        }
        output_bytes = output_bytes.saturating_add(output.stdout.len() as u64);
        if output_bytes > MAX_GIT_OUTPUT_BYTES {
            return Err(format!(
                "dirty path output exceeds the {MAX_GIT_OUTPUT_BYTES}-byte limit"
            ));
        }
        parse_paths(&output.stdout, &mut paths)?;
    }
    Ok(paths)
}

fn parse_paths(output: &[u8], paths: &mut BTreeSet<String>) -> Result<(), String> {
    if output.is_empty() {
        return Ok(());
    }
    if !output.ends_with(&[0]) {
        return Err("Git returned an unterminated NUL-delimited path list".to_string());
    }

    for raw_path in output[..output.len() - 1].split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            return Err("Git returned an empty dirty path".to_string());
        }
        let path = std::str::from_utf8(raw_path)
            .map_err(|_| "Git returned a non-UTF-8 dirty path".to_string())?;
        validate_relative_path(path)?;
        if !is_evidence_path(path)? {
            paths.insert(path.to_string());
            if paths.len() > MAX_PATHS {
                return Err(format!(
                    "dirty path count exceeds the {MAX_PATHS}-path limit"
                ));
            }
        }
    }
    Ok(())
}
