//! Native scanner/CLI coverage. Fixture values are synthetic, not credentials.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn bounded(command: Command, input: Option<&str>) -> Output {
    try_bounded(command, input).expect("child starts")
}

fn try_bounded(mut command: Command, input: Option<&str>) -> Option<Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("input writes");
    } else {
        drop(child.stdin.take());
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("child status").is_some() {
            return Some(child.wait_with_output().expect("child output"));
        }
        if Instant::now() >= deadline {
            child.kill().expect("timed-out child killed");
            child.wait().expect("timed-out child reaped");
            panic!("fixture command exceeded 60 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct Repo(PathBuf);
impl Repo {
    fn new() -> Option<Self> {
        let mut version = Command::new("gitleaks");
        version.arg("version");
        if !try_bounded(version, None).is_some_and(|output| output.status.success()) {
            eprintln!("native guarded-commit test skipped: gitleaks unavailable");
            return None;
        }
        let repo = Self(std::env::temp_dir().join(format!(
            "lgtm-guarded-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&repo.0).expect("fixture directory");
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.name", "LGTM fixture"]);
        repo.git(&[
            "config",
            "user.email",
            "254259785+tcbuilds@users.noreply.github.com",
        ]);
        repo.write("base.txt", "initial\n");
        repo.git(&["add", "base.txt"]);
        repo.git(&["commit", "-qm", "initial"]);
        let synthetic = format!("{:x}", Sha256::digest(b"LGTM synthetic heuristic fixture"));
        repo.write("app.conf", &format!("api_key = \"{synthetic}\"\n"));
        repo.git(&["add", "app.conf"]);
        Some(repo)
    }
    fn write(&self, path: &str, content: &str) {
        let target = self.0.join(path);
        std::fs::create_dir_all(target.parent().expect("parent")).expect("directory");
        std::fs::write(target, content).expect("fixture writes");
    }
    fn git(&self, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.current_dir(&self.0).args(args);
        let output = bounded(command, None);
        assert!(output.status.success(), "fixture git failed");
        output
    }
    fn head(&self) -> Vec<u8> {
        self.git(&["rev-parse", "HEAD"]).stdout
    }
    fn hook(&self, command: &str, mode: Value) -> Value {
        let payload = json!({
            "cwd":self.0,"session_id":"claude-approval-test","tool_name":"Bash",
            "permission_mode":mode,
            "tool_input":{"command":command,"description":"keep description","timeout":120000}
        });
        let mut cli = Command::new(env!("CARGO_BIN_EXE_lgtm"));
        cli.args(["hook", "pre-tool-use"]);
        let output = bounded(cli, Some(&payload.to_string()));
        assert!(
            output.status.success(),
            "hook failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("decision JSON")
    }
    fn approval_command(&self) -> String {
        let response = self.hook("git commit -m fixture", json!("default"));
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"], "ask",
            "{response}"
        );
        let input = &response["hookSpecificOutput"]["updatedInput"];
        assert_eq!(input["description"], "keep description");
        assert_eq!(input["timeout"], 120000);
        input["command"]
            .as_str()
            .expect("replacement command")
            .to_owned()
    }
    fn execute(&self, command: &str) -> Output {
        let argv = shlex::split(command).expect("canonical quoted command");
        let mut cli = Command::new(env!("CARGO_BIN_EXE_lgtm"));
        cli.current_dir(&self.0).args(&argv[1..]);
        bounded(cli, None)
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("fixture cleanup");
    }
}

#[test]
fn literal_wrapper_name_in_a_commit_message_is_not_a_wrapper_call() {
    let Some(repo) = Repo::new() else { return };
    let response = repo.hook("git commit -m 'document guarded-commit'", json!("default"));
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn failed_repository_command_never_prompts() {
    let Some(repo) = Repo::new() else { return };
    let config = json!({
        "version":"2", "profile":"default", "disabled_rules":[], "severity_overrides":{},
        "workspaces":[{
            "id":"fixture", "language":"rust", "root":".", "coverage":[],
            "commands":[{"argv":["git","lgtm-nonexistent-subcommand"], "cwd":".",
                "purpose":"test", "tier":"full", "source":"discovery",
                "confidence":"high", "timeout_seconds":5}]
        }]
    });
    repo.write(".lgtm/config.json", &config.to_string());
    let response = repo.hook("git commit -m fixture", json!("default"));
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        response.to_string().contains("lgtm-nonexistent-subcommand"),
        "{response}"
    );
}

#[cfg(unix)]
#[test]
fn git_hook_failure_is_visible_and_does_not_create_a_commit() {
    use std::os::unix::fs::PermissionsExt;
    let Some(repo) = Repo::new() else { return };
    let command = repo.approval_command();
    repo.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 7\n");
    std::fs::set_permissions(
        repo.0.join(".git/hooks/pre-commit"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("hook executable");
    let before = repo.head();
    let output = repo.execute(&command);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Git execution failed"));
    assert_eq!(repo.head(), before);
}

#[test]
fn native_ask_rewrites_all_input_and_direct_wrapper_requires_another_ask() {
    let Some(repo) = Repo::new() else { return };
    let command = repo.approval_command();
    let response = repo.hook(&command, json!("default"));
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "ask");
    assert_eq!(
        response["hookSpecificOutput"]["updatedInput"]["command"],
        command
    );
}

#[test]
fn unchanged_candidate_commits_and_replay_is_denied() {
    let Some(repo) = Repo::new() else { return };
    let command = repo.approval_command();
    let before = repo.head();
    let output = repo.execute(&command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(repo.head(), before);
    assert!(!repo.execute(&command).status.success());
}

#[test]
fn candidate_and_policy_mutations_prevent_git_execution() {
    for mutation in [
        "index",
        "config",
        "ignore",
        "head",
        "policy",
        "waivers",
        "execution-policy",
    ] {
        let Some(repo) = Repo::new() else { return };
        let command = repo.approval_command();
        match mutation {
            "index" => {
                repo.write("app.conf", "clean changed candidate\n");
                repo.git(&["add", "app.conf"]);
            }
            "config" => repo.write(".gitleaks.toml", "[extend]\nuseDefault = true\n"),
            "ignore" => repo.write(".gitleaksignore", "# changed scanner policy\n"),
            "head" => {
                repo.git(&["commit", "-qm", "changed outside prompt"]);
            }
            "policy" => repo.write(".lgtm/config.json", "{}\n"),
            "waivers" => repo.write(".lgtm/waivers.json", "[]\n"),
            "execution-policy" => repo.write(".lgtm/execpolicy.json", "{}\n"),
            _ => unreachable!(),
        }
        let before = repo.head();
        assert!(
            !repo.execute(&command).status.success(),
            "mutation {mutation} allowed"
        );
        assert_eq!(
            repo.head(),
            before,
            "Git executed after mutation {mutation}"
        );
    }
}

#[test]
fn unsafe_or_unknown_permission_modes_never_ask() {
    let Some(repo) = Repo::new() else { return };
    let command = repo.approval_command();
    for mode in [
        json!("bypassPermissions"),
        json!("dontAsk"),
        json!("auto"),
        json!("plan"),
        json!("unknown"),
        Value::Null,
    ] {
        for invocation in ["git commit -m fixture", &command] {
            let response = repo.hook(invocation, mode.clone());
            assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
        }
    }
}

#[test]
fn known_credentials_and_custom_generic_rules_do_not_prompt() {
    let Some(repo) = Repo::new() else { return };
    let key = ["AKIA", "Z3ROBME2X7HGKLMN"].concat();
    repo.write("provider.conf", &format!("key={key}\n"));
    repo.git(&["add", "provider.conf"]);
    let response = repo.hook("git commit -m fixture", json!("default"));
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(!response.to_string().contains(&key));
    repo.git(&["reset", "--", "provider.conf"]);
    repo.write(".gitleaks.toml", "[extend]\nuseDefault = true\n");
    let response = repo.hook("git commit -m fixture", json!("default"));
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn tampered_requests_and_shell_wrappers_do_not_execute() {
    let Some(repo) = Repo::new() else { return };
    let command = repo.approval_command();
    let args = shlex::split(&command).expect("argv");
    for key in [
        "identity",
        "executable_digest",
        "argv",
        "approved",
        "version",
    ] {
        let mut request: Value = serde_json::from_str(&args[3]).expect("request");
        request[key] = match key {
            "argv" => json!(["git", "commit", "-am", "wrong"]),
            "approved" => json!(true),
            "version" => json!(2),
            _ => json!("0".repeat(64)),
        };
        let altered = shlex::try_join([
            args[0].as_str(),
            "guarded-commit",
            "--request",
            &request.to_string(),
        ])
        .expect("quoted");
        let before = repo.head();
        assert!(!repo.execute(&altered).status.success());
        assert_eq!(repo.head(), before);
    }
    for altered in [
        format!("{command}; echo extra"),
        format!("sh -c {}", shlex::try_quote(&command).expect("quoted")),
    ] {
        let response = repo.hook(&altered, json!("default"));
        assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
    }
}
