mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use common::TempRepo;
use serde_json::json;

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "production Ruff containment is Linux-only"
)]
#[test]
fn fake_ruff_blocks_python_edit_and_persists_both_rules() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "try:\n    work()\nexcept:\n    pass\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nprintf '%s' '[{\"code\":\"E722\",\"filename\":\"src/app.py\",\"message\":\"bare except\",\"location\":{\"row\":3}}]'\nexit 1\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-it",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = child.wait_with_output().expect("hook completes");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(stdout.contains("no-broad-exception-handling"));
    let ledger = repo.read(".lgtm/evidence/current-task.results.jsonl");
    assert!(ledger.contains("no-swallowed-errors"));
    assert!(ledger.contains("no-broad-exception-handling"));
}

#[cfg(target_os = "linux")]
fn wait_for_hook(mut child: std::process::Child) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().expect("hook wait status").is_some() {
            return child.wait_with_output().expect("hook output");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("hook did not finish before the bounded test deadline");
}

#[cfg(target_os = "linux")]
fn wait_for_file(path: &std::path::Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.trim().is_empty()
        {
            return contents;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "fixture did not create {} before the deadline",
        path.display()
    );
}

#[cfg(target_os = "linux")]
fn assert_process_gone(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("escaped Ruff descendant {pid} survived the bounded cleanup");
}

#[cfg(target_os = "linux")]
struct DescendantCleanup {
    marker: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for DescendantCleanup {
    fn drop(&mut self) {
        let Ok(pid) = std::fs::read_to_string(&self.marker)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .ok_or(())
        else {
            return;
        };
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        let pid_text = pid.to_string();
        let _ = Command::new("/bin/kill")
            .args(["-KILL", pid_text.as_str()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && std::path::Path::new(&format!("/proc/{pid}")).exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn escaped_ruff_descendant_makes_real_hook_unverified_and_is_reaped() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "print('ok')\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nmarker=\"$6.escaped-pid\"\n/usr/bin/setsid /bin/sh -c 'echo $$ > \"$1\"; exec /bin/sleep 120' ruff-descendant \"$marker\" &\ni=0\nwhile [ ! -s \"$marker\" ] && [ \"$i\" -lt 100 ]; do i=$((i + 1)); /bin/sleep 0.001; done\nprintf '%s' '[]'\nexit 0\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");
    let marker = repo.path().join("src/app.py.escaped-pid");
    let _cleanup = DescendantCleanup {
        marker: marker.clone(),
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-escaped-descendant",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = wait_for_hook(child);

    let pid = wait_for_file(&marker, Duration::from_secs(2))
        .trim()
        .parse::<u32>()
        .expect("descendant pid");
    assert_process_gone(pid, Duration::from_secs(2));
    assert!(output.status.success());
    let ledger = repo.read(".lgtm/evidence/current-task.results.jsonl");
    let ruff_result = ledger
        .lines()
        .find(|line| line.contains("\"check\":\"ruff.check\""))
        .expect("Ruff result persisted");
    assert!(ruff_result.contains("\"status\":\"unverified\""));
}

#[cfg(target_os = "linux")]
#[test]
fn clean_ruff_empty_json_passes_both_rules_through_real_hook() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "print('ok')\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nprintf '%s' '[]'\nexit 0\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-clean-empty-json",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = wait_for_hook(child);

    assert!(output.status.success());
    let passed_rules = repo
        .read(".lgtm/evidence/current-task.results.jsonl")
        .lines()
        .filter(|line| {
            line.contains("\"check\":\"ruff.check\"") && line.contains("\"status\":\"passed\"")
        })
        .count();
    assert_eq!(passed_rules, 2, "empty Ruff JSON must pass both rules");
}

#[cfg(target_os = "linux")]
#[test]
fn ruff_retains_its_one_megabyte_bounded_capture_limit() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "print('ok')\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nprintf '['\n/usr/bin/head -c 300000 /dev/zero | /usr/bin/tr '\\000' ' '\nprintf ']'\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-one-megabyte-capture",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = wait_for_hook(child);

    assert!(output.status.success());
    let passed_rules = repo
        .read(".lgtm/evidence/current-task.results.jsonl")
        .lines()
        .filter(|line| {
            line.contains("\"check\":\"ruff.check\"") && line.contains("\"status\":\"passed\"")
        })
        .count();
    assert_eq!(passed_rules, 2, "bounded valid Ruff JSON must be parsed");
}

#[cfg(target_os = "linux")]
#[test]
fn ruff_inherits_the_hook_environment_without_narrowing_it() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "print('ok')\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\n[ \"$LGTM_RUFF_ENV_SENTINEL\" = preserved ] || exit 1\nprintf '%s' '[]'\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .env("LGTM_RUFF_ENV_SENTINEL", "preserved")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-environment-preservation",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = wait_for_hook(child);
    assert!(output.status.success());
    let ledger = repo.read(".lgtm/evidence/current-task.results.jsonl");
    let ruff_results: Vec<_> = ledger
        .lines()
        .filter(|line| line.contains("\"check\":\"ruff.check\""))
        .collect();
    assert_eq!(ruff_results.len(), 2);
    assert!(
        ruff_results
            .iter()
            .all(|line| line.contains("\"status\":\"passed\""))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn truncated_ruff_capture_is_unverified_instead_of_parsed() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "print('ok')\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nprintf '%s' '[]'\n/usr/bin/head -c 1100000 /dev/zero | /usr/bin/tr '\\000' ' '\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-capture-truncation",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = wait_for_hook(child);
    assert!(output.status.success());
    let ledger = repo.read(".lgtm/evidence/current-task.results.jsonl");
    let ruff_results: Vec<_> = ledger
        .lines()
        .filter(|line| line.contains("\"check\":\"ruff.check\""))
        .collect();
    assert_eq!(ruff_results.len(), 2);
    assert!(
        ruff_results
            .iter()
            .all(|line| line.contains("\"status\":\"unverified\""))
    );
}
