//! Integration checks for Jev tools in the actual generated Pi extension.

use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::TempRepo;

fn run_bounded(command: &mut Command) -> ExitStatus {
    let mut child = command
        .stdout(Stdio::null())
        .spawn()
        .expect("start integration process");
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        if let Some(status) = child.try_wait().expect("observe integration process") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out integration process");
            child.wait().expect("reap integration process");
            panic!("integration process exceeded 35 seconds");
        }
        // This integration-only poll supervises a subprocess, not application timing.
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn generated_jev_tool_is_default_on_private_bounded_and_optional() {
    for scope in ["project", "global", "both"] {
        let repo = TempRepo::new();
        let binary = env!("CARGO_BIN_EXE_lgtm");
        if scope == "both" {
            let mut global = Command::new(binary);
            global
                .args(["init", "--global"])
                .env("HOME", repo.path())
                .current_dir(repo.path());
            assert!(run_bounded(&mut global).success());
        }
        let mut init = Command::new(binary);
        init.arg("init");
        if scope == "global" {
            init.arg("--global");
        } else {
            init.args(["--agent", "pi", "--accept-guesses"]);
        }
        assert!(run_bounded(init.env("HOME", repo.path()).current_dir(repo.path())).success());
        let extension = if scope == "global" {
            repo.path().join(".pi/agent/extensions/lgtm.ts")
        } else {
            repo.path().join(".pi/extensions/lgtm.ts")
        };
        let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pi/jev_integration.cjs");
        let mut node = Command::new("node");
        node.arg(harness)
            .arg(&extension)
            .current_dir(repo.path())
            .env("HOME", repo.path());
        if scope == "both" {
            node.arg(repo.path().join(".pi/agent/extensions/lgtm.ts"));
        }
        assert!(
            run_bounded(&mut node).success(),
            "generated Jev integration failed for {scope}"
        );
    }
}
