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

#[test]
fn generated_jev_scout_previews_batches_and_never_invents_matches() {
    let repo = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--agent", "pi", "--accept-guesses"])
        .env("HOME", repo.path())
        .current_dir(repo.path());
    assert!(run_bounded(&mut init).success());
    let extension = repo.path().join(".pi/extensions/lgtm.ts");
    let harness =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi/jev_scout.cjs");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .current_dir(repo.path())
        .env("HOME", repo.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev scouting failed"
    );
}

#[test]
fn generated_jev_replay_preflight_covers_versioned_real_cases() {
    let home = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--global"])
        .env("HOME", home.path())
        .current_dir(home.path());
    assert!(run_bounded(&mut init).success());
    let extension = home.path().join(".pi/agent/extensions/lgtm.ts");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest.join("tests/fixtures/pi/jev_replay.cjs");
    let corpus = manifest.join("tests/fixtures/pi/jev_replay_corpus.json");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .arg(&corpus)
        .current_dir(manifest)
        .env("HOME", home.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev replay preflight failed"
    );
}

#[test]
fn generated_jev_review_flags_are_independent_and_advisory() {
    let home = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--global"])
        .env("HOME", home.path())
        .current_dir(home.path());
    assert!(run_bounded(&mut init).success());
    let extension = home.path().join(".pi/agent/extensions/lgtm.ts");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest.join("tests/fixtures/pi/jev_review.cjs");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .current_dir(manifest)
        .env("HOME", home.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev review failed"
    );
}

#[test]
fn generated_jev_scope_advice_never_claims_verification() {
    let home = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--global"])
        .env("HOME", home.path())
        .current_dir(home.path());
    assert!(run_bounded(&mut init).success());
    let extension = home.path().join(".pi/agent/extensions/lgtm.ts");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest.join("tests/fixtures/pi/jev_scope.cjs");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .current_dir(manifest)
        .env("HOME", home.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev scope advice failed"
    );
}

#[test]
fn generated_jev_triage_minimizes_before_transport() {
    let home = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--global"])
        .env("HOME", home.path())
        .current_dir(home.path());
    assert!(run_bounded(&mut init).success());
    let extension = home.path().join(".pi/agent/extensions/lgtm.ts");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest.join("tests/fixtures/pi/jev_triage.cjs");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .current_dir(manifest)
        .env("HOME", home.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev triage failed"
    );
}

#[test]
fn generated_jev_compaction_advice_cannot_compact() {
    let home = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let mut init = Command::new(binary);
    init.args(["init", "--global"])
        .env("HOME", home.path())
        .current_dir(home.path());
    assert!(run_bounded(&mut init).success());
    let extension = home.path().join(".pi/agent/extensions/lgtm.ts");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest.join("tests/fixtures/pi/jev_compaction.cjs");
    let mut node = Command::new("node");
    node.arg(harness)
        .arg(&extension)
        .current_dir(manifest)
        .env("HOME", home.path());
    assert!(
        run_bounded(&mut node).success(),
        "generated Jev compaction advice failed"
    );
}
