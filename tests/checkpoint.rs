//! CLI installation and pre-compaction lifecycle coverage for the global checkpoint.

use std::process::Command;

mod common;
use common::TempRepo;

const EXTENSION: &str = ".pi/agent/extensions/lgtm-checkpoint.ts";

#[test]
fn every_init_variant_installs_one_global_checkpoint() {
    let variants: &[&[&str]] = &[
        &["init", "--accept-guesses"],
        &["init", "--agent", "pi", "--accept-guesses"],
        &["init", "--agent", "codex", "--accept-guesses"],
        &["init", "--rules-only"],
        &["init", "--rules-only", "--agent", "pi"],
        &["init", "--rules-only", "--agent", "codex"],
        &["init", "--global"],
    ];
    for args in variants {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        for _ in 0..2 {
            let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
                .args(*args)
                .current_dir(repo.path())
                .env("HOME", home.path())
                .output()
                .expect("init executes");
            assert!(output.status.success(), "{args:?}: {output:?}");
            assert_eq!(
                home.read(EXTENSION),
                include_str!("../templates/pi/checkpoint.ts")
            );
            assert!(!repo.exists(EXTENSION));
        }
    }
}

#[test]
fn dry_run_and_failed_init_do_not_install_a_checkpoint() {
    for args in [
        vec!["init", "--dry-run"],
        vec!["init", "--global", "--dry-run"],
        vec!["init", "--accept-guesses"],
    ] {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        if !args.contains(&"--dry-run") {
            repo.write(".lgtm/config.json", "invalid json");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(&args)
            .current_dir(repo.path())
            .env("HOME", home.path())
            .output()
            .expect("init executes");
        assert_eq!(output.status.success(), args.contains(&"--dry-run"));
        assert!(!home.exists(".pi"));
    }
}

#[test]
fn checkpoint_install_preserves_custom_content() {
    let home = TempRepo::new();
    home.write(EXTENSION, "// personal checkpoint\n");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--rules-only"])
        .current_dir(home.path())
        .env("HOME", home.path())
        .output()
        .expect("init executes");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(home.read(EXTENSION), "// personal checkpoint\n");
}

#[cfg(unix)]
#[test]
fn checkpoint_install_rejects_symlinks_before_repository_writes() {
    let home = TempRepo::new();
    let repo = TempRepo::new();
    home.write("outside.ts", "// do not change\n");
    std::fs::create_dir_all(home.path().join(".pi/agent/extensions")).unwrap();
    std::os::unix::fs::symlink(home.path().join("outside.ts"), home.path().join(EXTENSION))
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--accept-guesses"])
        .current_dir(repo.path())
        .env("HOME", home.path())
        .output()
        .expect("init executes");
    assert!(!output.status.success());
    assert!(!repo.exists(".lgtm"));
    assert_eq!(home.read("outside.ts"), "// do not change\n");
}

/// Absolute path to the tracked template, so V8 coverage maps to the real source file.
const CHECKPOINT_TEMPLATE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/templates/pi/checkpoint.ts");

/// Node harness that loads the template from CHECKPOINT_TEMPLATE, replaces its fs and
/// path imports with test globals, and runs one named scenario against real git and
/// real files in the current directory. The model registry and notifications are mocks.
const CHECKPOINT_HARNESS: &str = include_str!("fixtures/pi/checkpoint_harness.js");

/// Run one named harness scenario in a throwaway repository.
fn run_checkpoint_scenario(scenario: &str) {
    let repo = TempRepo::new();
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            CHECKPOINT_HARNESS,
            CHECKPOINT_TEMPLATE,
            scenario,
        ])
        .current_dir(repo.path())
        .output()
        .expect("Node executes");
    assert!(
        output.status.success(),
        "checkpoint scenario {scenario} failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("checkpoint scenario passed: {scenario}")),
        "checkpoint scenario {scenario} did not report success: {output:?}"
    );
}

#[test]
fn manual_compaction_and_toggle_are_respected() {
    run_checkpoint_scenario("manual_and_toggle");
}

#[test]
fn only_verified_exact_plan_lines_are_checked() {
    run_checkpoint_scenario("plan_evidence_guard");
}

#[test]
fn plan_task_records_are_bounded_and_validated() {
    run_checkpoint_scenario("plan_task_bounds");
}

#[test]
fn a_missing_plan_and_handoff_write_the_snapshot_only() {
    run_checkpoint_scenario("missing_files_snapshot_only");
}

#[test]
fn unusable_model_output_preserves_an_existing_handoff() {
    run_checkpoint_scenario("unusable_output_preserves_handoff");
}

#[test]
fn unusable_model_output_writes_the_fallback_without_a_handoff() {
    run_checkpoint_scenario("fallback_without_handoff");
}

#[test]
fn a_throwing_model_call_is_reported_without_files() {
    run_checkpoint_scenario("model_call_throws");
}

#[test]
fn a_working_directory_outside_git_is_skipped() {
    run_checkpoint_scenario("outside_git_repository");
}

#[test]
fn symlinks_directories_and_oversized_inputs_are_rejected() {
    run_checkpoint_scenario("unsafe_and_oversized_files");
}

#[test]
fn a_stale_handoff_moves_to_a_dated_file_without_overwriting() {
    run_checkpoint_scenario("stale_archive_collisions");
}

#[test]
fn archive_write_attempts_stay_bounded() {
    run_checkpoint_scenario("archive_attempt_bounds");
}

#[test]
fn archive_overflow_and_the_byte_budget_move_old_blocks_out() {
    run_checkpoint_scenario("archive_overflow_and_budget");
}

#[test]
fn concurrent_edits_and_aborts_never_overwrite_owner_changes() {
    run_checkpoint_scenario("concurrent_edits_and_abort");
}

#[test]
fn a_foreign_lock_blocks_the_checkpoint_and_lock_changes_survive() {
    run_checkpoint_scenario("lock_contention_and_release");
}

#[test]
fn write_failures_leave_no_partial_files() {
    run_checkpoint_scenario("write_errors_are_isolated");
}

#[test]
fn notification_failures_do_not_change_checkpoint_behavior() {
    run_checkpoint_scenario("notification_failures");
}

#[test]
fn unborn_degraded_and_unsafe_git_states_are_reported() {
    run_checkpoint_scenario("unborn_and_degraded_git");
}

#[test]
fn upstream_unpushed_and_detached_states_are_recorded() {
    run_checkpoint_scenario("upstream_and_detached_head");
}

#[test]
fn fenced_model_output_is_normalized_and_bounded() {
    run_checkpoint_scenario("model_response_shapes");
}

#[test]
fn evidence_rendering_is_bounded() {
    run_checkpoint_scenario("evidence_bounds");
}

#[test]
fn an_aborted_signal_stops_the_checkpoint() {
    run_checkpoint_scenario("aborted_signal_is_respected");
}

#[test]
fn unreadable_repository_paths_are_reported() {
    run_checkpoint_scenario("unreadable_paths_are_reported");
}
