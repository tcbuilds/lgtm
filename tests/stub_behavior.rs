use std::process::Command;

/// Run the compiled `lgtm` binary with the given arguments and return its
/// exit code and captured stderr.
fn run(args: &[&str]) -> (i32, String) {
    let (code, _stdout, stderr) = run_full(args);
    (code, stderr)
}

/// Run the binary and return its exit code, stdout, and stderr.
fn run_full(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(args)
        .output()
        .expect("lgtm binary should execute");
    let code = output
        .status
        .code()
        .expect("process should exit with a code, not a signal");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    (code, stdout, stderr)
}

/// Every stub must fail safe: exit 0 so a stub never blocks an agent session,
/// and announce itself on stderr so the missing implementation is visible.
#[test]
fn stubs_exit_zero_and_report_on_stderr() {
    let cases = [
        (vec!["init"], "not yet implemented: init\n"),
        (
            vec!["hook", "session-start"],
            "not yet implemented: hook session-start\n",
        ),
        (vec!["doctor"], "not yet implemented: doctor\n"),
        (vec!["compile"], "not yet implemented: compile\n"),
        (vec!["report"], "not yet implemented: report\n"),
    ];
    for (args, expected_stderr) in cases {
        let (code, stderr) = run(&args);
        assert_eq!(code, 0, "stub {args:?} must exit 0 to fail safe");
        assert_eq!(
            stderr, expected_stderr,
            "stub {args:?} must report the exact unimplemented line"
        );
    }
}

/// `compile --validate` is no longer a stub: it validates the embedded
/// registry, prints a summary table on stdout, and exits 0.
#[test]
fn compile_validate_prints_summary_and_exits_zero() {
    let (code, stdout, _stderr) = run_full(&["compile", "--validate"]);
    assert_eq!(code, 0, "valid registry must exit 0");
    assert!(
        stdout.contains("ENFORCEMENT"),
        "summary table header must appear on stdout"
    );
    assert!(
        stdout.contains("no-committed-secrets"),
        "summary must list seed rule ids"
    );
    assert!(
        stdout.contains("3 rules validated."),
        "summary must report the validated rule count"
    );
}
