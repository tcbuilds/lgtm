use super::*;

#[test]
fn incomplete_overlapping_and_oversized_windows_stay_unverified() {
    for case in [
        "pending",
        "overlap",
        "oversized",
        "symlink",
        "duplicate",
        "wrong-command",
        "missing-id",
    ] {
        let repo = tracked_repo();
        let script = "printf changed > clean.txt";
        if case == "oversized" {
            let file = File::create(repo.path().join("large.txt")).unwrap();
            file.set_len(8 * 1024 * 1024 + 1).unwrap();
        }
        if case == "symlink" {
            std::os::unix::fs::symlink("clean.txt", repo.path().join("link.txt")).unwrap();
        }
        let call = if case == "missing-id" { "" } else { "call-a" };
        run_hook(&repo, "pre-tool-use", call, script);
        if case == "overlap" {
            run_hook(&repo, "pre-tool-use", "call-b", script);
        }
        run_shell_script(&repo, script);
        if case != "pending" {
            let command = if case == "wrong-command" {
                "different"
            } else {
                script
            };
            run_hook(&repo, "post-tool-use", "call-a", command);
        }
        if case == "duplicate" {
            run_hook(&repo, "post-tool-use", "call-a", script);
        } else {
            assert!(
                edited_paths(&read_records(&repo)).is_empty(),
                "{case} claimed paths"
            );
        }
        assert_tracking_uncertain(&repo);
        for record in read_records(&repo) {
            assert!(!record["session_id"].as_str().is_some_and(str::is_empty));
            assert_ne!(record["persistence_failed"], true);
        }
    }
}

#[test]
fn mode_changes_and_failed_shell_edits_are_observed() {
    use std::os::unix::fs::PermissionsExt;
    let repo = tracked_repo();
    let script = "chmod +x clean.txt; printf changed > dirty.txt; exit 1";
    run_hook(&repo, "pre-tool-use", "failed-call", script);
    let mut command = Command::new("sh");
    command.current_dir(repo.path()).args(["-c", script]);
    assert!(!run_bounded(command, None).status.success());
    assert_ne!(
        fs::metadata(repo.path().join("clean.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    let payload = json!({
        "cwd":repo.path(), "session_id":SESSION_ID, "tool_use_id":"failed-call",
        "hook_event_name":"PostToolUseFailure", "tool_name":"Bash",
        "tool_input":{"command":script}
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command
        .current_dir(repo.path())
        .args(["hook", "post-tool-use"]);
    let post = run_bounded(command, Some(&payload.to_string()));
    assert!(post.status.success() && post.stdout.is_empty());
    assert_eq!(
        edited_paths(&read_records(&repo)),
        BTreeSet::from(["clean.txt".to_string(), "dirty.txt".to_string()])
    );
}

#[test]
fn shell_post_without_a_matching_pre_never_attributes_paths() {
    for (case, pre_tool_use_id, post_tool_use_id) in [
        ("without-pre", None, "post-only"),
        ("mismatched-id", Some("pre-id"), "post-id"),
    ] {
        let repo = tracked_repo();
        let path = format!("uncertain-{case}.txt");
        let script = format!("printf '%s\\n' changed > {path}");
        if let Some(tool_use_id) = pre_tool_use_id {
            let pre = run_hook(&repo, "pre-tool-use", tool_use_id, &script);
            assert!(
                pre.status.success(),
                "pre-tool-use failed: {:?}",
                pre.stderr
            );
            assert!(
                pre.stdout.is_empty(),
                "allowed Bash pre-hook should be silent"
            );
        }

        run_shell_script(&repo, &script);
        let post = run_hook(&repo, "post-tool-use", post_tool_use_id, &script);
        assert!(
            post.status.success(),
            "post-tool-use failed: {:?}",
            post.stderr
        );
        let records = read_records(&repo);
        assert!(
            records.iter().all(|record| record["edited_file"].is_null()),
            "{case} must not attribute uncertain shell changes: {records:?}"
        );
        assert_tracking_uncertain(&repo);
    }
}

#[test]
fn cross_session_reset_does_not_clear_outstanding_shell_calls() {
    let repo = tracked_repo();
    let script = "printf changed > clean.txt";
    run_hook(&repo, "pre-tool-use", "a", script);
    run_hook(&repo, "pre-tool-use", "a-overlap", script);
    let event = |name: &str, session: &str, id: &str| {
        let payload = json!({"cwd":repo.path(), "session_id":session, "tool_use_id":id,
            "tool_name":"Bash","tool_input":{"command":script}});
        let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
        command.current_dir(repo.path()).args(["hook", name]);
        run_bounded(command, Some(&payload.to_string()))
    };
    event("pre-tool-use", "session-b", "b");
    run_shell_script(&repo, script);
    event("post-tool-use", "session-b", "b");
    assert!(edited_paths(&read_records(&repo)).is_empty());
    assert_tracking_uncertain(&repo);
    run_hook(&repo, "post-tool-use", "a", script);
    run_hook(&repo, "post-tool-use", "a-overlap", script);
    event("pre-tool-use", "session-c", "c");
    repo.write("clean.txt", "next session edit");
    event("post-tool-use", "session-c", "c");
    assert_eq!(
        edited_paths(&read_records(&repo)),
        BTreeSet::from(["clean.txt".to_string()])
    );
}

#[test]
fn managed_refresh_adds_failure_hook_once_and_preserves_opt_out() {
    let repo = tracked_repo();
    let home = TempRepo::new();
    let run = |arguments: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
        command
            .current_dir(repo.path())
            .env("HOME", home.path())
            .args(arguments);
        let output = run_bounded(command, None);
        assert!(output.status.success(), "{output:?}");
    };
    run(&["init", "--agent", "claude", "--accept-guesses"]);
    let mut settings = repo.read_json(".claude/settings.json");
    settings["hooks"]
        .as_object_mut()
        .unwrap()
        .remove("PostToolUseFailure");
    settings["hooks"]["PostToolUse"][0]["matcher"] = json!("Edit|Write");
    let original = settings["hooks"]["PostToolUse"][0]["hooks"][0].clone();
    repo.write(".claude/settings.json", &settings.to_string());
    run(&["refresh"]);
    settings = repo.read_json(".claude/settings.json");
    assert_eq!(
        settings["hooks"]["PostToolUseFailure"][0]["matcher"],
        "Bash"
    );
    assert_eq!(
        settings["hooks"]["PostToolUseFailure"][0]["hooks"][0],
        original
    );
    settings["hooks"]
        .as_object_mut()
        .unwrap()
        .remove("PostToolUseFailure");
    repo.write(".claude/settings.json", &settings.to_string());
    run(&["refresh"]);
    assert!(
        repo.read_json(".claude/settings.json")["hooks"]
            .get("PostToolUseFailure")
            .is_none()
    );
}

#[test]
fn pi_normalization_preserves_shell_call_identity() {
    let repo = tracked_repo();
    let home = TempRepo::new();
    let mut init = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    init.current_dir(repo.path())
        .env("HOME", home.path())
        .args(["init", "--agent", "pi", "--accept-guesses"]);
    assert!(run_bounded(init, None).status.success());
    let script = "printf changed > clean.txt";
    for (event, kind) in [
        ("pre-tool-use", "tool_call"),
        ("post-tool-use", "tool_result"),
    ] {
        let payload = json!({"type":kind,"cwd":repo.path(),"sessionId":SESSION_ID,
            "toolCallId":"pi-call","toolName":"bash","input":{"command":script}});
        let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
        command
            .current_dir(repo.path())
            .args(["hook", event, "--adapter", "pi"]);
        let output = run_bounded(command, Some(&payload.to_string()));
        if event == "pre-tool-use" {
            assert!(output.status.success(), "{output:?}");
            run_shell_script(&repo, script);
        }
    }
    assert_eq!(
        edited_paths(&read_records(&repo)),
        BTreeSet::from(["clean.txt".to_string()])
    );
}
