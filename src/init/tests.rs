use super::*;

#[test]
fn build_config_uses_default_profile_and_empty_overrides() {
    let detection = Detection {
        languages: vec!["python".to_string()],
        required_commands: vec![("python".to_string(), vec!["pytest".to_string()])],
        is_git_repo: true,
    };
    let config = build_config(&detection);
    assert_eq!(config["profile"], json!("default"));
    assert_eq!(config["languages"], json!(["python"]));
    assert_eq!(config["disabled_rules"], json!([]));
    assert_eq!(config["severity_overrides"], json!({}));
    assert_eq!(config["required_commands"]["python"], json!(["pytest"]));
}

#[test]
fn merge_settings_into_empty_adds_all_five_events() {
    let merged = merge_settings(&Map::new());
    let hooks = merged["hooks"].as_object().expect("hooks object");
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "Stop",
    ] {
        assert!(hooks.contains_key(event), "missing event {event}");
    }
}

#[test]
fn merge_settings_preserves_unrelated_settings_and_hooks() {
    let existing = json!({
        "permissions": {"allow": ["Bash"]},
        "hooks": {
            "SessionStart": [
                {"hooks": [{"type": "command", "command": "other tool"}]}
            ]
        }
    });
    let existing = existing.as_object().expect("object").clone();

    let merged = merge_settings(&existing);
    assert_eq!(merged["permissions"], json!({"allow": ["Bash"]}));

    let session_start = merged["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart array");
    assert_eq!(
        session_start.len(),
        2,
        "unrelated hook preserved, lgtm added"
    );
    assert!(entry_runs_command(&session_start[0], "other tool"));
    assert!(entry_runs_command(
        &session_start[1],
        "lgtm hook session-start"
    ));
}

#[test]
fn merge_settings_is_idempotent() {
    let once = merge_settings(&Map::new());
    let twice = merge_settings(&once);
    assert_eq!(once, twice, "second merge must not add duplicate entries");
}

#[test]
fn pre_tool_use_entry_carries_matcher() {
    let merged = merge_settings(&Map::new());
    let pre = &merged["hooks"]["PreToolUse"][0];
    assert_eq!(pre["matcher"], json!("Edit|Write"));
    assert_eq!(pre["hooks"][0]["command"], json!("lgtm hook pre-tool-use"));
}

#[test]
fn session_start_entry_omits_matcher() {
    let merged = merge_settings(&Map::new());
    let entry = &merged["hooks"]["SessionStart"][0];
    assert!(
        entry.get("matcher").is_none(),
        "unmatched events omit matcher"
    );
}

#[test]
fn merge_settings_corrects_wrong_matcher_on_existing_lgtm_entry() {
    let existing = json!({
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "lgtm hook pre-tool-use"}]}
            ]
        }
    });
    let existing = existing.as_object().expect("object").clone();

    let merged = merge_settings(&existing);
    let entries = merged["hooks"]["PreToolUse"].as_array().expect("array");
    assert_eq!(
        entries.len(),
        1,
        "existing lgtm entry corrected, not duplicated"
    );
    assert_eq!(entries[0]["matcher"], json!("Edit|Write"));
}

#[test]
fn merge_settings_recognizes_path_qualified_lgtm_command() {
    let existing = json!({
        "hooks": {
            "Stop": [
                {"hooks": [{"type": "command", "command": "/usr/local/bin/lgtm hook stop"}]}
            ]
        }
    });
    let existing = existing.as_object().expect("object").clone();

    let merged = merge_settings(&existing);
    let entries = merged["hooks"]["Stop"].as_array().expect("array");
    assert_eq!(
        entries.len(),
        1,
        "path-qualified lgtm hook must not be duplicated"
    );
    assert_eq!(
        entries[0]["hooks"][0]["command"],
        json!("/usr/local/bin/lgtm hook stop"),
        "already-correct path-qualified entry is left as authored"
    );
}

#[test]
fn commands_match_tolerates_path_qualified_binary() {
    assert!(commands_match("lgtm hook stop", "lgtm hook stop"));
    assert!(commands_match("/usr/bin/lgtm hook stop", "lgtm hook stop"));
    assert!(commands_match("./bin/lgtm hook stop", "lgtm hook stop"));
    assert!(!commands_match("mylgtm hook stop", "lgtm hook stop"));
    assert!(!commands_match("lgtm hook start", "lgtm hook stop"));
}

#[test]
fn non_command_type_hook_does_not_suppress_lgtm_entry() {
    let existing = json!({
        "hooks": {
            "Stop": [
                {"hooks": [{"type": "notification", "command": "lgtm hook stop"}]}
            ]
        }
    });
    let existing = existing.as_object().expect("object").clone();

    let merged = merge_settings(&existing);
    let entries = merged["hooks"]["Stop"].as_array().expect("Stop array");
    assert_eq!(
        entries.len(),
        2,
        "a non-command hook with the same command must not suppress the required command hook"
    );
    let has_command_hook = entries.iter().any(|entry| {
        entry["hooks"][0]["type"] == json!("command")
            && entry["hooks"][0]["command"] == json!("lgtm hook stop")
    });
    assert!(
        has_command_hook,
        "the executable command-typed lgtm hook must be added"
    );
}

#[test]
fn entry_runs_command_requires_command_type() {
    let command_hook = json!({"hooks": [{"type": "command", "command": "lgtm hook stop"}]});
    assert!(entry_runs_command(&command_hook, "lgtm hook stop"));

    let non_command_hook =
        json!({"hooks": [{"type": "notification", "command": "lgtm hook stop"}]});
    assert!(!entry_runs_command(&non_command_hook, "lgtm hook stop"));
}

#[cfg(unix)]
#[test]
fn stage_write_copies_target_mode_onto_temp_before_commit() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("lgtm-stage-mode-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir creatable");

    let target = dir.join("settings.json");
    std::fs::write(&target, "{}\n").expect("target writable");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600 must succeed");

    let staged = stage_write(&target, b"{\"changed\": true}\n").expect("stage must succeed");

    let temp_mode = std::fs::metadata(&staged.temp_path)
        .expect("temp metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        temp_mode, 0o600,
        "the staged temp must inherit the existing target's restrictive mode before commit"
    );

    let temp_path = staged.temp_path.clone();
    drop(staged);
    assert!(
        !temp_path.exists(),
        "dropping an uncommitted StagedWrite must remove its temp file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn stage_write_creates_temp_at_0600_then_committed_new_file_is_0644() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("lgtm-stage-fresh-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir creatable");

    let target = dir.join("config.json");

    let staged = stage_write(&target, b"{\"fresh\": true}\n").expect("stage must succeed");

    let temp_mode = std::fs::metadata(&staged.temp_path)
        .expect("temp metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        temp_mode, 0o644,
        "a freshly-created target's temp must relax to the readable default after the 0600 write"
    );

    commit_write(staged).expect("commit must succeed");

    let committed_mode = std::fs::metadata(&target)
        .expect("committed metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        committed_mode, 0o644,
        "a committed file with no prior target must end at the readable 0644 default"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_is_ignored_honors_negation_ordering() {
    assert!(evidence_is_ignored(".lgtm/\n"));
    assert!(evidence_is_ignored(".lgtm/evidence/\n"));
    assert!(
        !evidence_is_ignored(".lgtm/\n!.lgtm/evidence/\n"),
        "a later negation of the evidence path flips the final effect to not-ignored"
    );
    assert!(
        evidence_is_ignored(".lgtm/\n!.lgtm/evidence/\n.lgtm/evidence/\n"),
        "a re-ignore after the negation restores the ignored effect"
    );
    assert!(!evidence_is_ignored("target/\n"));
}

/// Create a unique temporary directory for a `read_if_exists` test.
fn read_test_dir(label: &str) -> PathBuf {
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("lgtm-read-{label}-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir creatable");
    dir
}

#[test]
fn read_if_exists_returns_contents_for_a_regular_file() {
    let dir = read_test_dir("regular");
    let path = dir.join("config.json");
    std::fs::write(&path, "{\"profile\": \"default\"}\n").expect("target writable");

    let contents = read_if_exists(&path).expect("read must succeed");
    assert_eq!(contents.as_deref(), Some("{\"profile\": \"default\"}\n"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_if_exists_reports_absent_as_none() {
    let dir = read_test_dir("absent");
    let path = dir.join("config.json");

    let result = read_if_exists(&path).expect("absence is not an error");
    assert_eq!(result, None);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_if_exists_rejects_oversized_file() {
    let dir = read_test_dir("oversized");
    let path = dir.join("config.json");
    let payload = "x".repeat((MAX_READ_BYTES as usize) + 1);
    std::fs::write(&path, payload).expect("target writable");

    let error = read_if_exists(&path).expect_err("oversized file must be rejected");
    assert!(
        matches!(
            error,
            InitError::FileTooLarge { max_bytes, .. } if max_bytes == MAX_READ_BYTES
        ),
        "an oversized file must map to a non-retryable FileTooLarge, got {error:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file exactly at the cap must still be read; only strictly-larger files
/// are rejected, matching the `max + 1` read window.
#[test]
fn read_if_exists_accepts_file_at_the_cap() {
    let dir = read_test_dir("atcap");
    let path = dir.join("config.json");
    let payload = "x".repeat(MAX_READ_BYTES as usize);
    std::fs::write(&path, &payload).expect("target writable");

    let contents = read_if_exists(&path).expect("a file at the cap must be read");
    assert_eq!(contents.as_deref(), Some(payload.as_str()));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A FIFO planted where init expects a config must not hang and must not be
/// read: the atomic open treats a non-regular path as absent (`None`).
#[cfg(unix)]
#[test]
fn read_if_exists_treats_fifo_as_absent_without_hanging() {
    let dir = read_test_dir("fifo");
    let path = dir.join("config.json");
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .expect("path has no interior NUL");
    let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo must create the FIFO");

    let result = read_if_exists(&path).expect("a FIFO must not surface as an error");
    assert_eq!(
        result, None,
        "a planted FIFO must be treated as absent, never opened or blocked on"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A symlink planted where init expects a config must not be followed: the
/// atomic `O_NOFOLLOW` open treats it as absent (`None`) rather than reading
/// the target out of the repo.
#[cfg(unix)]
#[test]
fn read_if_exists_does_not_follow_symlink() {
    let dir = read_test_dir("symlink");
    let real = dir.join("real.json");
    std::fs::write(&real, "{\"secret\": true}\n").expect("target writable");
    let link = dir.join("config.json");
    std::os::unix::fs::symlink(&real, &link).expect("symlink creatable");

    let result = read_if_exists(&link).expect("a symlink must not surface as an error");
    assert_eq!(
        result, None,
        "a symlinked config must be treated as absent, never followed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
