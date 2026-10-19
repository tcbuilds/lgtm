use super::*;

#[cfg(unix)]
#[test]
fn init_preflight_rejects_unsafe_destinations_before_scaffolding() {
    // Symlink standing in for the extension directory.
    let scratch = Scratch::new();
    let outside = scratch.root().join("outside-extension");
    fs::create_dir_all(&outside).expect("outside");
    let link = path_in(&scratch.home(), ".pi/agent/extensions/jev-auto");
    symlink_at(&outside, &link);
    reject_init(&scratch, "jev-auto");
    assert!(
        fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
    assert!(
        fs::read_dir(&outside).expect("outside").next().is_none(),
        "target touched"
    );

    // Symlink standing in for the state directory.
    let scratch = Scratch::new();
    let outside_state = scratch.root().join("outside-state");
    fs::create_dir_all(&outside_state).expect("outside state");
    let link = path_in(&scratch.home(), ".local/state/lgtm/jev-auto");
    symlink_at(&outside_state, &link);
    reject_init(&scratch, "jev-auto");
    assert!(
        fs::read_dir(&outside_state)
            .expect("outside state")
            .next()
            .is_none()
    );

    // Symlink standing in for the entrypoint file.
    let scratch = Scratch::new();
    let outside_file = scratch.root().join("outside-index.ts");
    fs::write(&outside_file, "owner bytes").expect("outside file");
    symlink_at(&outside_file, &path_in(&scratch.home(), ENTRYPOINT));
    reject_init(&scratch, "index.ts");
    assert_eq!(
        fs::read_to_string(&outside_file).expect("file"),
        "owner bytes"
    );

    // Directory where the entrypoint file belongs.
    let scratch = Scratch::new();
    fs::create_dir_all(path_in(&scratch.home(), ENTRYPOINT)).expect("entrypoint dir");
    reject_init(&scratch, "index.ts");

    // Regular file where the extension directory belongs.
    let scratch = Scratch::new();
    write_file(
        &scratch.home(),
        ".pi/agent/extensions/jev-auto",
        "not a directory",
    );
    reject_init(&scratch, "jev-auto");
    assert_eq!(
        read_file(&scratch.home(), ".pi/agent/extensions/jev-auto"),
        "not a directory"
    );

    // Special file (Unix socket) where the entrypoint belongs.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        let scratch = Scratch::new();
        let home = scratch.home().join("long-socket-home-".repeat(8));
        let entrypoint = path_in(&home, ENTRYPOINT);
        assert!(entrypoint.as_os_str().as_encoded_bytes().len() > 108);
        fs::create_dir_all(entrypoint.parent().expect("parent")).expect("parent");
        // Bind a relative name in the child so long macOS HOME paths fit sun_path.
        let mut binder = Command::new("python3");
        binder
            .args([
                "-c",
                "import socket; s=socket.socket(socket.AF_UNIX); s.bind('index.ts')",
            ])
            .current_dir(entrypoint.parent().expect("parent"));
        let bound = run_bounded(&mut binder);
        assert!(bound.status.success(), "socket fixture: {}", text(&bound));
        let output = scratch.run_home(&["init"], &home);
        assert!(
            !output.status.success(),
            "socket accepted: {}",
            text(&output)
        );
        assert!(text(&output).contains("index.ts"), "{}", text(&output));
        assert_work_untouched(&scratch, "socket");
        assert!(
            fs::symlink_metadata(&entrypoint)
                .expect("socket")
                .file_type()
                .is_socket()
        );
    }
}

#[test]
fn init_preflight_rejects_invalid_receipts_before_scaffolding() {
    let index = sha256_hex(CURRENT_ENTRYPOINT.as_bytes());
    let gates = sha256_hex(CURRENT_HELPER.as_bytes());
    let receipts = [
        ("malformed", "{ this is not json".to_string()),
        (
            "unknown field",
            format!(
                "{{\"version\":1,\"index_sha256\":\"{index}\",\"gates_sha256\":\"{gates}\",\"extra\":true}}"
            ),
        ),
        (
            "wrong version",
            format!("{{\"version\":2,\"index_sha256\":\"{index}\",\"gates_sha256\":\"{gates}\"}}"),
        ),
        (
            "non-hex digest",
            format!(
                "{{\"version\":1,\"index_sha256\":\"not-a-digest\",\"gates_sha256\":\"{gates}\"}}"
            ),
        ),
    ];
    for (label, receipt) in receipts {
        let scratch = Scratch::new();
        write_file(&scratch.home(), RECEIPT, &receipt);
        reject_init(&scratch, "receipt");
        assert_eq!(
            read_file(&scratch.home(), RECEIPT),
            receipt,
            "{label}: overwritten"
        );
        assert_no_pair(&scratch.home(), label);
    }
}

#[test]
fn receipt_read_accepts_the_limit_and_rejects_oversized_or_invalid_text() {
    for length in [4096, 4097] {
        let scratch = Scratch::new();
        let receipt = receipt_for(CURRENT_ENTRYPOINT, CURRENT_HELPER);
        let padded = format!("{receipt}{}", " ".repeat(length - receipt.len()));
        write_file(&scratch.home(), RECEIPT, &padded);
        let output = scratch.run(&["init"]);
        if length == 4096 {
            assert!(
                output.status.success(),
                "receipt at limit: {}",
                text(&output)
            );
            assert_installed(&scratch.home(), "receipt at limit");
        } else {
            assert!(
                !output.status.success(),
                "oversized receipt: {}",
                text(&output)
            );
            assert_no_pair(&scratch.home(), "oversized receipt");
            assert_work_untouched(&scratch, "oversized receipt");
        }
        assert_eq!(read_file(&scratch.home(), RECEIPT), padded);
    }
    let scratch = Scratch::new();
    write_file(&scratch.home(), RECEIPT, "placeholder");
    fs::write(scratch.home().join(RECEIPT), [0xff]).expect("invalid UTF-8 fixture");
    reject_init(&scratch, "receipt");
    assert_eq!(
        fs::read(scratch.home().join(RECEIPT)).expect("receipt bytes"),
        [0xff]
    );
    assert_no_pair(&scratch.home(), "invalid UTF-8 receipt");
}

#[cfg(unix)]
#[test]
fn symlinked_home_root_is_accepted() {
    let scratch = Scratch::new();
    let real_home = scratch.root().join("real-home");
    fs::create_dir_all(&real_home).expect("real home");
    let linked_home = scratch.root().join("linked-home");
    symlink_at(&real_home, &linked_home);
    let output = scratch.run_home(&["refresh"], &linked_home);
    assert!(output.status.success(), "symlinked HOME: {}", text(&output));
    assert_installed(&real_home, "symlinked HOME");
    assert_installed(&linked_home, "symlinked HOME via link");
}

#[test]
fn unknown_or_partial_legacy_layouts_fail_without_creating_a_new_entrypoint() {
    // Unknown entrypoint alone; orphan helper alone.
    for (name, relative, custom) in [
        ("legacy entrypoint", LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT),
        ("orphan helper", LEGACY_HELPER, CUSTOM_HELPER),
    ] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), relative, custom);
        let output = scratch.run(&["init"]);
        assert!(!output.status.success(), "{name}: {}", text(&output));
        let file_name = relative.rsplit('/').next().expect("file name");
        assert_legacy_guidance(&output, file_name);
        assert_eq!(
            read_file(&scratch.home(), relative),
            custom,
            "{name} preserved"
        );
        assert_no_pair(&scratch.home(), name);
        assert_work_untouched(&scratch, name);
    }

    // Partial exact entrypoint, and mixed exact entrypoint with custom helper.
    for helper in [None, Some(CUSTOM_HELPER)] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT);
        if let Some(helper) = helper {
            write_file(&scratch.home(), LEGACY_HELPER, helper);
        }
        let output = scratch.run(&["init"]);
        assert!(
            !output.status.success(),
            "partial/mixed legacy: {}",
            text(&output)
        );
        assert!(text(&output).contains("jev-auto.ts"), "{}", text(&output));
        assert_eq!(
            read_file(&scratch.home(), LEGACY_ENTRYPOINT),
            CURRENT_ENTRYPOINT
        );
        assert_no_pair(&scratch.home(), "legacy fail");
        assert_work_untouched(&scratch, "legacy fail");
    }

    // No duplicates: an unknown legacy entrypoint stays the only one.
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    let _ = scratch.run(&["init"]);
    assert_eq!(
        dir_names(&path_in(&scratch.home(), ".pi/agent/extensions")),
        vec!["jev-auto.ts".to_string()],
        "unknown legacy gained a duplicate entrypoint"
    );
}

#[test]
fn canonical_legacy_with_incompatible_destination_fails_before_scaffolding() {
    for (index, helper) in [
        (CUSTOM_ENTRYPOINT, Some(CUSTOM_HELPER)),
        (CURRENT_ENTRYPOINT, None),
    ] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT);
        write_file(&scratch.home(), LEGACY_HELPER, CURRENT_HELPER);
        write_file(&scratch.home(), ENTRYPOINT, index);
        if let Some(helper) = helper {
            write_file(&scratch.home(), HELPER, helper);
        }
        let output = scratch.run(&["init"]);
        assert!(
            !output.status.success(),
            "conflicting migration: {}",
            text(&output)
        );
        assert_legacy_guidance(&output, "jev-auto.ts");
        assert_work_untouched(&scratch, "conflicting migration");
        assert_eq!(read_file(&scratch.home(), ENTRYPOINT), index);
        assert_eq!(
            read_file(&scratch.home(), LEGACY_ENTRYPOINT),
            CURRENT_ENTRYPOINT
        );
        assert_eq!(read_file(&scratch.home(), LEGACY_HELPER), CURRENT_HELPER);
        if let Some(helper) = helper {
            assert_eq!(read_file(&scratch.home(), HELPER), helper);
        } else {
            assert!(!exists(&scratch.home(), HELPER));
        }
        for path in [RECEIPT, LEGACY_BACKUP_ENTRYPOINT, LEGACY_BACKUP_HELPER] {
            assert!(!exists(&scratch.home(), path), "unexpected write: {path}");
        }
    }
}

#[test]
fn exact_legacy_pair_migrates_with_backups_and_no_duplicates() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_HELPER, CURRENT_HELPER);
    let output = scratch.run(&["init"]);
    assert!(output.status.success(), "migration: {}", text(&output));
    assert_installed(&scratch.home(), "legacy migration");
    assert!(
        !exists(&scratch.home(), LEGACY_ENTRYPOINT),
        "legacy entrypoint remains"
    );
    assert!(
        !exists(&scratch.home(), LEGACY_HELPER),
        "legacy helper remains"
    );
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT),
        CURRENT_ENTRYPOINT
    );
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_HELPER),
        CURRENT_HELPER
    );
    let files = dir_names(&path_in(&scratch.home(), ".pi/agent/extensions"));
    assert!(
        !files.iter().any(|name| name.ends_with("jev-auto.ts")),
        "legacy entrypoint remains at the extensions root: {files:?}"
    );
    assert_eq!(
        files.iter().filter(|name| name.ends_with(".ts")).count(),
        1,
        "exactly one installed entrypoint must remain: {files:?}"
    );
}

#[test]
fn identical_legacy_backups_are_kept_and_migration_completes() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_HELPER, CURRENT_HELPER);
    write_file(
        &scratch.home(),
        LEGACY_BACKUP_ENTRYPOINT,
        CURRENT_ENTRYPOINT,
    );
    write_file(&scratch.home(), LEGACY_BACKUP_HELPER, CURRENT_HELPER);
    let output = scratch.run(&["init"]);
    assert!(
        output.status.success(),
        "identical backups: {}",
        text(&output)
    );
    assert_installed(&scratch.home(), "identical backup migration");
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT),
        CURRENT_ENTRYPOINT
    );
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_HELPER),
        CURRENT_HELPER
    );
    assert!(!exists(&scratch.home(), LEGACY_ENTRYPOINT));
    assert!(!exists(&scratch.home(), LEGACY_HELPER));
}

#[test]
fn different_legacy_backup_is_rejected_and_preserved() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_HELPER, CURRENT_HELPER);
    write_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    let output = scratch.run(&["init"]);
    assert!(
        !output.status.success(),
        "different backup: {}",
        text(&output)
    );
    assert!(text(&output).contains("jev-auto.ts"), "{}", text(&output));
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT),
        CUSTOM_ENTRYPOINT
    );
    assert_eq!(
        read_file(&scratch.home(), LEGACY_ENTRYPOINT),
        CURRENT_ENTRYPOINT
    );
    assert_eq!(read_file(&scratch.home(), LEGACY_HELPER), CURRENT_HELPER);
    assert_no_pair(&scratch.home(), "backup collision");
    assert!(
        !exists(&scratch.home(), RECEIPT),
        "rejected migration wrote a receipt"
    );
    assert_work_untouched(&scratch, "backup collision");
}

#[test]
fn concurrent_refreshes_converge_on_the_exact_pair() {
    let scratch = Scratch::new();
    let mut first = spawn_lgtm(&scratch, &["refresh"]);
    let mut second = spawn_lgtm(&scratch, &["refresh"]);
    reap_bounded(&mut first, "first concurrent refresh");
    reap_bounded(&mut second, "second concurrent refresh");
    let first = first.wait_with_output().expect("first output");
    let second = second.wait_with_output().expect("second output");
    assert!(
        first.status.success() || second.status.success(),
        "neither refresh completed: {}; {}",
        text(&first),
        text(&second)
    );
    for output in [&first, &second] {
        if !output.status.success() {
            assert!(
                text(output).contains("concurrently"),
                "unexpected failure: {}",
                text(output)
            );
        }
    }
    assert_installed(&scratch.home(), "concurrent refresh");
    let retry = scratch.run(&["refresh"]);
    assert!(retry.status.success(), "retry: {}", text(&retry));
    assert_installed(&scratch.home(), "concurrent refresh retry");
}
