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
