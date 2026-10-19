use super::*;

#[test]
fn exact_manual_pair_is_adopted_without_byte_changes() {
    for args in [&["refresh"][..], &["init"][..]] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), ENTRYPOINT, CURRENT_ENTRYPOINT);
        write_file(&scratch.home(), HELPER, CURRENT_HELPER);
        let output = scratch.run(args);
        assert!(output.status.success(), "adopt {args:?}: {}", text(&output));
        assert_installed(&scratch.home(), "manual adoption");
        assert_bytes(&scratch.home(), CURRENT_ENTRYPOINT, CURRENT_HELPER);
    }
}

#[test]
fn custom_or_partial_receipt_free_pairs_are_preserved_without_new_state() {
    // Custom complete pair, no receipt.
    let scratch = Scratch::new();
    write_file(&scratch.home(), ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), HELPER, CUSTOM_HELPER);
    let output = scratch.run(&["refresh"]);
    assert!(output.status.success(), "custom pair: {}", text(&output));
    assert_bytes(&scratch.home(), CUSTOM_ENTRYPOINT, CUSTOM_HELPER);
    assert!(
        !exists(&scratch.home(), RECEIPT),
        "custom pair gained a receipt"
    );

    // Receipt-free partial pair: entrypoint only, then helper only.
    for present in [ENTRYPOINT, HELPER] {
        let scratch = Scratch::new();
        let custom = if present == ENTRYPOINT {
            CUSTOM_ENTRYPOINT
        } else {
            CUSTOM_HELPER
        };
        write_file(&scratch.home(), present, custom);
        let output = scratch.run(&["refresh"]);
        assert!(output.status.success(), "partial pair: {}", text(&output));
        assert_eq!(
            read_file(&scratch.home(), present),
            custom,
            "partial file preserved"
        );
        assert!(
            !exists(&scratch.home(), RECEIPT),
            "partial pair gained a receipt"
        );
        let missing = if present == ENTRYPOINT {
            HELPER
        } else {
            ENTRYPOINT
        };
        assert!(
            !exists(&scratch.home(), missing),
            "partial pair gained {missing}"
        );
    }
}

#[test]
fn incomplete_canonical_pair_explains_and_supports_manual_recovery() {
    for (path, source) in [(ENTRYPOINT, CURRENT_ENTRYPOINT), (HELPER, CURRENT_HELPER)] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), path, source);
        let output = scratch.run(&["refresh"]);
        assert!(
            output.status.success(),
            "preserve interrupted install: {}",
            text(&output)
        );
        let message = text(&output).to_ascii_lowercase();
        assert!(
            message.contains("back up")
                && message.contains("outside")
                && message.contains("remove")
                && message.contains("lgtm init"),
            "missing actionable recovery: {message}"
        );
        assert_eq!(read_file(&scratch.home(), path), source);
        assert!(!exists(&scratch.home(), RECEIPT));
        fs::rename(
            scratch.home().join(path),
            scratch.root().join("saved-source.ts"),
        )
        .expect("move source outside extensions");
        let recovered = scratch.run(&["init"]);
        assert!(recovered.status.success(), "recovery: {}", text(&recovered));
        assert_installed(&scratch.home(), "recovered installation");
        assert_eq!(
            fs::read_to_string(scratch.root().join("saved-source.ts")).expect("backup"),
            source
        );
    }
}

#[test]
fn valid_receipt_over_a_previous_pair_upgrades_to_current() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), ENTRYPOINT, PREVIOUS_ENTRYPOINT);
    write_file(&scratch.home(), HELPER, PREVIOUS_HELPER);
    write_file(
        &scratch.home(),
        RECEIPT,
        &receipt_for(PREVIOUS_ENTRYPOINT, PREVIOUS_HELPER),
    );
    let output = scratch.run(&["refresh"]);
    assert!(output.status.success(), "upgrade: {}", text(&output));
    assert_installed(&scratch.home(), "upgraded pair");
    assert_ne!(read_file(&scratch.home(), ENTRYPOINT), PREVIOUS_ENTRYPOINT);
    assert_ne!(read_file(&scratch.home(), HELPER), PREVIOUS_HELPER);
}

#[test]
fn modified_tracked_file_is_preserved_with_an_unchanged_receipt() {
    let scratch = Scratch::new();
    install_pair(&scratch);
    let receipt = read_file(&scratch.home(), RECEIPT);
    write_file(&scratch.home(), ENTRYPOINT, CUSTOM_ENTRYPOINT);
    let output = scratch.run(&["refresh"]);
    assert!(output.status.success(), "preserve: {}", text(&output));
    assert_bytes(&scratch.home(), CUSTOM_ENTRYPOINT, CURRENT_HELPER);
    assert_eq!(
        read_file(&scratch.home(), RECEIPT),
        receipt,
        "receipt changed"
    );
}

#[test]
fn refresh_preserves_receipt_tracked_removal() {
    // One tracked file removed, then the whole pair removed.
    for remove_pair in [false, true] {
        let scratch = Scratch::new();
        install_pair(&scratch);
        let receipt = read_file(&scratch.home(), RECEIPT);
        fs::remove_file(path_in(&scratch.home(), ENTRYPOINT)).expect("remove index");
        if remove_pair {
            fs::remove_file(path_in(&scratch.home(), HELPER)).expect("remove helper");
        }
        let output = scratch.run(&["refresh"]);
        assert!(
            output.status.success(),
            "removal refresh: {}",
            text(&output)
        );
        assert!(!exists(&scratch.home(), ENTRYPOINT), "index restored");
        if remove_pair {
            assert!(!exists(&scratch.home(), HELPER), "helper restored");
        } else {
            assert_eq!(read_file(&scratch.home(), HELPER), CURRENT_HELPER);
        }
        assert_eq!(
            read_file(&scratch.home(), RECEIPT),
            receipt,
            "receipt changed"
        );
    }
}

#[test]
fn init_restores_a_missing_file_when_the_survivor_matches_the_receipt() {
    let scratch = Scratch::new();
    install_pair(&scratch);
    let receipt = read_file(&scratch.home(), RECEIPT);
    fs::remove_file(path_in(&scratch.home(), ENTRYPOINT)).expect("remove index");
    let output = scratch.run(&["init"]);
    assert!(output.status.success(), "restore: {}", text(&output));
    assert_bytes(&scratch.home(), CURRENT_ENTRYPOINT, CURRENT_HELPER);
    assert_eq!(
        read_file(&scratch.home(), RECEIPT),
        receipt,
        "receipt changed"
    );
}

#[test]
fn init_restores_and_upgrades_a_previous_recorded_survivor() {
    for removed in [ENTRYPOINT, HELPER] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), ENTRYPOINT, PREVIOUS_ENTRYPOINT);
        write_file(&scratch.home(), HELPER, PREVIOUS_HELPER);
        write_file(
            &scratch.home(),
            RECEIPT,
            &receipt_for(PREVIOUS_ENTRYPOINT, PREVIOUS_HELPER),
        );
        fs::remove_file(scratch.home().join(removed)).expect("remove tracked source");
        let output = scratch.run(&["init"]);
        assert!(
            output.status.success(),
            "restore older pair: {}",
            text(&output)
        );
        assert_installed(&scratch.home(), "restored and upgraded pair");
    }
}

#[test]
fn init_does_not_restore_when_the_survivor_is_custom() {
    let scratch = Scratch::new();
    install_pair(&scratch);
    let receipt = read_file(&scratch.home(), RECEIPT);
    fs::remove_file(path_in(&scratch.home(), ENTRYPOINT)).expect("remove index");
    write_file(&scratch.home(), HELPER, CUSTOM_HELPER);
    let output = scratch.run(&["init"]);
    assert!(
        output.status.success(),
        "custom survivor: {}",
        text(&output)
    );
    assert!(
        !exists(&scratch.home(), ENTRYPOINT),
        "restored beside custom survivor"
    );
    assert_eq!(read_file(&scratch.home(), HELPER), CUSTOM_HELPER);
    assert_eq!(
        read_file(&scratch.home(), RECEIPT),
        receipt,
        "receipt changed"
    );
}

#[test]
fn mixed_old_and_current_pair_is_preserved_with_a_recovery_note() {
    let scratch = Scratch::new();
    let receipt = receipt_for(PREVIOUS_ENTRYPOINT, PREVIOUS_HELPER);
    write_file(&scratch.home(), ENTRYPOINT, PREVIOUS_ENTRYPOINT);
    write_file(&scratch.home(), HELPER, CURRENT_HELPER);
    write_file(&scratch.home(), RECEIPT, &receipt);
    let output = scratch.run(&["refresh"]);
    let combined = text(&output);
    let lower = combined.to_ascii_lowercase();
    assert!(
        lower.contains("mixed")
            && lower.contains("back up")
            && lower.contains("remove")
            && lower.contains("lgtm init"),
        "mixed-pair run must explain recovery: {combined}"
    );
    assert_bytes(&scratch.home(), PREVIOUS_ENTRYPOINT, CURRENT_HELPER);
    assert_eq!(
        read_file(&scratch.home(), RECEIPT),
        receipt,
        "receipt changed"
    );
}
