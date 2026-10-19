use super::*;

const LEGACY_BACKUP_DIR: &str = ".local/state/lgtm/jev-auto/legacy";

const CUSTOM_ENTRY_ONLY: &[(&str, &str)] = &[(LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT)];
const CUSTOM_PAIR: &[(&str, &str)] = &[
    (LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT),
    (LEGACY_HELPER, CUSTOM_HELPER),
];
const EXACT_PAIR: &[(&str, &str)] = &[
    (LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT),
    (LEGACY_HELPER, CURRENT_HELPER),
];
const MIXED_PAIR: &[(&str, &str)] = &[
    (LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT),
    (LEGACY_HELPER, CUSTOM_HELPER),
];
const PARTIAL_EXACT: &[(&str, &str)] = &[(LEGACY_ENTRYPOINT, CURRENT_ENTRYPOINT)];

fn legacy_backup_files(home: &Path) -> Vec<(String, String)> {
    let dir = path_in(home, LEGACY_BACKUP_DIR);
    if !dir.exists() {
        return Vec::new();
    }
    let mut files: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{dir:?}: {e}"))
        .map(|entry| {
            let path = entry.expect("entry").path();
            let name = path.file_name().expect("name").to_string_lossy();
            (name.into_owned(), fs::read_to_string(&path).expect("bytes"))
        })
        .collect();
    files.sort();
    files
}

fn backup_slot_relative(legacy_relative: &str) -> &'static str {
    match legacy_relative {
        LEGACY_ENTRYPOINT => LEGACY_BACKUP_ENTRYPOINT,
        LEGACY_HELPER => LEGACY_BACKUP_HELPER,
        other => panic!("unexpected legacy source {other}"),
    }
}

fn hash_archive_name(file_name: &str, source: &str) -> String {
    format!("{file_name}.{}.bak", sha256_hex(source.as_bytes()))
}

fn hash_archive_path(file_name: &str, source: &str) -> String {
    format!(
        "{LEGACY_BACKUP_DIR}/{}",
        hash_archive_name(file_name, source)
    )
}

/// A completed migration installs the pair, removes every source, and stores
/// the exact source bytes in that source's backup slot.
fn assert_migration_completed(scratch: &Scratch, sources: &[(&str, &str)], ctx: &str) {
    assert_installed(&scratch.home(), ctx);
    let files = dir_names(&path_in(&scratch.home(), ".pi/agent/extensions"));
    assert!(
        !files
            .iter()
            .any(|name| matches!(name.as_str(), "jev-auto.ts" | "jev-auto-gates.ts")),
        "{ctx}: legacy duplicate: {files:?}"
    );
    for &(relative, bytes) in sources {
        let home = scratch.home();
        assert!(!exists(&home, relative), "{ctx}: {relative} remains");
        let slot = backup_slot_relative(relative);
        assert_eq!(read_file(&home, slot), bytes, "{ctx}: {relative} backup");
    }
}

fn assert_migration_note(combined: &str, ctx: &str) {
    let lower = combined.to_ascii_lowercase();
    let note_ok =
        lower.contains("legacy") && (lower.contains("backed up") || lower.contains("backup"));
    assert!(note_ok, "{ctx}: backup note? {combined}");
    let dir_named = combined.contains(LEGACY_BACKUP_DIR);
    assert!(dir_named, "{ctx}: backup dir? {combined}");
}

/// A later refresh must not rewrite the installed pair, receipt, or backups.
fn assert_migration_refresh_is_stable(scratch: &Scratch, ctx: &str) {
    let installed = snapshot(&scratch.home());
    let backups = legacy_backup_files(&scratch.home());
    let mut paths = [ENTRYPOINT, HELPER, RECEIPT]
        .map(|relative| scratch.home().join(relative))
        .to_vec();
    paths.extend(
        backups
            .iter()
            .map(|(name, _)| scratch.home().join(LEGACY_BACKUP_DIR).join(name)),
    );
    let modified = || {
        paths
            .iter()
            .map(|path| fs::metadata(path).unwrap().modified().unwrap())
            .collect::<Vec<_>>()
    };
    let before_times = modified();
    let output = scratch.run(&["refresh"]);
    let combined = text(&output);
    assert!(output.status.success(), "{ctx}: refresh: {combined}");
    assert_eq!(snapshot(&scratch.home()), installed, "{ctx}: state changed");
    assert_eq!(
        legacy_backup_files(&scratch.home()),
        backups,
        "{ctx}: backups changed"
    );
    assert_eq!(modified(), before_times, "{ctx}: file timestamps changed");
}

#[test]
fn custom_partial_and_exact_legacy_sources_migrate_with_exact_byte_backups() {
    let cases: [(&str, &[(&str, &str)]); 7] = [
        ("unknown entrypoint", CUSTOM_ENTRY_ONLY),
        ("custom pair", CUSTOM_PAIR),
        (
            "CRLF and Unicode",
            &[(LEGACY_ENTRYPOINT, "// café\r\n// saved bytes\r\n")],
        ),
        ("orphan helper", &[(LEGACY_HELPER, CUSTOM_HELPER)]),
        ("partial exact entrypoint", PARTIAL_EXACT),
        ("mixed entrypoint and helper", MIXED_PAIR),
        ("exact pair", EXACT_PAIR),
    ];
    for (label, sources) in cases {
        for args in [&["init"][..], &["refresh"][..]] {
            let scratch = Scratch::new();
            for &(relative, bytes) in sources {
                write_file(&scratch.home(), relative, bytes);
            }
            let output = scratch.run(args);
            let combined = text(&output);
            assert!(output.status.success(), "{label} {args:?}: {combined}");
            assert_migration_note(&combined, label);
            assert_migration_completed(&scratch, sources, label);
            if args[0] == "init" {
                assert_migration_refresh_is_stable(&scratch, label);
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_already_current_update_migrates_legacy_sources() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let output = scratch.run(&["update", "--version", &version]);
    let combined = text(&output);
    assert!(output.status.success(), "pinned update: {combined}");
    assert!(combined.contains("already current"), "{combined}");
    assert_migration_note(&combined, "pinned update");
    assert_migration_completed(&scratch, CUSTOM_ENTRY_ONLY, "pinned update");
}

#[test]
fn identical_legacy_backups_are_kept_unchanged_without_siblings() {
    let scratch = Scratch::new();
    for &(relative, bytes) in CUSTOM_PAIR {
        write_file(&scratch.home(), relative, bytes);
    }
    write_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_BACKUP_HELPER, CUSTOM_HELPER);
    let output = scratch.run(&["init"]);
    let combined = text(&output);
    assert!(output.status.success(), "identical backups: {combined}");
    assert_migration_completed(&scratch, CUSTOM_PAIR, "identical backup");
    let expected = vec![
        ("jev-auto-gates.ts".to_string(), CUSTOM_HELPER.to_string()),
        ("jev-auto.ts".to_string(), CUSTOM_ENTRYPOINT.to_string()),
    ];
    let found = legacy_backup_files(&scratch.home());
    assert_eq!(found, expected, "sibling appeared");
}

#[test]
fn different_fixed_backup_is_preserved_beside_a_hash_addressed_archive() {
    let preserved = "// previously preserved foreign backup\n";
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT, preserved);
    let output = scratch.run(&["init"]);
    assert!(output.status.success(), "hash archive: {}", text(&output));
    assert_migration_note(&text(&output), "hash archive");
    assert_installed(&scratch.home(), "hash archive");
    assert!(!exists(&scratch.home(), LEGACY_ENTRYPOINT));
    assert!(!exists(&scratch.home(), LEGACY_HELPER));
    let slot_bytes = read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT);
    assert_eq!(slot_bytes, preserved);
    let archive = hash_archive_path("jev-auto.ts", CUSTOM_ENTRYPOINT);
    assert_eq!(read_file(&scratch.home(), &archive), CUSTOM_ENTRYPOINT);
    let archived = hash_archive_name("jev-auto.ts", CUSTOM_ENTRYPOINT);
    let expected = vec![
        ("jev-auto.ts".to_string(), preserved.to_string()),
        (archived, CUSTOM_ENTRYPOINT.to_string()),
    ];
    let found = legacy_backup_files(&scratch.home());
    assert_eq!(found, expected, "archive listing");
    assert_migration_refresh_is_stable(&scratch, "hash archive");
}

#[test]
fn identical_hash_archive_is_reused_without_overwriting_existing_backups() {
    let scratch = Scratch::new();
    let preserved = "// older owner backup\n";
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT, preserved);
    let archive = hash_archive_path("jev-auto.ts", CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), &archive, CUSTOM_ENTRYPOINT);
    let fixed_time = fs::metadata(scratch.home().join(LEGACY_BACKUP_ENTRYPOINT))
        .unwrap()
        .modified()
        .unwrap();
    let archive_time = fs::metadata(scratch.home().join(&archive))
        .unwrap()
        .modified()
        .unwrap();
    let output = scratch.run(&["refresh"]);
    assert!(output.status.success(), "archive reuse: {}", text(&output));
    assert_installed(&scratch.home(), "archive reuse");
    assert!(!exists(&scratch.home(), LEGACY_ENTRYPOINT));
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT),
        preserved
    );
    assert_eq!(read_file(&scratch.home(), &archive), CUSTOM_ENTRYPOINT);
    assert_eq!(
        fs::metadata(scratch.home().join(LEGACY_BACKUP_ENTRYPOINT))
            .unwrap()
            .modified()
            .unwrap(),
        fixed_time
    );
    assert_eq!(
        fs::metadata(scratch.home().join(&archive))
            .unwrap()
            .modified()
            .unwrap(),
        archive_time
    );
    assert_eq!(legacy_backup_files(&scratch.home()).len(), 2);
}

#[cfg(unix)]
#[test]
fn selected_hash_archive_symlink_is_refused_without_external_writes() {
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(
        &scratch.home(),
        LEGACY_BACKUP_ENTRYPOINT,
        "// existing backup\n",
    );
    let archive = hash_archive_path("jev-auto.ts", CUSTOM_ENTRYPOINT);
    let outside = scratch.root().join("external-archive.ts");
    fs::write(&outside, CUSTOM_ENTRYPOINT).expect("outside archive");
    symlink_at(&outside, &scratch.home().join(&archive));
    reject_init(&scratch, "jev-auto.ts");
    assert!(
        fs::symlink_metadata(scratch.home().join(&archive))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(outside).unwrap(), CUSTOM_ENTRYPOINT);
    assert_eq!(
        read_file(&scratch.home(), LEGACY_ENTRYPOINT),
        CUSTOM_ENTRYPOINT
    );
    assert_eq!(
        read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT),
        "// existing backup\n"
    );
    assert_no_pair(&scratch.home(), "archive symlink");
    assert!(!exists(&scratch.home(), RECEIPT));
}

#[test]
fn conflicting_hash_archive_is_refused_before_scaffolding() {
    let preserved = "// previously preserved foreign backup\n";
    let archive_bytes = "// unrelated archive with different bytes\n";
    let scratch = Scratch::new();
    write_file(&scratch.home(), LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT, preserved);
    let archive = hash_archive_path("jev-auto.ts", CUSTOM_ENTRYPOINT);
    write_file(&scratch.home(), &archive, archive_bytes);
    let output = scratch.run(&["init"]);
    let combined = text(&output);
    assert!(!output.status.success(), "conflicting archive: {combined}");
    let digest = sha256_hex(CUSTOM_ENTRYPOINT.as_bytes());
    assert!(combined.contains(&digest), "names archive? {combined}");
    assert_work_untouched(&scratch, "conflicting archive");
    assert_no_pair(&scratch.home(), "conflicting archive");
    assert!(!exists(&scratch.home(), RECEIPT), "receipt written");
    let legacy_bytes = read_file(&scratch.home(), LEGACY_ENTRYPOINT);
    assert_eq!(legacy_bytes, CUSTOM_ENTRYPOINT);
    let slot_bytes = read_file(&scratch.home(), LEGACY_BACKUP_ENTRYPOINT);
    assert_eq!(slot_bytes, preserved);
    assert_eq!(read_file(&scratch.home(), &archive), archive_bytes);
}

#[cfg(unix)]
#[test]
fn flat_legacy_symlink_is_refused_and_the_external_target_is_untouched() {
    let scratch = Scratch::new();
    let outside = scratch.root().join("outside-legacy.ts");
    fs::write(&outside, CURRENT_ENTRYPOINT).expect("outside legacy");
    let link = path_in(&scratch.home(), LEGACY_ENTRYPOINT);
    symlink_at(&outside, &link);
    reject_init(&scratch, "jev-auto.ts");
    let metadata = fs::symlink_metadata(&link).expect("link");
    assert!(metadata.file_type().is_symlink());
    let outside_bytes = fs::read_to_string(&outside).expect("outside");
    assert_eq!(outside_bytes, CURRENT_ENTRYPOINT);
    assert_no_pair(&scratch.home(), "legacy symlink");
    assert!(!exists(&scratch.home(), RECEIPT), "receipt written");
    let backups = legacy_backup_files(&scratch.home());
    assert!(backups.is_empty(), "archived symlink: {backups:?}");
}

#[test]
fn canonical_legacy_with_incompatible_directory_bundle_fails_before_scaffolding() {
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
        let combined = text(&output);
        let refused = !output.status.success();
        assert!(refused, "conflicting migration: {combined}");
        assert_legacy_guidance(&output, "jev-auto.ts");
        let collision = combined.to_ascii_lowercase().contains("conflict");
        assert!(collision, "reports collision? {combined}");
        assert_work_untouched(&scratch, "conflicting migration");
        assert_eq!(read_file(&scratch.home(), ENTRYPOINT), index);
        let legacy_bytes = read_file(&scratch.home(), LEGACY_ENTRYPOINT);
        assert_eq!(legacy_bytes, CURRENT_ENTRYPOINT);
        assert_eq!(read_file(&scratch.home(), LEGACY_HELPER), CURRENT_HELPER);
        match helper {
            Some(helper) => assert_eq!(read_file(&scratch.home(), HELPER), helper),
            None => assert!(!exists(&scratch.home(), HELPER)),
        }
        for path in [RECEIPT, LEGACY_BACKUP_ENTRYPOINT, LEGACY_BACKUP_HELPER] {
            assert!(!exists(&scratch.home(), path), "wrote {path}");
        }
        let files = dir_names(&path_in(&scratch.home(), ".pi/agent/extensions"));
        let flat_ts = files.iter().filter(|name| name.ends_with(".ts")).count();
        assert_eq!(flat_ts, 2, "unexpected extensions entries: {files:?}");
    }
}

#[test]
fn dry_run_with_legacy_sources_writes_nothing() {
    for (relative, bytes) in [
        (LEGACY_ENTRYPOINT, CUSTOM_ENTRYPOINT),
        (LEGACY_HELPER, CURRENT_HELPER),
    ] {
        let scratch = Scratch::new();
        write_file(&scratch.home(), relative, bytes);
        let output = scratch.run(&["init", "--dry-run"]);
        let combined = text(&output);
        assert!(output.status.success(), "dry-run {relative}: {combined}");
        let planned = combined.to_ascii_lowercase().contains("would");
        assert!(planned, "reports the plan? {combined}");
        assert_eq!(read_file(&scratch.home(), relative), bytes);
        assert_no_pair(&scratch.home(), "dry-run");
        assert!(!exists(&scratch.home(), RECEIPT), "wrote receipt");
        let backups = legacy_backup_files(&scratch.home());
        assert!(backups.is_empty(), "wrote backup: {backups:?}");
        assert_work_untouched(&scratch, "dry-run legacy");
        let entries = dir_names(&scratch.home());
        assert_eq!(entries, vec![".pi".to_string()], "entries: {entries:?}");
    }
}
