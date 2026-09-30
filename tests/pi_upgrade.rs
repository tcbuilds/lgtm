//! Pi upgrade registration and refresh across project/global installations.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

mod common;
use common::TempRepo;

fn init(repo: &TempRepo, home: &Path, global: bool, dry_run: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.arg("init");
    if global {
        command.arg("--global");
    } else {
        command.args(["--agent", "pi", "--accept-guesses"]);
    }
    if dry_run {
        command.arg("--dry-run");
    }
    command
        .env("HOME", home)
        .current_dir(repo.path())
        .output()
        .expect("init runs")
}

fn refresh(home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("refresh-pi")
        .env("HOME", home)
        .output()
        .expect("refresh runs")
}

fn make_stale(target: &Path) -> String {
    let original = fs::read_to_string(target).expect("extension exists");
    let stale = original
        .lines()
        .map(|line| {
            if line.starts_with("const BINARY_DIGEST = ") {
                format!("const BINARY_DIGEST = \"{}\";", "0".repeat(64))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(target, &stale).expect("stale binary pin writes");
    stale
}

#[test]
fn refresh_updates_registered_project_and_global_pins_and_is_idempotent() {
    let home = TempRepo::new();
    let project = TempRepo::new();
    assert!(init(&project, home.path(), false, false).status.success());
    assert!(init(&project, home.path(), true, false).status.success());
    let targets = [
        project.path().join(".pi/extensions/lgtm.ts"),
        home.path().join(".pi/agent/extensions/lgtm.ts"),
    ];
    for target in &targets {
        make_stale(target);
    }
    let result = refresh(home.path());
    assert!(result.status.success(), "refresh failed: {result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("2 refreshed"));
    let registry = home.path().join(".local/state/lgtm/pi-installations");
    assert_eq!(fs::read_dir(registry).expect("registry exists").count(), 2);
    let expected = format!("const BINARY_DIGEST = \"{}\";", "0".repeat(64));
    for target in &targets {
        assert!(
            !fs::read_to_string(target)
                .expect("refreshed extension")
                .contains(&expected)
        );
        assert!(target.with_file_name("lgtm.ts.bak").is_file());
    }
    let result = refresh(home.path());
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("0 refreshed"));
}

// ELF accepts trailing bytes without invalidating executable loading. Other
// platforms exercise pin refresh without modifying their executable format.
#[cfg(target_os = "linux")]
#[test]
fn replacing_binary_refreshes_the_registered_extension_without_reinitializing() {
    use std::io::Write;

    let home = TempRepo::new();
    let project = TempRepo::new();
    let binary = home.path().join("installed-lgtm");
    fs::copy(env!("CARGO_BIN_EXE_lgtm"), &binary).expect("install executable");
    let result = Command::new(&binary)
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .env("HOME", home.path())
        .current_dir(project.path())
        .output()
        .expect("installed init runs");
    assert!(result.status.success(), "{result:?}");
    let target = project.path().join(".pi/extensions/lgtm.ts");
    let original = fs::read_to_string(&target).expect("original extension");
    fs::OpenOptions::new()
        .append(true)
        .open(&binary)
        .expect("installed binary opens")
        .write_all(b"\nLGTM upgrade fixture\n")
        .expect("change installed executable identity");
    let result = Command::new(&binary)
        .arg("refresh-pi")
        .env("HOME", home.path())
        .output()
        .expect("new binary refresh runs");
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 refreshed"));
    assert_ne!(
        fs::read_to_string(&target).expect("new extension"),
        original
    );
    assert_eq!(
        fs::read_to_string(target.with_file_name("lgtm.ts.bak")).expect("backup"),
        original
    );
}

#[test]
fn refresh_preserves_customized_disabled_and_repointed_extensions() {
    for case in ["customized", "disabled", "repointed"] {
        let home = TempRepo::new();
        let project = TempRepo::new();
        assert!(init(&project, home.path(), false, false).status.success());
        let target = project.path().join(".pi/extensions/lgtm.ts");
        let original = make_stale(&target);
        let expected = match case {
            "disabled" => {
                fs::remove_file(&target).expect("disable extension");
                None
            }
            "customized" => Some(format!("{original}\n// Owner customization\n")),
            "repointed" => Some(original.replace(env!("CARGO_BIN_EXE_lgtm"), "/owner/other-lgtm")),
            _ => unreachable!(),
        };
        if let Some(contents) = &expected {
            fs::write(&target, contents).expect("owner change writes");
        }
        let result = refresh(home.path());
        assert!(result.status.success(), "{case}: {result:?}");
        assert_eq!(fs::read_to_string(&target).ok(), expected, "{case}");
        assert!(!target.with_file_name("lgtm.ts.bak").exists());
    }
}

#[test]
fn dry_run_does_not_register_and_foreign_backup_is_not_overwritten() {
    let home = TempRepo::new();
    let project = TempRepo::new();
    assert!(init(&project, home.path(), false, true).status.success());
    assert!(
        !home
            .path()
            .join(".local/state/lgtm/pi-installations")
            .exists()
    );
    assert!(init(&project, home.path(), false, false).status.success());
    let target = project.path().join(".pi/extensions/lgtm.ts");
    let stale = make_stale(&target);
    let backup = target.with_file_name("lgtm.ts.bak");
    fs::write(&backup, "owner backup").expect("foreign backup writes");
    let result = refresh(home.path());
    assert!(!result.status.success());
    assert_eq!(
        fs::read_to_string(&target).expect("target preserved"),
        stale
    );
    assert_eq!(
        fs::read_to_string(backup).expect("backup preserved"),
        "owner backup"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("repair and run lgtm refresh-pi"));
}

#[test]
fn refresh_rejects_invalid_registry_records_without_changing_extensions() {
    for case in ["malformed", "unknown-version"] {
        let home = TempRepo::new();
        let project = TempRepo::new();
        assert!(init(&project, home.path(), false, false).status.success());
        let target = project.path().join(".pi/extensions/lgtm.ts");
        let stale = make_stale(&target);
        let registry = home.path().join(".local/state/lgtm/pi-installations");
        let record = fs::read_dir(registry)
            .expect("registry")
            .next()
            .expect("entry")
            .expect("record")
            .path();
        let contents = if case == "malformed" {
            "{not-json}".to_string()
        } else {
            fs::read_to_string(&record)
                .expect("record content")
                .replace("\"version\":1", "\"version\":2")
        };
        fs::write(record, contents).expect("invalid registration writes");
        assert!(!refresh(home.path()).status.success(), "{case}");
        assert_eq!(
            fs::read_to_string(target).expect("preserved extension"),
            stale
        );
    }
}

#[cfg(unix)]
#[test]
fn refresh_rejects_symlinked_registry_and_extension_ancestors() {
    use std::os::unix::fs::symlink;

    let home = TempRepo::new();
    let project = TempRepo::new();
    assert!(init(&project, home.path(), false, false).status.success());
    let registry = home.path().join(".local/state/lgtm/pi-installations");
    let moved = home.path().join("registry-moved");
    fs::rename(&registry, &moved).expect("move registry");
    symlink(&moved, &registry).expect("symlink registry");
    assert!(!refresh(home.path()).status.success());
    fs::remove_file(&registry).expect("remove registry link");
    fs::rename(&moved, &registry).expect("restore registry");
    let extensions = project.path().join(".pi/extensions");
    let moved = project.path().join("extensions-moved");
    fs::rename(&extensions, &moved).expect("move extensions");
    symlink(&moved, &extensions).expect("symlink extensions");
    assert!(!refresh(home.path()).status.success());
}
