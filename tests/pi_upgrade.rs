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

// These CLI checks exercise the updater without downloading or replacing a binary.
fn update_current(home: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args([
            "update",
            "--version",
            concat!("v", env!("CARGO_PKG_VERSION")),
        ])
        .env("HOME", home)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("update starts");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if child.try_wait().expect("update status").is_some() {
            return child.wait_with_output().expect("update output");
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("kill stalled update");
            child.wait().expect("reap update");
            panic!("update exceeded deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn update_migrates_unregistered_global_hook_and_shared_pi_guidance_once() {
    let home = TempRepo::new();
    assert!(init(&home, home.path(), true, false).status.success());
    fs::remove_dir_all(home.path().join(".local/state/lgtm/pi-installations"))
        .expect("simulate pre-registry installation");
    home.write(
        ".pi/agent/AGENTS.md",
        "# Personal guidance\nKeep my preferences.\n",
    );
    home.write(
        ".pi/agent/settings.json",
        r#"{"theme":"dark","defaultTools":["read","bash"],"codemode":{"mode":"on"}}"#,
    );
    let target = home.path().join(".pi/agent/extensions/lgtm.ts");
    let stale = make_stale(&target);
    assert!(update_current(home.path()).status.success());
    let refreshed = home.read(".pi/agent/extensions/lgtm.ts");
    assert_ne!(refreshed, stale);
    assert_eq!(home.read(".pi/agent/extensions/lgtm.ts.bak"), stale);
    let guidance = home.read(".pi/agent/AGENTS.md");
    assert!(guidance.starts_with("# Personal guidance\nKeep my preferences.\n"));
    let codex = home.read(".codex/AGENTS.md");
    assert!(guidance.ends_with(&codex));
    let settings: serde_json::Value =
        serde_json::from_str(&home.read(".pi/agent/settings.json")).expect("settings");
    assert_eq!(
        settings["defaultTools"],
        serde_json::json!(["read", "bash", "+codemode"])
    );
    assert_eq!(settings["theme"], "dark");
    assert!(update_current(home.path()).status.success());
    assert_eq!(home.read(".pi/agent/AGENTS.md"), guidance);
    assert_eq!(home.read(".pi/agent/extensions/lgtm.ts"), refreshed);
    home.write(".pi/agent/AGENTS.md", "Owner removed managed block\n");
    fs::remove_file(&target).expect("disable hook");
    assert!(update_current(home.path()).status.success());
    assert!(!target.exists());
    assert_eq!(
        home.read(".pi/agent/AGENTS.md"),
        "Owner removed managed block\n"
    );
}

#[test]
fn global_init_enables_codemode_and_preserves_owner_settings_and_opt_outs() {
    for tools in [
        None,
        Some(serde_json::json!(["read"])),
        Some(serde_json::json!([])),
        Some(serde_json::json!(["-codemode"])),
    ] {
        let home = TempRepo::new();
        let mut settings = serde_json::json!({"theme":"dark", "codemode":{"mode":"only"}});
        if let Some(tools) = &tools {
            settings["defaultTools"] = tools.clone();
        }
        home.write(".pi/agent/settings.json", &settings.to_string());
        home.write(".pi/agent/AGENTS.md", "Owner guidance\n");
        assert!(init(&home, home.path(), true, false).status.success());
        let actual: serde_json::Value =
            serde_json::from_str(&home.read(".pi/agent/settings.json")).expect("settings");
        let expected = match tools {
            None => serde_json::json!(["+codemode"]),
            Some(ref value) if value == &serde_json::json!(["read"]) => {
                serde_json::json!(["read", "+codemode"])
            }
            Some(value) => value,
        };
        assert_eq!(actual["defaultTools"], expected);
        assert_eq!(actual["codemode"], settings["codemode"]);
        assert_eq!(actual["theme"], "dark");
        assert!(
            home.read(".pi/agent/AGENTS.md")
                .starts_with("Owner guidance\n")
        );
    }
}

#[test]
fn no_write_global_migration_records_guidance_opt_out_boundary() {
    let home = TempRepo::new();
    let pi_guidance = fs::canonicalize(home.path())
        .expect("canonical HOME")
        .join(".pi/agent/AGENTS.md");
    assert!(init(&home, home.path(), true, false).status.success());
    let registry = home.path().join(".local/state/lgtm/pi-installations");
    let record = fs::read_dir(&registry)
        .expect("registry")
        .next()
        .expect("entry")
        .expect("record")
        .path();
    let mut registration: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record).expect("record")).expect("JSON");
    registration["managed"]["guidance"]
        .as_array_mut()
        .expect("guidance")
        .retain(|path| path.as_str() != pi_guidance.to_str());
    fs::write(&record, registration.to_string()).expect("old registration");
    let original = home.read(".pi/agent/AGENTS.md");
    assert!(update_current(home.path()).status.success());
    assert_eq!(home.read(".pi/agent/AGENTS.md"), original);
    let saved: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record).expect("record")).expect("JSON");
    assert!(
        saved["managed"]["guidance"]
            .as_array()
            .expect("guidance")
            .contains(&serde_json::json!(pi_guidance))
    );
    home.write(".pi/agent/AGENTS.md", "Owner opt-out\n");
    assert!(update_current(home.path()).status.success());
    assert_eq!(home.read(".pi/agent/AGENTS.md"), "Owner opt-out\n");
}

#[cfg(unix)]
#[test]
fn refresh_does_not_duplicate_global_registration_through_home_alias() {
    let actual = TempRepo::new();
    let alias_parent = TempRepo::new();
    let alias = alias_parent.path().join("home");
    std::os::unix::fs::symlink(actual.path(), &alias).expect("HOME alias");
    assert!(init(&actual, &alias, true, false).status.success());
    make_stale(&actual.path().join(".pi/agent/extensions/lgtm.ts"));
    assert!(update_current(&alias).status.success());
    let registry = actual.path().join(".local/state/lgtm/pi-installations");
    assert_eq!(fs::read_dir(&registry).expect("registry").count(), 1);
    actual.write(".pi/agent/AGENTS.md", "Owner opt-out\n");
    assert!(update_current(&alias).status.success());
    assert_eq!(fs::read_dir(&registry).expect("registry").count(), 1);
    assert_eq!(actual.read(".pi/agent/AGENTS.md"), "Owner opt-out\n");
}

#[test]
fn global_pi_documentation_packages_migrate_on_init_and_refresh() {
    for operation in ["init", "refresh"] {
        let home = TempRepo::new();
        assert!(init(&home, home.path(), true, false).status.success());
        let context7 = serde_json::json!({
            "source":"npm:@upstash/context7-pi@0.1.3", "skills":[]
        });
        let settings = serde_json::json!({
            "theme":"dark",
            "extensions":["-builtin:codemode"],
            "packages":[
                "npm:pi-mcp-extension",
                {"source":"npm:pi-mcp-extension@1.5.0", "extensions":[]},
                "npm:rtfd-pi@0.1.1",
                {"source":"npm:rtfd-pi", "skills":[]},
                "npm:owner-package@1.2.3",
                "rtfd-pi",
                {"source":"pi-mcp-extension", "extensions":[]},
                context7
            ]
        });
        home.write(".pi/agent/settings.json", &settings.to_string());
        let output = if operation == "init" {
            init(&home, home.path(), true, false)
        } else {
            refresh(home.path())
        };
        assert!(output.status.success(), "{operation}: {output:?}");
        let actual = home.read_json(".pi/agent/settings.json");
        assert_eq!(
            actual["packages"],
            serde_json::json!([
                "npm:owner-package@1.2.3",
                "rtfd-pi",
                {"source":"pi-mcp-extension", "extensions":[]},
                context7
            ])
        );
        assert_eq!(actual["theme"], settings["theme"]);
        assert_eq!(actual["extensions"], settings["extensions"]);
        let once = home.read(".pi/agent/settings.json");
        assert!(refresh(home.path()).status.success());
        assert_eq!(home.read(".pi/agent/settings.json"), once);
    }
}

#[test]
fn global_init_adds_npm_context7_without_replacing_a_local_package() {
    for operation in ["init", "refresh"] {
        let home = TempRepo::new();
        assert!(init(&home, home.path(), true, false).status.success());
        home.write(
            ".pi/agent/settings.json",
            r#"{"packages":["@upstash/context7-pi"]}"#,
        );
        let mcp = r#"{"mcpServers":{}}"#;
        home.write(".pi/agent/mcp.json", mcp);
        let output = if operation == "init" {
            init(&home, home.path(), true, false)
        } else {
            refresh(home.path())
        };
        assert!(output.status.success(), "{operation}: {output:?}");
        assert_eq!(
            home.read_json(".pi/agent/settings.json")["packages"],
            serde_json::json!(["@upstash/context7-pi", "npm:@upstash/context7-pi"])
        );
        assert_eq!(home.read(".pi/agent/mcp.json"), mcp);
    }
}

#[test]
fn global_init_preserves_disabled_builtin_codemode_and_rejects_invalid_tool_lists() {
    let home = TempRepo::new();
    let settings = r#"{"extensions":["-builtin:codemode"],"defaultTools":["read"],"packages":["npm:@upstash/context7-pi"]}"#;
    home.write(".pi/agent/settings.json", settings);
    assert!(init(&home, home.path(), true, false).status.success());
    assert_eq!(home.read(".pi/agent/settings.json"), settings);
    assert!(update_current(home.path()).status.success());
    assert_eq!(home.read(".pi/agent/settings.json"), settings);
    let invalid = TempRepo::new();
    invalid.write(".pi/agent/settings.json", r#"{"defaultTools":"read"}"#);
    assert!(!init(&invalid, invalid.path(), true, false).status.success());
    assert!(!invalid.exists(".pi/agent/extensions/lgtm.ts"));
    assert!(!invalid.exists(".pi/agent/AGENTS.md"));
}

#[test]
fn update_does_not_adopt_custom_or_repointed_unregistered_global_hooks() {
    for customized in [true, false] {
        let home = TempRepo::new();
        assert!(init(&home, home.path(), true, false).status.success());
        fs::remove_dir_all(home.path().join(".local/state/lgtm/pi-installations"))
            .expect("remove registry");
        let target = home.path().join(".pi/agent/extensions/lgtm.ts");
        let stale = make_stale(&target);
        let owner = if customized {
            format!("{stale}\n// Custom hook\n")
        } else {
            stale.replace(env!("CARGO_BIN_EXE_lgtm"), "/owner/lgtm")
        };
        fs::write(&target, &owner).expect("owner change");
        assert!(update_current(home.path()).status.success());
        assert_eq!(home.read(".pi/agent/extensions/lgtm.ts"), owner);
        assert!(!home.exists(".local/state/lgtm/pi-installations"));
    }
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
