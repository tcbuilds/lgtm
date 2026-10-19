//! CLI integration coverage for the embedded global Jev auto installer.
//!
//! Each test runs a copied built binary in an empty working directory with a
//! fresh scratch `HOME`, so nothing in the source checkout can influence the
//! result. Every child process is bounded, reaped, and its output captured.
//! Expected template bytes are embedded with `include_str!` and compared byte
//! for byte. Ownership and unsafe-path cases share this same CLI harness.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

mod common;
use common::TempRepo;

const ENTRYPOINT: &str = ".pi/agent/extensions/jev-auto/index.ts";
const HELPER: &str = ".pi/agent/extensions/jev-auto/jev-auto-gates.ts";
const RECEIPT: &str = ".local/state/lgtm/jev-auto/receipt.json";
const LEGACY_ENTRYPOINT: &str = ".pi/agent/extensions/jev-auto.ts";
const LEGACY_HELPER: &str = ".pi/agent/extensions/jev-auto-gates.ts";
const LEGACY_BACKUP_ENTRYPOINT: &str = ".local/state/lgtm/jev-auto/legacy/jev-auto.ts";
const LEGACY_BACKUP_HELPER: &str = ".local/state/lgtm/jev-auto/legacy/jev-auto-gates.ts";
const REGISTRY: &str = ".local/state/lgtm/pi-installations";
const GLOBAL_HOOK: &str = ".pi/agent/extensions/lgtm.ts";

/// Embedded expected bytes; asserted on, never read from the checkout at runtime.
const CURRENT_ENTRYPOINT: &str = include_str!("../templates/pi/jev-auto.ts");
const CURRENT_HELPER: &str = include_str!("../templates/pi/jev-auto-gates.ts");
const CUSTOM_ENTRYPOINT: &str = "// owner entrypoint override; never replaced\n";
const CUSTOM_HELPER: &str = "// owner gates override; never replaced\n";
/// Previous-release fixture bytes; test data, not a production source.
const PREVIOUS_ENTRYPOINT: &str = "// previous jev-auto template fixture\n";
const PREVIOUS_HELPER: &str = "// previous jev-auto-gates template fixture\n";
const V1_CONFIG: &str = r#"{"version":"1","required_commands":{"python":["pytest"]}}"#;

const BUDGET: Duration = Duration::from_secs(60);
/// Installed entrypoint, installed helper, and receipt bytes.
type Snapshot = (String, String, String);

/// Fresh HOME, empty workdir, and a copied built binary no source file sits beside.
struct Scratch {
    root: TempRepo,
    binary: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root = TempRepo::new();
        fs::create_dir_all(root.path().join("home")).expect("home");
        fs::create_dir_all(root.path().join("work")).expect("work");
        let binary = root.path().join("bin/lgtm");
        fs::create_dir_all(binary.parent().expect("bin parent")).expect("bin");
        fs::copy(env!("CARGO_BIN_EXE_lgtm"), &binary).expect("copy binary");
        Self { root, binary }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }
    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }
    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }
    fn run(&self, args: &[&str]) -> Output {
        self.run_home(args, &self.home())
    }
    fn run_home(&self, args: &[&str], home: &Path) -> Output {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .current_dir(self.work())
            .env("HOME", home);
        run_bounded(&mut command)
    }
}

// Parallel copies and process creation can briefly leave a copied executable
// busy on Linux. Retry only this OS spawn error, never a CLI failure or timeout.
fn spawn_bounded(command: &mut Command) -> Child {
    for attempt in 0..10 {
        match command.spawn() {
            Ok(child) => return child,
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 9 => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("command spawns: {error}"),
        }
    }
    unreachable!("the final attempt returns or fails")
}

fn run_bounded(command: &mut Command) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_bounded(command);
    reap_bounded(&mut child, "lgtm");
    child.wait_with_output().expect("output")
}

fn spawn_lgtm(scratch: &Scratch, args: &[&str]) -> Child {
    let mut command = Command::new(&scratch.binary);
    command
        .args(args)
        .current_dir(scratch.work())
        .env("HOME", scratch.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_bounded(&mut command)
}

/// Wait for the child, killing and reaping it when the budget expires.
fn reap_bounded(child: &mut Child, label: &str) {
    let deadline = Instant::now() + BUDGET;
    loop {
        match child.try_wait().expect("child observable") {
            Some(_) => return,
            None if Instant::now() >= deadline => {
                // Cleanup is best effort if the child exits between poll and kill;
                // the timeout still fails the test regardless of cleanup status.
                let _ = child.kill();
                let _ = child.wait();
                panic!("{label} exceeded {BUDGET:?}");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn path_in(root: &Path, relative: &str) -> PathBuf {
    root.join(relative)
}

fn write_file(root: &Path, relative: &str, contents: &str) {
    let target = path_in(root, relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).expect("fixture parent");
    }
    fs::write(target, contents).expect("fixture write");
}

fn read_file(root: &Path, relative: &str) -> String {
    fs::read_to_string(path_in(root, relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn exists(root: &Path, relative: &str) -> bool {
    path_in(root, relative).exists()
}

fn snapshot(home: &Path) -> Snapshot {
    (
        read_file(home, ENTRYPOINT),
        read_file(home, HELPER),
        read_file(home, RECEIPT),
    )
}

fn assert_bytes(home: &Path, entrypoint: &str, helper: &str) {
    assert_eq!(read_file(home, ENTRYPOINT), entrypoint, "entrypoint bytes");
    assert_eq!(read_file(home, HELPER), helper, "helper bytes");
}

#[cfg(unix)]
fn symlink_at(target: &Path, link: &Path) {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).expect("symlink parent");
    }
    std::os::unix::fs::symlink(target, link).expect("symlink");
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir:?}: {e}"))
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn receipt_for(entrypoint: &str, helper: &str) -> String {
    serde_json::json!({
        "version": 1,
        "index_sha256": sha256_hex(entrypoint.as_bytes()),
        "gates_sha256": sha256_hex(helper.as_bytes())
    })
    .to_string()
}

/// Assert the managed pair, receipt, and extension directory match the contract.
fn assert_installed(home: &Path, ctx: &str) {
    assert_bytes(home, CURRENT_ENTRYPOINT, CURRENT_HELPER);
    let raw = read_file(home, RECEIPT);
    let parsed: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{ctx}: receipt JSON: {e}: {raw}"));
    let expected: Value = serde_json::from_str(&receipt_for(CURRENT_ENTRYPOINT, CURRENT_HELPER))
        .expect("expected receipt is JSON");
    assert_eq!(
        parsed, expected,
        "{ctx}: receipt (fields, version, digests): {raw}"
    );
    let names = dir_names(&path_in(home, ".pi/agent/extensions/jev-auto"));
    assert_eq!(
        names,
        vec!["index.ts".to_string(), "jev-auto-gates.ts".to_string()],
        "{ctx}: extension directory holds exactly the managed pair"
    );
}

fn assert_no_pair(home: &Path, ctx: &str) {
    assert!(!exists(home, ENTRYPOINT), "{ctx}: no entrypoint");
    assert!(!exists(home, HELPER), "{ctx}: no helper");
}

/// Assert init produced no repository scaffolding, proving preflight ran first.
fn assert_work_untouched(scratch: &Scratch, ctx: &str) {
    for relative in [".lgtm", ".claude", ".gitignore"] {
        assert!(
            !exists(&scratch.work(), relative),
            "{ctx}: init scaffolded {relative}"
        );
    }
}

fn reject_init(scratch: &Scratch, needle: &str) {
    let output = scratch.run(&["init"]);
    assert!(
        !output.status.success(),
        "init must fail for {needle}: {}",
        text(&output)
    );
    assert!(
        text(&output).contains(needle),
        "error must name {needle}: {}",
        text(&output)
    );
    assert_work_untouched(scratch, needle);
}

/// Assert the unknown-legacy hard error names the file and explains the
/// backup-outside-extensions recovery; the contract fixes the guidance, not
/// its exact wording, so a small synonym set is accepted.
fn assert_legacy_guidance(output: &Output, name: &str) {
    let combined = text(output);
    assert!(combined.contains(name), "must name {name}: {combined}");
    let lower = combined.to_ascii_lowercase();
    assert!(
        (lower.contains("backup") || lower.contains("back up"))
            && lower.contains("outside")
            && lower.contains("extensions"),
        "must explain backup-outside-extensions recovery: {combined}"
    );
}

fn install_pair(scratch: &Scratch) {
    let output = scratch.run(&["refresh"]);
    assert!(
        output.status.success(),
        "fixture refresh: {}",
        text(&output)
    );
    assert_installed(&scratch.home(), "fixture refresh");
}

#[test]
fn every_init_mode_installs_the_pair_and_reruns_cleanly() {
    let modes: [(&str, &[&str], Option<&str>); 7] = [
        ("default", &["init"], None),
        ("claude", &["init", "--agent", "claude"], None),
        ("codex", &["init", "--agent", "codex"], None),
        ("pi", &["init", "--agent", "pi"], None),
        ("global", &["init", "--global"], None),
        ("rules-only", &["init", "--rules-only"], None),
        ("migrate", &["init", "--migrate-config"], Some(V1_CONFIG)),
    ];
    for (mode, args, config) in modes {
        let scratch = Scratch::new();
        if let Some(config) = config {
            write_file(&scratch.work(), ".lgtm/config.json", config);
        }
        let first = scratch.run(args);
        assert!(first.status.success(), "{mode}: {}", text(&first));
        assert_installed(&scratch.home(), mode);
        let before = snapshot(&scratch.home());
        let second = scratch.run(args);
        assert!(second.status.success(), "{mode} rerun: {}", text(&second));
        assert_eq!(
            snapshot(&scratch.home()),
            before,
            "{mode}: rerun changed state"
        );
    }
}

#[test]
fn refresh_on_a_fresh_home_installs_once_without_registry_or_global_hook() {
    let scratch = Scratch::new();
    assert!(!exists(&scratch.home(), REGISTRY), "fixture registry");
    assert!(!exists(&scratch.home(), GLOBAL_HOOK), "fixture global hook");
    let first = scratch.run(&["refresh"]);
    assert!(first.status.success(), "refresh: {}", text(&first));
    assert_installed(&scratch.home(), "fresh refresh");
    let before = snapshot(&scratch.home());
    let second = scratch.run(&["refresh"]);
    assert!(second.status.success(), "second refresh: {}", text(&second));
    assert_eq!(
        snapshot(&scratch.home()),
        before,
        "second refresh changed state"
    );
}

#[test]
fn refresh_creates_an_absent_fresh_home() {
    let scratch = Scratch::new();
    let absent = scratch.root().join("absent-home");
    assert!(!absent.exists(), "fixture home exists");
    let output = scratch.run_home(&["refresh"], &absent);
    assert!(output.status.success(), "absent HOME: {}", text(&output));
    assert_installed(&absent, "absent HOME");
}

#[test]
fn refresh_rejects_a_relative_home_without_writing() {
    let scratch = Scratch::new();
    let output = scratch.run_home(&["refresh"], Path::new("relative-home"));
    assert!(!output.status.success(), "relative HOME: {}", text(&output));
    assert!(
        text(&output).to_ascii_lowercase().contains("home"),
        "error must name HOME: {}",
        text(&output)
    );
    assert!(
        !exists(&scratch.work(), "relative-home"),
        "relative HOME created"
    );
    assert_work_untouched(&scratch, "relative HOME");
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn already_current_pinned_update_installs_the_embedded_pair_offline() {
    let scratch = Scratch::new();
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let output = scratch.run(&["update", "--version", &version]);
    assert!(output.status.success(), "update: {}", text(&output));
    assert!(
        text(&output).contains("already current"),
        "{}",
        text(&output)
    );
    assert_installed(&scratch.home(), "pinned update");
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_update_check_writes_nothing() {
    let scratch = Scratch::new();
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let output = scratch.run(&["update", "--check", "--version", &version]);
    assert!(output.status.success(), "update --check: {}", text(&output));
    assert!(text(&output).contains("is current"), "{}", text(&output));
    assert!(
        !exists(&scratch.home(), ".pi"),
        "check wrote HOME extensions"
    );
    assert!(!exists(&scratch.home(), ".local"), "check wrote HOME state");
    assert_work_untouched(&scratch, "update --check");
}

#[test]
fn dry_run_writes_nothing_in_every_mode() {
    let modes: [(&str, &[&str]); 4] = [
        ("default", &["init", "--dry-run"]),
        ("pi", &["init", "--agent", "pi", "--dry-run"]),
        ("codex", &["init", "--agent", "codex", "--dry-run"]),
        ("global", &["init", "--global", "--dry-run"]),
    ];
    for (mode, args) in modes {
        let scratch = Scratch::new();
        let output = scratch.run(args);
        assert!(output.status.success(), "dry-run {mode}: {}", text(&output));
        assert_work_untouched(&scratch, mode);
        let entries = dir_names(&scratch.home());
        assert!(
            entries.is_empty(),
            "dry-run {mode} wrote HOME entries: {entries:?}"
        );
    }
}

#[test]
fn copied_binary_installs_a_loadable_router_and_gates_bundle() {
    let scratch = Scratch::new();
    install_pair(&scratch);
    let mut node = Command::new("node");
    node.arg("--experimental-strip-types")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi/jev_auto.cjs"))
        .arg(scratch.home().join(ENTRYPOINT))
        .current_dir(scratch.work())
        .env("HOME", scratch.home());
    let output = run_bounded(&mut node);
    assert!(
        output.status.success(),
        "installed router/gates failed to load: {}",
        text(&output)
    );
}

#[path = "jev_auto_install/ownership.rs"]
mod ownership;
#[path = "jev_auto_install/safety.rs"]
mod safety;
