use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use lgtm::pi_state::{PI_VERSION, PiEnforcementState, assess_at, record_attestation};
use serde_json::json;

mod common;
use common::TempRepo;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_millis()
}

fn init_project(repo: &TempRepo) {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .current_dir(repo.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .output()
        .expect("Pi init runs");
    assert!(output.status.success(), "Pi init failed: {output:?}");
}

fn record(repo: &TempRepo, trusted: bool, tools_verified: bool) -> PathBuf {
    let session = repo.path().join("pi-session.jsonl");
    let extension =
        fs::read_to_string(repo.path().join(".pi/extensions/lgtm.ts")).expect("extension");
    let extension_digest = extension
        .lines()
        .find_map(|line| line.strip_prefix("const TEMPLATE_DIGEST = "))
        .and_then(|value| value.strip_suffix(';'))
        .and_then(|value| serde_json::from_str::<String>(value).ok())
        .expect("template digest");
    let binary_digest = extension
        .lines()
        .find_map(|line| line.strip_prefix("const BINARY_DIGEST = "))
        .and_then(|value| value.strip_suffix(';'))
        .and_then(|value| serde_json::from_str::<String>(value).ok())
        .expect("binary digest");
    let marker = json!({
        "id": "leaf",
        "customType": "lgtm-runtime",
        "data": {
            "nonce": "nonce",
            "extensionDigest": extension_digest,
            "binaryDigest": binary_digest,
            "scope": "project",
            "sessionId": "session"
        }
    });
    let prefix = "{\"id\":\"old\",\"customType\":\"lgtm\",\"data\":{\"reason\":\"old\"}}\n";
    fs::write(&session, format!("{prefix}{marker}\n")).expect("session fixture writes");
    record_attestation(
        repo.path(),
        &json!({
            "scope": "project",
            "trusted": trusted,
            "toolContractsVerified": tools_verified,
            "piVersion": PI_VERSION,
            "sessionFile": session,
            "sessionEntryId": "leaf",
            "runtimeNonce": "nonce",
            "binaryDigest": binary_digest,
            "runtimeMarkerPosition": 57,
            "sessionId": "session"
        }),
    )
    .expect("attestation writes");
    session
}

#[test]
fn state_precedence_distinguishes_presence_trust_tools_and_freshness() {
    let absent = TempRepo::new();
    assert_eq!(
        assess_at(absent.path(), None, now_ms()).state,
        PiEnforcementState::NotInstalled
    );

    let malformed = TempRepo::new();
    malformed.write(
        ".pi/extensions/lgtm.ts",
        "// lgtm-pi-extension: v1\n// lgtm-pi-scope: project\n",
    );
    assert_eq!(
        assess_at(malformed.path(), None, now_ms()).state,
        PiEnforcementState::InstalledUnloadable
    );

    let installed = TempRepo::new();
    init_project(&installed);
    assert_eq!(
        assess_at(installed.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );

    let untrusted = TempRepo::new();
    init_project(&untrusted);
    record(&untrusted, false, true);
    assert_eq!(
        assess_at(untrusted.path(), None, now_ms()).state,
        PiEnforcementState::ProjectUntrusted
    );

    let unverified_tools = TempRepo::new();
    init_project(&unverified_tools);
    record(&unverified_tools, true, false);
    assert_eq!(
        assess_at(unverified_tools.path(), None, now_ms()).state,
        PiEnforcementState::ToolContractUnverified
    );

    let stale = TempRepo::new();
    init_project(&stale);
    record(&stale, true, true);
    assert_eq!(
        assess_at(stale.path(), None, now_ms() + 10 * 60 * 1000 + 1).state,
        PiEnforcementState::StaleUnverified
    );
}

#[cfg(unix)]
#[test]
fn replacing_attested_executable_bytes_downgrades_active_state() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    let binary = repo.path().join("fake-lgtm");
    fs::copy(env!("CARGO_BIN_EXE_lgtm"), &binary).expect("binary copy");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("binary mode");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .current_dir(repo.path())
        .env("LGTM_HOOK_BINARY", &binary)
        .output()
        .expect("Pi init runs");
    assert!(output.status.success(), "Pi init failed: {output:?}");
    record(&repo, true, true);
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::Active
    );
    fs::OpenOptions::new()
        .write(true)
        .open(&binary)
        .expect("binary remains writable")
        .write_all(b"changed")
        .expect("binary replacement writes");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[test]
fn session_identity_prevents_session_b_from_inheriting_session_a_state() {
    let repo = TempRepo::new();
    init_project(&repo);
    let session = record(&repo, true, true);
    let marker = repo
        .read("pi-session.jsonl")
        .replace("\"sessionId\":\"session\"", "\"sessionId\":\"session-b\"");
    fs::write(&session, marker).expect("session B fixture");
    let binary_digest = repo
        .read(".pi/extensions/lgtm.ts")
        .lines()
        .find_map(|line| line.strip_prefix("const BINARY_DIGEST = "))
        .and_then(|value| value.strip_suffix(';'))
        .and_then(|value| serde_json::from_str::<String>(value).ok())
        .expect("binary digest");
    record_attestation(
        repo.path(),
        &json!({
            "scope": "project",
            "trusted": true,
            "toolContractsVerified": true,
            "piVersion": PI_VERSION,
            "sessionFile": session,
            "sessionEntryId": "leaf",
            "runtimeNonce": "nonce",
            "binaryDigest": binary_digest,
            "runtimeMarkerPosition": 57,
            "sessionId": "session-b"
        }),
    )
    .expect("session B attestation");
    assert_eq!(
        lgtm::pi_state::assess_at_for_session(repo.path(), None, now_ms(), Some("session-a")).state,
        PiEnforcementState::StaleUnverified
    );
    assert_eq!(
        lgtm::pi_state::assess_at_for_session(repo.path(), None, now_ms(), Some("session-b")).state,
        PiEnforcementState::Active
    );
}

#[test]
fn position_proof_accepts_a_session_file_larger_than_five_mib() {
    let repo = TempRepo::new();
    init_project(&repo);
    let session = record(&repo, true, true);
    let mut suffix = Vec::with_capacity(5 * 1024 * 1024 + 1024);
    while suffix.len() <= 5 * 1024 * 1024 {
        suffix.extend_from_slice(b"{\"type\":\"message\"}\n");
    }
    fs::OpenOptions::new()
        .append(true)
        .open(&session)
        .expect("session append")
        .write_all(&suffix)
        .expect("large suffix");
    assert!(fs::metadata(&session).expect("session metadata").len() > 5 * 1024 * 1024);
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::Active
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&session)
        .expect("session append")
        .write_all(
            b"{\"id\":\"late-failure\",\"customType\":\"lgtm\",\"data\":{\"reason\":\"timeout\"}}\n",
        )
        .expect("late failure entry");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[test]
fn oversized_runtime_marker_line_is_rejected_before_unbounded_read() {
    let repo = TempRepo::new();
    init_project(&repo);
    let session = record(&repo, true, true);
    let oversized = format!(
        "{{\"id\":\"old\",\"customType\":\"lgtm\",\"data\":{{\"reason\":\"old\"}}}}\n{{\"id\":\"leaf\",\"customType\":\"lgtm-runtime\",\"data\":{{\"nonce\":\"nonce\",\"extensionDigest\":\"x\",\"binaryDigest\":\"{}\",\"scope\":\"project\",\"sessionId\":\"session\",\"padding\":\"{}\"}}}}\n",
        "0".repeat(64),
        "x".repeat(300 * 1024)
    );
    fs::write(&session, oversized).expect("oversized marker fixture");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[test]
fn active_requires_attested_session_and_downgrades_after_native_failure_entry() {
    let repo = TempRepo::new();
    init_project(&repo);
    let session = record(&repo, true, true);
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::Active
    );

    fs::OpenOptions::new()
        .append(true)
        .open(&session)
        .expect("session remains appendable")
        .write_all(
            b"{\"id\":\"failure\",\"customType\":\"lgtm\",\"data\":{\"reason\":\"timeout\"}}\n",
        )
        .expect("failure entry appends");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[test]
fn global_attestation_wins_when_project_and_global_extensions_exist() {
    let root = TempRepo::new();
    init_project(&root);
    let home = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "-g"])
        .current_dir(root.path())
        .env("HOME", home.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .output()
        .expect("global Pi init runs");
    assert!(output.status.success(), "global Pi init failed: {output:?}");
    let extension = home.read(".pi/agent/extensions/lgtm.ts");
    let digest = extension
        .lines()
        .find_map(|line| line.strip_prefix("const TEMPLATE_DIGEST = "))
        .and_then(|value| value.strip_suffix(';'))
        .and_then(|value| serde_json::from_str::<String>(value).ok())
        .expect("global template digest");
    let binary_digest = extension
        .lines()
        .find_map(|line| line.strip_prefix("const BINARY_DIGEST = "))
        .and_then(|value| value.strip_suffix(';'))
        .and_then(|value| serde_json::from_str::<String>(value).ok())
        .expect("global binary digest");
    let session = root.path().join("global-session.jsonl");
    fs::write(
        &session,
        format!(
            "{{\"id\":\"global-leaf\",\"customType\":\"lgtm-runtime\",\"data\":{{\"nonce\":\"global-nonce\",\"extensionDigest\":\"{digest}\",\"binaryDigest\":\"{binary_digest}\",\"scope\":\"global\",\"sessionId\":\"global-session\"}}}}\n"
        ),
    )
    .expect("global session fixture");
    let payload = serde_json::json!({
        "type": "session_start",
        "scope": "global",
        "trusted": true,
        "toolContractsVerified": true,
        "piVersion": PI_VERSION,
        "sessionFile": session,
        "sessionEntryId": "global-leaf",
        "runtimeNonce": "global-nonce",
        "binaryDigest": binary_digest,
        "runtimeMarkerPosition": 0,
        "sessionId": "global-session"
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "session-start", "--adapter", "pi"])
        .current_dir(root.path())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("global attestation hook starts");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("hook payload");
    let result = child.wait_with_output().expect("hook exits");
    assert!(
        result.status.success(),
        "global attestation failed: {result:?}"
    );
    let report = assess_at(root.path(), Some(home.path()), now_ms());
    assert_eq!(report.scope.as_deref(), Some("global"));
    assert_eq!(report.state, PiEnforcementState::Active, "{report:?}");
}

#[test]
fn global_scope_is_reported_without_project_extension() {
    let root = TempRepo::new();
    let home = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "-g"])
        .current_dir(root.path())
        .env("HOME", home.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .output()
        .expect("global Pi init runs");
    assert!(output.status.success(), "global Pi init failed: {output:?}");
    let report = assess_at(root.path(), Some(home.path()), now_ms());
    assert_eq!(report.scope.as_deref(), Some("global"));
    assert_eq!(report.state, PiEnforcementState::StaleUnverified);
}

#[test]
fn edited_owned_extension_is_not_runtime_valid() {
    let repo = TempRepo::new();
    init_project(&repo);
    let path = repo.path().join(".pi/extensions/lgtm.ts");
    let edited = repo.read(".pi/extensions/lgtm.ts").replace(
        "findInitializedRoot(cwd)",
        "findInitializedRoot(cwd) /* edited */",
    );
    fs::write(&path, edited).expect("edit extension");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::InstalledUnloadable
    );
}

#[test]
fn edited_project_extension_does_not_shadow_valid_global_extension() {
    let root = TempRepo::new();
    init_project(&root);
    let home = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "-g"])
        .current_dir(root.path())
        .env("HOME", home.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .output()
        .expect("global Pi init runs");
    assert!(output.status.success(), "global Pi init failed: {output:?}");
    let edited = root.read(".pi/extensions/lgtm.ts").replace(
        "findInitializedRoot(cwd)",
        "findInitializedRoot(cwd) /* edited */",
    );
    root.write(".pi/extensions/lgtm.ts", &edited);
    let report = assess_at(root.path(), Some(home.path()), now_ms());
    assert_eq!(report.scope.as_deref(), Some("global"));
    assert_eq!(report.state, PiEnforcementState::StaleUnverified);
}

#[test]
fn missing_policy_prevents_pi_attestation_persistence() {
    for missing in [".lgtm/config.json", ".lgtm/execpolicy.json"] {
        let repo = TempRepo::new();
        init_project(&repo);
        let session = repo.path().join("missing-policy-session.jsonl");
        fs::write(
            &session,
            "{\"id\":\"leaf\",\"customType\":\"lgtm-runtime\",\"data\":{\"nonce\":\"nonce\",\"scope\":\"project\"}}\n",
        )
        .expect("session fixture");
        fs::remove_file(repo.path().join(missing)).expect("remove policy fixture");
        record_attestation(
            repo.path(),
            &json!({
                "scope": "project",
                "trusted": true,
                "toolContractsVerified": true,
                "piVersion": PI_VERSION,
                "sessionFile": session,
                "sessionEntryId": "leaf",
                "runtimeNonce": "nonce"
            }),
        )
        .expect_err("missing policy must not persist attestation");
        assert!(!repo.exists(".lgtm/evidence/pi-attestation.json"));
    }
}

#[test]
fn schema_invalid_json_policy_downgrades_existing_pi_attestation() {
    let repo = TempRepo::new();
    init_project(&repo);
    record(&repo, true, true);
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[]}"#,
    );
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[test]
fn caller_flags_without_runtime_marker_remain_stale() {
    let repo = TempRepo::new();
    init_project(&repo);
    let session = repo.path().join("unmarked-session.jsonl");
    fs::write(&session, "{\"id\":\"leaf\",\"type\":\"message\"}\n").expect("session");
    record_attestation(
        repo.path(),
        &json!({
            "scope": "project",
            "trusted": true,
            "toolContractsVerified": true,
            "piVersion": PI_VERSION,
            "sessionFile": session,
            "sessionEntryId": "leaf",
            "runtimeNonce": "caller-supplied"
        }),
    )
    .expect_err("attestation requires the runtime marker before persistence");
    assert!(!repo.exists(".lgtm/evidence/pi-attestation.json"));
}

#[test]
fn user_project_file_does_not_shadow_valid_global_extension() {
    let root = TempRepo::new();
    let home = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "-g"])
        .current_dir(root.path())
        .env("HOME", home.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .output()
        .expect("global Pi init runs");
    assert!(output.status.success(), "global Pi init failed: {output:?}");
    root.write(
        ".pi/extensions/lgtm.ts",
        "export default function user() {}\n",
    );
    let report = assess_at(root.path(), Some(home.path()), now_ms());
    assert_eq!(report.scope.as_deref(), Some("global"));
    assert_eq!(report.state, PiEnforcementState::StaleUnverified);
}

#[test]
fn unknown_attestation_schema_is_stale() {
    let repo = TempRepo::new();
    init_project(&repo);
    let _ = record(&repo, true, true);
    let path = repo.path().join(".lgtm/evidence/pi-attestation.json");
    let changed = repo
        .read(".lgtm/evidence/pi-attestation.json")
        .replace("\"schema_version\": 1", "\"schema_version\": 999");
    fs::write(path, changed).expect("mutate attestation schema");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::StaleUnverified
    );
}

#[cfg(unix)]
#[test]
fn non_executable_embedded_binary_is_unloadable() {
    let repo = TempRepo::new();
    let binary = repo.path().join("fake-lgtm");
    fs::write(&binary, "#!/bin/sh\n").expect("binary fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("binary mode");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .current_dir(repo.path())
        .env("LGTM_HOOK_BINARY", &binary)
        .output()
        .expect("Pi init runs");
    assert!(output.status.success(), "Pi init failed: {output:?}");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o644)).expect("binary mode");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::InstalledUnloadable
    );
}

#[test]
fn foreign_global_file_is_not_classified_as_lgtm() {
    let root = TempRepo::new();
    let home = TempRepo::new();
    home.write(
        ".pi/agent/extensions/lgtm.ts",
        "export default function user() {}\n",
    );
    assert_eq!(
        assess_at(root.path(), Some(home.path()), now_ms()).state,
        PiEnforcementState::NotInstalled
    );
}

#[cfg(unix)]
#[test]
fn attestation_file_is_private() {
    let repo = TempRepo::new();
    init_project(&repo);
    let _ = record(&repo, true, true);
    let mode = fs::metadata(repo.path().join(".lgtm/evidence/pi-attestation.json"))
        .expect("attestation metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn symlinked_attestation_or_extension_never_becomes_active() {
    use std::os::unix::fs::symlink;

    let repo = TempRepo::new();
    init_project(&repo);
    let target = repo.path().join("real-extension.ts");
    fs::copy(repo.path().join(".pi/extensions/lgtm.ts"), &target).expect("copy extension");
    fs::remove_file(repo.path().join(".pi/extensions/lgtm.ts")).expect("remove extension");
    symlink(&target, repo.path().join(".pi/extensions/lgtm.ts")).expect("symlink extension");
    assert_eq!(
        assess_at(repo.path(), None, now_ms()).state,
        PiEnforcementState::InstalledUnloadable
    );
}
