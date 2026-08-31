//! End-to-end project Pi extension installation tests.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use lgtm::pi_state::{PiEnforcementState, assess_at};

mod common;
use common::TempRepo;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_millis()
}

fn run_init(repo: &TempRepo, binary: Option<&str>, dry_run: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.args(["init", "--agent", "pi"]);
    if !dry_run {
        command.arg("--accept-guesses");
    } else {
        command.arg("--dry-run");
    }
    if let Some(binary) = binary {
        command.env("LGTM_HOOK_BINARY", binary);
    }
    command
        .current_dir(repo.path())
        .output()
        .expect("Pi init should execute")
}

#[test]
fn project_init_installs_versioned_extension_at_the_pi_path() {
    let repo = TempRepo::new();
    let binary = env!("CARGO_BIN_EXE_lgtm");

    let output = run_init(&repo, Some(binary), false);
    assert!(output.status.success(), "Pi init failed: {output:?}");
    let extension = repo.read(".pi/extensions/lgtm.ts");
    assert!(extension.contains("// lgtm-pi-extension: v1"));
    assert!(extension.contains("// lgtm-pi-scope: project"));
    assert!(extension.contains("// lgtm-pi-extension: end"));
    assert!(extension.contains("const PI_VERSION = \"0.84.3\""));
    assert!(extension.contains(&format!("const LGTM_BINARY = {binary:?}")));
    assert!(!repo.exists(".pi/extension/lgtm.ts"));
    assert!(!repo.exists(".pi/extensions/lgtm.ts.bak"));
    assert!(extension.contains("shell: false"));
    assert!(extension.contains("NORMAL_TIMEOUT_MS = 10_000"));
    assert!(extension.contains("PRE_TOOL_TIMEOUT_MS = 40_000"));
    assert!(!extension.contains("event.input ="));
    assert!(extension.contains("getAllTools"));
    assert!(extension.contains("sourceInfo"));
    assert!(extension.contains("TOOL_CONTRACTS"));
    assert!(
        extension.contains("entry.data?.nonce === nonce")
            && !extension.contains("const sessionEntryId = ctx.sessionManager?.getLeafId?.()")
    );
    let supported_tool_check = extension
        .find("if (!supported) return undefined;")
        .expect("unsupported tools are ignored");
    let provenance_check = extension
        .find("if (!verifiedToolContract(pi, event))")
        .expect("supported tools require provenance");
    assert!(supported_tool_check < provenance_check);
    assert!(
        extension.contains("hasDescription ? [\"type\", \"items\", \"description\"]")
            && extension.contains("primitivePropertyMatches(property.items.properties[key], type)")
            && extension.contains("tool_provenance_unverified")
    );
    assert!(extension.contains("mergeToolResult"));
    assert!(extension.contains("if (toolName === \"read\")"));
    assert!(extension.contains("[\"read\", \"edit\", \"write\"].includes(event.toolName)"));
    assert!(!extension.contains("details: event.details"));
    assert!(!extension.contains("isError: event.isError"));
    assert!(!extension.contains("usage: cloneJson(event.usage)"));
    assert!(extension.contains("BINARY_DIGEST"));
    assert!(extension.contains("child.unref()"));
    assert!(!extension.contains("console.log"));

    let first = extension;
    let second_output = run_init(&repo, Some(binary), false);
    assert!(second_output.status.success());
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), first);
}

#[test]
fn project_init_preserves_user_extension_and_dry_run_is_side_effect_free() {
    let repo = TempRepo::new();
    let user_extension = "export default function userExtension() {}\n";
    repo.write(".pi/extensions/lgtm.ts", user_extension);

    let output = run_init(&repo, None, false);
    assert!(output.status.success(), "user extension must be preserved");
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), user_extension);
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("preserved existing .pi/extensions/lgtm.ts")
    );
    assert!(!repo.exists(".pi/extensions/lgtm.ts.bak"));

    let dry_repo = TempRepo::new();
    let output = run_init(&dry_repo, None, true);
    assert!(output.status.success(), "Pi dry-run must succeed");
    assert!(!dry_repo.exists(".pi"));
    assert!(!dry_repo.exists(".lgtm"));
}

#[test]
fn known_project_extension_upgrade_makes_one_collision_safe_backup() {
    let repo = TempRepo::new();
    let first_binary = "/opt/lgtm/first";
    let second_binary = "/opt/lgtm/second";

    assert!(run_init(&repo, Some(first_binary), false).status.success());
    let first = repo.read(".pi/extensions/lgtm.ts");
    assert!(run_init(&repo, Some(second_binary), false).status.success());
    assert_eq!(repo.read(".pi/extensions/lgtm.ts.bak"), first);
    assert!(repo.read(".pi/extensions/lgtm.ts").contains(second_binary));

    let backup = repo.read(".pi/extensions/lgtm.ts.bak");
    assert!(
        run_init(&repo, Some("/opt/lgtm/third"), false)
            .status
            .success()
    );
    assert_eq!(repo.read(".pi/extensions/lgtm.ts.bak"), backup);
}

#[test]
fn foreign_backup_aborts_owned_extension_upgrade_without_data_loss() {
    let repo = TempRepo::new();
    assert!(
        run_init(&repo, Some("/opt/lgtm/first"), false)
            .status
            .success()
    );
    let target_before = repo.read(".pi/extensions/lgtm.ts");
    let foreign_backup = "export default function foreign() {}\n";
    repo.write(".pi/extensions/lgtm.ts.bak", foreign_backup);
    let output = run_init(&repo, Some("/opt/lgtm/second"), false);
    assert!(!output.status.success());
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), target_before);
    assert_eq!(repo.read(".pi/extensions/lgtm.ts.bak"), foreign_backup);
}

#[test]
fn foreign_target_and_backup_are_both_preserved_without_installation() {
    let repo = TempRepo::new();
    let foreign_target = "export default function target() {}\n";
    let foreign_backup = "export default function backup() {}\n";
    repo.write(".pi/extensions/lgtm.ts", foreign_target);
    repo.write(".pi/extensions/lgtm.ts.bak", foreign_backup);

    let output = run_init(&repo, Some(env!("CARGO_BIN_EXE_lgtm")), false);
    assert!(
        output.status.success(),
        "foreign collision must be preserved"
    );
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), foreign_target);
    assert_eq!(repo.read(".pi/extensions/lgtm.ts.bak"), foreign_backup);
    assert!(String::from_utf8_lossy(&output.stdout).contains("not installed"));
}

#[test]
fn malformed_owned_project_extension_fails_before_scaffolding() {
    let repo = TempRepo::new();
    let malformed = "// lgtm-pi-extension: v1\n// lgtm-pi-scope: project\n";
    repo.write(".pi/extensions/lgtm.ts", malformed);

    let output = run_init(&repo, None, false);
    assert!(!output.status.success());
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), malformed);
    assert!(!repo.exists(".lgtm/config.json"));
}

#[test]
fn edited_owned_project_extension_is_not_upgraded_by_marker_alone() {
    let repo = TempRepo::new();
    assert!(
        run_init(&repo, Some(env!("CARGO_BIN_EXE_lgtm")), false)
            .status
            .success()
    );
    let edited = repo.read(".pi/extensions/lgtm.ts").replace(
        "findInitializedRoot(cwd)",
        "findInitializedRoot(cwd) /* edited */",
    );
    repo.write(".pi/extensions/lgtm.ts", &edited);

    let output = run_init(&repo, Some("/opt/lgtm/replacement"), false);
    assert!(!output.status.success());
    assert_eq!(repo.read(".pi/extensions/lgtm.ts"), edited);
    assert!(!repo.exists(".pi/extensions/lgtm.ts.bak"));
}

#[test]
fn generated_session_marker_produces_active_runtime_state() {
    let repo = TempRepo::new();
    assert!(
        run_init(&repo, Some(env!("CARGO_BIN_EXE_lgtm")), false)
            .status
            .success()
    );
    let session = repo.path().join("pi-session.jsonl");
    let harness = repo.path().join("run-extension.cjs");
    fs::write(
        &harness,
        r#"const fs = require("node:fs");
const source = fs.readFileSync(process.argv[2], "utf8");
const drift = process.argv[4] === "drift";
const digest = source.match(/const TEMPLATE_DIGEST = "([^"]+)"/)[1];
const session = process.argv[3];
const handlers = {};
const entries = [];
const extension = source
  .replace('import { dirname, join, resolve } from "node:path";', 'const { dirname, join, resolve } = require("node:path");')
  .replace('import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";', 'const { existsSync, lstatSync, readFileSync, statSync } = require("node:fs");')
  .replace('new URL(import.meta.url)', 'process.argv[2]')
  .replace('import { spawn } from "node:child_process";', 'const { spawn } = require("node:child_process");')
  .replace('import { createHash, randomUUID } from "node:crypto";', 'const { createHash, randomUUID } = require("node:crypto");')
  .replace('export default function lgtm', 'function lgtm') + "\nmodule.exports = lgtm;";
const lgtm = (() => { const module = { exports: {} }; eval(extension); return module.exports; })();
const pi = {
  on: (event, handler) => { handlers[event] = handler; },
  appendEntry: (customType, data) => {
    const entry = { type: "custom", id: "leaf", customType, data };
    entries.push(entry);
    fs.appendFileSync(session, JSON.stringify(entry) + "\n");
  },
  getAllTools: () => [
    { name: "read", sourceInfo: { source: "builtin", path: "<builtin:read>" }, parameters: { type: "object", required: ["path"], properties: { path: { type: "string", description: "Path to the file to read (relative or absolute)" }, offset: { type: "number", description: "Line number to start reading from (1-indexed)" }, limit: { type: "number", description: "Maximum number of lines to read" } } } },
    { name: "bash", sourceInfo: { source: "builtin", path: "<builtin:bash>" }, parameters: { type: "object", required: ["command"], properties: { command: { type: "string", description: "Bash command to execute" }, timeout: { type: "number", description: "Timeout in seconds (optional, no default timeout)" } } } },
    { name: "edit", sourceInfo: { source: "builtin", path: "<builtin:edit>" }, parameters: { type: "object", required: ["path", "edits"], properties: { path: { type: "string", description: "Path to the file to edit (relative or absolute)" }, edits: Object.assign({ type: "array", description: "One or more targeted replacements. Each edit is matched against the original file, not incrementally. Do not include overlapping or nested edits. If two changes touch the same block or nearby lines, merge them into one edit instead.", items: { type: "object", required: ["oldText", "newText"], properties: { oldText: { type: "string", description: "Exact text for one targeted replacement. It must be unique in the original file and must not overlap with any other edits[].oldText in the same call." }, newText: { type: "string", description: "Replacement text for this targeted edit." } } } }, drift ? { minItems: 0 } : {}) } } },
    { name: "write", sourceInfo: { source: "builtin", path: "<builtin:write>" }, parameters: { type: "object", required: ["path", "content"], properties: { path: { type: "string", description: "Path to the file to write (relative or absolute)" }, content: { type: "string", description: "Content to write to the file" } } } },
  ],
};
lgtm(pi);
handlers.session_start({}, {
  cwd: process.cwd(),
  isProjectTrusted: () => true,
  sessionManager: { getSessionId: () => "session", getSessionFile: () => session, getEntries: () => entries },
}).then(() => process.exit(0));
"#,
    )
    .expect("write runtime harness");
    let output = Command::new("node")
        .arg(&harness)
        .arg(repo.path().join(".pi/extensions/lgtm.ts"))
        .arg(&session)
        .current_dir(repo.path())
        .output()
        .expect("Node runtime harness executes");
    assert!(
        output.status.success(),
        "runtime harness failed: {output:?}"
    );
    let report = assess_at(repo.path(), None, now_ms());
    assert_eq!(report.state, PiEnforcementState::Active, "{report:?}");

    let drift_session = repo.path().join("pi-drift-session.jsonl");
    let output = Command::new("node")
        .arg(&harness)
        .arg(repo.path().join(".pi/extensions/lgtm.ts"))
        .arg(&drift_session)
        .arg("drift")
        .current_dir(repo.path())
        .output()
        .expect("Node schema-drift harness executes");
    assert!(
        output.status.success(),
        "schema-drift harness failed: {output:?}"
    );
    let report = assess_at(repo.path(), None, now_ms());
    assert_eq!(
        report.state,
        PiEnforcementState::ToolContractUnverified,
        "{report:?}"
    );
}

#[cfg(unix)]
#[test]
fn generated_handlers_preserve_tool_results_and_record_bounded_failures() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    let fake = repo.path().join("fake-lgtm.cjs");
    fs::write(
        &fake,
        r##"#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
let input = "";
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", () => {
  fs.writeFileSync("captured.json", input);
  if (args.includes("pre-tool-use")) process.exit(7);
  if (process.env.DIAGNOSTIC) process.stderr.write("diagnostic\n");
  const response = JSON.stringify(process.env.WRONG_RESPONSE
    ? { content: [{ type: "text", text: "policy feedback" }], unexpected: true }
    : { content: [{ type: "text", text: process.env.SPLIT_UTF8 ? "héllo" : "policy feedback" }] });
  if (process.env.SPLIT_UTF8) {
    const bytes = Buffer.from(response);
    const marker = bytes.indexOf(Buffer.from("é"));
    process.stdout.write(bytes.subarray(0, marker + 1));
    setTimeout(() => process.stdout.write(bytes.subarray(marker + 1)), 10);
  } else {
    process.stdout.write(response);
  }
});
"##,
    )
    .expect("fake binary writes");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).expect("fake executable");
    assert!(
        run_init(&repo, Some(fake.to_str().expect("fake path")), false)
            .status
            .success()
    );
    let harness = repo.path().join("invoke-extension.cjs");
    fs::write(
        &harness,
        r##"const fs = require("node:fs");
const source = fs.readFileSync(process.argv[2], "utf8");
const handlers = {};
const failures = [];
const extension = source
  .replace('import { dirname, join, resolve } from "node:path";', 'const { dirname, join, resolve } = require("node:path");')
  .replace('import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";', 'const { existsSync, lstatSync, readFileSync, statSync } = require("node:fs");')
  .replace('new URL(import.meta.url)', 'process.argv[2]')
  .replace('import { spawn } from "node:child_process";', 'const { spawn } = require("node:child_process");')
  .replace('import { createHash, randomUUID } from "node:crypto";', 'const { createHash, randomUUID } = require("node:crypto");')
  .replace('export default function lgtm', 'function lgtm') + "\nmodule.exports = lgtm;";
const lgtm = (() => { const module = { exports: {} }; eval(extension); return module.exports; })();
const pi = {
  on: (event, handler) => { handlers[event] = handler; },
  appendEntry: (type, data) => failures.push({ type, data }),
  getAllTools: () => [
    { name: "read", sourceInfo: { source: "builtin", path: "<builtin:read>" }, parameters: { type: "object", required: ["path"], properties: { path: { type: "string", description: "Path to the file to read (relative or absolute)" }, offset: { type: "number", description: "Line number to start reading from (1-indexed)" }, limit: { type: "number", description: "Maximum number of lines to read" } } } },
    { name: "bash", sourceInfo: { source: "builtin", path: "<builtin:bash>" }, parameters: { type: "object", required: ["command"], properties: { command: { type: "string", description: "Bash command to execute" }, timeout: { type: "number", description: "Timeout in seconds (optional, no default timeout)" } } } },
    { name: "edit", sourceInfo: { source: "builtin", path: "<builtin:edit>" }, parameters: {
      type: "object",
      required: ["path", "edits"],
      properties: {
        path: { type: "string", description: "Path to the file to edit (relative or absolute)" },
        edits: {
          type: "array",
          items: {
            type: "object",
            required: ["oldText", "newText"],
            properties: {
              oldText: { type: "string", description: "Exact text for one targeted replacement. It must be unique in the original file and must not overlap with any other edits[].oldText in the same call." },
              newText: { type: "string", description: "Replacement text for this targeted edit." }
            }
          }
        }
      }
    } },
    { name: "write", sourceInfo: { source: "builtin", path: "<builtin:write>" }, parameters: { type: "object", required: ["path", "content"], properties: { path: { type: "string", description: "Path to the file to write (relative or absolute)" }, content: { type: "string", description: "Content to write to the file" } } } },
  ],
};
lgtm(pi);
const ctx = {
  cwd: process.cwd(),
  isProjectTrusted: () => true,
  sessionManager: { getSessionId: () => "tool-session" },
  ui: { notify: () => {} },
};
function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
const toolCall = deepFreeze({ toolName: "bash", input: { command: "echo safe", nested: { values: [1, 2] } } });
const toolCallBefore = JSON.stringify(toolCall);
const toolResult = deepFreeze({ toolName: "edit", input: { path: "file", edits: [{ oldText: "old", newText: "new" }] }, content: [{ type: "text", text: "original" }], details: { source: "pi" }, isError: true, usage: { input: 3, output: 4 } });
const toolResultBefore = JSON.stringify(toolResult);
const readResult = deepFreeze({ toolName: "read", input: { path: "src/app.py", offset: 0, limit: 20 }, content: [{ type: "text", text: "file contents" }], details: { source: "pi" }, isError: false, usage: { input: 2 } });
const readResultBefore = JSON.stringify(readResult);
Promise.resolve(handlers.tool_call(toolCall, ctx))
  .then((failureResult) => {
    if (failureResult !== undefined || failures.length !== 1 || failures[0].data.reason !== "nonzero") { console.error(JSON.stringify({failureResult, failures})); process.exit(2); }
    if (JSON.stringify(toolCall) !== toolCallBefore) process.exit(6);
    return handlers.tool_result(toolResult, ctx);
  })
  .then((merged) => {
    if (JSON.stringify(toolResult) !== toolResultBefore) process.exit(7);
    if (!merged || merged.content.length !== 2 || merged.content[0].text !== "original" || merged.content[1].text !== "policy feedback") process.exit(3);
    if (Object.keys(merged).join("\u0000") !== "content") process.exit(4);
    return handlers.tool_result(readResult, ctx);
  })
  .then((readMerged) => {
    if (JSON.stringify(readResult) !== readResultBefore) process.exit(10);
    if (!readMerged || readMerged.content.length !== 2
        || readMerged.content[0].text !== "file contents"
        || readMerged.content[1].text !== "policy feedback"
        || Object.keys(readMerged).join("\u0000") !== "content") process.exit(11);
    return handlers.tool_result({ toolName: "read", input: { path: "src/app.py" }, content: "invalid", isError: false }, ctx);
  })
  .then((invalidResult) => {
    if (invalidResult !== undefined || failures.length !== 2
        || failures[1].data.reason !== "tool_result_unverified") process.exit(12);
    process.env.DIAGNOSTIC = "1";
    return handlers.tool_result(readResult, ctx);
  })
  .then((diagnosticResult) => {
    if (!diagnosticResult || diagnosticResult.content.length !== 2
        || failures.length !== 3 || failures[2].data.reason !== "child_diagnostics") process.exit(13);
    delete process.env.DIAGNOSTIC;
    process.env.SPLIT_UTF8 = "1";
    return handlers.tool_result(readResult, ctx);
  })
  .then((splitResult) => {
    if (!splitResult || splitResult.content.length !== 2
        || splitResult.content[1].text !== "héllo" || failures.length !== 3) process.exit(14);
    delete process.env.SPLIT_UTF8;
    process.env.WRONG_RESPONSE = "1";
    return handlers.tool_result(toolResult, ctx);
  })
  .then((wrongShape) => {
    if (wrongShape !== undefined || failures.length !== 4 || failures[3].data.reason !== "invalid_tool_result_response") process.exit(8);
    return handlers.tool_call({ toolName: "bash", input: { nested: { value: "x".repeat(300 * 1024) } } }, ctx);
  })
  .then((oversized) => {
    if (oversized !== undefined || failures.length !== 5 || failures[4].data.reason !== "handler") process.exit(5);
    ctx.isProjectTrusted = () => false;
    return handlers.tool_call(toolCall, ctx);
  })
  .then((untrusted) => {
    if (untrusted !== undefined || failures.length !== 6
        || failures[5].data.reason !== "project_untrusted") process.exit(9);
  })
  .catch(() => process.exit(6));
"##,
    )
    .expect("extension harness writes");
    let output = Command::new("node")
        .arg(&harness)
        .arg(repo.path().join(".pi/extensions/lgtm.ts"))
        .current_dir(repo.path())
        .output()
        .expect("extension harness executes");
    assert!(
        output.status.success(),
        "extension behavior failed: {output:?}"
    );
    let captured = repo.read("captured.json");
    assert!(!captured.contains("oldText"));
    assert!(!captured.contains("newText"));
    assert!(!captured.contains("original"));
    assert!(!captured.contains("source"));
    assert!(!captured.contains("usage"));
}

#[cfg(unix)]
#[test]
fn generated_bash_timeout_kills_child_and_records_unverified_failure() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    let fake = repo.path().join("slow-lgtm.cjs");
    fs::write(&fake, "#!/usr/bin/env node\nsetTimeout(() => {}, 1000);\n")
        .expect("slow binary writes");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).expect("slow binary mode");
    assert!(
        run_init(&repo, Some(fake.to_str().expect("fake path")), false)
            .status
            .success()
    );
    let harness = repo.path().join("timeout-extension.cjs");
    fs::write(
        &harness,
        r#"const fs = require("node:fs");
const source = fs.readFileSync(process.argv[2], "utf8")
  .replace('import { dirname, join, resolve } from "node:path";', 'const { dirname, join, resolve } = require("node:path");')
  .replace('import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";', 'const { existsSync, lstatSync, readFileSync, statSync } = require("node:fs");')
  .replace('import { spawn } from "node:child_process";', 'const { spawn } = require("node:child_process");')
  .replace('import { createHash, randomUUID } from "node:crypto";', 'const { createHash, randomUUID } = require("node:crypto");')
  .replace('new URL(import.meta.url)', 'process.argv[2]')
  .replace('const PRE_TOOL_TIMEOUT_MS = 40_000;', 'const PRE_TOOL_TIMEOUT_MS = 25;')
  .replace('export default function lgtm', 'function lgtm') + "\nglobalThis.__lgtm = lgtm;";
eval(source);
const handlers = {};
const failures = [];
const pi = {
  on: (event, handler) => { handlers[event] = handler; },
  appendEntry: (type, data) => failures.push({ type, data }),
  getAllTools: () => [{ name: "bash", sourceInfo: { source: "builtin", path: "<builtin:bash>" }, parameters: { type: "object", required: ["command"], properties: { command: { type: "string" }, timeout: { type: "number" } } } }],
};
const ctx = { cwd: process.cwd(), isProjectTrusted: () => true, sessionManager: { getSessionId: () => "timeout-session" }, ui: { notify: () => {} } };
globalThis.__lgtm(pi);
Promise.resolve(handlers.tool_call({ toolName: "bash", input: { command: "echo safe" } }, ctx)).then((result) => {
  if (result !== undefined || failures.length !== 1 || failures[0].data.reason !== "timeout") process.exit(2);
}).catch(() => process.exit(3));
"#,
    )
    .expect("timeout harness writes");
    let output = Command::new("node")
        .arg(&harness)
        .arg(repo.path().join(".pi/extensions/lgtm.ts"))
        .current_dir(repo.path())
        .output()
        .expect("timeout harness executes");
    assert!(
        output.status.success(),
        "timeout behavior failed: {output:?}"
    );
}

#[test]
fn agent_settled_without_runtime_attestation_fails_closed_without_evidence() {
    let repo = TempRepo::new();
    assert!(
        run_init(&repo, Some(env!("CARGO_BIN_EXE_lgtm")), false)
            .status
            .success()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "agent-settled", "--adapter", "pi"])
        .current_dir(repo.path())
        .env("HOME", repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("agent_settled hook starts");
    child
        .stdin
        .take()
        .expect("settled stdin")
        .write_all(br#"{"type":"agent_settled","sessionId":"settled-session"}"#)
        .expect("settled payload");
    let output = child.wait_with_output().expect("agent_settled hook runs");
    assert!(
        !output.status.success(),
        "unattested settlement must fail: {output:?}"
    );
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
}

#[test]
fn generated_scope_guard_covers_root_nested_and_unrelated_projects() {
    let repo = TempRepo::new();
    assert!(
        run_init(&repo, Some(env!("CARGO_BIN_EXE_lgtm")), false)
            .status
            .success()
    );
    let extension = repo.read(".pi/extensions/lgtm.ts");
    for required in [
        "findInitializedRoot",
        "projectScopeLoaded",
        "PROJECT_SCOPE_LOADED",
        "SCOPE === \"project\"",
        "resolve(cwd) !== root",
        "appendFailure",
        "appendEntry(FAILURE_ENTRY",
        "canonicalTemplateDigest",
        "PROJECT_TEMPLATE_DIGEST",
        "TOOL_INPUT_BYTES = 256 * 1024",
        "itemType: \"object\"",
        "itemProperties: { oldText: \"string\", newText: \"string\" }",
        "offset: \"number\"",
        "timeout: \"number\"",
    ] {
        assert!(
            extension.contains(required),
            "missing guard behavior: {required}"
        );
    }
    assert!(!extension.contains("shell: true"));
    assert!(!extension.contains("console.log"));
}
