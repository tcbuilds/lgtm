//! Pi extension generation for project and global installation scopes.

use std::path::{Path, PathBuf};

use serde_json::to_string;
use sha2::{Digest, Sha256};

use super::{InitError, fs::read_if_exists};

const OWNED_START: &str = "// lgtm-pi-extension: v1";
const OWNED_END: &str = "// lgtm-pi-extension: end";
// Only known canonical revisions may cross the ownership boundary during an
// upgrade. The b45c/ed0f entries are the v0.10.1 Pi 0.84.2 project/global
// templates.
const KNOWN_TEMPLATE_DIGESTS: &[&str] = &[
    "524b3d58c2f839420c14f8ec081855ea3499d4e219d1f5c4c131fe4051d28c2c",
    "a6719ad16be1e48543acb3ae7014afa6b1361d4b85110cd56350807798cb2caa",
    "b45c8c6756955338325fd4d80386523b846b14cc6066a07dc506ce71219079ca",
    "becaa0ca4bc7006cd2d30c9844d24d063ec76e1a69af32725e5967d854a51793",
    "ed0ff523f79e64c395184b3b3253a90b3643e088863ef683c60baa45699b1df3",
];
const EXTENSION_TEMPLATE: &str = r#"// lgtm-pi-extension: v1
// lgtm-pi-scope: __LGTM_SCOPE__

import { dirname, join, resolve } from "node:path";
import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

const LGTM_BINARY = __LGTM_BINARY__;
const SCOPE = "__LGTM_SCOPE__";
const PI_VERSION = "0.84.3";
const TEMPLATE_DIGEST = "__LGTM_TEMPLATE_DIGEST__";
const PROJECT_TEMPLATE_DIGEST = "__LGTM_PROJECT_TEMPLATE_DIGEST__";
const BINARY_DIGEST = "__LGTM_BINARY_DIGEST__";
const MAX_INPUT_BYTES = 1024 * 1024;
const TOOL_INPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const NORMAL_TIMEOUT_MS = 10_000;
const PRE_TOOL_TIMEOUT_MS = 40_000;
const POLICY_INPUT_MARKER = "lgtm-pi-policy-input-v1";
const FAILURE_ENTRY = "lgtm";
const TOOL_CONTRACTS = {
  read: { required: ["path"], properties: { path: "string", offset: "number", limit: "number" } },
  bash: { required: ["command"], properties: { command: "string", timeout: "number" } },
  edit: {
    required: ["path", "edits"],
    properties: {
      path: "string",
      edits: {
        type: "array",
        itemType: "object",
        itemRequired: ["oldText", "newText"],
        itemProperties: { oldText: "string", newText: "string" },
      },
    },
  },
  write: { required: ["path", "content"], properties: { path: "string", content: "string" } },
};
const CLI_EVENTS = {
  session_start: "session-start",
  before_agent_start: "before-agent-start",
  tool_call: "pre-tool-use",
  tool_result: "post-tool-use",
  agent_settled: "agent-settled",
};

function regularFile(path) {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

function hasPartialLgtmMarker(root) {
  return regularFile(join(root, ".lgtm", "execpolicy.json"))
    || existsSync(join(root, ".lgtm", "evidence"));
}

function findInitializedRoot(cwd) {
  let current = resolve(cwd);
  let partialRoot;
  for (let depth = 0; depth < 128; depth += 1) {
    if (regularFile(join(current, ".lgtm", "config.json"))) return current;
    if (!partialRoot && hasPartialLgtmMarker(current)) partialRoot = current;
    const parent = dirname(current);
    if (parent === current) return partialRoot;
    current = parent;
  }
  return partialRoot;
}

function policyFilesPresent(root) {
  try {
    return ["config.json", "execpolicy.json"].every((name) =>
      lstatSync(join(root, ".lgtm", name)).isFile());
  } catch {
    return false;
  }
}

function canonicalTemplateDigest(source) {
  let lines = source.replace(/\r\n/g, "\n").split("\n");
  if (lines.at(-1) === "") lines = lines.slice(0, -1);
  const binaryPlaceholder = "__LGTM_" + "BINARY__";
  const digestPlaceholder = "__LGTM_" + "TEMPLATE_DIGEST__";
  const projectDigestPlaceholder = "__LGTM_" + "PROJECT_TEMPLATE_DIGEST__";
  const binaryDigestPlaceholder = "__LGTM_" + "BINARY_DIGEST__";
  const normalized = lines.map((line) => {
    if (line.startsWith("const LGTM_BINARY = ")) return `const LGTM_BINARY = ${binaryPlaceholder};`;
    if (line.startsWith("const BINARY_DIGEST = ")) {
      return `const BINARY_DIGEST = "${binaryDigestPlaceholder}";`;
    }
    if (line.startsWith("const TEMPLATE_DIGEST = ")) {
      return `const TEMPLATE_DIGEST = "${digestPlaceholder}";`;
    }
    if (line.startsWith("const PROJECT_TEMPLATE_DIGEST = ")) {
      return `const PROJECT_TEMPLATE_DIGEST = "${projectDigestPlaceholder}";`;
    }
    return line;
  }).join("\n");
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

const PROJECT_SCOPE_LOADED = Symbol.for("lgtm.project-extension-loaded");

function projectBinaryIsRunnable() {
  try {
    const metadata = statSync(LGTM_BINARY);
    if (!metadata.isFile()) return false;
    return process.platform === "win32" || (metadata.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function projectTemplateIsCanonical() {
  try {
    return canonicalTemplateDigest(readFileSync(new URL(import.meta.url), "utf8"))
      === TEMPLATE_DIGEST;
  } catch {
    return false;
  }
}

function projectScopeLoaded() {
  return globalThis[PROJECT_SCOPE_LOADED] === true;
}

function resolveScopeRoot(cwd) {
  const root = findInitializedRoot(cwd);
  if (!root) return undefined;
  if (SCOPE === "project" && resolve(cwd) !== root) return undefined;
  if (SCOPE === "global" && resolve(cwd) === root && projectScopeLoaded()) return undefined;
  return root;
}

const MAX_CLONE_DEPTH = 64;
const MAX_CLONE_ITEMS = 16_384;

function cloneJson(value, maxBytes = MAX_INPUT_BYTES) {
  if (value === undefined) return undefined;
  const budget = { bytes: 0, items: 0 };
  return cloneBounded(value, 0, maxBytes, budget);
}

function cloneBounded(value, depth, maxBytes, budget) {
  if (depth > MAX_CLONE_DEPTH) throw new Error("value_too_deep");
  if (value === null || typeof value !== "object") {
    if (typeof value === "string") {
      budget.bytes += Buffer.byteLength(value, "utf8");
      if (budget.bytes > maxBytes) throw new Error("value_too_large");
    }
    return value;
  }
  const keys = Array.isArray(value) ? value : Object.keys(value);
  budget.items += keys.length;
  if (budget.items > MAX_CLONE_ITEMS) throw new Error("value_too_many_items");
  if (Array.isArray(value)) {
    return value.map((item) => cloneBounded(item, depth + 1, maxBytes, budget));
  }
  const result = {};
  for (const key of keys) {
    budget.bytes += Buffer.byteLength(key, "utf8");
    if (budget.bytes > maxBytes) throw new Error("value_too_large");
    result[key] = cloneBounded(value[key], depth + 1, maxBytes, budget);
  }
  return result;
}

function withinJsonBudget(value, maxBytes) {
  try {
    cloneBounded(value, 0, maxBytes, { bytes: 0, items: 0 });
    return true;
  } catch {
    return false;
  }
}

function boundedReason(reason) {
  const clean = String(reason).replace(/[\u0000-\u001f\u007f]/g, " ");
  return clean.length <= 256 ? clean : `${clean.slice(0, 255)}…`;
}

function verifiedToolContract(pi, event) {
  const contract = TOOL_CONTRACTS[event.toolName];
  if (!contract) return false;
  let tools;
  try {
    tools = pi.getAllTools();
  } catch {
    return false;
  }
  const tool = tools.find((candidate) => candidate?.name === event.toolName);
  if (!tool || tool.sourceInfo?.source !== "builtin"
      || tool.sourceInfo?.path !== `<builtin:${event.toolName}` + ">") return false;
  const parameters = tool.parameters;
  if (!parameters || !sameKeys(parameters, ["type", "required", "properties"])
      || parameters.type !== "object"
      || !sameValues(parameters.required, contract.required)
      || !parameters.properties || !sameKeys(parameters.properties, Object.keys(contract.properties))) {
    return false;
  }
  return Object.entries(contract.properties).every(([key, expected]) =>
    propertyMatches(parameters.properties[key], expected));
}

function sameKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("\u0000") === expected.slice().sort().join("\u0000");
}

function sameValues(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function primitivePropertyMatches(property, expectedType) {
  if (!property || typeof property !== "object" || Array.isArray(property)) return false;
  const hasDescription = Object.prototype.hasOwnProperty.call(property, "description");
  return sameKeys(property, hasDescription ? ["type", "description"] : ["type"])
    && property.type === expectedType
    && (!hasDescription || typeof property.description === "string");
}

function propertyMatches(property, expected) {
  if (typeof expected === "string") return primitivePropertyMatches(property, expected);
  if (!property || typeof property !== "object" || Array.isArray(property)) return false;
  const hasDescription = Object.prototype.hasOwnProperty.call(property, "description");
  if (!sameKeys(property, hasDescription ? ["type", "items", "description"] : ["type", "items"])
      || (hasDescription && typeof property.description !== "string")
      || property.type !== expected.type || !property.items
      || !sameKeys(property.items, ["type", "required", "properties"])
      || property.items.type !== expected.itemType
      || !sameValues(property.items.required, expected.itemRequired)
      || !sameKeys(property.items.properties, Object.keys(expected.itemProperties))) {
    return false;
  }
  return Object.entries(expected.itemProperties).every(([key, type]) =>
    primitivePropertyMatches(property.items.properties[key], type));
}

function verifiedAllToolContracts(pi) {
  return ["read", "bash", "edit", "write"].every((toolName) =>
    verifiedToolContract(pi, { toolName }));
}

function sessionId(ctx) {
  try {
    return ctx.sessionManager?.getSessionId?.();
  } catch {
    return undefined;
  }
}

function runtimeAttestation(pi, ctx) {
  const currentSessionId = sessionId(ctx);
  if (!currentSessionId) throw new Error("session_id_unavailable");
  let trusted = false;
  let toolContractsVerified = false;
  try {
    trusted = ctx.isProjectTrusted();
    toolContractsVerified = verifiedAllToolContracts(pi);
  } catch {
    // The marker below still distinguishes a loaded extension from a direct CLI call.
  }
  const nonce = randomUUID();
  try {
    const sessionFile = ctx.sessionManager?.getSessionFile?.();
    if (!sessionFile) throw new Error("session evidence unavailable");
    const sessionMarkerPosition = existsSync(sessionFile) ? statSync(sessionFile).size : 0;
    pi.appendEntry("lgtm-runtime", {
      extensionDigest: TEMPLATE_DIGEST,
      binaryDigest: BINARY_DIGEST,
      nonce,
      protocolVersion: 1,
      scope: SCOPE,
      sessionId: currentSessionId,
    });
    const sessionEntryId = ctx.sessionManager?.getLeafId?.();
    if (!sessionEntryId) throw new Error("session evidence unavailable");
    return {
      trusted,
      toolContractsVerified,
      runtimeNonce: nonce,
      extensionDigest: TEMPLATE_DIGEST,
      binaryDigest: BINARY_DIGEST,
      sessionFile,
      sessionEntryId,
      runtimeMarkerPosition: sessionMarkerPosition,
    };
  } catch {
    return {
      trusted: false,
      toolContractsVerified: false,
    };
  }
}

function policyToolInput(toolName, input) {
  if (!withinJsonBudget(input, TOOL_INPUT_BYTES)
      || !input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("tool_input_unverified");
  }
  if (toolName === "read") {
    if (typeof input.path !== "string") throw new Error("tool_input_unverified");
    return { path: input.path, __lgtmPolicyInput: POLICY_INPUT_MARKER };
  }
  if (toolName === "bash") {
    if (typeof input.command !== "string") throw new Error("tool_input_unverified");
    return { command: input.command, __lgtmPolicyInput: POLICY_INPUT_MARKER };
  }
  if (toolName === "edit") {
    if (typeof input.path !== "string" || !Array.isArray(input.edits)
        || !input.edits.every((edit) => edit && typeof edit === "object"
          && !Array.isArray(edit) && typeof edit.oldText === "string"
          && typeof edit.newText === "string")) {
      throw new Error("tool_input_unverified");
    }
    return { path: input.path, __lgtmPolicyInput: POLICY_INPUT_MARKER };
  }
  if (toolName === "write") {
    if (typeof input.path !== "string" || typeof input.content !== "string") {
      throw new Error("tool_input_unverified");
    }
    return { path: input.path, __lgtmPolicyInput: POLICY_INPUT_MARKER };
  }
  throw new Error("tool_input_unverified");
}

function buildPayload(eventType, event, ctx, pi) {
  const currentSessionId = sessionId(ctx);
  if (!currentSessionId) throw new Error("session_id_unavailable");
  const payload = {
    type: eventType,
    cwd: ctx.cwd,
    sessionId: currentSessionId,
    scope: SCOPE,
  };
  if (eventType === "session_start") {
    payload.piVersion = PI_VERSION;
    Object.assign(payload, runtimeAttestation(pi, ctx));
  } else if (eventType === "before_agent_start") {
    payload.prompt = event.prompt;
    payload.systemPrompt = event.systemPrompt;
  } else if (eventType === "tool_call") {
    payload.toolName = event.toolName;
    payload.input = policyToolInput(event.toolName, event.input);
  } else if (eventType === "tool_result") {
    payload.toolName = event.toolName;
    payload.input = policyToolInput(event.toolName, event.input);
  }
  return payload;
}

function appendFailure(pi, ctx, eventType, reason) {
  const entry = {
    extensionVersion: 1,
    protocolVersion: 1,
    scope: SCOPE,
    event: eventType,
    reason: boundedReason(reason),
    timestamp: new Date().toISOString(),
  };
  // Failure persistence is best effort: a secondary Pi API error must not block the session.
  try {
    pi.appendEntry(FAILURE_ENTRY, entry);
  } catch {
    // The original hook failure remains fail-open even if Pi cannot persist it.
  }
  try {
    ctx.ui?.notify("LGTM Pi hook is unverified", "warning");
  } catch {
    // UI notification is optional and must not change the hook decision.
  }
}

function killChild(child) {
  if (process.platform !== "win32" && child.pid) {
    try { process.kill(-child.pid, "SIGKILL"); } catch {}
  }
  try { child.kill("SIGKILL"); } catch {}
}

function invoke(binary, root, eventType, payload) {
  return new Promise((resolveResult) => {
    const maxInputBytes = eventType === "tool_call" || eventType === "tool_result"
      ? TOOL_INPUT_BYTES
      : MAX_INPUT_BYTES;
    if (!withinJsonBudget(payload, maxInputBytes)) {
      resolveResult({ failure: "input_too_large" });
      return;
    }
    let serialized;
    try {
      serialized = JSON.stringify(payload);
    } catch {
      resolveResult({ failure: "malformed_input" });
      return;
    }
    if (Buffer.byteLength(serialized, "utf8") > maxInputBytes) {
      resolveResult({ failure: "input_too_large" });
      return;
    }
    const child = spawn(binary, ["hook", CLI_EVENTS[eventType], "--adapter", "pi"], {
      cwd: root,
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdoutChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timedOut = false;
    let reapTimer;
    const timeoutMs = eventType === "tool_call" && payload.toolName === "bash"
      ? PRE_TOOL_TIMEOUT_MS
      : NORMAL_TIMEOUT_MS;
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      killChild(child);
      reapTimer = setTimeout(() => finish({ failure: "timeout" }), 1_000);
    }, timeoutMs);

    function finish(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (reapTimer) clearTimeout(reapTimer);
      if (!result.failure && stderrBytes > 0) result.diagnostics = true;
      if (result.failure === "timeout") {
        for (const stream of [child.stdin, child.stdout, child.stderr]) {
          try { stream?.destroy(); } catch {}
        }
        try { child.unref(); } catch {}
        child.removeAllListeners();
      }
      resolveResult(result);
    }

    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        killChild(child);
        finish({ failure: timedOut ? "timeout" : "output_too_large" });
        return;
      }
      stdoutChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_OUTPUT_BYTES) killChild(child);
    });
    child.stdin.on("error", () => {
      killChild(child);
      finish({ failure: timedOut ? "timeout" : "stdin" });
    });
    child.on("error", () => finish({ failure: timedOut ? "timeout" : "spawn" }));
    child.on("close", (code, signal) => {
      if (settled) return;
      if (timedOut) {
        finish({ failure: "timeout" });
        return;
      }
      if (code !== 0 || signal) {
        finish({ failure: code === null ? "signal" : "nonzero" });
        return;
      }
      const text = Buffer.concat(stdoutChunks).toString("utf8").trim();
      if (text === "") {
        finish({ response: undefined });
        return;
      }
      try {
        const response = JSON.parse(text);
        if (response === null || typeof response !== "object" || Array.isArray(response)) {
          finish({ failure: "response_not_object" });
          return;
        }
        const failure = validateResponse(eventType, response);
        finish(failure ? { failure } : { response });
      } catch {
        finish({ failure: "malformed_output" });
      }
    });
    child.stdin.end(serialized);
  });
}

function responseKeys(value) {
  return Object.keys(value).sort().join("\u0000");
}

function validateResponse(eventType, response) {
  if (response === undefined) return undefined;
  if (response === null || typeof response !== "object" || Array.isArray(response)) {
    return "response_not_object";
  }
  if (eventType === "tool_call") {
    if (responseKeys(response) !== "block\u0000reason"
        || response.block !== true || typeof response.reason !== "string"
        || !withinJsonBudget(response, 4096)) return "invalid_tool_call_response";
    return undefined;
  }
  if (eventType === "tool_result") {
    if (responseKeys(response) !== "content" || !Array.isArray(response.content)
        || !response.content.every((item) => item && typeof item === "object"
          && !Array.isArray(item)
          && responseKeys(item) === "text\u0000type"
          && item.type === "text"
          && typeof item.text === "string")
        || !withinJsonBudget(response, TOOL_INPUT_BYTES)) return "invalid_tool_result_response";
    return undefined;
  }
  return "unexpected_response";
}

function validToolResultContentItem(item) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return false;
  if (item.type === "text") return typeof item.text === "string";
  return item.type === "image"
    && typeof item.data === "string"
    && typeof item.mimeType === "string";
}

function validToolResultEvent(event) {
  if (!Array.isArray(event.content)
      || !event.content.every(validToolResultContentItem)
      || typeof event.isError !== "boolean"
      || !withinJsonBudget(event.content, TOOL_INPUT_BYTES)) {
    return false;
  }
  return event.usage === undefined
    || (event.usage && typeof event.usage === "object"
      && !Array.isArray(event.usage)
      && withinJsonBudget(event.usage, TOOL_INPUT_BYTES));
}

function mergeToolResult(event, response) {
  if (response === undefined) return undefined;
  const originalContent = cloneJson(event.content, TOOL_INPUT_BYTES);
  return {
    content: [
      ...originalContent,
      ...cloneJson(response.content, TOOL_INPUT_BYTES),
    ],
  };
}

async function handle(pi, eventType, event, ctx) {
  try {
    const root = resolveScopeRoot(ctx.cwd);
    if (!root) return undefined;
    const policyEvent = eventType === "tool_call" || eventType === "tool_result";
    const settledEvent = eventType === "agent_settled";
    if (policyEvent || settledEvent) {
      let trusted = false;
      try { trusted = ctx.isProjectTrusted?.() === true; } catch {}
      if (!trusted) {
        appendFailure(pi, ctx, eventType, "project_untrusted");
        return undefined;
      }
    }
    if (!policyFilesPresent(root)) {
      appendFailure(pi, ctx, eventType, "policy_unverified");
      return undefined;
    }
    if (policyEvent) {
      if (!verifiedToolContract(pi, event)) {
        appendFailure(pi, ctx, eventType, "tool_provenance_unverified");
        return undefined;
      }
      const supported = eventType === "tool_call"
        ? ["bash", "edit", "write"].includes(event.toolName)
        : ["read", "edit", "write"].includes(event.toolName);
      if (!supported) return undefined;
      if (eventType === "tool_result" && !validToolResultEvent(event)) {
        appendFailure(pi, ctx, eventType, "tool_result_unverified");
        return undefined;
      }
    }
    if (settledEvent && !verifiedAllToolContracts(pi)) {
      appendFailure(pi, ctx, eventType, "tool_provenance_unverified");
      return undefined;
    }
    const result = await invoke(LGTM_BINARY, root, eventType, buildPayload(eventType, event, ctx, pi));
    if (result.failure) {
      appendFailure(pi, ctx, eventType, result.failure);
      return undefined;
    }
    if (result.diagnostics) appendFailure(pi, ctx, eventType, "child_diagnostics");
    return eventType === "tool_result" ? mergeToolResult(event, result.response) : result.response;
  } catch {
    appendFailure(pi, ctx, eventType, "handler");
    return undefined;
  }
}

export default function lgtm(pi) {
  if (SCOPE === "project" && projectBinaryIsRunnable() && projectTemplateIsCanonical()) {
    globalThis[PROJECT_SCOPE_LOADED] = true;
  }
  pi.on("session_start", (event, ctx) => handle(pi, "session_start", event, ctx));
  pi.on("tool_call", (event, ctx) => handle(pi, "tool_call", event, ctx));
  pi.on("tool_result", (event, ctx) => handle(pi, "tool_result", event, ctx));
  pi.on("agent_settled", (event, ctx) => handle(pi, "agent_settled", event, ctx));
}

// lgtm-pi-extension: end
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionScope {
    Project,
    Global,
}

impl ExtensionScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExtensionPlan {
    pub(crate) target: PathBuf,
    pub(crate) backup: PathBuf,
    pub(crate) target_contents: Option<Vec<u8>>,
    pub(crate) backup_contents: Option<Vec<u8>>,
    pub(crate) preserved_collision: bool,
}

pub(crate) fn hook_binary() -> Result<String, InitError> {
    if let Some(binary) = std::env::var_os("LGTM_HOOK_BINARY") {
        let path = PathBuf::from(binary);
        if !path.is_absolute() {
            return Err(InitError::UnwritableTarget {
                path,
                reason: "Pi extension binary must be an absolute path".to_string(),
            });
        }
        return Ok(path.to_string_lossy().into_owned());
    }
    std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|source| InitError::Read {
            path: PathBuf::from("current executable"),
            source,
        })
}

pub(crate) fn render(binary: &str, scope: ExtensionScope) -> Result<Vec<u8>, InitError> {
    let binary_digest = digest_binary(Path::new(binary));
    let binary = to_string(binary).map_err(|error| InitError::MalformedGuidance {
        path: PathBuf::from(".pi/extensions/lgtm.ts"),
        reason: format!("could not encode binary path: {error}"),
    })?;
    let project_digest = expected_template_digest(ExtensionScope::Project);
    let scope_digest = expected_template_digest(scope);
    Ok(EXTENSION_TEMPLATE
        .replace("__LGTM_BINARY__", &binary)
        .replace("__LGTM_SCOPE__", scope.as_str())
        .replace("__LGTM_TEMPLATE_DIGEST__", &scope_digest)
        .replace("__LGTM_PROJECT_TEMPLATE_DIGEST__", &project_digest)
        .replace("__LGTM_BINARY_DIGEST__", &binary_digest)
        .into_bytes())
}

pub(crate) fn expected_template_digest(scope: ExtensionScope) -> String {
    let canonical = EXTENSION_TEMPLATE.replace("__LGTM_SCOPE__", scope.as_str());
    digest(&normalize_template(&canonical))
}

pub(crate) fn plan(
    target: &Path,
    backup: &Path,
    binary: &str,
    scope: ExtensionScope,
) -> Result<ExtensionPlan, InitError> {
    let generated = render(binary, scope)?;
    let existing = read_if_exists(target)?;
    let backup_contents_existing = read_if_exists(backup)?;
    let backup_is_owned = backup_contents_existing
        .as_deref()
        .is_none_or(|contents| owned_template(contents, &generated, scope));
    let backup_exists = backup_contents_existing.is_some();
    let (target_contents, backup_contents, preserved_collision) = match existing {
        None => (Some(generated), None, false),
        Some(existing) if existing.as_bytes() == generated.as_slice() => (None, None, false),
        Some(existing) if owned_template(&existing, &generated, scope) => {
            if !backup_is_owned {
                return Err(InitError::UnwritableTarget {
                    path: backup.to_path_buf(),
                    reason: "existing Pi backup is not a canonical LGTM extension".to_string(),
                });
            }
            (
                Some(generated),
                (!backup_exists).then_some(existing.into_bytes()),
                false,
            )
        }
        Some(existing) if existing.contains(OWNED_START) || existing.contains(OWNED_END) => {
            return Err(InitError::MalformedGuidance {
                path: target.to_path_buf(),
                reason: "Pi extension has incomplete or mismatched LGTM ownership markers"
                    .to_string(),
            });
        }
        Some(_) => (None, None, true),
    };
    Ok(ExtensionPlan {
        target: target.to_path_buf(),
        backup: backup.to_path_buf(),
        target_contents,
        backup_contents,
        preserved_collision,
    })
}

fn owned_template(contents: &str, generated: &[u8], scope: ExtensionScope) -> bool {
    let Ok(generated) = std::str::from_utf8(generated) else {
        return false;
    };
    contents.contains(OWNED_START)
        && contents.contains(OWNED_END)
        && contents.contains(&format!("// lgtm-pi-scope: {}", scope.as_str()))
        && (normalize_template(contents) == normalize_template(generated)
            || KNOWN_TEMPLATE_DIGESTS
                .iter()
                .any(|known| *known == digest(&normalize_template(contents))))
}

pub(crate) fn normalize_for_attestation(contents: &str) -> String {
    normalize_template(contents)
}

fn normalize_template(contents: &str) -> String {
    contents
        .replace("\r\n", "\n")
        .lines()
        .map(|line| {
            if line.starts_with("const LGTM_BINARY = ") {
                "const LGTM_BINARY = __LGTM_BINARY__;"
            } else if line.starts_with("const BINARY_DIGEST = ") {
                "const BINARY_DIGEST = \"__LGTM_BINARY_DIGEST__\";"
            } else if line.starts_with("const TEMPLATE_DIGEST = ") {
                "const TEMPLATE_DIGEST = \"__LGTM_TEMPLATE_DIGEST__\";"
            } else if line.starts_with("const PROJECT_TEMPLATE_DIGEST = ") {
                "const PROJECT_TEMPLATE_DIGEST = \"__LGTM_PROJECT_TEMPLATE_DIGEST__\";"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn digest(contents: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn digest_binary(path: &Path) -> String {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return String::new();
    };
    if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
        return String::new();
    }
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_ARRAY_CHECK: &str = r#"  if (!property || typeof property !== "object" || Array.isArray(property)) return false;
  const hasDescription = Object.prototype.hasOwnProperty.call(property, "description");
  if (!sameKeys(property, hasDescription ? ["type", "items", "description"] : ["type", "items"])
      || (hasDescription && typeof property.description !== "string")
      || property.type !== expected.type || !property.items"#;
    const V0101_ARRAY_CHECK: &str = r#"  if (!property || !sameKeys(property, ["type", "items"])
      || property.type !== expected.type || !property.items"#;

    #[test]
    fn v0101_project_and_global_templates_remain_upgradeable() {
        for (scope, expected_digest) in [
            (
                ExtensionScope::Project,
                "b45c8c6756955338325fd4d80386523b846b14cc6066a07dc506ce71219079ca",
            ),
            (
                ExtensionScope::Global,
                "ed0ff523f79e64c395184b3b3253a90b3643e088863ef683c60baa45699b1df3",
            ),
        ] {
            let old = EXTENSION_TEMPLATE
                .replace("__LGTM_SCOPE__", scope.as_str())
                .replace(
                    "const PI_VERSION = \"0.84.3\";",
                    "const PI_VERSION = \"0.84.2\";",
                )
                .replace(CURRENT_ARRAY_CHECK, V0101_ARRAY_CHECK);
            assert_eq!(digest(&normalize_template(&old)), expected_digest);
            let current = render("/opt/lgtm", scope).expect("current template renders");
            assert!(owned_template(&old, &current, scope));
        }
    }
}
