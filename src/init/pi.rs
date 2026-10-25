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
    "baeeb98fad031a77dccce410102224dbec3fafaf8313fefa4ebbaa02404ee626",
    "e3b405dda0afb72a0b0ef697b2277c37cc4395203dd941896ce5e33768dd0d47",
    "439c5f58c1bca50a4c3b6d8932f8f6200b38758bca5e0571512c4547270f67d8",
    "9d6ff3f2a1eae81f37a979989c94def375cf7bd3b95ce466257bf331b7164003",
    "8375bd687e10d6ffb7af82ed5fdcc452682eefbac485474931ddf83760581c25",
    "8c2d8f5b69f12eb6f416ea3cb9f941109b93408724b0e49d5c8669a82d6c1efe",
    "23c1852ff08ed3441e7c8f3f90219135b1ba316025e8dc6f811c4802c62c8f55",
    "b030a8b6d3abfd438249526df3b2348585963daa13a9c77a2f8dd7a72669c2ac",
    "ca4ba7eacae8b1f138933e6a4c7e7d443ac4880018c7faa429eae6c5b650ed18",
    "1b823a8b1b6b847ebc970652afd2c30d67a70abc04796514765d878ae76a70e5",
    "524b3d58c2f839420c14f8ec081855ea3499d4e219d1f5c4c131fe4051d28c2c",
    "a6719ad16be1e48543acb3ae7014afa6b1361d4b85110cd56350807798cb2caa",
    "b45c8c6756955338325fd4d80386523b846b14cc6066a07dc506ce71219079ca",
    "becaa0ca4bc7006cd2d30c9844d24d063ec76e1a69af32725e5967d854a51793",
    "ed0ff523f79e64c395184b3b3253a90b3643e088863ef683c60baa45699b1df3",
    "9214f126c80ebe905f7c9b3441c36c4cd5dbeed8a4cf2d64359f002dff44826c",
    "fe98f5b39be7610f8b2ba9286d9637cb45a25205de018b915ccfbcc1ac284a71",
    "fdbd8826b5446203b0b749524a8905cbd50999a6b64f2fdc692e28b05e027512",
    "ec19a05c2caef1c3f0a18c149642c0df1617b0645782f905de87ec007320384b",
    "f479f973d8a69973cc1fe77a304c24d871d6b1497f6ff82c3b16a5e13bf4a4cc",
    "79c6df8037cb89d0df8992204df8d34de9d547952a14a528b0954fc054b66473",
    "9088869510d83eac68780e9f96290b692384907f310088e3734bb77cd543889e",
    "2df34d5ff7811cd79d643abcb070240b8a4da9dd5be23d2802e08c23b25ee804",
    "9266761d4afcae5543ddf964ef46271421f0fde5935c2fc4e70fcd1966c9a32b",
    "68e46acf24556ed72ac3d72b07354e61cc12048f5af079d967928d3cf1b93b02",
    "2efe84b9a95bc0a7e8e7dbe9d8dab83c64a1bd724d5413af9416316e7b108caf",
    "9ddfc541d0c49e5a913fdee50581fd0529e83c1bee5f913b30697d7e6d54343d",
    "bf5e4d5e2ef1c37aadd1fc2bd8fab1727ba34c633116313f774dd3f444721214",
    "45896a7fc24d1c7ece746d3fd63055c0dac591f51de00e11139c01085a9b2266",
    "aeeca057a8cf4e768318d996d9abf8cb15332e220c5813c4469420cf33b5d405",
    "b7ed808b9b7c0a7c4861734c710f7d1cda627832c7a4830cd24b44eb4a9dbd03",
    "5c8ca58c8552b0ab499d6d9d27c609bdc928a9b95181e250fa919b9ee16aceb0",
    "858495a96c997a2374377519195c8bfca57707420ea0eb5ce6bbfd121751d2d7",
    "4cb2af8b32a71b07860fcb4210b4564045c0f72a05d76c82dd4e0ab5f6a176b1",
    "0fef7ed7f1cf0ffc600f5f664c0adbecf1de051fa6c543acebb02b5d50d66408",
    "63b956a48a4c617901ccc47633b5cd664c6f3c93e9038f27e4b6eb48404bf862",
    "944af599664d9908adad99bc74bbb330ec4b76726b72448b6fc0fea4582bc593",
    "48ece1bf940d19769ea526c38c8743510af934141211563e5ab9b4ccaaa6dcce",
    "fb7abda05c353b6f867767ffb24e7abaa582df0e7ab041f1a64739523ac5641d",
    "4ffe2fd3104e653447393f13cc1aa325508a457069c3da8c11ebdac73e1c77e4",
    "51d9e0a62f3f96e2e63a05ecd0e50e83dedce7902cdc9b06642c2770d96d3a0d",
    // Canonical v0.13.0 project and global extensions.
    "94930f303d7556618ca14e4c5c83845fb1c4054ecd41f6dc414898c3dd489832",
    "54d143beac8424999b4d93748c87cbf492f8bdd4d0bca3911bb91e34e52bf6f4",
    // Canonical pre-removal v0.14.2 project and global extensions.
    "09d706e7bc7259513a5757f79c1a95ea996866a535334222c68cd59bd24a1064",
    "b4a0bb18dd4e4783e348139b68df044066b183ab21b9b9eab51d8e8174786500",
];
const JEV_COMMON_TEMPLATE: &str = include_str!("../../templates/pi/jev_common.js");
const JEV_TEMPLATE: &str = include_str!("../../templates/pi/jev.js");
const JEV_REVIEW_TEMPLATE: &str = include_str!("../../templates/pi/jev_review.js");
const JEV_SCOPE_TEMPLATE: &str = include_str!("../../templates/pi/jev_scope.js");
const JEV_TRIAGE_TEMPLATE: &str = include_str!("../../templates/pi/jev_triage.js");
const JEV_COMPACTION_TEMPLATE: &str = include_str!("../../templates/pi/jev_compaction.js");
const JEV_UNTRUSTED_TEMPLATE: &str = include_str!("../../templates/pi/jev_untrusted.js");
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
const MAX_BINARY_BYTES = 128 * 1024 * 1024;
const NORMAL_TIMEOUT_MS = 10_000;
const POLICY_INPUT_MARKER = "lgtm-pi-policy-input-v1";
const NOTICE_PROTOCOL = "lgtm-pi-heuristic-notices";
const NOTICE_TIMEOUT_MS = 1_500;
const MAX_NOTICE_COORDINATE = 1_000_000_000;
const FAILURE_ENTRY = "lgtm";
const MAX_NOTIFIED_FAILURES = 32;
const SCHEMA_ANNOTATIONS = ["description", "title", "$comment", "examples", "default", "deprecated", "readOnly", "writeOnly"];
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
    const metadata = lstatSync(LGTM_BINARY);
    if (!metadata.isFile()) return false;
    return process.platform === "win32" || (metadata.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function extensionLocation() {
  return new URL(import.meta.url);
}

function projectTemplateIsCanonical() {
  try {
    const extensionUrl = extensionLocation();
    const metadata = lstatSync(extensionUrl);
    if (!metadata.isFile()) return false;
    return canonicalTemplateDigest(readFileSync(extensionUrl, "utf8")) === TEMPLATE_DIGEST;
  } catch {
    return false;
  }
}

// Optional Jev requests use this provenance check before sending advisory data.
// It never decides whether a development tool or commit may run.
function currentBinaryDigest() {
  try {
    const metadata = lstatSync(LGTM_BINARY);
    if (!metadata.isFile() || metadata.size > MAX_BINARY_BYTES) return undefined;
    return createHash("sha256").update(readFileSync(LGTM_BINARY)).digest("hex");
  } catch {
    return undefined;
  }
}

function trustedRuntimeVersion() {
  return projectTemplateIsCanonical()
    && projectBinaryIsRunnable()
    && currentBinaryDigest() === BINARY_DIGEST;
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
      || ![`builtin:${event.toolName}`, `<builtin:${event.toolName}>`].includes(tool.sourceInfo.path)) {
    return false;
  }
  return objectSchemaMatches(tool.parameters, contract.required, contract.properties);
}

function schemaKeysMatch(value, structuralKeys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => structuralKeys.includes(key) || SCHEMA_ANNOTATIONS.includes(key));
}

function sameValues(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length
    && expected.every((value) => actual.includes(value));
}

function objectSchemaMatches(schema, required, properties) {
  if (!schemaKeysMatch(schema, ["type", "required", "properties"])
      || schema.type !== "object" || !sameValues(schema.required, required)
      || !schema.properties || typeof schema.properties !== "object" || Array.isArray(schema.properties)) {
    return false;
  }
  // Extra optional inputs belong to the verified built-in; required policy inputs must not change.
  return Object.entries(properties).every(([key, expected]) =>
    (!Object.prototype.hasOwnProperty.call(schema.properties, key) && !required.includes(key))
      || propertyMatches(schema.properties[key], expected));
}

function primitivePropertyMatches(property, expectedType) {
  return schemaKeysMatch(property, ["type"]) && property.type === expectedType;
}

function propertyMatches(property, expected) {
  if (typeof expected === "string") return primitivePropertyMatches(property, expected);
  return schemaKeysMatch(property, ["type", "items"])
    && property.type === expected.type
    && objectSchemaMatches(property.items, expected.itemRequired, expected.itemProperties);
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
    const sessionEntryId = ctx.sessionManager?.getEntries?.()
      .find((entry) => entry?.type === "custom"
        && entry.customType === "lgtm-runtime"
        && entry.data?.nonce === nonce)?.id;
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
    payload.toolCallId = event.toolCallId;
  } else if (eventType === "tool_result") {
    payload.toolName = event.toolName;
    payload.input = policyToolInput(event.toolName, event.input);
    payload.toolCallId = event.toolCallId;
  }
  return payload;
}

function appendFailure(pi, ctx, eventType, reason, sessionState, generation) {
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
  if (generation !== sessionState.generation) return;
  const warningKey = entry.reason;
  if (sessionState.notifiedFailures.has(warningKey)
      || sessionState.notifiedFailures.size >= MAX_NOTIFIED_FAILURES) return;
  sessionState.notifiedFailures.add(warningKey);
  try {
    // Presentation is optional; a classifier never changes this failure or its gate decision.
    void presentGateNotices(pi, ctx, eventType, { identity: null, items: [{
      kind: "unverified", ruleId: `pi-${warningKey}`, path: null, line: null, candidateId: null,
    }] }, sessionState, sessionState.controller.signal);
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

function invoke(binary, root, eventType, payload, signal) {
  return new Promise((resolveResult) => {
    if (signal?.aborted) {
      resolveResult({ failure: "aborted" });
      return;
    }
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
    let terminationReason;
    let reapTimer;
    const timer = setTimeout(() => terminate("timeout"), NORMAL_TIMEOUT_MS);

    function finish(result) {
      if (settled) return;
      settled = true;
      if (terminationReason) result = { failure: terminationReason };
      signal?.removeEventListener("abort", abort);
      process.removeListener("exit", killOnExit);
      clearTimeout(timer);
      if (reapTimer) clearTimeout(reapTimer);
      if (!result.failure && stderrBytes > 0) result.diagnostics = true;
      if (result.failure === "timeout" || result.failure === "aborted") {
        for (const stream of [child.stdin, child.stdout, child.stderr]) {
          try { stream?.destroy(); } catch {}
        }
        try { child.unref(); } catch {}
        child.removeAllListeners();
      }
      resolveResult(result);
    }

    function killOnExit() { killChild(child); }
    function terminate(reason) {
      if (settled || terminationReason) return;
      terminationReason = reason;
      killChild(child);
      reapTimer = setTimeout(() => finish({ failure: reason }), 1_000);
    }
    function abort() { terminate("aborted"); }
    process.once("exit", killOnExit);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();

    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        killChild(child);
        finish({ failure: terminationReason ?? "output_too_large" });
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
      finish({ failure: terminationReason ?? "stdin" });
    });
    child.on("error", () => finish({ failure: terminationReason ?? "spawn" }));
    child.on("close", (code, signal) => {
      if (settled) return;
      if (terminationReason) {
        finish({ failure: terminationReason });
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
  if (Object.prototype.hasOwnProperty.call(response, "notices")) {
    return validNoticeResponse(eventType, response) ? undefined : "invalid_notice_response";
  }
  if (eventType === "tool_call") {
    // Legacy denial and approval payloads are invalid advisory responses here;
    // they are rejected instead of being forwarded as a tool veto.
    return "invalid_tool_call_response";
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

function validNoticeResponse(eventType, response) {
  if (!["tool_call", "tool_result", "agent_settled"].includes(eventType)
      || responseKeys(response) !== "notices" || !withinJsonBudget(response, 64 * 1024)) return false;
  const notices = response.notices;
  if (!notices || typeof notices !== "object" || Array.isArray(notices)
      || responseKeys(notices) !== "identity\u0000items\u0000protocol\u0000version"
      || notices.protocol !== NOTICE_PROTOCOL || notices.version !== 1
      || !Array.isArray(notices.items) || notices.items.length < 1 || notices.items.length > 32) return false;
  if (eventType === "tool_call"
      ? typeof notices.identity !== "string" || !/^[0-9a-f]{64}$/.test(notices.identity)
      : notices.identity !== null) return false;
  return notices.items.every((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)
        || responseKeys(item) !== "candidateId\u0000kind\u0000line\u0000path\u0000ruleId"
        || !["generic-secret", "review", "unverified"].includes(item.kind)
        || typeof item.ruleId !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(item.ruleId)
        || (item.path !== null && (typeof item.path !== "string" || item.path.length > 512 || /[\u0000-\u001f\u007f]/.test(item.path)))
        || (item.line !== null && (!Number.isSafeInteger(item.line) || item.line < 0 || item.line > MAX_NOTICE_COORDINATE))
        || (item.candidateId !== null && (typeof item.candidateId !== "string" || !/^[0-9a-f]{64}$/.test(item.candidateId)))) return false;
    return eventType === "tool_call"
      ? item.kind === "generic-secret" && item.ruleId === "generic-api-key" && item.path !== null && item.candidateId !== null
      : item.kind !== "generic-secret";
  });
}

async function presentGateNotices(pi, ctx, eventType, notices, state, signal) {
  const generation = state.generation;
  const key = createHash("sha256").update(JSON.stringify([eventType, notices])).digest("hex");
  if (state.noticeKeys.has(key)) return;
  if (state.noticeKeys.size >= 256) state.noticeKeys.delete(state.noticeKeys.keys().next().value);
  const owner = {};
  state.noticeKeys.set(key, owner);
  let delivered = false;
  const fallback = () => {
    if (generation !== state.generation || signal?.aborted) return;
    delivered = true;
    try {
      const diagnostic = notices.items.length === 1 && notices.items[0].kind === "unverified"
        && notices.items[0].ruleId.startsWith("pi-") ? notices.items[0].ruleId.slice(3) : undefined;
      if (diagnostic) {
        ctx.ui?.notify(`LGTM Pi hook is unverified (${diagnostic}). Check LGTM session entries; after updating LGTM, run lgtm refresh and /reload.`, "warning");
      } else {
        pi.appendEntry("lgtm-heuristic-notices", { event: eventType, key, count: notices.items.length, visibility: "warning" });
        ctx.ui?.notify(`LGTM: ${notices.items.length} nonblocking review notice(s). See session entries.`, "warning");
      }
    } catch {
      // Optional presentation cannot deny an operation or manufacture evidence.
    }
  };
  let timer;
  try {
    if (ctx.isProjectTrusted?.() !== true || typeof pi.events?.emit !== "function") return fallback();
    let done;
    const completed = new Promise((resolve) => {
      done = (presented = true) => { delivered = presented; resolve(presented); };
    });
    const request = { protocol: NOTICE_PROTOCOL, version: 1, event: eventType,
      notices: cloneJson(notices), ctx, signal, handled: false, done };
    pi.events.emit("jev-auto:gate", request);
    if (request.handled !== true) return fallback();
    const finished = await Promise.race([completed, new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), NOTICE_TIMEOUT_MS);
    })]);
    if (!finished) fallback();
  } catch {
    fallback();
  } finally {
    clearTimeout(timer);
    if (!delivered && generation === state.generation && state.noticeKeys.get(key) === owner) state.noticeKeys.delete(key);
  }
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

function nativeReadBinding(event, ctx) {
  if (event.toolName !== "read" || event.isError || typeof event.structuredContent !== "string"
      || typeof event.input?.path !== "string" || typeof ctx?.cwd !== "string"
      || event.details?.truncation?.truncated || !withinJsonBudget(event.structuredContent, TOOL_INPUT_BYTES)) return undefined;
  return {
    protocol: "lgtm-pi-read-v1",
    pathDigest: createHash("sha256").update(resolve(ctx.cwd, event.input.path)).digest("hex"),
    textDigest: createHash("sha256").update(event.structuredContent).digest("hex"),
  };
}

function jevNativeFailure(event) {
  if (event.isError !== true || !lgtmJevCommon.owns(event.parentToolCallId)) return undefined;
  return { content: [{ type: "text", text: "LGTM Jev native tool failed; output omitted" }], details: {} };
}

function mergeToolResult(event, response, ctx) {
  let patch;
  if (response !== undefined) {
    patch = { content: [...cloneJson(event.content, TOOL_INPUT_BYTES), ...cloneJson(response.content, TOOL_INPUT_BYTES)] };
    // Appending guidance retains all current authorized data; never resurrect a dropped field.
    if (event.structuredContent !== undefined) patch.structuredContent = cloneJson(event.structuredContent, TOOL_INPUT_BYTES);
  }
  const binding = nativeReadBinding(event, ctx);
  const owned = lgtmJevCommon.owns(event.parentToolCallId);
  if ((!binding && !owned) || (event.details !== undefined && (event.details === null || typeof event.details !== "object" || Array.isArray(event.details)))) return patch;
  return { ...patch, details: { ...event.details,
    ...(owned ? { lgtmAdvisory: { protocol: "lgtm-pi-advisory-v1" } } : {}),
    ...(binding ? { lgtmRead: binding } : {}) } };
}

async function handle(pi, eventType, event, ctx, sessionState) {
  let generation = sessionState.generation;
  try {
    const currentSessionId = sessionId(ctx);
    if (eventType === "session_start"
        || (sessionState.sessionId && sessionState.sessionId !== currentSessionId)) {
      sessionState.generation += 1;
      sessionState.controller.abort();
      sessionState.controller = new AbortController();
      sessionState.notifiedFailures.clear();
      sessionState.noticeKeys.clear();
    }
    sessionState.sessionId = currentSessionId;
    generation = sessionState.generation;
    const signal = ctx.signal instanceof AbortSignal
      ? AbortSignal.any([ctx.signal, sessionState.controller.signal])
      : sessionState.controller.signal;
    const root = resolveScopeRoot(ctx.cwd);
    if (!root) return undefined;
    const policyEvent = eventType === "tool_call" || eventType === "tool_result";
    const settledEvent = eventType === "agent_settled";
    if (policyEvent || settledEvent) {
      let trusted = false;
      try { trusted = ctx.isProjectTrusted?.() === true; } catch {}
      if (!trusted) {
        appendFailure(pi, ctx, eventType, "project_untrusted", sessionState, generation);
        return undefined;
      }
    }
    if (!policyFilesPresent(root)) {
      appendFailure(pi, ctx, eventType, "policy_unverified", sessionState, generation);
      return undefined;
    }
    if (policyEvent) {
      const supported = eventType === "tool_call"
        ? ["bash", "edit", "write"].includes(event.toolName)
        : ["read", "bash", "edit", "write"].includes(event.toolName);
      if (!supported) return undefined;
      if (!verifiedToolContract(pi, event)) {
        appendFailure(pi, ctx, eventType, "tool_provenance_unverified", sessionState, generation);
        return undefined;
      }
      if (eventType === "tool_result" && !validToolResultEvent(event)) {
        appendFailure(pi, ctx, eventType, "tool_result_unverified", sessionState, generation);
        return undefined;
      }
    }
    if (settledEvent && !verifiedAllToolContracts(pi)) {
      appendFailure(pi, ctx, eventType, "tool_provenance_unverified", sessionState, generation);
      return undefined;
    }
    const payload = buildPayload(eventType, event, ctx, pi);
    const result = await invoke(LGTM_BINARY, root, eventType, payload, signal);
    if (result.failure) {
      appendFailure(pi, ctx, eventType, result.failure, sessionState, generation);
      return undefined;
    }
    if (result.diagnostics) {
      appendFailure(pi, ctx, eventType, "child_diagnostics", sessionState, generation);
    }
    if (result.response?.notices) {
      await presentGateNotices(pi, ctx, eventType, result.response.notices, sessionState, signal);
      return eventType === "tool_result" ? mergeToolResult(event, undefined, ctx) : undefined;
    }
    return eventType === "tool_result" ? mergeToolResult(event, result.response, ctx) : undefined;
  } catch {
    appendFailure(pi, ctx, eventType, "handler", sessionState, generation);
    return undefined;
  }
}

__LGTM_JEV_COMMON__

__LGTM_JEV__

__LGTM_JEV_REVIEW__

__LGTM_JEV_SCOPE__

__LGTM_JEV_TRIAGE__

__LGTM_JEV_COMPACTION__

__LGTM_JEV_UNTRUSTED__

export default function lgtm(pi) {
  if (SCOPE === "project" && projectBinaryIsRunnable() && projectTemplateIsCanonical()) {
    globalThis[PROJECT_SCOPE_LOADED] = true;
  }
  const sessionState = {
    sessionId: undefined,
    generation: 0,
    controller: new AbortController(),
    notifiedFailures: new Set(),
    noticeKeys: new Map(),
  };
  pi.on("session_start", (event, ctx) => {
    registerLgtmJev(pi, () => sessionState.controller.signal);
    registerLgtmJevReview(pi, () => sessionState.controller.signal);
    registerLgtmJevScope(pi, () => sessionState.controller.signal);
    registerLgtmJevTriage(pi, () => sessionState.controller.signal);
    registerLgtmJevCompaction(pi, () => sessionState.controller.signal);
    registerLgtmJevUntrusted(pi, () => sessionState.controller.signal);
    return handle(pi, "session_start", event, ctx, sessionState);
  });
  pi.on("session_shutdown", () => {
    sessionState.controller.abort();
    sessionState.generation += 1;
    sessionState.sessionId = undefined;
    sessionState.notifiedFailures.clear();
    sessionState.noticeKeys.clear();
  });
  pi.on("tool_call", (event, ctx) =>
    handle(pi, "tool_call", event, ctx, sessionState));
  pi.on("tool_result", async (event, ctx) => {
    const response = await handle(pi, "tool_result", event, ctx, sessionState);
    // Deterministic post checks still run; only advisory-native error output is suppressed.
    return jevNativeFailure(event) ?? response;
  });
  pi.on("agent_settled", (event, ctx) =>
    handle(pi, "agent_settled", event, ctx, sessionState));
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
        .replace("__LGTM_JEV_COMMON__", JEV_COMMON_TEMPLATE)
        .replace("__LGTM_JEV__", JEV_TEMPLATE)
        .replace("__LGTM_JEV_REVIEW__", JEV_REVIEW_TEMPLATE)
        .replace("__LGTM_JEV_SCOPE__", JEV_SCOPE_TEMPLATE)
        .replace("__LGTM_JEV_TRIAGE__", JEV_TRIAGE_TEMPLATE)
        .replace("__LGTM_JEV_COMPACTION__", JEV_COMPACTION_TEMPLATE)
        .replace("__LGTM_JEV_UNTRUSTED__", JEV_UNTRUSTED_TEMPLATE)
        .replace("__LGTM_BINARY__", &binary)
        .replace("__LGTM_SCOPE__", scope.as_str())
        .replace("__LGTM_TEMPLATE_DIGEST__", &scope_digest)
        .replace("__LGTM_PROJECT_TEMPLATE_DIGEST__", &project_digest)
        .replace("__LGTM_BINARY_DIGEST__", &binary_digest)
        .into_bytes())
}

pub(crate) fn expected_template_digest(scope: ExtensionScope) -> String {
    let canonical = EXTENSION_TEMPLATE
        .replace("__LGTM_JEV_COMMON__", JEV_COMMON_TEMPLATE)
        .replace("__LGTM_JEV__", JEV_TEMPLATE)
        .replace("__LGTM_JEV_REVIEW__", JEV_REVIEW_TEMPLATE)
        .replace("__LGTM_JEV_SCOPE__", JEV_SCOPE_TEMPLATE)
        .replace("__LGTM_JEV_TRIAGE__", JEV_TRIAGE_TEMPLATE)
        .replace("__LGTM_JEV_COMPACTION__", JEV_COMPACTION_TEMPLATE)
        .replace("__LGTM_JEV_UNTRUSTED__", JEV_UNTRUSTED_TEMPLATE)
        .replace("__LGTM_SCOPE__", scope.as_str());
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

pub(crate) fn owned_template(contents: &str, generated: &[u8], scope: ExtensionScope) -> bool {
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
    const CURRENT_MARKER_LOOKUP: &str = r#"    const sessionEntryId = ctx.sessionManager?.getEntries?.()
      .find((entry) => entry?.type === "custom"
        && entry.customType === "lgtm-runtime"
        && entry.data?.nonce === nonce)?.id;"#;
    const V0110_MARKER_LOOKUP: &str =
        r#"    const sessionEntryId = ctx.sessionManager?.getLeafId?.();"#;
    const CURRENT_POLICY_ORDER: &str = r#"      const supported = eventType === "tool_call"
        ? ["bash", "edit", "write"].includes(event.toolName)
        : ["read", "edit", "write"].includes(event.toolName);
      if (!supported) return undefined;
      if (!verifiedToolContract(pi, event)) {
        appendFailure(pi, ctx, eventType, "tool_provenance_unverified");
        return undefined;
      }"#;
    const V0110_POLICY_ORDER: &str = r#"      if (!verifiedToolContract(pi, event)) {
        appendFailure(pi, ctx, eventType, "tool_provenance_unverified");
        return undefined;
      }
      const supported = eventType === "tool_call"
        ? ["bash", "edit", "write"].includes(event.toolName)
        : ["read", "edit", "write"].includes(event.toolName);
      if (!supported) return undefined;"#;

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
            let old = include_str!("../../tests/fixtures/pi-v0120-extension.txt")
                .replace("__LGTM_SCOPE__", scope.as_str())
                .replace(
                    "const PI_VERSION = \"0.84.3\";",
                    "const PI_VERSION = \"0.84.2\";",
                )
                .replace(
                    "const PRE_TOOL_TIMEOUT_MS = 310_000;",
                    "const PRE_TOOL_TIMEOUT_MS = 40_000;",
                )
                .replace(CURRENT_ARRAY_CHECK, V0101_ARRAY_CHECK)
                .replace(CURRENT_MARKER_LOOKUP, V0110_MARKER_LOOKUP)
                .replace(CURRENT_POLICY_ORDER, V0110_POLICY_ORDER);
            assert_eq!(digest(&normalize_template(&old)), expected_digest);
            let current = render("/opt/lgtm", scope).expect("current template renders");
            assert!(owned_template(&old, &current, scope));
        }
    }

    #[test]
    fn previous_pi_timeout_templates_remain_upgradeable() {
        for scope in [ExtensionScope::Project, ExtensionScope::Global] {
            let old = include_str!("../../tests/fixtures/pi-v0120-extension.txt")
                .replace("__LGTM_SCOPE__", scope.as_str())
                .replace(
                    "const PRE_TOOL_TIMEOUT_MS = 310_000;",
                    "const PRE_TOOL_TIMEOUT_MS = 40_000;",
                );
            let current = render("/opt/lgtm", scope).expect("current template renders");
            assert!(owned_template(&old, &current, scope));
        }
    }
}
