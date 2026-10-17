// Exercises the advisory diff-review tool with real structured Bash IO and a fake provider.
const assert = require("node:assert/strict");
const { bashResult, loadExtension } = require("./jev_harness.cjs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);

const PATH_COMMAND = "git diff --no-ext-diff --no-textconv --no-renames --name-only -z HEAD";
const DIFF_COMMAND = "git diff --no-ext-diff --no-textconv --no-renames --no-color --unified=3 HEAD";
const DISPLAY_PATH_MARKER = ".env DISPLAY_PATH_CANARY";
const DISPLAY_PATCH_MARKER = "DISPLAY_PATCH_CANARY";
const RISKY = [
  "diff --git a/src/auth/session.rs b/src/auth/session.rs",
  "--- a/src/auth/session.rs",
  "+++ b/src/auth/session.rs",
  "@@ -1,2 +1,3 @@",
  "-let token = read_token();",
  "+let token = read_token().unwrap_or_default();",
  "+delete_all_sessions();",
  "",
].join("\n");
const HARMLESS = [
  "diff --git a/doc/readme.md b/doc/readme.md",
  "--- a/doc/readme.md",
  "+++ b/doc/readme.md",
  "@@ -1 +1 @@",
  "-Old wording.",
  "+Clearer wording.",
  "",
].join("\n");

const handlers = {};
const tools = new Map();
const pi = {
  on: (name, handler) => {
    if (!handlers[name]) handlers[name] = [];
    handlers[name].push(handler);
  },
  registerTool: (definition) => { tools.set(definition.name, definition); },
  appendEntry: () => {},
  getAllTools: () => [...tools.values()],
};

async function emit(name, event, context) {
  for (const handler of handlers[name] ?? []) await handler(event, context);
}

function flag(raised) {
  return { type: "bool", probability: raised ? 0.9 : 0.05 };
}

function allFlags(raised) {
  return () => ({
    stopReason: "stop",
    model: "~typesafe/jev-latest",
    provider: "openrouter",
    answers: {
      auth: flag(raised),
      data_loss: flag(raised),
      public_interface: flag(raised),
      state_complexity: flag(raised),
    },
    usage: { input: 20, output: 0, totalTokens: 20, cost: { total: 0.0000008 } },
  });
}

function nulList(paths) {
  return paths.length === 0 ? "" : `${paths.join("\0")}\0`;
}

let patchOutput = RISKY;
let patchDisplay = DISPLAY_PATCH_MARKER;
let pathDisplay = DISPLAY_PATH_MARKER;
let nativeTruncated = false;
let beforePaths = nulList(["src/auth/session.rs"]);
let afterPaths = beforePaths;
let pathReads = 0;
let diffReads = 0;
let calls = 0;
const requests = [];
let classifier = allFlags(true);
const context = {
  cwd: process.cwd(),
  isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async (name, args) => {
    assert.equal(name, "bash");
    if (args.command === PATH_COMMAND) {
      const output = pathReads++ === 0 ? beforePaths : afterPaths;
      return bashResult(output, { display: pathDisplay });
    }
    assert.equal(args.command, DIFF_COMMAND);
    diffReads++;
    return bashResult(patchOutput, { display: patchDisplay, truncated: nativeTruncated });
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier");
      assert.equal(provider, "openrouter");
      assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input) => {
      calls++;
      requests.push(input);
      return classifier(model, input);
    },
  },
};

function configure({
  patch = RISKY,
  patchText = DISPLAY_PATCH_MARKER,
  pathText = DISPLAY_PATH_MARKER,
  truncated = false,
  pathsBefore = nulList(["src/auth/session.rs"]),
  pathsAfter = pathsBefore,
} = {}) {
  patchOutput = patch;
  patchDisplay = patchText;
  pathDisplay = pathText;
  nativeTruncated = truncated;
  beforePaths = pathsBefore;
  afterPaths = pathsAfter;
  pathReads = 0;
  diffReads = 0;
}

async function invoke(signal = context.signal) {
  const tool = tools.get("lgtm_jev_review");
  assert.ok(tool, "init must supply the diff-review tool");
  const result = await tool.execute("review", {}, signal, () => {}, context);
  assert.ok(result.structuredContent);
  return result.structuredContent;
}

async function assertRejectedWithoutProvider(reason) {
  const before = calls;
  const result = await invoke();
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, reason);
  assert.equal(calls, before, `${reason} reached the provider`);
  return result;
}

async function verifyToolRegistration() {
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_review");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["bash"]);
  assert.ok(!tool.reachesTools().includes("write") && !tool.reachesTools().includes("edit"), "review tool may not write");
  assert.ok(tools.has("lgtm_jev_files"), "file tool must still be registered");
  assert.equal(tool.parameters.additionalProperties, false);
  assert.equal(calls, 0, "startup made a paid request");
}

async function verifyFlagOutcomes() {
  const result = await invoke();
  assert.equal(result.status, "ok");
  assert.equal(result.advisory, true);
  for (const id of ["auth", "data_loss", "public_interface", "state_complexity"]) {
    assert.equal(result.flags[id].raised, true, `${id} was not raised`);
    assert.equal(result.flags[id].evidence, "d0");
    assert.equal(result.flags[id].unknown, false);
  }
  assert.equal(result.evidence.coverage, "complete");
  assert.deepEqual(result.evidence.files, ["src/auth/session.rs"]);
  assert.ok(!("score" in result) && !("risk" in result), "an aggregate score could hide a security concern");
  assert.ok(!JSON.stringify(result).includes("delete_all_sessions"), "diff text reached the caller");
  assert.equal(result.usage.totalTokens, 20);
  assert.equal(calls, 1);
  assert.equal(pathReads, 2, "changed paths were not read both before and after the diff");
  assert.equal(diffReads, 1);
  assert.equal(requests[0].state.review.diff.patch, RISKY, "structured stdout was not used as patch text");
  assert.deepEqual(requests[0].state.review.diff.files, ["src/auth/session.rs"]);
  assert.ok(!JSON.stringify(requests[0]).includes(DISPLAY_PATH_MARKER), "path display text entered the provider request");
  assert.ok(!JSON.stringify(requests[0]).includes(DISPLAY_PATCH_MARKER), "patch display text entered the provider request");

  configure({ patch: HARMLESS, pathsBefore: nulList(["doc/readme.md"]) });
  classifier = allFlags(false);
  const harmless = await invoke();
  assert.equal(harmless.status, "ok");
  assert.deepEqual(Object.values(harmless.flags).map((item) => item.raised), [false, false, false, false]);
}

async function verifyMalformedProviderResponses() {
  classifier = () => ({
    stopReason: "stop",
    model: "~typesafe/jev-latest",
    provider: "openrouter",
    answers: {
      auth: { type: "bool", probability: Number.NaN },
      data_loss: flag(false),
      public_interface: flag(false),
      state_complexity: flag(false),
    },
    usage: null,
  });
  const partial = await invoke();
  assert.equal(partial.status, "partial");
  assert.equal(partial.flags.auth.unknown, true);
  assert.equal(partial.flags.auth.raised, null);

  classifier = () => { throw new Error("secret provider message"); };
  const unavailable = await invoke();
  assert.equal(unavailable.status, "unavailable");
  assert.equal(unavailable.flags, null);
  assert.ok(!JSON.stringify(unavailable).includes("secret provider message"));
}

async function verifyEmptyAndOversizedDiffs() {
  const before = calls;
  configure({ patch: "", patchText: "(no output)", pathsBefore: nulList(["src/empty.rs"]) });
  const empty = await invoke();
  assert.equal(empty.status, "empty");
  assert.equal(empty.reason, "diff_empty");
  assert.equal(diffReads, 1);
  assert.equal(calls, before, "an empty structured diff reached the provider");

  configure({ patch: "x".repeat(48 * 1024 * 4 + 10) });
  await assertRejectedWithoutProvider("diff_too_large");
}

async function verifyPrivatePaths() {
  const privatePatch = [
    "diff --git a/.env b/.env",
    "--- a/.env",
    "+++ b/.env",
    "@@ -1 +1 @@",
    "-OLD=1",
    "+PASSWORD=private_canary",
    "diff --git a/src/app.rs b/src/app.rs",
    "--- a/src/app.rs",
    "+++ b/src/app.rs",
    "@@ -1 +1 @@",
    "-a",
    "+b",
    "",
  ].join("\n");
  configure({ patch: privatePatch, pathsBefore: nulList([".env", "src/app.rs"]) });
  const before = calls;
  const privateResult = await invoke();
  assert.equal(privateResult.status, "rejected");
  assert.equal(privateResult.reason, "diff_private");
  assert.equal(calls, before, "a private path reached the provider");
  assert.ok(!requests.some((input) => JSON.stringify(input).includes("private_canary")), "private hunk content was transmitted");
  assert.ok(!requests.some((input) => JSON.stringify(input).includes(".env")), "private path was transmitted");
  assert.equal(diffReads, 0, "a private path should be rejected before reading patch text");

  configure({ patch: '--- a/app.rs\n+++ b/app.rs\n+"-----BEGIN PRIVATE KEY-----"\n' });
  await assertRejectedWithoutProvider("diff_sensitive");
  await verifyQuotedPrivatePaths();
}

async function verifyQuotedPrivatePaths() {
  for (const quotedPath of ["private dir/.env", "dir/signing\\t.key", "private dir\\tsigning\\t.key"]) {
    const quotedPatch = [
      `diff --git "a/${quotedPath}" "b/${quotedPath}"`,
      `--- "a/${quotedPath}"`,
      `+++ "b/${quotedPath}"`,
      "@@ -1 +1 @@",
      "-a",
      "+private_canary",
      "",
    ].join("\n");
    configure({ patch: quotedPatch, pathsBefore: nulList([quotedPath]) });
    await assertRejectedWithoutProvider("diff_private");
  }
}

async function verifyPrivatePathInStructuredTail() {
  const hiddenEnvPatch = `${"x".repeat(48 * 1024 + 100)}\ndiff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n+TAIL_PRIVATE_CANARY\n`;
  configure({
    patch: hiddenEnvPatch,
    pathsBefore: nulList(["src/app.rs"]),
    pathsAfter: nulList(["src/app.rs", ".env"]),
  });
  const result = await assertRejectedWithoutProvider("diff_private");
  assert.equal(pathReads, 2, "the independent path list was not checked after reading the patch");
  assert.equal(diffReads, 1, "the structured patch tail was not read");
  assert.ok(!JSON.stringify(result).includes("TAIL_PRIVATE_CANARY"));
}

async function verifyNativeTruncationAndSensitiveTails() {
  configure({ patch: RISKY, truncated: true });
  const before = calls;
  const truncated = await invoke();
  assert.equal(truncated.status, "rejected");
  assert.equal(truncated.reason, "diff_unavailable");
  assert.equal(calls, before, "truncated native stdout reached the provider");

  for (const secretTail of [
    '+{"password":"json_secret_canary"}',
    "+ghp_123456789012345678901234567890",
  ]) {
    configure({ patch: `${"x".repeat(48 * 1024 + 100)}\n${secretTail}\n` });
    await assertRejectedWithoutProvider("diff_sensitive");
    assert.ok(!requests.some((input) => JSON.stringify(input).includes(secretTail)), "tail secret reached the provider");
  }
}

async function verifyPathListBoundaries() {
  const tooManyPaths = nulList(Array.from({ length: 201 }, (_, index) => `src/file-${index}.rs`));
  configure({ pathsBefore: tooManyPaths });
  await assertRejectedWithoutProvider("diff_too_large");
  assert.equal(diffReads, 0);

  configure({ pathsBefore: "src/unterminated.rs" });
  await assertRejectedWithoutProvider("diff_paths_incomplete");
  assert.equal(diffReads, 0);

  configure({ pathsBefore: `${"x".repeat(192 * 1024 + 1)}\0` });
  await assertRejectedWithoutProvider("diff_paths_incomplete");
  assert.equal(diffReads, 0);

  const maximumPaths = Array.from({ length: 200 }, (_, index) => `src/file-${index}.rs`);
  classifier = allFlags(false);
  configure({ pathsBefore: nulList(maximumPaths) });
  const before = calls;
  const accepted = await invoke();
  assert.equal(accepted.status, "ok", "the maximum allowed path count was rejected");
  assert.equal(accepted.evidence.files.length, 200);
  assert.equal(pathReads, 2);
  assert.equal(calls, before + 1);

  configure({
    patch: HARMLESS,
    pathsBefore: nulList(["src/before.rs"]),
    pathsAfter: nulList(["src/after.rs"]),
  });
  await assertRejectedWithoutProvider("diff_changed");
  assert.equal(pathReads, 2);
  assert.equal(diffReads, 1);
}

async function verifyHunkTextDoesNotBecomeEvidencePath() {
  const hunkPathPatch = [
    "diff --git a/src/query.sql b/src/query.sql",
    "--- a/src/query.sql",
    "+++ b/src/query.sql",
    "@@ -1 +1 @@",
    "--- SOURCE_BODY_CANARY",
    "+SELECT 1;",
    "",
  ].join("\n");
  configure({ patch: hunkPathPatch, pathsBefore: nulList(["src/query.sql"]) });
  classifier = allFlags(false);
  const result = await invoke();
  assert.equal(result.status, "ok");
  assert.deepEqual(result.evidence.files, ["src/query.sql"]);
  assert.ok(!result.evidence.files.some((name) => name.includes("SOURCE_BODY_CANARY")));
  const request = requests[requests.length - 1];
  assert.deepEqual(request.state.review.diff.files, ["src/query.sql"]);
  assert.ok(request.state.review.diff.patch.includes("--- SOURCE_BODY_CANARY"));
}

async function verifyProviderTimeoutAndCancellation() {
  configure({ patch: RISKY });
  classifier = () => new Promise(() => {});
  const timedOut = await invoke();
  assert.equal(timedOut.status, "unavailable", "hung provider blocked review");
  assert.equal(timedOut.status === "passed", false, "review never claims passed");
  assert.equal((await invoke(AbortSignal.abort())).reason, "cancelled");
}

(async () => {
  loadExtension(sourcePath)(pi);
  await verifyToolRegistration();
  await verifyFlagOutcomes();
  await verifyMalformedProviderResponses();
  await verifyEmptyAndOversizedDiffs();
  await verifyPrivatePaths();
  await verifyPrivatePathInStructuredTail();
  await verifyNativeTruncationAndSensitiveTails();
  await verifyPathListBoundaries();
  await verifyHunkTextDoesNotBecomeEvidencePath();
  await verifyProviderTimeoutAndCancellation();
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
