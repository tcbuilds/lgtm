// Exercises the advisory diff-review tool with real IO and a fake provider.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);

function loadExtension(file) {
  const source = fs.readFileSync(file, "utf8")
    .replace(/^import \{([^\n]+)\} from "([^"]+)";$/gm, 'const {$1} = require("$2");')
    .replaceAll("new URL(import.meta.url)", JSON.stringify(file))
    .replace("export default function lgtm", "function lgtm");
  return new Function("require", "process", source + "\nreturn lgtm;")(require, process);
}

const handlers = {}, tools = new Map();
const pi = {
  on: (name, handler) => { (handlers[name] ??= []).push(handler); },
  registerTool: (definition) => { tools.set(definition.name, definition); },
  appendEntry: () => {},
  getAllTools: () => [...tools.values()],
};
async function emit(name, event, ctx) { for (const handler of handlers[name] ?? []) await handler(event, ctx); }

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

let diff = RISKY, calls = 0, requests = [], classify = allFlags(true);
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async (name, args) => {
    assert.equal(name, "bash");
    assert.equal(args.command, "git diff --no-ext-diff --no-color --unified=3 HEAD");
    return { content: [{ type: "text", text: diff }] };
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter"); assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input) => { calls++; requests.push(input); return classify(model, input); },
  },
};

function flag(raised) { return { type: "bool", probability: raised ? 0.9 : 0.05 }; }
function allFlags(raised) {
  return () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { auth: flag(raised), data_loss: flag(raised), public_interface: flag(raised), state_complexity: flag(raised) },
    usage: { input: 20, output: 0, totalTokens: 20, cost: { total: 0.0000008 } } });
}

async function invoke(signal = context.signal) {
  const tool = tools.get("lgtm_jev_review");
  assert.ok(tool, "init must supply the diff-review tool");
  const result = await tool.execute("review", {}, signal, () => {}, context);
  assert.ok(result.structuredContent);
  return result.structuredContent;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_review");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["bash"]);
  assert.ok(!tool.reachesTools().includes("write") && !tool.reachesTools().includes("edit"), "review tool may not write");
  assert.ok(tools.has("lgtm_jev_files"), "file tool must still be registered");
  assert.equal(calls, 0, "startup made a paid request");

  let before = calls;
  let result = await invoke();
  assert.equal(result.status, "ok");
  assert.equal(result.advisory, true);
  for (const id of ["auth", "data_loss", "public_interface", "state_complexity"]) {
    assert.equal(result.flags[id].raised, true, `${id} was not raised`);
    assert.equal(result.flags[id].evidence, "d0");
    assert.equal(result.flags[id].unknown, false);
  }
  assert.equal(result.evidence.coverage, "complete");
  assert.ok(!("score" in result) && !("risk" in result), "an aggregate score could hide a security concern");
  assert.ok(!JSON.stringify(result).includes("delete_all_sessions"), "diff text reached the caller");
  assert.equal(result.usage.totalTokens, 20);
  assert.equal(calls - before, 1);

  diff = HARMLESS;
  classify = allFlags(false);
  result = await invoke();
  assert.equal(result.status, "ok");
  assert.deepEqual(Object.values(result.flags).map((f) => f.raised), [false, false, false, false]);

  classify = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { auth: { type: "bool", probability: Number.NaN }, data_loss: flag(false), public_interface: flag(false), state_complexity: flag(false) },
    usage: null });
  result = await invoke();
  assert.equal(result.status, "partial");
  assert.equal(result.flags.auth.unknown, true);
  assert.equal(result.flags.auth.raised, null);

  classify = () => { throw new Error("secret provider message"); };
  result = await invoke();
  assert.equal(result.status, "unavailable");
  assert.equal(result.flags, null);
  assert.ok(!JSON.stringify(result).includes("secret provider message"));

  before = calls;
  diff = "";
  result = await invoke();
  assert.equal(result.status, "empty");
  diff = "x".repeat(48 * 1024 * 4 + 10);
  result = await invoke();
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, "diff_too_large");
  diff = "--- a/app.rs\n+++ b/app.rs\n+AWS_SECRET = \"-----BEGIN PRIVATE KEY-----\"\n";
  result = await invoke();
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, "diff_ineligible");
  assert.equal(calls, before, "rejected diffs reached the provider");

  before = calls;
  diff = ["diff --git a/.env b/.env", "--- a/.env", "+++ b/.env", "@@ -1 +1 @@", "-OLD=1", "+PASSWORD=private_canary", "diff --git a/src/app.rs b/src/app.rs", "--- a/src/app.rs", "+++ b/src/app.rs", "@@ -1 +1 @@", "-a", "+b", ""].join("\n");
  classify = allFlags(false);
  result = await invoke();
  assert.equal(result.status, "rejected", "a private diff was accepted");
  assert.equal(result.reason, "diff_private");
  assert.equal(calls, before, "a private diff reached the provider");
  assert.ok(!requests.some((input) => JSON.stringify(input).includes("private_canary")), "private hunk content was transmitted");
  assert.ok(!requests.some((input) => JSON.stringify(input).includes(".env")), "private path was transmitted");

  // Git-quoted paths with spaces or escapes must each be rejected independently.
  before = calls;
  for (const quotedPath of ["private dir/.env", "dir/signing\\t.key", "private dir\\tsigning\\t.key"]) {
    diff = [
      `diff --git "a/${quotedPath}" "b/${quotedPath}"`,
      `--- "a/${quotedPath}"`,
      `+++ "b/${quotedPath}"`,
      "@@ -1 +1 @@",
      "-a",
      "+private_canary",
      "",
    ].join("\n");
    result = await invoke();
    assert.equal(result.status, "rejected", `quoted private path accepted: ${quotedPath}`);
    assert.equal(result.reason, "diff_private", `quoted private path reason: ${quotedPath}`);
  }
  assert.equal(calls, before, "a quoted private diff reached the provider");

  diff = RISKY;
  classify = () => new Promise(() => {});
  result = await invoke();
  assert.equal(result.status, "unavailable", "hung provider blocked review");
  assert.equal(result.status === "passed", false, "review never claims passed");

  assert.notEqual((await invoke(AbortSignal.abort())).status, "ok");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
