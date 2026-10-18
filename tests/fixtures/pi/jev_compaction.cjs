// Exercises the advisory compaction tool with a fake provider boundary.
const assert = require("node:assert/strict");
const { loadExtension, writeRequest, readResult } = require("./jev_harness.cjs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);


const handlers = {}, tools = new Map();
const pi = {
  on: (name, handler) => { (handlers[name] ??= []).push(handler); },
  registerTool: (definition) => { tools.set(definition.name, definition); },
  appendEntry: () => {},
  getAllTools: () => [...tools.values()],
};
async function emit(name, event, ctx) { for (const handler of handlers[name] ?? []) await handler(event, ctx); }

let requests = [], calls = 0, scripted = () => { throw new Error("scripted provider not set"); };
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async (name, args) => { assert.equal(name, "read", "compaction may only read its request"); return readResult(args); },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter"); assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input) => { calls++; requests.push(input); return scripted(model, input); },
  },
};

function advice(recommendation, unfinished) {
  return () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: {
      boundary: { type: "choice", choice: recommendation, probabilities: { [recommendation]: 0.7 }, confidence: 0.7 },
      unfinished: { type: "bool", probability: unfinished ? 0.9 : 0.1 },
    },
    usage: { input: 25, output: 0, totalTokens: 25, cost: { total: 0.000001 } } });
}

const base = { changedPaths: ["src/a.rs", "tests/a.rs"], unfinished: ["wire refresh path"], constraints: ["keep owner edits"] };
async function invoke(params = base, signal = context.signal) {
  const tool = tools.get("lgtm_jev_compaction");
  assert.ok(tool, "init must supply the compaction tool");
  const result = await tool.execute("compact", { requestPath: writeRequest(params) }, signal, () => {}, context);
  assert.ok(result.structuredContent);
  return result.structuredContent;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_compaction");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["read"], "compaction advice may only read its bounded request");
  assert.equal(calls, 0, "startup made a paid request");

  let before = calls;
  scripted = advice("compact_after_finishing", true);
  let result = await invoke();
  assert.equal(result.status, "ok");
  assert.equal(result.advisory, true);
  assert.equal(result.compaction.recommendation, "compact_after_finishing");
  assert.equal(result.compaction.unfinished, true);
  assert.deepEqual(result.preservation.constraints, ["keep owner edits"]);
  assert.deepEqual(result.preservation.paths, ["src/a.rs", "tests/a.rs"]);
  assert.match(result.note, /cannot compact/, "advice must state it cannot compact");
  assert.equal(calls - before, 1);

  scripted = advice("compact_now", false);
  result = await invoke();
  assert.equal(result.compaction.recommendation, "compact_now");
  assert.equal(result.compaction.unfinished, false);

  scripted = advice("stay_put", true);
  result = await invoke();
  assert.equal(result.compaction.recommendation, "stay_put");

  scripted = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { boundary: { type: "choice", choice: "invented", probabilities: {}, confidence: 0.4 }, unfinished: { type: "bool", probability: 0.5 } },
    usage: null });
  result = await invoke();
  assert.equal(result.compaction.recommendation, null, "an unmapped recommendation was accepted");
  assert.equal(result.status, "partial");

  scripted = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter", answers: {}, usage: null });
  result = await invoke();
  assert.equal(result.status, "unavailable", "a missing answer was accepted");

  scripted = () => { throw new Error("provider secret"); };
  result = await invoke();
  assert.equal(result.status, "unavailable");
  assert.ok(!JSON.stringify(result).includes("provider secret"));

  before = calls;
  assert.equal((await invoke({})).status, "rejected");
  assert.equal((await invoke({ changedPaths: Array.from({ length: 201 }, (_, i) => `src/f${i}.rs`) })).status, "rejected");
  assert.equal((await invoke({ unfinished: Array.from({ length: 9 }, () => "x") })).status, "rejected");
  assert.equal((await invoke({ constraints: ["x".repeat(513)] })).status, "rejected");
  assert.equal(calls, before, "rejected input reached the provider");

  scripted = () => new Promise(() => {});
  assert.equal((await invoke()).status, "unavailable", "hung provider blocked compaction advice");
  assert.notEqual((await invoke(base, AbortSignal.abort())).status, "ok");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
