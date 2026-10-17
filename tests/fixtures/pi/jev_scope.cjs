// Exercises the advisory scope/claim tool with a fake git and provider boundary.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const sourcePath = process.argv[2];
setTimeout(() => process.exit(124), 30_000).unref();

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

const REVISION = "a".repeat(40);
let paths = ["src/init/pi.rs"]; // installer edit outside a docs-only scope
let calls = 0;
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async (name, args) => {
    assert.equal(name, "bash");
    if (args.command === "git rev-parse HEAD") return { content: [{ type: "text", text: `${REVISION}\n` }] };
    assert.equal(args.command, "git diff --name-only HEAD");
    return { content: [{ type: "text", text: paths.join("\n") }] };
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter"); assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input) => { calls++; return scripted(model, input); },
  },
};

let scripted = () => { throw new Error("scripted provider not set"); };
function answers(input, options) {
  const result = { scope_drift: { type: "bool", probability: options.drift ? 0.9 : 0.1 } };
  Object.keys(input.questions).filter((id) => id.startsWith("c")).forEach((id, index) => {
    result[id] = { type: "choice", choice: options.verdicts[index] ?? "supported", probabilities: {}, confidence: 0.7 };
  });
  return result;
}
function scriptFor(options) {
  return (_model, input) => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: answers(input, options), usage: { input: 30, output: 0, totalTokens: 30, cost: { total: 0.0000012 } } });
}

const base = { scope: "documentation only, no production code", claims: ["Only markdown changed"] };
async function invoke(params = base, signal = context.signal) {
  const tool = tools.get("lgtm_jev_scope");
  assert.ok(tool, "init must supply the scope tool");
  const result = await tool.execute("scope", params, signal, () => {}, context);
  assert.ok(result.structuredContent);
  assert.ok(!JSON.stringify(result).includes("documentation only"), "caller text reached the output");
  return result.structuredContent;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_scope");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["bash"]);
  assert.deepEqual([...tools.keys()].sort(), ["lgtm_jev_files", "lgtm_jev_review", "lgtm_jev_scope", "lgtm_jev_triage"]);
  assert.equal(calls, 0, "startup made a paid request");

  let before = calls;
  scripted = scriptFor({ drift: true, verdicts: ["contradicted"] });
  let result = await invoke();
  assert.equal(result.status, "ok");
  assert.equal(result.advisory, true);
  assert.equal(result.scope.drift, true);
  assert.equal(result.scope.revision, REVISION);
  assert.deepEqual(result.scope.paths, ["src/init/pi.rs"]);
  assert.equal(result.claims[0].verdict, "contradicted");
  assert.equal(result.claims[0].id, "c0");
  assert.equal(result.claims[0].unknown, false);
  assert.ok(!("passed" in result) && !("status" in result.scope), "scope advice never claims verification");
  assert.equal(calls - before, 1);

  paths = ["doc/adapters/pi.md"];
  scripted = scriptFor({ drift: false, verdicts: ["supported"] });
  result = await invoke();
  assert.equal(result.status, "ok");
  assert.equal(result.scope.drift, false);
  assert.equal(result.claims[0].verdict, "supported");

  paths = ["src/init/pi.rs"];
  scripted = scriptFor({ drift: true, verdicts: ["unmapped"] });
  result = await invoke();
  assert.equal(result.claims[0].verdict, "invalid");
  assert.equal(result.claims[0].unknown, true);
  assert.equal(result.status, "partial");

  scripted = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { scope_drift: { type: "bool", probability: 0.5 } }, usage: null });
  result = await invoke();
  assert.equal(result.claims[0].verdict, "missing");
  assert.equal(result.status, "partial", "a missing claim must not become a clean result");

  scripted = () => { throw new Error("provider secret"); };
  result = await invoke();
  assert.equal(result.status, "unavailable");
  assert.equal(result.scope, null);
  assert.ok(!JSON.stringify(result).includes("provider secret"));

  before = calls;
  result = await invoke({ ...base, revision: "b".repeat(40) });
  assert.equal(result.status, "stale");
  assert.equal(result.reason, "stale_revision");
  paths = [];
  result = await invoke();
  assert.equal(result.status, "empty");
  paths = Array.from({ length: 201 }, (_, i) => `src/f${i}.rs`);
  result = await invoke();
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, "diff_too_large");
  assert.equal(calls, before, "stale/empty/oversized checks reached the provider");

  paths = ["src/init/pi.rs"];
  assert.equal((await invoke({ scope: "", claims: ["x"] })).status, "rejected");
  assert.equal((await invoke({ scope: "docs", claims: [] })).status, "rejected");
  assert.equal((await invoke({ scope: "docs", claims: Array.from({ length: 9 }, () => "x") })).status, "rejected");
  assert.equal((await invoke({ scope: "docs", claims: Array.from({ length: 9 }, () => "x") })).reason, "invalid_request");

  scripted = () => new Promise(() => {});
  result = await invoke();
  assert.equal(result.status, "unavailable", "hung provider blocked scope advice");

  assert.notEqual((await invoke(base, AbortSignal.abort())).status, "ok");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
