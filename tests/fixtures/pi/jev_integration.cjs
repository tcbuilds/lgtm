// Runs the generated extension with real file IO and a fake paid-provider boundary.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);
function loadExtension(file) {
  const source = fs.readFileSync(file, "utf8")
    .replace(/^import \{([^\n]+)\} from "([^\"]+)";$/gm, 'const {$1} = require("$2");')
    .replaceAll("new URL(import.meta.url)", JSON.stringify(file))
    .replace("export default function lgtm", "function lgtm");
  return new Function("require", "process", source + "\nreturn lgtm;")(require, process);
}
const handlers = {}, tools = new Map(), entries = [];
let registrations = 0;
async function emit(name, event, ctx) {
  for (const handler of handlers[name] ?? []) await handler(event, ctx);
}
const pi = {
  on: (name, handler) => { (handlers[name] ??= []).push(handler); },
  registerTool: (tool) => { registrations++; tools.set(tool.name, tool); },
  appendEntry: (type, data) => { entries.push({ type, data }); },
  getAllTools: () => [...tools.values()],
};
const body = "pub fn validate_policy(input: &str) -> bool { !input.is_empty() }\n";
fs.writeFileSync("app.rs", body);
let requests = [], reads = 0, classify, readTransform = (text) => text, readBlocks;
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  sessionManager: { getSessionId: () => "jev-integration", getSessionFile: () => undefined },
  ui: { notify: () => {} },
  executeTool: async (name, args) => {
    assert.equal(name, "read"); reads++;
    const text = fs.readFileSync(path.resolve(args.path), "utf8");
    if (readBlocks) return { result: { content: readBlocks(readTransform(text)) }, isError: false };
    return { result: { content: [{ type: "text", text: readTransform(text) },
      { type: "text", text: "Appended LGTM path-scoped guidance is not file content." }] }, isError: false };
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter");
      assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: async (model, input, options) => {
      requests.push(input); return classify(model, input, options);
    },
  },
};
function answer(_model, input) {
  return { stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: Object.fromEntries(Object.keys(input.questions).map((id) => [id, { type: "bool", probability: 0.95 }])),
    usage: { input: 50, output: 0, totalTokens: 50, cost: { total: 0.0000021 } } };
}
const params = { paths: ["app.rs"], questions: { validates: { type: "bool",
  instructions: "Does the file validate policy input?", criteria: { true: "Validation code", false: "No validation" } } } };
async function invoke(p = params, signal = context.signal) {
  const tool = tools.get("lgtm_jev_files");
  assert.ok(tool, "init must supply the Jev file tool without opt-in");
  const result = await tool.execute("query", p, signal, () => {}, context);
  assert.ok(result.structuredContent);
  assert.ok(!JSON.stringify(result).includes(body.trim()), "raw source reached the calling model");
  return result.structuredContent;
}
(async () => {
  classify = answer;
  loadExtension(sourcePath)(pi);
  if (process.argv[3]) loadExtension(process.argv[3])(pi);
  await emit("session_start", {}, context);
  assert.equal(registrations, 6, "project/global loading registered duplicate Jev tools");
  assert.deepEqual([...tools.keys()].sort(), ["lgtm_jev_compaction", "lgtm_jev_files", "lgtm_jev_review", "lgtm_jev_scope", "lgtm_jev_triage", "lgtm_jev_untrusted"], "every Jev tool must register once");
  assert.equal(requests.length, 0, "startup made a paid request");
  assert.equal(tools.get("lgtm_jev_files").exposure, "codemode");
  let r = await invoke();
  assert.equal(r.status, "ok");
  assert.equal(r.files[0].answers.validates.probability, 0.95);
  assert.match(r.files[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(requests.at(-1).state.file.content, body);
  assert.equal(reads, 1, "file access did not use the governed read tool");

  const runtime = context.modelRegistry;
  context.modelRegistry = undefined;
  assert.equal((await invoke()).status, "unavailable");
  context.modelRegistry = runtime;
  const find = runtime.findOfType;
  runtime.findOfType = () => undefined;
  assert.equal((await invoke()).status, "unavailable");
  runtime.findOfType = find;
  const before = requests.length;
  for (const file of ["../outside.rs", ".env", "auth.json"]) {
    assert.notEqual((await invoke({ ...params, paths: [file] })).status, "ok");
  }
  fs.writeFileSync("large.txt", "x".repeat(16_385));
  assert.notEqual((await invoke({ ...params, paths: ["large.txt"] })).status, "ok");
  fs.writeFileSync("private.txt", "-----BEGIN PRIVATE KEY-----\n");
  assert.notEqual((await invoke({ ...params, paths: ["private.txt"] })).status, "ok");
  fs.writeFileSync("settings.yaml", "password: canary\n");
  assert.notEqual((await invoke({ ...params, paths: ["settings.yaml"] })).status, "ok");
  const policyPath = path.resolve(".lgtm/config.json");
  const oldPolicy = fs.existsSync(policyPath) ? fs.readFileSync(policyPath) : undefined;
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, JSON.stringify({ prohibited_paths: ["app.rs"] }));
  assert.notEqual((await invoke()).status, "ok");
  if (oldPolicy) fs.writeFileSync(policyPath, oldPolicy); else fs.unlinkSync(policyPath);
  fs.symlinkSync(path.resolve("app.rs"), "linked.rs");
  assert.notEqual((await invoke({ ...params, paths: ["linked.rs"] })).status, "ok");
  context.isProjectTrusted = () => false;
  assert.notEqual((await invoke()).status, "ok");
  context.isProjectTrusted = () => true;
  assert.equal(requests.length, before, "rejected/private input was transmitted");

  readTransform = () => "[REDACTED]";
  assert.notEqual((await invoke()).status, "ok");
  assert.equal(requests.length, before, "a tool-result redaction was bypassed");
  readTransform = (text) => "Trusted tool guidance\n\n" + text;
  assert.equal((await invoke()).status, "ok", "governed source preceded by guidance was not recognized");
  assert.equal(requests.at(-1).state.file.content, body);
  readTransform = (text) => text + "\n\nAppended LGTM guidance";
  assert.equal((await invoke()).status, "ok", "governed source wrapped by trailing guidance was not recognized");
  assert.equal(requests.at(-1).state.file.content, body);
  readTransform = (text) => text;
  readBlocks = (text) => [{ type: "text", text: "Leading LGTM guidance" }, { type: "text", text }, { type: "text", text: "Trailing LGTM guidance" }];
  assert.equal((await invoke()).status, "ok", "multi-block governed read was not recognized");
  assert.equal(requests.at(-1).state.file.content, body);
  readBlocks = () => [{ type: "text", text: "Leading guidance" }, { type: "text", text: "[REDACTED]" }];
  assert.notEqual((await invoke()).status, "ok", "multi-block redaction was bypassed");
  readBlocks = undefined;
  classify = () => { throw new Error("provider message must not escape"); };
  r = await invoke();
  assert.equal(r.status, "unavailable");
  assert.ok(!JSON.stringify(r).includes("provider message"));
  classify = (_m, input) => ({ ...answer(_m, input), answers: { validates: { type: "bool", probability: NaN } } });
  assert.equal((await invoke()).status, "unavailable");
  classify = (_m, input) => { fs.appendFileSync("app.rs", "// changed\n"); return answer(_m, input); };
  r = await invoke();
  assert.equal(r.files[0].status, "stale");
  assert.equal(r.files[0].answers, undefined);
  fs.writeFileSync("app.rs", body);
  assert.notEqual((await invoke(params, AbortSignal.abort())).status, "ok");
  classify = () => new Promise(() => {});
  r = await invoke();
  assert.equal(r.status, "unavailable", "hung provider blocked normal work");
  assert.equal(fs.readFileSync("app.rs", "utf8"), body, "ordinary reads stopped working");
  assert.ok(!JSON.stringify(entries).includes(body.trim()), "session records leaked source");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
