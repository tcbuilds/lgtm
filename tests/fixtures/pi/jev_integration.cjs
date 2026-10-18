// Runs the generated extension with real file IO and a fake paid-provider boundary.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { loadExtension, writeRequest, readResult, readResponse, nativeResponse } = require("./jev_harness.cjs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);
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
    assert.equal(name, "read");
    if (path.basename(args.path) === "request.json") return readResult(args);
    reads++;
    const text = fs.readFileSync(path.resolve(args.path), "utf8");
    const content = readBlocks ? readBlocks(readTransform(text)) : [{ type: "text", text: readTransform(text) },
      { type: "text", text: "Appended LGTM path-scoped guidance is not file content." }];
    const retained = content.filter((block) => block.type === "text").map((block) => block.text).join("\n").includes(text);
    return readResponse(args, content, retained ? text : undefined);
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
  const { preview, ...request } = p;
  const result = await tool.execute("query", { requestPath: writeRequest(request), ...(preview === undefined ? {} : { preview }) }, signal, () => {}, context);
  assert.ok(result.structuredContent);
  assert.ok(!JSON.stringify(result).includes(body.trim()), "raw source reached the calling model");
  return result.structuredContent;
}
async function proveNoRawSourceReads() {
  const sync = require("node:module").syncBuiltinESMExports;
  const open = fs.openSync, read = fs.readSync, executeTool = context.executeTool;
  const selected = new Set();
  let rawReads = 0;
  fs.openSync = (filename, ...args) => {
    const fd = open(filename, ...args);
    if (path.resolve(String(filename)) === path.resolve("app.rs")) selected.add(fd);
    else selected.delete(fd);
    return fd;
  };
  fs.readSync = (fd, ...args) => { if (selected.has(fd)) rawReads++; return read(fd, ...args); };
  sync();
  const before = requests.length;
  try {
    context.executeTool = async (name, args) => {
      assert.equal(name, "read");
      if (path.basename(args.path) === "request.json") return readResult(args);
      return { isError: true, result: { isError: true, content: [{ type: "text", text: "denied" }] } };
    };
    const preview = await invoke({ ...params, preview: true });
    assert.equal(preview.status, "preview");
    assert.equal(preview.files[0].coverage, "estimated");
    assert.equal(rawReads, 0, "metadata preview read source bytes");
    assert.notEqual((await invoke()).status, "ok");
    assert.equal(rawReads, 0, "a denied native read was followed by raw source access");
    assert.equal(requests.length, before);
    for (const sanitized of [body, body.replace("validate_policy", "validate_record")]) {
      fs.writeFileSync("sanitized.rs", sanitized);
      context.executeTool = async (name, args) => {
        assert.equal(name, "read");
        return readResult(path.basename(args.path) === "request.json" ? args : { path: path.resolve("sanitized.rs") });
      };
      const redirected = await invoke();
      assert.equal(redirected.files[0].reason, "read_redirected");
      assert.equal(rawReads, 0, "a redirected read accessed original source bytes");
      assert.equal(requests.length, before, "a redirected read reached the classifier");
    }
  } finally {
    context.executeTool = executeTool;
    fs.openSync = open;
    fs.readSync = read;
    sync();
  }
}

async function proveContentOnlyGuidance() {
  const executeTool = context.executeTool;
  const before = requests.length;
  let mode = "guidance";
  context.executeTool = async (...args) => {
    const outcome = await executeTool(...args);
    const result = outcome.result;
    const original = result.structuredContent;
    // Match Pi's merge rule when a later hook returns content only.
    delete result.structuredContent;
    result.content = [{ type: "text", text: "Path-scoped rules" }, ...result.content];
    if (mode === "redacted") result.content = [{ type: "text", text: "[REDACTED]" }];
    if (mode === "changed") result.content = [{ type: "text", text: original + " changed" }];
    if (mode === "structured") result.structuredContent = "[REDACTED]";
    if (mode === "binding") result.details.lgtmRead.textDigest = "0".repeat(64);
    if (mode === "advisory") delete result.details.lgtmAdvisory;
    return outcome;
  };
  try {
    assert.equal((await invoke({ ...params, preview: true })).status, "preview", "content-only guidance broke the request read");
    assert.equal(requests.length, before, "preview contacted the classifier");
    assert.equal((await invoke()).status, "ok", "content-only guidance broke the selected-file read");
    assert.equal(requests.at(-1).state.file.content, body, "guidance reached the classifier");
    const accepted = requests.length;
    for (mode of ["redacted", "changed", "structured", "binding", "advisory"]) {
      assert.equal((await invoke()).status, "rejected", `${mode} request output was accepted`);
      assert.equal(requests.length, accepted, `${mode} output reached the classifier`);
    }
  } finally {
    context.executeTool = executeTool;
  }
}

async function proveLazyContextGuards() {
  const tool = tools.get("lgtm_jev_files");
  const requestPath = writeRequest(params);
  const guarded = Object.defineProperties({}, Object.getOwnPropertyDescriptors(context));
  Object.defineProperty(guarded, "unusedGuard", { enumerable: true,
    get() { throw new Error("unused native-context getter was evaluated"); } });
  const preview = await tool.execute("lazy-preview", { requestPath, preview: true }, context.signal, undefined, guarded);
  assert.equal(preview.structuredContent.status, "preview", "a context wrapper eagerly evaluated native getters");
  let registry = context.modelRegistry;
  const current = Object.defineProperties({}, Object.getOwnPropertyDescriptors(context));
  Object.defineProperty(current, "modelRegistry", { get: () => registry });
  current.executeTool = async (...args) => {
    const result = await context.executeTool(...args);
    registry = undefined;
    return result;
  };
  const before = requests.length;
  const stale = await tool.execute("lazy-stale", { requestPath }, context.signal, undefined, current);
  assert.equal(stale.structuredContent.status, "unavailable");
  assert.equal(requests.length, before, "a wrapper cached native state before the governed read");
}

async function proveLateNativeFailureIsSafe() {
  const executeTool = context.executeTool;
  const controller = new AbortController();
  const canary = "LATE_NATIVE_SOURCE_CANARY";
  const before = requests.length;
  let release;
  let late = Promise.resolve({ isError: false });
  const gate = new Promise((resolve) => { release = resolve; });
  context.executeTool = async (name, args) => {
    assert.equal(name, "read");
    if (path.basename(args.path) === "request.json") return readResult(args);
    controller.abort();
    late = gate.then(() => nativeResponse("read", args, { isError: true,
      content: [{ type: "text", text: canary }], details: { raw: canary }, structuredContent: canary }));
    return late;
  };
  try {
    const cancelled = await invoke(params, controller.signal);
    assert.equal(cancelled.status, "unavailable");
    assert.equal(controller.signal.aborted, true, "the selected native read never ran");
    assert.equal(requests.length, before);
    release();
    const outcome = await late;
    assert.equal(outcome.isError, true, "error sanitizing must preserve native failure status");
    assert.ok(!JSON.stringify(outcome).includes(canary), "late native output escaped after advisory cancellation");
    // Drain settled continuations; this is not a wall-clock sleep.
    await new Promise((resolve) => setImmediate(resolve));
  } finally {
    release();
    context.executeTool = executeTool;
  }
}

async function proveRequestBounds() {
  const tool = tools.get("lgtm_jev_files");
  const before = requests.length;
  const requestPath = writeRequest({ ...params, questions: { validates: { ...params.questions.validates,
    instructions: "Judge this public file. " + "字".repeat(500) } } });
  fs.appendFileSync(requestPath, " ".repeat(32_768 - fs.statSync(requestPath).size));
  let output = await tool.execute("boundary", { requestPath, preview: true }, context.signal, undefined, context);
  assert.equal(output.structuredContent.status, "preview", "32 KiB request was rejected");
  fs.appendFileSync(requestPath, " ");
  output = await tool.execute("boundary", { requestPath, preview: true }, context.signal, undefined, context);
  assert.equal(output.structuredContent.status, "rejected", "32 KiB + 1 request was accepted");
  for (const ending of ["\n", "\r\n"]) {
    const lines = writeRequest(params);
    fs.appendFileSync(lines, ending.repeat(1499));
    output = await tool.execute("boundary", { requestPath: lines, preview: true }, context.signal, undefined, context);
    assert.equal(output.structuredContent.status, "preview", "1500-line request was rejected");
    fs.appendFileSync(lines, ending);
    output = await tool.execute("boundary", { requestPath: lines, preview: true }, context.signal, undefined, context);
    assert.equal(output.structuredContent.status, "rejected", "1501-line request was accepted");
  }
  assert.equal(requests.length, before, "request previews contacted the classifier");
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

  await proveNoRawSourceReads();
  await proveRequestBounds();
  await proveLateNativeFailureIsSafe();
  await proveLazyContextGuards();

  readTransform = () => "[REDACTED]";
  assert.notEqual((await invoke()).status, "ok");
  assert.equal(requests.length, before, "a tool-result redaction was bypassed");
  readTransform = (text) => text;
  await proveContentOnlyGuidance();
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
