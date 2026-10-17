// Exercises bounded multi-file Jev scouting with real file IO and a fake provider boundary.
// Preview must make zero classifier calls; batches must never invent a negative match.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sourcePath = process.argv[2];
setTimeout(() => process.exit(124), 30_000).unref();

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

const bodies = {
  "a.rs": "pub fn validate_policy(input: &str) -> bool { !input.is_empty() }\n",
  "b.ts": "export function parseRecord(raw: unknown): string { return String(raw) }\n",
  "c.py": "def parse_record(raw):\n    return str(raw)\n",
};
for (const [name, body] of Object.entries(bodies)) fs.writeFileSync(name, body);

function answerFor(question) {
  if (question.type === "bool") return { type: "bool", probability: 0.8 };
  if (question.type === "choice") {
    const labels = Object.keys(question.criteria);
    return { type: "choice", choice: labels[0], probabilities: Object.fromEntries(labels.map((label) => [label, 1 / labels.length])), confidence: 0.7 };
  }
  return { type: "score", score: 1, confidence: 0.6 };
}

function answer(_model, input) {
  return {
    stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: Object.fromEntries(Object.entries(input.questions).map(([id, question]) => [id, answerFor(question)])),
    usage: { input: 40, output: 0, totalTokens: 40, cost: { total: 0.0000017 } },
  };
}

let requests = [], reads = 0;
let classify = answer;
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  sessionManager: { getSessionId: () => "jev-scout", getSessionFile: () => undefined },
  ui: { notify: () => {} },
  executeTool: async (name, args) => {
    assert.equal(name, "read"); reads++;
    return { content: [{ type: "text", text: fs.readFileSync(path.resolve(args.path), "utf8") },
      { type: "text", text: "Appended LGTM path-scoped guidance is not file content." }] };
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter");
      assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input, options) => {
      requests.push(input);
      return classify(model, input, options);
    },
  },
};

const questions = {
  risky: { type: "bool", instructions: "Does this file touch auth or permissions?", criteria: { true: "Auth code", false: "No auth code" } },
  layer: { type: "choice", instructions: "Which layer holds the main logic?", criteria: { domain: "Domain rules", api: "HTTP/API", infra: "Infrastructure" } },
  quality: { type: "score", instructions: "Rate boundary validation strength.", criteria: ["none", "partial", "strong"] },
};
const params = { paths: ["a.rs", "b.ts", "c.py"], questions };

async function invoke(p = params, signal = context.signal) {
  const tool = tools.get("lgtm_jev_files");
  assert.ok(tool, "init must supply the Jev file tool without opt-in");
  const result = await tool.execute("query", p, signal, () => {}, context);
  assert.ok(result.structuredContent);
  assert.ok(!JSON.stringify(result).includes("validate_policy"), "raw source reached the calling model");
  return result.structuredContent;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  assert.equal(registrations, 5);
  const tool = tools.get("lgtm_jev_files");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["read"], "Jev may only reach the governed read tool");
  assert.deepEqual([...tools.keys()].sort(), ["lgtm_jev_compaction", "lgtm_jev_files", "lgtm_jev_review", "lgtm_jev_scope", "lgtm_jev_triage"], "unexpected Jev tool set");
  assert.equal(requests.length, 0, "startup made a paid request");

  const readsBefore = reads;
  let result = await invoke({ ...params, preview: true });
  assert.equal(result.status, "preview");
  assert.equal(requests.length, 0, "preview made a paid request");
  assert.equal(reads, readsBefore, "preview read file content");
  assert.deepEqual(result.counts, { requested: 3, included: 3, skipped: 0 });
  assert.deepEqual(result.files.map((item) => item.status), ["eligible", "eligible", "eligible"]);
  assert.deepEqual(result.questions.map((item) => item.id), ["risky", "layer", "quality"]);
  assert.equal(result.estimated.classifierCalls, 3);
  assert.equal(result.bounds.maxFiles, 8);
  assert.equal(result.bounds.maxTotalBytes, 65_536);
  assert.equal(result.usage, null);

  fs.writeFileSync("large.rs", "x".repeat(16_385));
  fs.symlinkSync(path.resolve("a.rs"), "linked.rs");
  result = await invoke({ paths: ["large.rs", "linked.rs", "missing.rs", "a.rs"], questions, preview: true });
  assert.equal(result.status, "preview");
  assert.equal(requests.length, 0);
  const preview = Object.fromEntries(result.files.map((item) => [item.path, item]));
  assert.equal(preview["large.rs"].reason, "file_ineligible");
  assert.equal(preview["linked.rs"].reason, "symlink_denied");
  assert.equal(preview["missing.rs"].reason, "unavailable");
  assert.equal(preview["a.rs"].status, "eligible");
  assert.deepEqual(result.counts, { requested: 4, included: 1, skipped: 3 });

  result = await invoke();
  assert.equal(result.status, "ok");
  assert.deepEqual(result.files.map((item) => item.id), ["f0", "f1", "f2"]);
  assert.equal(result.files[0].coverage, "complete");
  assert.match(result.files[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.files[0].answers.risky.probability, 0.8);
  assert.equal(result.files[0].answers.layer.choice, "domain");
  assert.equal(result.files[1].answers.quality.level, "partial");
  assert.equal(result.counts.ok, 3);
  assert.equal(requests.length, 3, "one classifier call per scouted file");
  assert.equal(reads - readsBefore, 3, "each scouted file used one governed read");
  assert.ok(requests.every((input) => Object.keys(input.state).length === 1 && typeof input.state.file.content === "string"),
    "a request carried more than the one judged file");
  assert.ok(result.usage.totalTokens > 0 && result.usage.cost.total > 0, "reported usage was not aggregated");

  const before = requests.length;
  assert.equal((await invoke({ ...params, paths: ["a.rs", "b.ts", "c.py", "a.rs"] })).status, "rejected");
  assert.equal((await invoke({ ...params, paths: Array.from({ length: 9 }, (_, i) => `n${i}.rs`) })).status, "rejected");
  const tooMany = { ...questions, other: { type: "bool", instructions: "x", criteria: { true: "a", false: "b" } }, extra: { type: "bool", instructions: "y", criteria: { true: "a", false: "b" } } };
  assert.equal((await invoke({ ...params, questions: tooMany })).status, "rejected");
  assert.equal(requests.length, before, "rejected requests reached the provider");

  const volume = Array.from({ length: 7 }, (_, i) => `v${i}.rs`);
  for (const name of volume) fs.writeFileSync(name, "x".repeat(10_000));
  result = await invoke({ paths: volume, questions, preview: true });
  assert.equal(result.counts.included, 6);
  assert.equal(result.files.at(-1).reason, "volume_limit");
  assert.equal(result.estimated.classifierCalls, 6);

  classify = (_model, input) => ({ ...answer(_model, input), answers: {
    risky: { type: "bool", probability: 0.5 },
    layer: { type: "choice", choice: "other", probabilities: { domain: 0.4 }, confidence: 0.4 },
    quality: { type: "score", score: 1, confidence: 0.4 },
  } });
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.status, "ok");
  assert.equal(result.files[0].answers.layer.noMatch, true);
  assert.equal(result.files[0].answers.layer.choice, null);

  classify = (_model, input) => ({ ...answer(_model, input), answers: {
    risky: { type: "bool", probability: 0.5 },
    layer: { type: "choice", choice: "api", probabilities: {}, confidence: 0.4 },
    quality: { type: "score", score: 3, confidence: 0.4 },
  } });
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.status, "unavailable", "an out-of-range score was accepted");
  assert.equal(result.files[0].status, "unavailable");

  classify = (_model, input) => { fs.appendFileSync("a.rs", "// edited\n"); return answer(_model, input); };
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.files[0].status, "stale");
  assert.equal(result.files[0].answers, undefined, "stale content produced a negative match");
  assert.equal(result.status, "partial");
  fs.writeFileSync("a.rs", bodies["a.rs"]);

  classify = answer;
  result = await invoke({ paths: ["a.rs", "large.rs"], questions });
  assert.equal(result.status, "partial");
  assert.equal(result.counts.ok, 1);
  assert.equal(result.counts.unavailable, 1);
  assert.equal(result.files[1].coverage, "none");

  assert.notEqual((await invoke(params, AbortSignal.abort())).status, "ok");

  classify = () => { throw new Error("secret-provider-message"); };
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.status, "unavailable");
  assert.ok(!JSON.stringify(result).includes("secret-provider-message"), "provider errors escaped containment");

  classify = () => new Promise(() => {});
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.status, "unavailable", "hung provider blocked normal work");

  const runtime = context.modelRegistry;
  context.modelRegistry = undefined;
  assert.equal((await invoke()).status, "unavailable");
  context.modelRegistry = runtime;

  assert.ok(!JSON.stringify(entries).includes("validate_policy"), "session records leaked source");
  assert.equal(fs.readFileSync("a.rs", "utf8"), bodies["a.rs"], "ordinary reads stopped working");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
