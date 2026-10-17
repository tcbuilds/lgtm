// Exercises bounded multi-file Jev scouting through native reads and a fake provider.
// Preview must make zero classifier calls; fractional scores stay within their rubric.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { loadExtension, readResult, readResponse, writeRequest } = require("./jev_harness.cjs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);

const handlers = {};
const tools = new Map();
const entries = [];
let registrations = 0;

async function emit(name, event, context) {
  for (const handler of handlers[name] ?? []) await handler(event, context);
}

const pi = {
  on: (name, handler) => {
    if (!handlers[name]) handlers[name] = [];
    handlers[name].push(handler);
  },
  registerTool: (tool) => { registrations += 1; tools.set(tool.name, tool); },
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
    return {
      type: "choice",
      choice: labels[0],
      probabilities: Object.fromEntries(labels.map((label) => [label, 1 / labels.length])),
      confidence: 0.7,
    };
  }
  return { type: "score", score: 1, confidence: 0.6 };
}

function answer(_model, input) {
  return {
    stopReason: "stop",
    model: "~typesafe/jev-latest",
    provider: "openrouter",
    answers: Object.fromEntries(Object.entries(input.questions).map(([id, question]) => [id, answerFor(question)])),
    usage: { input: 40, output: 0, totalTokens: 40, cost: { total: 0.0000017 } },
  };
}

function answerWithScore(score) {
  return (_model, input) => {
    const response = answer(_model, input);
    return {
      ...response,
      answers: { ...response.answers, quality: { type: "score", score, confidence: 0.6 } },
    };
  };
}

function isRequestFile(filename) {
  const relative = path.relative(process.cwd(), path.resolve(filename));
  return path.basename(filename) === "request.json"
    && relative.split(path.sep).some((part) => part.startsWith(".jev-request-"));
}

const requests = [];
let requestReads = 0;
let sourceReads = 0;
let classify = answer;
const context = {
  cwd: process.cwd(),
  isProjectTrusted: () => true,
  signal: new AbortController().signal,
  sessionManager: { getSessionId: () => "jev-scout", getSessionFile: () => undefined },
  ui: { notify: () => {} },
  executeTool: async (name, args) => {
    assert.equal(name, "read");
    if (isRequestFile(args.path)) {
      requestReads += 1;
      return readResult(args);
    }
    sourceReads += 1;
    const text = fs.readFileSync(path.resolve(args.path), "utf8");
    return readResponse(args, [{ type: "text", text }, { type: "text", text: "Appended path-scoped guidance is not file content." }], text);
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier");
      assert.equal(provider, "openrouter");
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
const requestBody = { paths: ["a.rs", "b.ts", "c.py"], questions };

async function runTool(params, signal = context.signal) {
  const tool = tools.get("lgtm_jev_files");
  assert.ok(tool, "init must supply the Jev file tool without opt-in");
  const result = await tool.execute("query", params, signal, () => {}, context);
  assert.ok(result.structuredContent);
  assert.ok(!JSON.stringify(result).includes("validate_policy"), "raw source reached the calling model");
  return result.structuredContent;
}

async function invoke(body = requestBody, outer = {}, signal = context.signal) {
  const beforeRequestReads = requestReads;
  const result = await runTool({ requestPath: writeRequest(body), ...outer }, signal);
  if (!signal.aborted) assert.equal(requestReads, beforeRequestReads + 1, "request JSON bypassed the governed read");
  return result;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  assert.equal(registrations, 6);
  const tool = tools.get("lgtm_jev_files");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["read"], "Jev may only reach the governed read tool");
  assert.deepEqual([...tools.keys()].sort(), ["lgtm_jev_compaction", "lgtm_jev_files", "lgtm_jev_review", "lgtm_jev_scope", "lgtm_jev_triage", "lgtm_jev_untrusted"], "unexpected Jev tool set");
  assert.equal(requests.length, 0, "startup made a paid request");

  const sourceReadsBeforePreview = sourceReads;
  let result = await invoke(requestBody, { preview: true });
  assert.equal(result.status, "preview");
  assert.equal(requests.length, 0, "preview made a paid request");
  assert.equal(sourceReads, sourceReadsBeforePreview, "preview read source content");
  assert.deepEqual(result.counts, { requested: 3, included: 3, skipped: 0 });
  assert.deepEqual(result.files.map((item) => item.status), ["eligible", "eligible", "eligible"]);
  assert.deepEqual(result.questions.map((item) => item.id), ["risky", "layer", "quality"]);
  assert.equal(result.estimated.classifierCalls, 3);
  assert.equal(result.bounds.maxFiles, 8);
  assert.equal(result.bounds.maxTotalBytes, 65_536);
  assert.equal(result.usage, null);

  fs.writeFileSync("large.rs", "x".repeat(16_385));
  fs.symlinkSync(path.resolve("a.rs"), "linked.rs");
  result = await invoke({ paths: ["large.rs", "linked.rs", "missing.rs", "a.rs"], questions }, { preview: true });
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
  assert.equal(result.files[0].coverage, "governed");
  assert.equal(result.files[0].hashKind, "governed_output");
  assert.match(result.files[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.files[0].answers.risky.probability, 0.8);
  assert.equal(result.files[0].answers.layer.choice, "domain");
  assert.equal(result.files[1].answers.quality.score, 1);
  assert.equal(result.counts.ok, 3);
  assert.equal(requests.length, 3, "one classifier call per scouted file");
  assert.equal(sourceReads - sourceReadsBeforePreview, 3, "each scouted file used one governed read");
  assert.ok(requests.every((input) => Object.keys(input.state).length === 1 && typeof input.state.file.content === "string"),
    "a request carried more than the one judged file");
  assert.ok(result.usage.totalTokens > 0 && result.usage.cost.total > 0, "reported usage was not aggregated");

  const beforeRejected = requests.length;
  assert.equal((await invoke({ paths: ["a.rs", "b.ts", "c.py", "a.rs"], questions })).status, "rejected");
  assert.equal((await invoke({ paths: Array.from({ length: 9 }, (_, index) => `n${index}.rs`), questions })).status, "rejected");
  const tooManyQuestions = {
    ...questions,
    other: { type: "bool", instructions: "x", criteria: { true: "a", false: "b" } },
    extra: { type: "bool", instructions: "y", criteria: { true: "a", false: "b" } },
  };
  assert.equal((await invoke({ paths: requestBody.paths, questions: tooManyQuestions })).status, "rejected");
  assert.equal(requests.length, beforeRejected, "rejected requests reached the provider");

  const inlineBeforeReads = requestReads;
  const inlineResult = await runTool(requestBody);
  assert.equal(inlineResult.status, "rejected", "legacy inline paths/questions were accepted");
  assert.equal(requestReads, inlineBeforeReads, "legacy inline arguments reached a governed read");
  assert.equal(requests.length, beforeRejected, "legacy inline arguments reached the provider");

  result = await invoke({ paths: ["../outside.rs"], questions }, { preview: true });
  assert.equal(result.files[0].reason, "path_denied", "traversal path was not rejected");
  assert.equal(requests.length, beforeRejected, "preview made a classifier call");

  const volume = Array.from({ length: 7 }, (_, index) => `v${index}.rs`);
  for (const name of volume) fs.writeFileSync(name, "x".repeat(10_000));
  result = await invoke({ paths: volume, questions }, { preview: true });
  assert.equal(result.counts.included, 6);
  assert.equal(result.files.at(-1).reason, "volume_limit");
  assert.equal(result.estimated.classifierCalls, 6);

  const beforeVolume = requests.length;
  classify = answer;
  result = await invoke({ paths: volume, questions });
  const sentBytes = requests.slice(beforeVolume).reduce((total, input) => total + Buffer.byteLength(input.state.file.content, "utf8"), 0);
  assert.ok(sentBytes <= 65_536, `classification transmitted ${sentBytes} bytes`);
  assert.equal(result.counts.unavailable, 1, "the excess file was not skipped");
  assert.equal(result.files.at(-1).reason, "volume_limit");

  const boundaryFiles = Array.from({ length: 5 }, (_, index) => `boundary${index}.rs`);
  for (const name of boundaryFiles) fs.writeFileSync(name, "x".repeat(16_384));
  const beforeBoundary = requests.length;
  result = await invoke({ paths: boundaryFiles, questions });
  const boundaryBytes = requests.slice(beforeBoundary).reduce((total, input) => total + Buffer.byteLength(input.state.file.content, "utf8"), 0);
  assert.equal(requests.length - beforeBoundary, 4, "the exact aggregate byte boundary was exceeded");
  assert.equal(boundaryBytes, 65_536, `boundary batch transmitted ${boundaryBytes} bytes`);
  assert.equal(result.files.at(-1).reason, "volume_limit");

  const twoLevelQuestions = {
    ...questions,
    quality: { ...questions.quality, criteria: ["weak", "strong"] },
  };
  for (const testCase of [
    { label: "two-level fractional score", questionSet: twoLevelQuestions, score: 0.5 },
    { label: "three-level fractional score", questionSet: questions, score: 1.5 },
  ]) {
    classify = answerWithScore(testCase.score);
    result = await invoke({ paths: ["a.rs"], questions: testCase.questionSet });
    assert.equal(result.status, "ok", `${testCase.label} discarded valid sibling answers`);
    assert.equal(result.files[0].answers.quality.score, testCase.score, `${testCase.label} was not preserved`);
    assert.equal(result.files[0].answers.risky.probability, 0.8, `${testCase.label} discarded the bool answer`);
    assert.equal(result.files[0].answers.layer.choice, "domain", `${testCase.label} discarded the choice answer`);
  }

  for (const testCase of [
    { label: "negative score", questionSet: questions, score: -0.01 },
    { label: "above two-level range", questionSet: twoLevelQuestions, score: 1.01 },
    { label: "above three-level range", questionSet: questions, score: 2.01 },
    { label: "NaN score", questionSet: questions, score: Number.NaN },
    { label: "positive infinity score", questionSet: questions, score: Number.POSITIVE_INFINITY },
  ]) {
    classify = answerWithScore(testCase.score);
    result = await invoke({ paths: ["a.rs"], questions: testCase.questionSet });
    assert.equal(result.status, "unavailable", `${testCase.label} was accepted`);
    assert.equal(result.files[0].status, "unavailable", `${testCase.label} produced an answer`);
    assert.equal(result.files[0].answers, undefined, `${testCase.label} returned sibling answers as complete`);
  }

  classify = (_model, input) => ({ ...answer(_model, input), answers: {
    risky: { type: "bool", probability: 0.5 },
    layer: { type: "choice", choice: "other", probabilities: { domain: 0.4 }, confidence: 0.4 },
    quality: { type: "score", score: 1, confidence: 0.4 },
  } });
  result = await invoke({ paths: ["a.rs"], questions });
  assert.equal(result.status, "ok");
  assert.equal(result.files[0].answers.layer.noMatch, true);
  assert.equal(result.files[0].answers.layer.choice, null);

  const privatePaths = [".npmrc", ".netrc", ".aws/credentials"];
  const readsBeforePrivatePaths = sourceReads;
  const callsBeforePrivatePaths = requests.length;
  result = await invoke({ paths: privatePaths, questions });
  assert.deepEqual(result.files.map((item) => item.reason), ["path_denied", "path_denied", "path_denied"]);
  assert.equal(sourceReads, readsBeforePrivatePaths, "private credential paths were read");
  assert.equal(requests.length, callsBeforePrivatePaths, "private credential paths reached the provider");

  const credentialCanary = "scout-json-password-canary";
  fs.writeFileSync("settings.json", JSON.stringify({ password: credentialCanary }));
  const callsBeforeCredential = requests.length;
  result = await invoke({ paths: ["settings.json"], questions });
  assert.equal(result.files[0].reason, "content_ineligible", "JSON password source was not rejected");
  assert.equal(requests.length, callsBeforeCredential, "JSON password source reached the provider");
  assert.ok(!JSON.stringify(result).includes(credentialCanary), "JSON password appeared in the result");
  result = await invoke({ paths: ["../password=PATH_BODY_CANARY"], questions });
  assert.equal(result.files[0].path, null, "rejected sensitive paths must not echo request-file bodies");
  assert.ok(!JSON.stringify(result).includes("PATH_BODY_CANARY"));
  assert.equal(requests.length, callsBeforeCredential, "a rejected path reached the provider");

  const rubricCanary = "scout-rubric-secret-canary";
  const secretRubric = {
    ...questions,
    quality: { ...questions.quality, criteria: ["none", `password=${rubricCanary}`, "strong"] },
  };
  const callsBeforeRubric = requests.length;
  result = await invoke({ paths: ["a.rs"], questions: secretRubric });
  assert.equal(result.status, "rejected", "a credential-bearing question rubric was accepted");
  assert.equal(requests.length, callsBeforeRubric, "credential-bearing rubric reached the provider");
  assert.ok(!JSON.stringify(result).includes(rubricCanary), "rubric credential appeared in the result");

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

  assert.notEqual((await invoke(requestBody, {}, AbortSignal.abort())).status, "ok");

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

  const stored = JSON.stringify({ entries, requests });
  assert.ok(!JSON.stringify(entries).includes("validate_policy"), "session records leaked source");
  assert.ok(!stored.includes(credentialCanary), "JSON password reached a session record or provider request");
  assert.ok(!stored.includes(rubricCanary), "rubric credential reached a session record or provider request");
  assert.equal(fs.readFileSync("a.rs", "utf8"), bodies["a.rs"], "ordinary reads stopped working");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
