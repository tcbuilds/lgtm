// Exercises advisory diagnostic triage with a fake provider and native-shaped reads.
const assert = require("node:assert/strict");
const { loadExtension, readResult, writeRequest } = require("./jev_harness.cjs");
const sourcePath = process.argv[2];
const watchdog = setTimeout(() => process.exit(124), 30_000);

const handlers = {}, tools = new Map(), persistedEntries = [];
const pi = {
  on: (name, handler) => {
    if (!handlers[name]) handlers[name] = [];
    handlers[name].push(handler);
  },
  registerTool: (definition) => { tools.set(definition.name, definition); },
  appendEntry: (name, result) => { persistedEntries.push({ name, result }); },
  getAllTools: () => [...tools.values()],
};
async function emit(name, event, ctx) { for (const handler of handlers[name] ?? []) await handler(event, ctx); }

const SECRET_EXCERPT = [
  "error: request failed at /home/ada/project/src/app.rs:42",
  "contact ada@example.com from 10.0.0.7 with token=abcdefghijklmnop",
  "trace 3f9a1c0d5b7e8f2a4c6d8e0f1a3b5c7d9e0f1a3b",
].join("\n");
const base = { command: "cargo test", exitCode: 101, excerpt: SECRET_EXCERPT, cwd: "/tmp/ws", finding: "test-failure" };
const JSON_METADATA_PASSWORD = "TRIAGE_JSON_METADATA_PASSWORD_CANARY";
const JSON_METADATA_SECRET = "TRIAGE_JSON_METADATA_SECRET_CANARY";
const JSON_EXCERPT_TOKEN = "TRIAGE_JSON_EXCERPT_TOKEN_CANARY";
const PRIVATE_KEY_BLOCK = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY_CANARY\n-----END PRIVATE KEY-----";

let providerRequests = [], calls = 0;
let scripted = () => { throw new Error("scripted provider not set"); };
let afterRequestRead = () => {};
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async (name, args) => {
    assert.equal(name, "read", "triage must use a governed native read for request files");
    const result = readResult(args);
    afterRequestRead();
    return result;
  },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter"); assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input, options) => {
      calls++;
      providerRequests.push(input);
      return scripted(model, input, options);
    },
  },
};

function choice(category) {
  return () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { cause: { type: "choice", choice: category, probabilities: { [category]: 0.8 }, confidence: 0.8 } },
    usage: { input: 15, output: 0, totalTokens: 15, cost: { total: 0.0000006 } } });
}

async function invoke(body = base, outer = {}, signal = context.signal) {
  const params = { requestPath: writeRequest(body, context.cwd), ...outer };
  return execute(params, signal);
}

async function invokeInline(params, signal = context.signal) {
  return execute(params, signal);
}

async function execute(params, signal) {
  const tool = tools.get("lgtm_jev_triage");
  assert.ok(tool, "init must supply the triage tool");
  const result = await tool.execute("triage", params, signal, () => {}, context);
  assert.ok(result.structuredContent);
  return result.structuredContent;
}

function assertAbsent(value, ...canaries) {
  const serialized = JSON.stringify(value);
  for (const canary of canaries) assert.ok(!serialized.includes(canary), `sensitive canary reached output: ${canary}`);
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_triage");
  assert.equal(tool.exposure, "codemode");
  assert.deepEqual(tool.reachesTools(), ["read"]);
  assert.deepEqual(tool.parameters.required, ["requestPath"]);
  assert.equal(calls, 0, "startup made a paid request");

  let before = calls;
  let result = await invoke();
  assert.equal(result.status, "preview");
  assert.equal(result.triage, null);
  assert.ok(result.evidence.redactions > 0, "redaction preview reported nothing");
  assert.equal(result.facts.command, "cargo test");
  assert.equal(result.facts.exitCode, 101);
  assert.equal(calls, before, "preview transmitted the excerpt");
  assertAbsent(result, "ada@example.com", "abcdefghijklmnop");
  assert.equal(persistedEntries.at(-1).name, "lgtm-jev");
  assertAbsent(persistedEntries.at(-1).result, "ada@example.com", "abcdefghijklmnop");

  const quotedCredentials = {
    ...base,
    command: `{"password":"${JSON_METADATA_PASSWORD}"}`,
    cwd: "/home/ada/project",
    finding: `{"clientSecret":"${JSON_METADATA_SECRET}"}`,
    excerpt: `${SECRET_EXCERPT}\ndiagnostic metadata: {"access_token":"${JSON_EXCERPT_TOKEN}"}`,
  };
  before = calls;
  result = await invoke(quotedCredentials);
  assert.equal(result.status, "preview");
  assert.equal(calls, before, "metadata preview transmitted without outer consent");
  assert.ok(result.facts.command.includes("«credential»"), "quoted JSON password in metadata was not redacted");
  assert.ok(result.facts.finding.includes("«credential»"), "quoted JSON secret in metadata was not redacted");
  assert.ok(result.evidence.redactions > 0, "quoted JSON excerpt credential was not redacted");
  assertAbsent(result, JSON_METADATA_PASSWORD, JSON_METADATA_SECRET, JSON_EXCERPT_TOKEN, "/home/ada");
  assertAbsent(persistedEntries.at(-1).result, JSON_METADATA_PASSWORD, JSON_METADATA_SECRET, JSON_EXCERPT_TOKEN);

  scripted = choice("code");
  before = calls;
  result = await invoke(quotedCredentials, { allowSend: true });
  assert.equal(calls - before, 1, "outer send consent must make one provider call");
  assert.equal(result.status, "ok");
  assert.equal(result.triage.category, "code");
  assert.equal(result.triage.unknown, false);
  assert.equal(result.facts.cwd, "/«home»/project");
  const sent = JSON.stringify(providerRequests.at(-1));
  assertAbsent(sent, JSON_METADATA_PASSWORD, JSON_METADATA_SECRET, JSON_EXCERPT_TOKEN,
    "ada@example.com", "abcdefghijklmnop", "/home/ada");
  assert.ok(sent.includes("«credential»"), "redaction markers were not sent to the provider");
  assertAbsent(result, JSON_METADATA_PASSWORD, JSON_METADATA_SECRET, JSON_EXCERPT_TOKEN);
  assertAbsent(persistedEntries.at(-1).result, JSON_METADATA_PASSWORD, JSON_METADATA_SECRET, JSON_EXCERPT_TOKEN);

  for (const scheme of ["Bearer", "Basic", "Digest", "Token", "Negotiate"]) {
    const credential = `AUTHORIZATION_${scheme}_CANARY_123456789`;
    const authorized = { ...base, command: `Authorization: ${scheme} ${credential}`,
      excerpt: `request failed\nAuthorization: ${scheme} ${credential}\nretry stopped` };
    before = calls;
    result = await invoke(authorized);
    assert.equal(result.status, "preview");
    assert.equal(calls, before, "authorization preview contacted the provider");
    assertAbsent(result, credential);
    assertAbsent(persistedEntries.at(-1), credential);
    result = await invoke(authorized, { allowSend: true });
    assert.equal(result.status, "ok");
    assert.equal(calls, before + 1);
    assertAbsent(result, credential);
    assertAbsent(providerRequests.at(-1), credential);
    assertAbsent(persistedEntries.at(-1), credential);
  }

  const privateKeyCases = [
    { body: { ...base, excerpt: PRIVATE_KEY_BLOCK }, reason: "sensitive_excerpt" },
    { body: { ...base, finding: PRIVATE_KEY_BLOCK }, reason: "sensitive_metadata" },
    { body: { ...base, command: `{"privateKey":"${PRIVATE_KEY_BLOCK}"}` }, reason: "sensitive_metadata" },
  ];
  before = calls;
  for (const { body, reason } of privateKeyCases) {
    for (const outer of [{}, { allowSend: true }]) {
      result = await invoke(body, outer);
      assert.equal(result.status, "rejected");
      assert.equal(result.reason, reason);
      assertAbsent(result, "BEGIN PRIVATE KEY", "SYNTHETIC_PRIVATE_KEY_CANARY");
      assertAbsent(persistedEntries.at(-1).result, "BEGIN PRIVATE KEY", "SYNTHETIC_PRIVATE_KEY_CANARY");
    }
  }
  assert.equal(calls, before, "private-key material reached the provider");

  before = calls;
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.status, "rejected", "request-body consent must not enable sending");
  assert.equal(result.reason, "invalid_request");
  assert.equal(calls, before, "body allowSend reached the provider");
  result = await invokeInline({ ...base, allowSend: true });
  assert.equal(result.status, "rejected", "the retired inline-argument API was accepted");
  assert.equal(result.reason, "invalid_request");
  assert.equal(calls, before, "inline arguments reached the provider");

  scripted = choice("environment");
  result = await invoke(base, { allowSend: true });
  assert.equal(result.triage.category, "environment");
  assert.equal(result.triage.unknown, false);

  scripted = choice("unknown");
  result = await invoke(base, { allowSend: true });
  assert.equal(result.triage.unknown, true);

  scripted = choice("not-a-category");
  result = await invoke(base, { allowSend: true });
  assert.equal(result.triage.category, "unknown", "an unmapped category invented a cause");
  assert.equal(result.triage.unknown, true);

  scripted = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { cause: { type: "choice", choice: 5 } }, usage: null });
  result = await invoke(base, { allowSend: true });
  assert.equal(result.status, "unavailable", "a malformed answer was accepted");
  assert.equal(result.reason, "invalid_or_unavailable_response");

  scripted = () => { throw new Error("synthetic provider failure"); };
  result = await invoke(base, { allowSend: true });
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "request_unavailable");
  assertAbsent(result, "synthetic provider failure");

  before = calls;
  for (const body of [
    { command: "", exitCode: 1, excerpt: "x" },
    { command: "x", exitCode: 1.5, excerpt: "x" },
    { ...base, excerpt: "x".repeat(16 * 1024 + 1) },
  ]) {
    result = await invoke(body, { allowSend: true });
    assert.equal(result.status, "rejected");
    assert.equal(result.reason, "invalid_request");
  }
  assert.equal(calls, before, "rejected input reached the provider");

  scripted = choice("tool");
  result = await invoke({ ...base, excerpt: "word ".repeat(3_000) }, { allowSend: true });
  assert.equal(result.status, "ok");
  assert.equal(result.evidence.clipped, true, "clipping was not reported");
  assert.ok(result.evidence.bytes <= 8 * 1024);

  result = await invoke({ ...base, excerpt: "字".repeat(9_000) }, { allowSend: true });
  assert.equal(result.status, "ok");
  assert.ok(Buffer.byteLength(providerRequests.at(-1).state.triage.excerpt, "utf8") <= 8 * 1024,
    "CJK excerpt exceeded the UTF-8 byte bound");
  assert.equal(result.evidence.clipped, true);

  const readController = new AbortController();
  before = calls;
  afterRequestRead = () => readController.abort();
  result = await invoke(base, { allowSend: true }, readController.signal);
  afterRequestRead = () => {};
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "cancelled_or_timeout");
  assert.equal(calls, before, "cancellation after the governed read reached the provider");

  const providerController = new AbortController();
  scripted = () => { providerController.abort(); return choice("code")(); };
  result = await invoke(base, { allowSend: true }, providerController.signal);
  assert.equal(result.status, "unavailable", "late provider cancellation returned a triage result");
  assert.equal(result.reason, "cancelled_or_timeout");
  assert.notEqual(result.status, "ok");

  result = await invoke(base, { allowSend: true }, AbortSignal.abort());
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "cancelled_or_timeout");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
