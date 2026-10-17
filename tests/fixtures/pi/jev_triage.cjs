// Exercises the advisory diagnostic-triage tool with a fake provider boundary.
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

const SECRET_EXCERPT = [
  "error: request failed at /home/ada/project/src/app.rs:42",
  "contact ada@example.com from 10.0.0.7 with token=abcdefghijklmnop",
  "trace 3f9a1c0d5b7e8f2a4c6d8e0f1a3b5c7d9e0f1a3b",
].join("\n");

let requests = [], calls = 0, scripted = () => { throw new Error("scripted provider not set"); };
const context = {
  cwd: process.cwd(), isProjectTrusted: () => true,
  signal: new AbortController().signal,
  executeTool: async () => { throw new Error("triage must not call tools"); },
  modelRegistry: {
    findOfType: (type, provider, id) => {
      assert.equal(type, "classifier"); assert.equal(provider, "openrouter"); assert.equal(id, "~typesafe/jev-latest");
      return { type, provider, id };
    },
    classify: (model, input) => { calls++; requests.push(input); return scripted(model, input); },
  },
};

function choice(category) {
  return () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { cause: { type: "choice", choice: category, probabilities: { [category]: 0.8 }, confidence: 0.8 } },
    usage: { input: 15, output: 0, totalTokens: 15, cost: { total: 0.0000006 } } });
}

const base = { command: "cargo test", exitCode: 101, excerpt: SECRET_EXCERPT, cwd: "/tmp/ws", finding: "test-failure" };
async function invoke(params = base, signal = context.signal) {
  const tool = tools.get("lgtm_jev_triage");
  assert.ok(tool, "init must supply the triage tool");
  const result = await tool.execute("triage", params, signal, () => {}, context);
  assert.ok(result.structuredContent);
  return result.structuredContent;
}

(async () => {
  loadExtension(sourcePath)(pi);
  await emit("session_start", {}, context);
  const tool = tools.get("lgtm_jev_triage");
  assert.equal(tool.exposure, "codemode");
  assert.equal(calls, 0, "startup made a paid request");

  let before = calls;
  let result = await invoke();
  assert.equal(result.status, "preview");
  assert.equal(result.triage, null);
  assert.equal(result.evidence.redactions > 0, true, "redaction preview reported nothing");
  assert.equal(result.facts.command, "cargo test");
  assert.equal(result.facts.exitCode, 101);
  assert.equal(calls, 0, "preview transmitted the excerpt");
  assert.ok(!JSON.stringify(result).includes("ada@example.com"), "preview leaked an email");
  assert.ok(!JSON.stringify(result).includes("abcdefghijklmnop"), "preview leaked a token");

  // Metadata is minimized too: secrets never persist or transmit.
  before = calls;
  result = await invoke({ ...base, command: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'", cwd: "/home/ada/project", finding: "token=abcdefghijklmnop", excerpt: "plain failure text" });
  assert.equal(result.status, "preview");
  assert.ok(!JSON.stringify(result).includes("abcdefghijklmnop"), "metadata secret reached preview");
  assert.ok(!JSON.stringify(result).includes("/home/ada"), "metadata home path reached preview");
  assert.equal(calls, before, "metadata preview transmitted");
  result = await invoke({ ...base, command: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'", finding: "token=abcdefghijklmnop", excerpt: "plain failure text", allowSend: true });
  assert.ok(!JSON.stringify(requests.at(-1)).includes("abcdefghijklmnop"), "metadata secret was transmitted");
  assert.ok(!JSON.stringify(result).includes("abcdefghijklmnop"), "metadata secret was returned");
  result = await invoke({ ...base, command: "-----BEGIN RSA PRIVATE KEY-----", excerpt: "x" });
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, "sensitive_metadata");

  scripted = choice("code");
  const approvedBefore = calls;
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.status, "ok");
  assert.equal(result.triage.category, "code");
  assert.equal(result.triage.unknown, false);
  assert.equal(result.facts.cwd, "/tmp/ws");
  assert.equal(calls - approvedBefore, 1, "approved send must make exactly one call");
  const sent = JSON.stringify(requests.at(-1));
  assert.ok(!sent.includes("ada@example.com"), "email was not redacted before transport");
  assert.ok(!sent.includes("abcdefghijklmnop"), "token was not redacted before transport");
  assert.ok(!sent.includes("/home/ada"), "home path was not redacted before transport");
  assert.ok(sent.includes("«credential»") || sent.includes("«token»"), "no redaction marker was sent");

  scripted = choice("environment");
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.triage.category, "environment");

  scripted = choice("unknown");
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.triage.unknown, true);

  scripted = choice("not-a-category");
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.triage.category, "unknown", "an unmapped category invented a cause");
  assert.equal(result.triage.unknown, true);

  scripted = () => ({ stopReason: "stop", model: "~typesafe/jev-latest", provider: "openrouter",
    answers: { cause: { type: "choice", choice: 5 } }, usage: null });
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.status, "unavailable", "a malformed answer was accepted");

  scripted = () => { throw new Error("provider secret"); };
  result = await invoke({ ...base, allowSend: true });
  assert.equal(result.status, "unavailable");
  assert.ok(!JSON.stringify(result).includes("provider secret"));

  before = calls;
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
  result = await invoke({ ...base, excerpt: key, allowSend: true });
  assert.equal(result.status, "rejected");
  assert.equal(result.reason, "sensitive_excerpt");
  assert.ok(!JSON.stringify(result).includes("BEGIN RSA PRIVATE KEY"), "private key material reached the output");
  result = await invoke({ command: "", exitCode: 1, excerpt: "x" });
  assert.equal(result.status, "rejected");
  result = await invoke({ command: "x", exitCode: 1.5, excerpt: "x" });
  assert.equal(result.status, "rejected");
  result = await invoke({ ...base, excerpt: "x".repeat(16 * 1024 + 1) });
  assert.equal(result.status, "rejected");
  assert.equal(calls, before, "rejected input reached the provider");

  scripted = choice("tool");
  result = await invoke({ ...base, excerpt: "word ".repeat(3_000), allowSend: true });
  assert.equal(result.status, "ok");
  assert.equal(result.evidence.clipped, true, "clipping was not reported");
  assert.ok(result.evidence.bytes <= 8 * 1024);

  // Bounds are UTF-8 bytes, not UTF-16 units.
  result = await invoke({ ...base, excerpt: "字".repeat(9_000), allowSend: true });
  assert.equal(result.status, "ok");
  assert.ok(Buffer.byteLength(requests.at(-1).state.triage.excerpt, "utf8") <= 8 * 1024, "CJK excerpt exceeded the byte bound");
  assert.equal(result.evidence.clipped, true);

  assert.notEqual((await invoke({ ...base, allowSend: true }, AbortSignal.abort())).status, "ok");
  await emit("session_shutdown", {}, context);
})().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
