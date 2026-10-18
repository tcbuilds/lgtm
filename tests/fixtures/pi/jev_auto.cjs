// Integration smoke: load the real TypeScript extension, with only the provider boundary scripted.
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const watchdog = setTimeout(() => process.exit(124), 15_000);

(async () => {
  const { default: install } = await import(pathToFileURL(path.resolve(process.argv[2])).href);
  const handlers = new Map(), bus = new Map(), entries = [], notifications = [], sent = [];
  const commands = new Map();
  let active = ["read"], activationCalls = 0, mode = "ok", hold, release;
  const tools = [
    { name: "read", description: "Read files", exposure: "direct" },
    { name: "bash", description: "Run commands", exposure: "deferred" },
    { name: "advice", description: "Read-only advice", exposure: "codemode" },
    { name: "hidden", description: "Private tool", exposure: "hidden" },
  ];
  const pi = {
    on(name, handler) { const list = handlers.get(name) ?? []; list.push(handler); handlers.set(name, list); },
    registerCommand(name, definition) { commands.set(name, definition); },
    getAllTools: () => tools, getActiveTools: () => active,
    setActiveTools(value) { active = value; activationCalls++; },
    appendEntry(type, data) { entries.push({ type, data }); },
    events: {
      on(name, handler) { bus.set(name, handler); return () => bus.delete(name); },
      emit(name, value) { bus.get(name)?.(value); },
    },
  };
  const ctx = {
    hasUI: true, isProjectTrusted: () => true, signal: new AbortController().signal,
    ui: { notify: (...args) => notifications.push(args) },
    modelRegistry: {
      findOfType: () => ({ provider: "openrouter", id: "~typesafe/jev-latest" }),
      classify(_model, input) {
        sent.push(input);
        if (mode === "held") return hold;
        if (mode === "error") return Promise.reject(new Error("PROVIDER_PRIVATE_CANARY"));
        return Promise.resolve({ stopReason: "stop", answers: Object.fromEntries(Object.keys(input.questions).map((id) => [id,
          { type: "bool", probability: mode === "invalid" ? 2 : id.startsWith("noise_") ? (mode === "warn" ? 0.2 : 0.99) : 0.8 }])) });
      },
    },
  };
  install(pi);
  async function emit(name, value = {}) {
    let result;
    for (const handler of handlers.get(name) ?? []) result = await handler(value, ctx);
    return result;
  }
  const user = { role: "user", content: "Implement the next change", timestamp: 1 };
  const messages = [user];
  const first = await emit("context", { messages });
  assert.equal(sent.length, 1);
  assert.equal(messages.length, 1, "original context was mutated");
  assert.deepEqual(active, ["read", "bash"]);
  assert.equal(first.messages.filter((m) => m.customType === "jev-auto").length, 1);
  assert.match(first.messages.at(-1).content, /next model turn/);
  assert.match(first.messages.at(-1).content, /must use tools already declared/);
  await emit("context", { messages: first.messages });
  assert.equal(sent.length, 1, "unchanged input reached provider");
  assert.equal(activationCalls, 1, "unchanged input reactivated tools");
  const result = { role: "toolResult", toolName: "bash", isError: true, content: [{ type: "text", text: "RAW_OUTPUT_CANARY" }], details: { exit_code: 1 }, timestamp: 2 };
  const next = await emit("context", { messages: [user, result] });
  assert.equal(sent.length, 2, "next model step did not route");
  assert.equal(next.messages.filter((m) => m.customType === "jev-auto").length, 1);
  assert.ok(!JSON.stringify(sent).includes("RAW_OUTPUT_CANARY"));
  assert.ok(!JSON.stringify(sent).includes('"hidden"'));
  const changedOutput = { ...result, content: [{ type: "text", text: "CHANGED_OUTPUT_CANARY" }] };
  await emit("context", { messages: [user, changedOutput] });
  assert.equal(sent.length, 2, "raw output affected the signature");
  await emit("session_start");
  const secret = ["ghp_", "CREDENTIAL_CANARY_1234567890"].join("");
  await emit("context", { messages: [{ ...user, content: `Inspect token ${secret}` }] });
  assert.ok(!JSON.stringify(sent.at(-1)).includes(secret));
  mode = "error";
  const failedInput = [user, { ...result, details: { exit_code: 2 } }];
  await emit("context", { messages: failedInput });
  const failureCalls = sent.length;
  await emit("context", { messages: failedInput });
  assert.equal(sent.length, failureCalls, "provider error was retried unchanged");
  assert.ok(!JSON.stringify(notifications).includes("PROVIDER_PRIVATE_CANARY"));

  mode = "ok";
  function gate(items, identity = null, signal = ctx.signal) {
    return new Promise((resolve) => {
      const request = { protocol: "lgtm-pi-heuristic-notices", version: 1, event: "tool_result",
        notices: { identity, items }, ctx, signal, handled: false, done: () => resolve(request) };
      pi.events.emit("jev-auto:gate", request);
      if (!request.handled) resolve(request);
    });
  }
  const notice = { kind: "review", ruleId: "function-size", path: "/home/private/tests/example.rs", line: 4, candidateId: null };
  const beforeGate = sent.length, beforeWarnings = notifications.length;
  const accepted = await gate([notice]);
  assert.equal(accepted.handled, true);
  assert.equal(sent.length, beforeGate + 1);
  assert.equal(entries.at(-1).data.visibility, "silent");
  assert.equal(notifications.length, beforeWarnings, "likely noise interrupted the user");
  assert.ok(!JSON.stringify(sent.at(-1)).includes("/home/private"));
  await gate([notice]);
  assert.equal(sent.length, beforeGate + 1, "repeated gate notice was resent");
  mode = "error";
  await gate([{ ...notice, ruleId: "naming-review" }]);
  assert.equal(entries.at(-1).data.visibility, "warning");
  assert.equal(entries.at(-1).data.noiseProbability, null);
  const rejected = await gate([{ ...notice, kind: "hard-denial" }]);
  assert.equal(rejected.handled, false, "hard denial entered the noise filter");
  assert.ok(!JSON.stringify(entries).includes("PROVIDER_PRIVATE_CANARY"));

  const cancelled = { ...notice, ruleId: "cancelled-notice" };
  const recordsBeforeCancel = entries.length;
  await gate([cancelled], null, AbortSignal.abort());
  assert.equal(entries.length, recordsBeforeCancel);
  await gate([cancelled]);
  assert.equal(entries.length, recordsBeforeCancel + 1, "cancelled delivery poisoned dedup");

  mode = "held";
  hold = new Promise((resolve) => { release = resolve; });
  const oldController = new AbortController();
  const reserved = { ...notice, ruleId: "reserved-notice" };
  const oldDelivery = gate([reserved], null, oldController.signal);
  for (let batch = 0; batch < 9; batch++) {
    await gate(Array.from({ length: 32 }, (_v, index) => ({ ...notice, ruleId: "overflow-" + batch + "-" + index })));
  }
  assert.equal(entries.at(-1).data.ruleId, "overflow-8-31", "cache saturation dropped a new notice");
  await gate([reserved]);
  oldController.abort();
  await oldDelivery;
  const afterNewDelivery = entries.length;
  await gate([reserved]);
  assert.equal(entries.length, afterNewDelivery, "old cancelled owner removed a new reservation");
  release({ stopReason: "stop", answers: {} });
  await Promise.resolve(); await Promise.resolve();

  await emit("session_start");
  mode = "held";
  hold = new Promise((resolve) => { release = resolve; });
  const activationsBefore = activationCalls;
  await emit("context", { messages });
  const heldCalls = sent.length;
  await emit("session_start");
  await emit("context", { messages: [user, result] });
  assert.equal(sent.length, heldCalls, "session reset freed an unresolved provider slot");
  release({ stopReason: "stop", answers: {} });
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(activationCalls, activationsBefore, "late response changed active tools");
  console.log("Jev auto integration passed: per-step routing, dedup, privacy, no-prompt gate triage, failure and session safety.");
})().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
