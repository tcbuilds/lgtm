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
  const nameCanaries = ["ghp_" + "N".repeat(24), "ghp_" + "M".repeat(24)];
  tools.push(...nameCanaries.map((name) => ({ name, description: "Inspect local files", exposure: "deferred" })));
  await emit("session_start");
  const namedMessages = [user,
    { role: "assistant", content: [{ type: "toolCall", id: "private-name", name: nameCanaries[0], arguments: {} }] },
    { ...result, toolName: nameCanaries[1] },
  ];
  const namedRoute = await emit("context", { messages: namedMessages });
  for (const name of nameCanaries) {
    assert.ok(!JSON.stringify(sent.at(-1)).includes(name), "tool name leaked through catalog, questions, or recent metadata");
    assert.ok(!namedRoute.messages.at(-1).content.includes(name), "tool name leaked through the generated hint");
    assert.ok(active.includes(name), "redaction merged or changed a local activation identity");
  }
  assert.equal(sent.at(-1).state.tools.filter((tool) => tool.name === "[redacted token]").length, 2);
  assert.equal(sent.at(-1).state.recent.lastCalls.length, 1);
  assert.equal(sent.at(-1).state.recent.lastTool.exitCode, 1);
  assert.ok(active.includes("read") && active.includes("bash"));
  assert.ok(!active.includes("advice") && !active.includes("hidden"));
  const beforeNamedCache = sent.length;
  const cachedNameRoute = await emit("context", { messages: namedMessages });
  assert.equal(sent.length, beforeNamedCache);
  mode = "held";
  hold = new Promise((resolve) => { release = resolve; });
  const namedHeld = emit("context", { messages: [user, { ...result, toolName: nameCanaries[0], details: { exit_code: 4 } }] });
  await Promise.resolve();
  assert.equal(sent.length, beforeNamedCache + 1, "held-name request never started");
  const heldNameInput = sent.at(-1);
  const busyNameRoute = await emit("context", { messages: [user, { ...result, toolName: nameCanaries[1], details: { exit_code: 5 } }] });
  assert.equal(sent.length, beforeNamedCache + 1, "busy-name context reached the provider");
  for (const name of nameCanaries) {
    assert.ok(!cachedNameRoute.messages.at(-1).content.includes(name));
    assert.ok(!busyNameRoute.messages.at(-1).content.includes(name));
    assert.ok(!JSON.stringify(notifications).includes(name), "tool name leaked through status notifications");
  }
  release({ stopReason: "stop", answers: Object.fromEntries(Object.keys(heldNameInput.questions)
    .map((id) => [id, { type: "bool", probability: 0.8 }])) });
  await namedHeld;
  mode = "ok";
  tools.splice(-2);
  active = active.filter((name) => !nameCanaries.includes(name));
  const jsonCanary = "JSON_FIELD_CANARY_1234567890";
  const bearerCanary = "BEARER_FIELD_CANARY_1234567890";
  const escapedCanary = "ESCAPED_FIELD_CANARY_1234567890";
  const continuationCanary = "CONTINUED_FIELD_CANARY_1234567890";
  const privacyCases = [
    ...["npm_", "ghs_", "ghu_", "ghr_"].map((prefix) => {
      const value = prefix + "R".repeat(24);
      return [value, [value]];
    }),
    ["AKIA" + "R".repeat(16), ["AKIA" + "R".repeat(16)]],
    [`{"api_key":"${jsonCanary}"}`, [jsonCanary]],
    [`{"password":"${jsonCanary}"}`, [jsonCanary]],
    [`bearer ${bearerCanary}`, [bearerCanary]],
    [`{"client_secret":${JSON.stringify(escapedCanary + '" ' + continuationCanary)}}`, [escapedCanary, continuationCanary]],
    [`api_key='${escapedCanary} ${continuationCanary}`, [escapedCanary, continuationCanary]],
    [`token=${jsonCanary}`, [jsonCanary]],
    [`aws_secret_access_key=${jsonCanary}`, [jsonCanary]],
    [`Authorization: Digest username="public", response="${jsonCanary}"`, [jsonCanary]],
    [`authorization: Custom ${jsonCanary}`, [jsonCanary]],
    [JSON.stringify({ credentials: { nested: jsonCanary } }), [jsonCanary]],
    ["bearer B7rX9t2Z", ["B7rX9t2Z"]],
    [`Bearer\n${bearerCanary}`, [bearerCanary]],
    [`authorization: bearer\n${bearerCanary}`, [bearerCanary]],
    ["password=S7vQ", ["S7vQ"]],
    [`password: 'first''${jsonCanary}'`, [jsonCanary]],
    [`password="first"${jsonCanary}`, [jsonCanary]],
  ];
  for (const [index, [text, canaries]] of privacyCases.entries()) {
    await emit("session_start");
    tools[0].description = `Read privacy case ${index}: ${text}`;
    const before = sent.length;
    await emit("context", { messages: [{ ...user, content: `Inspect privacy case ${index}: ${text}` }] });
    assert.equal(sent.length, before + 1, "privacy case never reached the provider boundary");
    const request = JSON.stringify(sent.at(-1));
    for (const canary of canaries) assert.ok(!request.includes(canary), `credential leaked in privacy case ${index}`);
    assert.match(sent.at(-1).state.task, /Inspect privacy case/, "ordinary task text was lost");
    assert.match(sent.at(-1).state.tools.find((tool) => tool.name === "read").description, /Read privacy case/);
  }
  tools[0].description = "Read files";
  await emit("session_start");
  mode = "invalid";
  const beforeInvalid = activationCalls, beforeInvalidCalls = sent.length;
  const invalidRoute = await emit("context", { messages });
  assert.equal(sent.length, beforeInvalidCalls + 1);
  assert.equal(activationCalls, beforeInvalid, "out-of-range scores activated tools");
  assert.match(invalidRoute.messages.at(-1).content, /invalid-response/);
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
  mode = "warn";
  const beforeThresholdWarning = notifications.length;
  await gate([{ ...notice, ruleId: "below-noise-threshold" }]);
  assert.equal(entries.at(-1).data.visibility, "warning");
  assert.equal(entries.at(-1).data.noiseProbability, 0.2);
  assert.equal(notifications.length, beforeThresholdWarning + 1);
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

  await emit("session_start");
  hold = new Promise((resolve) => { release = resolve; });
  active = ["read"];
  const beforeStale = activationCalls, beforeStaleCalls = sent.length;
  const pendingRoute = emit("context", { messages });
  await Promise.resolve();
  assert.equal(sent.length, beforeStaleCalls + 1, "stale-session request never started");
  const pendingInput = sent.at(-1);
  await emit("session_start");
  release({ stopReason: "stop", answers: Object.fromEntries(Object.keys(pendingInput.questions)
    .map((id) => [id, { type: "bool", probability: 0.8 }])) });
  await pendingRoute;
  assert.equal(activationCalls, beforeStale, "pre-timeout response from an old session activated tools");
  assert.deepEqual(active, ["read"]);
  console.log("Jev auto integration passed: per-step routing, dedup, privacy, no-prompt gate triage, failure and session safety.");
})().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => clearTimeout(watchdog));
