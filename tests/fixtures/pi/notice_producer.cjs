// Exercise the actual Rust producer and generated extension; script only scanner/provider boundaries.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const binary = path.resolve(process.argv[2]);
const gateSource = path.resolve(process.argv[3]);
const scenario = process.argv[4];
assert.ok(["commit", "review"].includes(scenario), "explicit observer scenario required");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "lgtm-real-notice-"));
const prior = process.cwd();
const watchdog = setTimeout(() => {
  console.error(`Notice producer scenario ${scenario} exceeded its 60-second budget`);
  process.exit(124);
}, 60_000);

(async () => {
  process.chdir(root);
  const env = { ...process.env, HOME: root };
  function run(file, args, options = {}) {
    return execFileSync(file, args, { cwd: root, env, timeout: 12_000, encoding: "utf8", ...options });
  }
  run("git", ["init", "-q"]);
  run("git", ["config", "user.email", "254259785+tcbuilds@users.noreply.github.com"]);
  run("git", ["config", "user.name", "LGTM fixture"]);
  fs.mkdirSync("src"); fs.writeFileSync("src/app.rs", "pub fn value() -> u8 { 1 }\n");
  run(binary, ["init", "--agent", "pi", "--accept-guesses"]);
  fs.mkdirSync("bin");
  const scanner = path.join(root, "bin/gitleaks");
  fs.writeFileSync(scanner, `#!/usr/bin/env node
const fs=require('node:fs');
if(process.argv.includes('version')) {console.log('fixture-1');process.exit(0);}
const report=process.argv[process.argv.indexOf('--report-path')+1];
const make=(rule)=>({RuleID:rule,Description:'fixture',File:'src/app.rs',StartLine:1,StartColumn:1,EndLine:1,EndColumn:2,Fingerprint:rule+':fixture'});
let rules=['generic-api-key'];
if(process.env.SCANNER_CASE==='clean')rules=[];
fs.appendFileSync('.scanner-count','x');
fs.writeFileSync(report,JSON.stringify(rules.map(make)));process.exit(rules.length ? 2 : 0);
`, { mode: 0o700 });
  env.PATH = path.join(root, "bin") + path.delimiter + process.env.PATH;
  run("git", ["add", "-A"]);
  run("git", ["commit", "-qm", "fixture"]);
  process.env.PATH = env.PATH;
  process.env.HOME = root;
  const extensionFile = path.join(root, ".pi/extensions/lgtm.ts");
  const rendered = fs.readFileSync(extensionFile, "utf8")
    .replace(/^import \{([^\n]+)\} from "([^"]+)";$/gm, 'const {$1} = require("$2");')
    .replaceAll("new URL(import.meta.url)", JSON.stringify(extensionFile))
    .replace("export default function lgtm", "function lgtm");
  const install = new Function("require", "process", rendered + "\nreturn lgtm;")(require, process);
  const handlers = {}, entries = [], listeners = new Map(), providerInputs = [];
  const sessionFile = path.join(root, "session.jsonl");
  fs.writeFileSync(sessionFile, "", { mode: 0o600 });
  let confirms = 0;
  const definitions = [
    { name: "bash", required: ["command"], properties: { command: { type: "string" }, timeout: { type: "number" } } },
    { name: "read", required: ["path"], properties: { path: { type: "string" }, offset: { type: "number" }, limit: { type: "number" } } },
    { name: "write", required: ["path", "content"], properties: { path: { type: "string" }, content: { type: "string" } } },
    { name: "edit", required: ["path", "edits"], properties: { path: { type: "string" }, edits: { type: "array", items: { type: "object", required: ["oldText", "newText"], properties: { oldText: { type: "string" }, newText: { type: "string" } } } } } },
  ];
  const pi = {
    on(name, handler) { const list = handlers[name] ?? []; list.push(handler); handlers[name] = list; },
    appendEntry(customType, data) {
      const entry = { type: "custom", id: "entry-" + entries.length, customType, data };
      entries.push(entry); fs.appendFileSync(sessionFile, JSON.stringify(entry) + "\n");
    },
    getAllTools: () => definitions.map((tool) => ({ name: tool.name, sourceInfo: { source: "builtin", path: "builtin:" + tool.name }, parameters: { type: "object", required: tool.required, properties: tool.properties } })),
    events: { on(name, handler) { listeners.set(name, handler); return () => listeners.delete(name); }, emit(name, data) { listeners.get(name)?.(data); } },
  };
  const ctx = { cwd: root, hasUI: true, signal: new AbortController().signal, isProjectTrusted: () => true,
    sessionManager: { getSessionId: () => "real-producer", getSessionFile: () => sessionFile, getEntries: () => entries },
    ui: { notify() {}, async confirm() { confirms++; return true; } },
    modelRegistry: { findOfType: () => ({ provider: "openrouter", id: "~typesafe/jev-latest" }),
      async classify(_model, input) { providerInputs.push(input); return { stopReason: "stop", answers: Object.fromEntries(Object.keys(input.questions).map((id) => [id, { type: "bool", probability: 0.99 }])) }; } },
  };
  const { registerGateFilter } = await import(pathToFileURL(gateSource).href);
  registerGateFilter(pi, () => true);
  install(pi);
  async function call() {
    let response;
    for (const handler of handlers.tool_call) response = await handler({ toolName: "bash", toolCallId: "commit", input: { command: "git commit -m fixture" } }, ctx);
    return response;
  }
  if (scenario === "commit") {
    process.env.SCANNER_CASE = "generic";
    const beforeHead = run("git", ["rev-parse", "HEAD"]);
    fs.writeFileSync("src/app.rs", "pub fn value() -> u8 { 2 }\n");
    run("git", ["add", "src/app.rs"]);
    assert.equal(await call(), undefined, "commit observer returned a tool veto");
    assert.equal(fs.existsSync(".lgtm/evidence/shell-tracking.json"), true,
      "the observer request did not reach Rust shell tracking");
    assert.equal(fs.existsSync(".scanner-count"), false, "commit observer ran a secret scan");
    assert.equal(providerInputs.length, 0, "commit observer invoked the classifier");
    assert.equal(entries.some((entry) => entry.customType === "jev-auto-gate"), false,
      "commit observer started a notice/approval transaction");
    assert.equal(run("git", ["rev-parse", "HEAD"]), beforeHead,
      "commit observer executed the requested Git command");
  }
  if (scenario === "review") {
    process.env.SCANNER_CASE = "clean";
    const config = JSON.parse(fs.readFileSync(".lgtm/config.json", "utf8"));
    config.severity_overrides["function-size"] = "error";
    fs.writeFileSync(".lgtm/config.json", JSON.stringify(config));
    run(binary, ["hook", "pre-tool-use", "--adapter", "pi"], { input: JSON.stringify({
      type: "tool_call", toolName: "write", input: { path: "src/app.rs", content: "pub fn value() -> u8 { 2 }" },
      cwd: root, sessionId: "real-producer",
    }) });
    fs.writeFileSync("src/app.rs", "pub fn value() -> u8 {\n    let value = 1;\n" + "    let value = value + 1;\n".repeat(31) + "    value\n}\n");
    const deferred = spawnSync(binary, ["hook", "post-tool-use", "--adapter", "pi"], {
      cwd: root, env: process.env, timeout: 12_000, encoding: "utf8",
      input: JSON.stringify({ type: "tool_result", toolName: "write",
        input: { path: "src/app.rs", content: "pub fn value() -> u8 { 2 }" },
        cwd: root, sessionId: "real-producer" }),
    });
    assert.ok([0, 1].includes(deferred.status), "post-tool hook crashed");
    assert.match(deferred.stderr, /review failed: entity=function-size/);
    assert.ok(!deferred.stdout.includes('"block":true'), "review warning became a tool denial");
    const records = fs.readdirSync(".lgtm/evidence").filter((name) => name.endsWith(".jsonl"))
      .flatMap((name) => fs.readFileSync(path.join(".lgtm/evidence", name), "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)));
    const warning = records.findLast((entry) => entry.result?.rule_id === "function-size")?.result;
    assert.equal(warning?.status, "warning");
    assert.equal(warning?.severity, "error");
    console.log("pi_preserves_error_severity_warning: PASS");
  }
  assert.equal(confirms, 0);
  console.log(`Real notice producer scenario passed: ${scenario}`);
})().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => {
  clearTimeout(watchdog); process.chdir(prior); fs.rmSync(root, { recursive: true, force: true });
});
