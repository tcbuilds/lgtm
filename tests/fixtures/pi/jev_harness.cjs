// Execute exact rendered fragments under their source filenames for real V8 coverage.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { AsyncLocalStorage } = require("node:async_hooks");
const sourceRoot = path.resolve(__dirname, "../../../templates/pi");
const fragments = ["jev_common", "jev", "jev_review", "jev_scope", "jev_triage", "jev_compaction", "jev_untrusted"];
const requests = new Set();
const invocations = new AsyncLocalStorage();

function evaluate(source, filename, context) {
  return new vm.Script(source, {
    filename, importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
  }).runInContext(context, { timeout: 10_000 });
}

function sameRealmRegistry(runtime) {
  if (!runtime) return runtime;
  return {
    findOfType: typeof runtime.findOfType === "function" ? (...args) => runtime.findOfType(...args) : runtime.findOfType,
    classify: typeof runtime.classify === "function" ? (model, input, ...args) => runtime.classify(model, structuredClone(input), ...args) : runtime.classify,
  };
}

function sameRealmContext(ctx) {
  const descriptors = Object.getOwnPropertyDescriptors(ctx);
  descriptors.modelRegistry = { get: () => sameRealmRegistry(ctx.modelRegistry), configurable: true };
  return Object.create(Object.getPrototypeOf(ctx), descriptors);
}

function loadExtension(file) {
  const real = fs.realpathSync(file);
  assert.equal(path.basename(real), "lgtm.ts");
  assert.ok(real.endsWith(path.join(".pi", "extensions", "lgtm.ts")) || real.endsWith(path.join(".pi", "agent", "extensions", "lgtm.ts")));
  assert.ok(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink());
  const original = fs.readFileSync(real, "utf8");
  assert.ok(original.startsWith("// lgtm-pi-extension: v1\n"));
  const source = original
    .replace(/^import \{([^\n]+)\} from "([^"]+)";$/gm, 'const {$1} = require("$2");')
    .replaceAll("new URL(import.meta.url)", JSON.stringify(real))
    .replace("export default function lgtm", "function lgtm");
  const context = vm.createContext({ require, process, Buffer, TextEncoder, TextDecoder, AbortController, AbortSignal,
    setTimeout, clearTimeout, console, globalThis, Error });
  let cursor = 0;
  for (const name of fragments) {
    const filename = path.join(sourceRoot, name + ".js");
    const fragment = fs.readFileSync(filename, "utf8");
    const offset = source.indexOf(fragment, cursor);
    assert.ok(offset >= cursor && source.indexOf(fragment, offset + 1) < 0, "rendered fragment must match its source exactly once");
    const prefix = source.slice(cursor, offset);
    if (prefix.trim()) evaluate(prefix, real + ".bootstrap.cjs", context);
    evaluate(source.slice(offset, offset + fragment.length), filename, context);
    cursor = offset + fragment.length;
  }
  const api = evaluate(source.slice(cursor) + "\n({factory: lgtm, mergeToolResult, jevNativeFailure});\n", real + ".bootstrap.cjs", context);
  const factory = api.factory;
  return (pi) => {
    if (typeof pi.registerTool !== "function") return factory(pi);
    return factory({ ...pi, appendEntry: (type, data) => pi.appendEntry(type, structuredClone(data)), registerTool(definition) {
      // Clone only cross-realm data; execute the unmodified production callbacks.
      const { execute, reachesTools, ...data } = definition;
      const tool = { ...structuredClone(data), execute: (id, params, signal, update, ctx) => invocations.run({ id, api, cwd: ctx.cwd }, async () => structuredClone(await execute(id, params, signal, update, sameRealmContext(ctx)))) };
      if (reachesTools) tool.reachesTools = () => Array.from(reachesTools());
      pi.registerTool(tool);
    } });
  };
}

function writeRequest(value, root = process.cwd()) {
  const directory = fs.mkdtempSync(path.join(root, ".jev-request-"));
  requests.add(directory);
  const file = path.join(directory, "request.json");
  fs.writeFileSync(file, JSON.stringify(value) ?? "null", { mode: 0o600 });
  return file;
}

function nativeResponse(toolName, input, result) {
  const current = invocations.getStore();
  if (!current) return { result, isError: result.isError === true };
  const event = { toolName, input, parentToolCallId: current.id, ...result };
  const patch = current.api.jevNativeFailure(event) ?? current.api.mergeToolResult(event, undefined, { cwd: current.cwd });
  const merged = { ...result, ...structuredClone(patch) };
  if (patch?.content !== undefined && !Object.hasOwn(patch, "structuredContent")) delete merged.structuredContent;
  return { result: merged, isError: result.isError === true };
}

function readResponse(args, content, structuredContent, details = {}, isError = false) {
  return nativeResponse("read", args, { content, details, ...(structuredContent === undefined ? {} : { structuredContent }), isError });
}

function readResult(args) {
  const text = fs.readFileSync(args.path, "utf8");
  return readResponse(args, [{ type: "text", text }], text);
}

function bashResult(output, { display, truncated = false, exitCode = 0 } = {}) {
  return nativeResponse("bash", {}, {
    content: [{ type: "text", text: display ?? (output || "(no output)") }],
    structuredContent: { output, truncated, exit_code: exitCode, wall_time_seconds: 0 },
    isError: exitCode !== 0,
  });
}

process.on("exit", () => {
  for (const directory of requests) fs.rmSync(directory, { recursive: true, force: true });
});
module.exports = { loadExtension, writeRequest, readResult, readResponse, bashResult, nativeResponse };
