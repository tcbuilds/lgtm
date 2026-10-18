// Shared transport and privacy boundaries for the advisory Jev tools.
const lgtmJevCommon = (() => {
  const MODEL = "~typesafe/jev-latest";
  const active = new Map();
  const MAX_ACTIVE = 64;
  const owns = (id) => typeof id === "string" && active.has(id);
  const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const probability = (value) => Number.isFinite(value) && value >= 0 && value <= 1;
  const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
  const PRIVATE_NAMES = new Set([".git", ".lgtm", ".pi", ".claude", ".ssh", ".aws", ".azure", ".kube", ".gnupg", "node_modules", "target", "dist", "vendor", ".npmrc", ".netrc", ".pypirc", ".git-credentials", "auth.json", "id_rsa", "id_ed25519"]);
  const CREDENTIAL_NAMES = ["password", "passwd", "secret", "token", "apikey", "accesskey", "accesskeyid", "clientsecret", "authorization", "signature", "credential"];
  const AUTH_SCHEMES = new Set(["bearer", "basic", "digest", "token", "negotiate"]);
  const TOKEN = /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[A-Z0-9]{16})\b/g;

  function privatePath(name) {
    if (typeof name !== "string" || /[\x00-\x1f\x7f]/.test(name)) return true;
    return name.replaceAll("\\", "/").split("/").some((part) => {
      const lower = part.toLowerCase();
      return PRIVATE_NAMES.has(lower) || /^\.env(?:\.|$)/.test(lower)
        || /^credentials(?:\.|$)/.test(lower) || /\.(?:pem|key|p12|pfx|keystore)$/.test(lower);
    });
  }

  function valueStart(text, cursor) {
    if (text[cursor] === '"' || text[cursor] === "'") cursor += 1;
    while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1;
    if (text[cursor] !== ":" && text[cursor] !== "=") return undefined;
    cursor += 1;
    while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1;
    return cursor;
  }

  function quotedEnd(text, start) {
    const quote = text[start];
    let cursor = start + 1;
    while (cursor < text.length && text[cursor] !== quote && text[cursor] !== "\n" && text[cursor] !== "\r") {
      if (text[cursor] === "\\" && cursor + 1 < text.length) cursor += 1;
      cursor += 1;
    }
    return text[cursor] === quote ? cursor + 1 : cursor;
  }

  function authorizationEnd(text, start) {
    let end = start;
    while (end < text.length && text[end] !== "\n" && text[end] !== "\r") end += 1;
    return end;
  }

  function credentialEnd(text, start) {
    if (text[start] === '"' || text[start] === "'") return quotedEnd(text, start);
    let end = start;
    while (end < text.length && /[A-Za-z0-9._+/=-]/.test(text[end])) end += 1;
    if (AUTH_SCHEMES.has(text.slice(start, end).toLowerCase()) && /[ \t]/.test(text[end] ?? "")) return authorizationEnd(text, start);
    return text[end] === "(" ? start : end;
  }

  function minimumCredentialLength(text, start, name) {
    const quoted = text[start] === '"' || text[start] === "'";
    if (name.endsWith("password") || name.endsWith("passwd")) return quoted ? 3 : 1;
    return quoted ? 6 : 4;
  }

  function credentialSpans(text) {
    const spans = [];
    const words = /[A-Za-z_][A-Za-z0-9_.-]*/g;
    let match;
    while ((match = words.exec(text)) !== null) {
      const name = match[0].toLowerCase().replaceAll(/[_.-]/g, "");
      if (!CREDENTIAL_NAMES.some((key) => name.endsWith(key))) continue;
      const start = valueStart(text, words.lastIndex);
      if (start === undefined) continue;
      const end = credentialEnd(text, start);
      if (end - start < minimumCredentialLength(text, start, name)) continue;
      spans.push([start, end]);
      words.lastIndex = end;
    }
    return spans;
  }

  function emailToken(word) {
    const at = word.indexOf("@");
    if (at <= 0 || at !== word.lastIndexOf("@")) return false;
    const domain = word.slice(at + 1);
    const dot = domain.lastIndexOf(".");
    if (dot <= 0 || dot === domain.length - 1) return false;
    return /^[A-Za-z0-9.-]+$/.test(domain) && /^[A-Za-z]{2,}$/.test(domain.slice(dot + 1));
  }

  function redact(text) {
    if (PRIVATE_KEY.test(text)) return { text: "", redactions: 0, rejected: true };
    let redactions = 0;
    let cursor = 0;
    let output = "";
    for (const [start, end] of credentialSpans(text)) {
      output += text.slice(cursor, start) + "«credential»";
      cursor = end;
      redactions += 1;
    }
    output += text.slice(cursor);
    const replace = (_match, value) => { redactions += 1; return value; };
    output = output.replace(TOKEN, (match) => replace(match, "«token»"));
    output = output.replace(/\bBearer[ \t]+[A-Za-z0-9._~+/=-]{4,}/gi, (match) => replace(match, "«credential»"));
    output = output.replace(/\S+/g, (word) => word.includes("://") && word.includes("@") ? replace(word, "«credential-url»") : word);
    output = output.replace(/[A-Za-z0-9._%+@-]+/g, (word) => emailToken(word) ? replace(word, "«email»") : word);
    output = output.replace(/\/(?:home|Users)\/[^/\s"']+/g, (match) => replace(match, "/«home»"));
    output = output.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (match) => replace(match, "«ip»"));
    return { text: output, redactions, rejected: false };
  }

  function hasSensitive(text) {
    const result = redact(text);
    return result.rejected || result.redactions > 0;
  }

  function clip(text, limit) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.length <= limit) return { text, bytes: bytes.length, clipped: false };
    let end = limit;
    while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
    return { text: new TextDecoder().decode(bytes.subarray(0, end)), bytes: end, clipped: true };
  }

  function usageOf(result) {
    const usage = result?.usage;
    if (!record(usage) || ![usage.input, usage.output, usage.totalTokens].every((value) => Number.isFinite(value) && value >= 0)) return null;
    const cost = record(usage.cost) && Number.isFinite(usage.cost.total) && usage.cost.total >= 0 ? { total: usage.cost.total } : undefined;
    return { input: usage.input, output: usage.output, totalTokens: usage.totalTokens, ...(cost ? { cost } : {}) };
  }

  function classifier(ctx) {
    const runtime = ctx.modelRegistry;
    if (typeof runtime?.classify !== "function" || typeof runtime?.findOfType !== "function") throw new Error("native_api_unavailable");
    const model = runtime.findOfType("classifier", "openrouter", MODEL);
    if (!model) throw new Error("model_unavailable");
    return model;
  }

  async function request(ctx, state, questions, signal, model) {
    signal?.throwIfAborted();
    try {
      const selected = model ?? classifier(ctx);
      const result = await ctx.modelRegistry.classify(selected, { state, questions }, { signal });
      signal?.throwIfAborted();
      return { result };
    } catch (error) {
      signal?.throwIfAborted();
      const code = ["native_api_unavailable", "model_unavailable"].includes(error?.message) ? error.message : "request_unavailable";
      return { failure: code };
    }
  }

  async function workspaceFor(ctx) {
    try {
      const root = findInitializedRoot(ctx.cwd) ?? resolve(ctx.cwd);
      if (ctx.isProjectTrusted?.() !== true || !trustedRuntimeVersion()) return undefined;
      const fs = await import("node:fs");
      if (SCOPE === "project" && fs.realpathSync(join(root, ".pi/extensions/lgtm.ts")) !== fs.realpathSync(extensionLocation())) return undefined;
      return root;
    } catch {
      return undefined;
    }
  }

  function readBytes(fs, full, limit) {
    const fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 || before.size > limit) throw new Error("file_ineligible");
      const named = fs.statSync(full);
      if (fs.realpathSync(full) !== full || named.ino !== before.ino || named.dev !== before.dev) throw new Error("path_changed");
      const buffer = Buffer.alloc(limit + 1);
      const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
      const after = fs.fstatSync(fd);
      if (length > limit || length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error("file_changed");
      return buffer.subarray(0, length);
    } finally {
      fs.closeSync(fd);
    }
  }

  function policyPatterns(fs, file) {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(readBytes(fs, file, 64 * 1024)));
    if (!record(value) || !Array.isArray(value.prohibited_paths ?? [])) throw new Error("invalid_policy");
    const patterns = value.prohibited_paths ?? [];
    if (patterns.length > 1024) throw new Error("invalid_policy");
    return patterns;
  }

  function patternProhibits(pattern, relative) {
    if (typeof pattern !== "string" || !pattern || pattern.length > 4096 || /[\x00-\x1f]/.test(pattern)) throw new Error("invalid_policy");
    const normalized = pattern.replaceAll("\\", "/");
    if (normalized === "*" || normalized === "**") return true;
    const prefix = normalized.endsWith("/**") ? normalized.slice(0, -3) : normalized;
    if (prefix.includes("*") || prefix.startsWith("/") || prefix.split("/").some((part) => !part || part === "." || part === "..")) throw new Error("invalid_policy");
    return relative === prefix || (normalized.endsWith("/**") && relative.startsWith(prefix + "/"));
  }

  function policyAllows(fs, root, relative) {
    const directory = join(root, ".lgtm");
    if (fs.lstatSync(directory, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error("policy_symlink");
    for (const name of ["config.json", "execpolicy.json"]) {
      const file = join(directory, name);
      if (!fs.lstatSync(file, { throwIfNoEntry: false })) continue;
      if (policyPatterns(fs, file).some((pattern) => patternProhibits(pattern, relative))) throw new Error("prohibited_path");
    }
  }

  async function candidatePath(root, name, limit = 16384) {
    if (typeof name !== "string" || !name || name.length > 512 || /[\x00-\x1f\x7f]/.test(name)) throw new Error("invalid_path");
    const fs = await import("node:fs");
    const path = await import("node:path");
    const base = fs.realpathSync(root);
    const full = path.resolve(base, name);
    const relative = path.relative(base, full);
    const parts = relative.split(path.sep);
    if (!relative || path.isAbsolute(relative) || parts.length > 64 || parts.includes("..") || privatePath(relative) || hasSensitive(relative)) throw new Error("path_denied");
    policyAllows(fs, base, relative.replaceAll("\\", "/"));
    let parent = base;
    for (const part of parts) {
      parent = path.join(parent, part);
      if (fs.lstatSync(parent).isSymbolicLink()) throw new Error("symlink_denied");
    }
    const metadata = fs.lstatSync(full);
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size > limit) throw new Error("file_ineligible");
    return full;
  }

  // Selected files use metadata only here; source bytes come solely from the governed read.
  async function snapshot(root, name, limit = 16384) {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const full = await candidatePath(root, name, limit);
    const metadata = fs.lstatSync(full, { bigint: true });
    if (!metadata.isFile() || metadata.nlink !== 1n || metadata.size > BigInt(limit)) throw new Error("file_ineligible");
    const identity = [metadata.dev, metadata.ino, metadata.size, metadata.mtimeNs, metadata.ctimeNs, metadata.mode].join(":");
    return { path: path.relative(fs.realpathSync(root), full), bytes: Number(metadata.size),
      identity: createHash("sha256").update(identity).digest("hex") };
  }

  function visibleText(result) {
    if (!Array.isArray(result.content)) return undefined;
    return result.content.filter((block) => block.type === "text").map((block) => block.text).join("\n");
  }

  function boundReadContent(result, binding) {
    const visible = visibleText(result);
    if (typeof visible !== "string" || visible.length > 256 * 1024) throw new Error("read_filtered");
    // Content-only guidance hooks can drop structuredContent. Use only a complete
    // visible block that still matches the binding; never recover removed text.
    const content = result.structuredContent === undefined
      ? result.content.find((block) => block.type === "text" && typeof block.text === "string"
        && createHash("sha256").update(block.text).digest("hex") === binding.textDigest)?.text
      : result.structuredContent;
    if (typeof content !== "string" || !visible.includes(content)) throw new Error("read_filtered");
    return content;
  }

  function governedText(result, full, limit) {
    const binding = result?.details?.lgtmRead;
    if (!record(binding) || binding.protocol !== "lgtm-pi-read-v1" || result.details?.lgtmAdvisory?.protocol !== "lgtm-pi-advisory-v1" || result.details?.truncation?.truncated) throw new Error("read_filtered");
    if (binding.pathDigest !== createHash("sha256").update(full).digest("hex")) throw new Error("read_redirected");
    const content = boundReadContent(result, binding);
    const sha256 = createHash("sha256").update(content).digest("hex");
    if (binding.textDigest !== sha256 || content.includes("\0")) throw new Error("read_filtered");
    const bytes = new TextEncoder().encode(content).length;
    if (bytes > limit || content.split("\n").length > 1500) throw new Error("file_ineligible");
    return { content, bytes, sha256 };
  }

  async function readFile(ctx, root, name, signal, limit = 16384) {
    signal?.throwIfAborted();
    if (typeof ctx.executeTool !== "function") throw new Error("native_api_unavailable");
    const before = await snapshot(root, name, limit);
    const full = await candidatePath(root, name, limit);
    const outcome = await ctx.executeTool("read", { path: full }, { signal });
    signal?.throwIfAborted();
    const result = outcome?.result ?? outcome;
    if (outcome?.isError || result?.isError) throw new Error("read_denied");
    const output = governedText(result, full, limit);
    const after = await snapshot(root, name, limit);
    if (before.identity !== after.identity) throw new Error("source_changed");
    if (output.bytes !== before.bytes) throw new Error("read_filtered");
    return { ...after, ...output };
  }

  async function readRequest(ctx, params, signal) {
    if (!record(params) || !Object.keys(params).every((key) => ["requestPath", "preview", "allowSend"].includes(key))
        || typeof params.requestPath !== "string" || params.requestPath.length > 512
        || (params.preview !== undefined && typeof params.preview !== "boolean")
        || (params.allowSend !== undefined && typeof params.allowSend !== "boolean")) throw new Error("invalid_request");
    const root = await workspaceFor(ctx);
    if (!root) throw new Error("workspace_unavailable");
    const file = await readFile(ctx, root, params.requestPath, signal, 32 * 1024);
    let value;
    try { value = JSON.parse(file.content); } catch { throw new Error("invalid_request"); }
    if (!record(value)) throw new Error("invalid_request");
    return { root, value };
  }

  async function bashText(ctx, command, signal) {
    signal?.throwIfAborted();
    if (typeof ctx.executeTool !== "function") throw new Error("native_api_unavailable");
    const outcome = await ctx.executeTool("bash", { command }, { signal });
    signal?.throwIfAborted();
    const result = outcome?.result ?? outcome;
    const data = result?.structuredContent;
    if (outcome?.isError || result?.isError || result?.details?.lgtmAdvisory?.protocol !== "lgtm-pi-advisory-v1" || !record(data) || data.exit_code !== 0 || data.truncated !== false || typeof data.output !== "string") throw new Error("native_output_unverified");
    if (new TextEncoder().encode(data.output).length > 1024 * 1024) throw new Error("native_output_unverified");
    return data.output;
  }

  async function bounded(signal, lifetime, timeoutMs, work) {
    const controller = new AbortController();
    const combined = AbortSignal.any([controller.signal, signal, lifetime?.()].filter(Boolean));
    let timer;
    let onAbort;
    try {
      combined.throwIfAborted();
      const cancelled = new Promise((_, reject) => {
        onAbort = () => reject(new Error("cancelled_or_timeout"));
        combined.addEventListener("abort", onAbort, { once: true });
      });
      timer = setTimeout(() => controller.abort(), timeoutMs);
      const result = await Promise.race([work(combined), cancelled]);
      combined.throwIfAborted();
      return result;
    } finally {
      clearTimeout(timer);
      if (onAbort) combined.removeEventListener("abort", onAbort);
      controller.abort();
    }
  }

  function referenceParameters(controls = []) {
    return { type: "object", required: ["requestPath"], additionalProperties: false,
      properties: { requestPath: { type: "string", minLength: 1, maxLength: 512 },
        ...Object.fromEntries(controls.map((name) => [name, { type: "boolean" }])) } };
  }

  function releaseFinished(id, state) {
    if (state.finished && state.pending === 0) active.delete(id);
  }

  function trackedContext(ctx, id, state) {
    if (typeof ctx.executeTool !== "function") return ctx;
    const descriptors = Object.getOwnPropertyDescriptors(ctx);
    // Native guarded getters must remain lazy, including stale-context checks.
    descriptors.executeTool = { value: async (...args) => {
      state.pending += 1;
      try { return await ctx.executeTool(...args); } finally {
        state.pending -= 1;
        releaseFinished(id, state);
      }
    } };
    return Object.create(Object.getPrototypeOf(ctx), descriptors);
  }

  function canStart(id) {
    return typeof id === "string" && id.length > 0 && id.length <= 1024 && active.size < MAX_ACTIVE && !active.has(id);
  }

  function register(pi, descriptor) {
    if (typeof pi.registerTool !== "function") return;
    try {
      if (pi.getAllTools?.().some((tool) => tool.name === descriptor.name)) return;
      const { run, ...definition } = descriptor;
      pi.registerTool({
        ...definition, exposure: "codemode",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
        outputSchema: { type: "object", required: ["status"], properties: { status: { type: "string" } }, additionalProperties: true },
        async execute(id, params, signal, _update, ctx) {
          if (!canStart(id)) {
            const busy = { status: "unavailable", reason: "advisory_busy", advisory: true, usage: null };
            return { content: [{ type: "text", text: JSON.stringify(busy) }], structuredContent: busy, details: busy };
          }
          const state = { pending: 0, finished: false };
          active.set(id, state);
          let result;
          try { result = await run(params, signal, trackedContext(ctx, id, state)); } catch {
            // Never let a read/provider error body enter Pi's nested-call error journal.
            result = { status: "unavailable", reason: "request_unavailable", advisory: true, usage: null };
          } finally {
            state.finished = true;
            releaseFinished(id, state);
          }
          // Pi can refuse optional metadata persistence without disabling advisory tools.
          try { pi.appendEntry("lgtm-jev", result); } catch {}
          return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result, details: result, ...(result.usage ? { usage: result.usage } : {}) };
        },
      });
    } catch {
      // Registration must not prevent deterministic enforcement from loading.
      try { pi.appendEntry("lgtm-jev", { status: "unavailable", reason: "registration" }); } catch {}
    }
  }

  return { MODEL, record, probability, owns, privatePath, hasSensitive, redact, clip, usageOf, classifier, request, workspaceFor, candidatePath, snapshot, readFile, readRequest, bashText, bounded, referenceParameters, register };
})();
