// Integration harness for the installed checkpoint template.
// This fixture exceeds 500 lines to keep the isolated scenario registry in one
// self-contained Node -e input; each scenario runs in a separate process.
//
// It loads the real template from the path given as the second-to-last argv entry so V8
// coverage maps to the original TypeScript source. The template's fs and path imports are
// replaced with test globals, and its default export becomes globalThis.__checkpoint.
// The model registry is mocked; git and the filesystem stay real.

import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';

const exec = promisify(execFile);
// Both `node file.mjs <template> <scenario>` and `node -e <script> <template> <scenario>` put
// the template and the scenario name last, so read them from the end of argv.
const [templateArgument, scenarioName] = process.argv.slice(-2);
const templatePath = path.resolve(templateArgument);
const sections = ['## Mission context', '## What shipped this session', '## What is mid-flight', '## What was tried and rejected', '## Open decisions', '## Build and test state', '## Files of interest', '## Continue here'];

// writeHook and openHook let a scenario inject one filesystem failure through the
// same test-global seam that replaces the template's fs import.
let writeHook = async () => {};
let openHook = async () => {};
let lstatHook = async () => {};
globalThis.__path = path;
globalThis.__checkpointFs = {
  ...fs,
  lstat: async (target, ...args) => {
    await lstatHook(String(target));
    return fs.lstat(target, ...args);
  },
  open: async (target, ...args) => {
    await openHook(String(target));
    return fs.open(target, ...args);
  },
  writeFile: async (target, ...args) => {
    await fs.writeFile(target, ...args);
    await writeHook(String(target));
  },
};

const rawTemplate = await fs.readFile(templatePath, 'utf8');
let executable = stripTypeScriptTypes(rawTemplate, { mode: 'strip' });
const declaration = executable.split('\n').find(line => line.startsWith('export default function'));
assert.ok(declaration, 'template has a default factory');
const replacements = [
  ['import { lstat, open, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";', 'const{lstat,open,readFile,realpath,rename,unlink,writeFile}=globalThis.__checkpointFs;'],
  ['import { dirname, join } from "node:path";', 'const{dirname,join}=globalThis.__path;'],
  [declaration, 'globalThis.__checkpoint = function (pi) {'],
];
for (const [original, replacement] of replacements) {
  assert.equal(executable.split(original).length, 2, 'each loader seam matches exactly once');
  assert.ok(replacement.length <= original.length, 'replacement fits the original UTF-16 span');
  executable = executable.replace(original, replacement.padEnd(original.length, ' '));
}
assert.deepEqual(executable.split('\n').map(line => line.length), rawTemplate.split('\n').map(line => line.length), 'every original UTF-16 source offset is preserved for V8 coverage');
vm.runInThisContext(executable, { filename: templatePath });
const checkpoint = globalThis.__checkpoint;
assert.equal(typeof checkpoint, 'function', 'template default export loads');

function defaultBranch() {
  return [
    { id: 'old', type: 'message', message: { role: 'assistant', content: [{ type: 'text', text: 'cargo build passed; Ship change verified' }] } },
    { id: 'kept', type: 'message', message: { role: 'user', content: 'continue' } },
  ];
}

function sectionBody(extra = '') {
  return sections.map((heading) => `${heading}\nObserved session evidence.\n`).join('\n') + extra;
}

function modelResult(body, tasks = []) {
  return { stopReason: 'stop', content: [{ type: 'text', text: JSON.stringify({ handoff: body, completedTasks: tasks }) }] };
}

function createHarness(options = {}) {
  const notices = [];
  const handlers = new Map();
  const commands = new Map();
  let controller = new AbortController();
  let callbackAssertion;
  const state = {
    sessionId: options.sessionId ?? 'session-a',
    branch: options.branch ?? defaultBranch(),
    model: 'model' in options ? options.model : { id: 'fixture' },
    hasUI: options.hasUI ?? true,
    notifyThrows: options.notifyThrows ?? false,
    hasAuth: options.hasAuth ?? true,
    complete: options.complete ?? (async () => modelResult(sectionBody())),
    execOverride: options.execOverride ?? null,
    cwd: options.cwd ?? path.join(process.cwd(), 'nested'),
    calls: 0,
  };
  const harness = {
    notices,
    handlers,
    commands,
    state,
    ctx: null,
    command: (name) => commands.get(name).handler,
    run: async (overrides = {}) => {
      controller = new AbortController();
      callbackAssertion = undefined;
      const event = {
        reason: overrides.reason ?? 'threshold',
        signal: overrides.signal ?? controller.signal,
        preparation: {
          tokensBefore: 1000,
          settings: { keepRecentTokens: 100 },
          firstKeptEntryId: 'kept',
          ...(overrides.preparation ?? {}),
        },
      };
      const result = await handlers.get('session_before_compact')(event, harness.ctx);
      if (callbackAssertion) throw callbackAssertion;
      return result;
    },
    abort: () => controller.abort(),
  };
  harness.ctx = {
    get cwd() { return state.cwd; },
    get hasUI() { return state.hasUI; },
    ui: {
      notify: (message, kind) => {
        if (state.notifyThrows) throw new Error('notify failed');
        notices.push(`${kind}: ${message}`);
      },
    },
    get model() { return state.model; },
    sessionManager: { getSessionId: () => state.sessionId, getBranch: () => state.branch },
    modelRegistry: {
      hasConfiguredAuth: () => state.hasAuth,
      complete: async (model, input, opts) => {
        state.calls += 1;
        try {
          return await state.complete(model, input, opts, harness);
        } catch (error) {
          if (error instanceof assert.AssertionError) callbackAssertion = error;
          throw error;
        }
      },
    },
  };
  const pi = {
    on: (name, handler) => handlers.set(name, handler),
    registerCommand: (name, handler) => commands.set(name, handler),
    exec: async (command, args, opts) => {
      if (state.execOverride) {
        const overridden = await state.execOverride(command, args, opts);
        if (overridden !== undefined) return overridden;
      }
      try {
        const result = await exec(command, args, { ...opts, timeout: 5000 });
        return { stdout: result.stdout, code: 0, killed: false };
      } catch (error) {
        return { stdout: '', code: typeof error.code === 'number' ? error.code : 1, killed: error.killed === true };
      }
    },
  };
  checkpoint(pi);
  return harness;
}

function expectNotice(harness, kind, fragment) {
  const wanted = `${kind}: ${fragment}`;
  assert.ok(
    harness.notices.some((notice) => notice.startsWith(`${kind}: `) && notice.includes(fragment)),
    `expected a ${wanted} notice; got ${JSON.stringify(harness.notices)}`,
  );
}

const read = (name) => fs.readFile(name, 'utf8');
const exists = async (name) => { try { await fs.lstat(name); return true; } catch { return false; } };
const listTmp = async () => (await fs.readdir('.')).filter((name) => name.endsWith('.tmp'));
const PLAN_INITIAL = '- [ ] Ship change\n- [ ] Still pending\n- [ ] Third item\n';

async function initRepo() {
  execFileSync('git', ['init', '-q'], { timeout: 5000 });
  execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'initial'], { timeout: 5000 });
  await fs.mkdir('nested', { recursive: true });
}

function git(args) {
  execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', ...args], { timeout: 5000 });
}

const scenarios = new Map();

scenarios.set('manual_and_toggle', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  const before = await read('HANDOFF.md');

  assert.equal(await h.run({ reason: 'manual' }), undefined);
  assert.equal(h.state.calls, 0);
  assert.deepEqual(h.notices, []);

  await h.command('checkpoint-auto')('off', h.ctx);
  assert.equal(await h.run(), undefined);
  assert.equal(h.state.calls, 0);
  assert.equal(await read('HANDOFF.md'), before);

  await h.command('checkpoint-auto')('status', h.ctx);
  await h.command('checkpoint-auto')('', h.ctx);
  await h.command('checkpoint-auto')('maybe', h.ctx);
  expectNotice(h, 'info', 'checkpoint-auto: off for this session');
  expectNotice(h, 'warning', 'Usage: /checkpoint-auto on|off|status');

  await h.command('checkpoint-auto')('on', h.ctx);
  await h.run();
  assert.equal(h.state.calls, 1);
  expectNotice(h, 'info', 'lgtm checkpoint wrote HANDOFF.md');
});

scenarios.set('plan_evidence_guard', async (h) => {
  await initRepo();
  const longText = `- [ ] ${'x'.repeat(450)}`;
  await fs.writeFile('implementation_plan.md', `${PLAN_INITIAL}Some prose line without a checkbox\n- [x] Already done\n${longText}\n`);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  h.state.complete = async () => modelResult(sectionBody(), [
    { line: 1, text: '- [ ] Ship change', evidence: 'cargo build passed' },
    { line: 2, text: '- [ ] Renamed text', evidence: 'cargo build passed' },
    { line: 2, text: '- [ ] Still pending', evidence: 'invented success' },
    { line: 2, text: '- [ ] Still pending', evidence: 'Still pending' },
    { line: 1, text: '- [ ] Ship change', evidence: 'cargo build passed' },
    { line: 40, text: '- [ ] Gone', evidence: 'cargo build passed' },
    { line: 2.5, text: '- [ ] Still pending', evidence: 'cargo build passed' },
    'not a record',
    { line: 3, text: '- [ ] Third item', evidence: '   ' },
    { line: 3, text: '- [ ] Third item', evidence: 'cargo build passed' },
    { line: 4, text: 'Some prose line without a checkbox', evidence: 'cargo build passed' },
    { line: 5, text: '- [x] Already done', evidence: 'cargo build passed' },
    { line: 6, text: longText, evidence: 'cargo build passed' },
    { line: 0, text: '- [ ] Zero', evidence: 'cargo build passed' },
    { line: '1', text: '- [ ] Ship change', evidence: 'cargo build passed' },
    { line: 1, text: 123, evidence: 'cargo build passed' },
    { line: 1, text: '   ', evidence: 'cargo build passed' },
    { line: 1, text: '- [ ] Ship change', evidence: 123 },
  ]);
  await h.run();
  const updated = await read('implementation_plan.md');
  assert.match(updated, /^- \[x\] Ship change$/m);
  assert.match(updated, /^- \[x\] Third item$/m);
  assert.match(updated, /^- \[ \] Still pending$/m);
  assert.ok(updated.includes(longText), 'oversized task text must not rewrite the plan line');
  const handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('line 1: `- [ ] Ship change` — evidence: cargo build passed'));
  assert.ok(handoff.includes('7 proposed line(s) did not match an existing unchecked line and were ignored'));
  assert.ok(handoff.includes('Previous owner notes'));
  assert.ok(handoff.includes('<details>'));
  assert.ok(handoff.includes('Resume in Pi'));
});

scenarios.set('plan_task_bounds', async (h) => {
  await initRepo();
  const plan = `${Array.from({ length: 25 }, (_, index) => `- [ ] Item ${index + 1}`).join('\n')}\n`;
  await fs.writeFile('implementation_plan.md', plan);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  let tasks = Array.from({ length: 21 }, (_, index) => ({ line: index + 1, text: `- [ ] Item ${index + 1}`, evidence: 'cargo build passed' }));
  h.state.complete = async () => modelResult(sectionBody(), tasks);
  await h.run();
  assert.equal(await read('implementation_plan.md'), plan);
  assert.ok((await read('HANDOFF.md')).includes('None. `implementation_plan.md` was inspected and left unchanged.'));
  tasks = 'not an array';
  await h.run();
  assert.equal(await read('implementation_plan.md'), plan);
  tasks = [
    { line: 1, text: '- [ ] Item 1', evidence: 'cargo build passed' },
    { line: 2, text: '- [ ] Item 2', evidence: '   ' },
  ];
  await h.run();
  assert.match(await read('implementation_plan.md'), /^- \[x\] Item 1$/m);
  assert.ok((await read('HANDOFF.md')).includes('line 1: `- [ ] Item 1` — evidence: cargo build passed'));
});

scenarios.set('missing_files_snapshot_only', async (h) => {
  await initRepo();
  await h.run();
  const handoff = await read('HANDOFF.md');
  assert.ok(!(await exists('implementation_plan.md')));
  assert.ok(handoff.includes('`implementation_plan.md` is not present, so no plan was created or edited.'));
  assert.ok(handoff.includes('Observed session evidence.'));
  assert.ok(handoff.includes('## Observed repository snapshot'));
  assert.ok(handoff.includes('Build and test gates: not run by this checkpoint'));
  expectNotice(h, 'info', 'lgtm checkpoint wrote HANDOFF.md');
});

scenarios.set('unusable_output_preserves_handoff', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  const preserved = async () => {
    await h.run();
    assert.equal(await read('HANDOFF.md'), 'Previous owner notes\n');
    expectNotice(h, 'warning', 'unusable_response_existing_handoff_preserved');
  };
  h.state.hasAuth = false;
  await preserved();
  h.state.hasAuth = true;
  h.state.complete = async () => ({ stopReason: 'error', content: [] });
  await preserved();
  h.state.complete = async () => ({ stopReason: 'aborted', content: [] });
  await preserved();
  h.state.complete = async () => modelResult(sectionBody().replace('## Open decisions\nObserved session evidence.\n', ''));
  await preserved();
  h.state.model = null;
  await preserved();
  h.state.model = { id: 'fixture' };
  h.state.complete = async () => modelResult(sectionBody() + 'x'.repeat(24000));
  await preserved();
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
});

scenarios.set('fallback_without_handoff', async (h) => {
  await initRepo();
  h.state.complete = async () => ({ stopReason: 'error', content: [] });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured. The checkpoint model response was unavailable or unusable'));
  expectNotice(h, 'warning', 'lgtm checkpoint: no usable model handoff, writing the repository snapshot only');

  await fs.rm('HANDOFF.md');
  h.state.complete = async () => ({ stopReason: 'stop', content: [{ type: 'text', text: 'unusable JSON' }] });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured.'));

  await fs.rm('HANDOFF.md');
  h.state.complete = async () => ({ stopReason: 'stop', content: [{ type: 'text', text: '[]' }] });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured.'));

  await fs.rm('HANDOFF.md');
  h.state.complete = async () => ({ stopReason: 'stop', content: [{ type: 'text', text: '{"handoff": 5}' }] });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured.'));

  await fs.rm('HANDOFF.md');
  h.state.complete = async () => ({ stopReason: 'stop', content: [{ type: 'text', text: '{"handoff": broken}' }] });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured.'));

  await fs.rm('HANDOFF.md');
  h.state.hasAuth = false;
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('Not captured.'));
  assert.ok(!(await exists('implementation_plan.md')));
  assert.equal((await listTmp()).length, 0);
});

scenarios.set('model_call_throws', async (h) => {
  await initRepo();
  h.state.complete = async () => { throw new Error('model exploded'); };
  await h.run();
  expectNotice(h, 'warning', 'lgtm checkpoint skipped: unexpected_error');
  assert.ok(!(await exists('HANDOFF.md')));
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  assert.equal((await listTmp()).length, 0);
  // Production may catch model errors, but it must not hide harness assertion failures.
  h.state.complete = async () => { assert.fail('model callback assertion'); };
  await assert.rejects(h.run(), { code: 'ERR_ASSERTION', message: 'model callback assertion' });
});

scenarios.set('outside_git_repository', async (h) => {
  h.state.cwd = process.cwd();
  await h.run();
  expectNotice(h, 'info', 'cwd is not inside a git repository, skipped');
  assert.ok(!(await exists('HANDOFF.md')));
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  assert.equal(h.state.calls, 0);
  h.state.execOverride = (command, args) => (args.join(' ') === 'rev-parse --show-toplevel' ? { stdout: '', code: 0, killed: false } : undefined);
  await h.run();
  expectNotice(h, 'info', 'cwd is not inside a git repository, skipped');
});

scenarios.set('unsafe_and_oversized_files', async (h) => {
  await initRepo();
  await fs.writeFile('outside.md', 'do not change\n');
  await fs.symlink(path.join(process.cwd(), 'outside.md'), 'HANDOFF.md');
  await h.run();
  expectNotice(h, 'warning', 'unsafe_target');
  assert.equal(await read('outside.md'), 'do not change\n');
  assert.ok((await fs.lstat('HANDOFF.md')).isSymbolicLink());

  await fs.unlink('HANDOFF.md');
  await fs.mkdir('HANDOFF.md');
  await h.run();
  expectNotice(h, 'warning', 'unsafe_target');
  await fs.rmdir('HANDOFF.md');

  await fs.writeFile('implementation_plan.md', `- [ ] Big\n${'x'.repeat(256 * 1024)}`);
  await h.run();
  expectNotice(h, 'warning', 'oversized_input');

  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  const oversized = 'y'.repeat(256 * 1024 + 1);
  await fs.writeFile('HANDOFF.md', oversized);
  await h.run();
  expectNotice(h, 'warning', 'oversized_input');
  assert.equal(await read('HANDOFF.md'), oversized);
  assert.equal((await listTmp()).length, 0);
});

scenarios.set('stale_archive_collisions', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  const stale = new Date('2020-01-02T03:04:05.000Z');
  await fs.utimes('HANDOFF.md', stale, stale);
  await fs.writeFile('HANDOFF.2020-01-02.md', 'occupied one\n');
  await fs.writeFile('HANDOFF.2020-01-02-2.md', 'occupied two\n');
  await h.run();
  expectNotice(h, 'info', 'lgtm checkpoint wrote HANDOFF.md');
  assert.match(await read('HANDOFF.md'), /> Archived history: `HANDOFF\.2020-01-02-3\.md`/);
  assert.equal(await read('HANDOFF.2020-01-02.md'), 'occupied one\n');
  assert.equal(await read('HANDOFF.2020-01-02-2.md'), 'occupied two\n');
  assert.ok((await read('HANDOFF.2020-01-02-3.md')).includes('Previous owner notes'));
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat('HANDOFF.2020-01-02-3.md')).mode & 0o077, 0);
  }
  assert.ok(!(await read('HANDOFF.md')).includes('<details>'), 'a stale handoff moves wholly to the archive file');
});

scenarios.set('archive_attempt_bounds', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  const stale = new Date('2020-01-02T03:04:05.000Z');
  await fs.utimes('HANDOFF.md', stale, stale);
  const names = ['HANDOFF.2020-01-02.md', ...Array.from({ length: 19 }, (_, index) => `HANDOFF.2020-01-02-${index + 2}.md`)];
  for (const name of names) await fs.writeFile(name, 'occupied\n');
  await h.run();
  expectNotice(h, 'warning', 'archive_collisions');
  assert.equal(await read('HANDOFF.md'), 'Previous owner notes\n');
  assert.equal((await listTmp()).length, 0);
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
});

scenarios.set('archive_overflow_and_budget', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  const block = (label) => `## Archived — ${label}\n\nHistorical notes for ${label}.`;
  const blocks = Array.from({ length: 6 }, (_, index) => block(`block ${index + 1}`));
  await fs.writeFile('HANDOFF.md', `# Old handoff\n\n> Session: other-session\n\n${blocks.join('\n\n')}\n`);
  const today = new Date().toISOString().slice(0, 10);
  await h.run();
  const handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes(`Older archived history: \`HANDOFF.${today}.md\``));
  assert.equal(handoff.split('## Archived — ').length - 1, 5);
  assert.ok((await read(`HANDOFF.${today}.md`)).includes('block 5'));

  const big = (label) => `## Archived — ${label}\n\n${'y'.repeat(55000)}`;
  await fs.writeFile('HANDOFF.md', `# Old handoff\n\n> Session: other-session\n\n${big('large one')}\n\n${big('large two')}\n\n${big('large three')}\n`);
  await h.run();
  const trimmed = await read('HANDOFF.md');
  assert.ok(trimmed.includes(`Oversized archived history: \`HANDOFF.${today}-2.md\``));
  assert.ok(trimmed.includes('large one'));
  assert.ok(!trimmed.includes('large three'), 'the oldest archive block moves to the dated file');
  assert.ok(Buffer.byteLength(trimmed, 'utf8') < 128 * 1024);
});

scenarios.set('concurrent_edits_and_abort', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  let action = 'none';
  h.state.complete = async () => {
    if (action === 'handoff-edit') await fs.writeFile('HANDOFF.md', 'Concurrent owner edit\n');
    if (action === 'plan-edit') await fs.writeFile('implementation_plan.md', 'Owner edit during planning\n');
    if (action === 'abort') h.abort();
    return modelResult(sectionBody(), [{ line: 1, text: '- [ ] Ship change', evidence: 'cargo build passed' }]);
  };

  action = 'handoff-edit';
  await h.run();
  expectNotice(h, 'warning', 'lgtm checkpoint skipped: HANDOFF.md changed while this checkpoint ran');
  assert.equal(await read('HANDOFF.md'), 'Concurrent owner edit\n');

  action = 'plan-edit';
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await h.run();
  assert.equal(await read('implementation_plan.md'), 'Owner edit during planning\n');
  assert.ok((await read('HANDOFF.md')).includes('A concurrent edit changed `implementation_plan.md`, so this checkpoint wrote nothing.'));

  action = 'none';
  writeHook = async (target) => {
    if (target.includes('.HANDOFF.md.') && target.endsWith('.tmp')) await fs.writeFile('HANDOFF.md', 'Owner edit during staging\n');
  };
  await h.run();
  expectNotice(h, 'warning', 'lgtm checkpoint skipped: HANDOFF.md changed while this checkpoint ran');
  assert.equal(await read('HANDOFF.md'), 'Owner edit during staging\n');
  writeHook = async () => {};
  assert.equal((await listTmp()).length, 0);

  action = 'abort';
  const beforeAbort = await read('HANDOFF.md');
  await h.run();
  assert.equal(await read('HANDOFF.md'), beforeAbort);
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  expectNotice(h, 'warning', 'lgtm checkpoint skipped: unexpected_error');
});

scenarios.set('lock_contention_and_release', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  await fs.writeFile('.lgtm-checkpoint.lock', 'foreign-token\n');
  await h.run();
  expectNotice(h, 'warning', 'another checkpoint holds the repository lock');
  assert.equal(await read('.lgtm-checkpoint.lock'), 'foreign-token\n');
  assert.ok(!(await exists('HANDOFF.md')));

  await fs.unlink('.lgtm-checkpoint.lock');
  openHook = async (target) => {
    if (path.basename(target) === '.lgtm-checkpoint.lock') throw Object.assign(new Error('i/o error'), { code: 'EIO' });
  };
  await h.run();
  expectNotice(h, 'warning', 'lock_error');
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  openHook = async () => {};

  h.state.complete = async () => {
    await fs.writeFile('.lgtm-checkpoint.lock', 'foreign-token\n');
    return modelResult(sectionBody());
  };
  await h.run();
  assert.equal(await read('.lgtm-checkpoint.lock'), 'foreign-token\n', 'a lock replaced mid-run is not stolen on release');
  expectNotice(h, 'info', 'lgtm checkpoint wrote HANDOFF.md');

  await fs.unlink('.lgtm-checkpoint.lock');
  h.state.complete = async () => modelResult(sectionBody());
  await h.run();
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));

  h.state.complete = async () => {
    await fs.unlink('.lgtm-checkpoint.lock');
    return modelResult(sectionBody());
  };
  await h.run();
  assert.ok(!(await exists('.lgtm-checkpoint.lock')), 'a lock removed mid-run stays removed');
  expectNotice(h, 'info', 'lgtm checkpoint wrote HANDOFF.md');
  h.state.complete = async () => modelResult(sectionBody());
});

scenarios.set('unreadable_paths_are_reported', async (h) => {
  await initRepo();
  // Inject the read error without depending on a platform-specific path limit.
  lstatHook = async (target) => {
    if (path.basename(target) === 'implementation_plan.md') throw Object.assign(new Error('access denied'), { code: 'EACCES' });
  };
  await h.run();
  expectNotice(h, 'warning', 'read_error');
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  lstatHook = async () => {};
});

scenarios.set('write_errors_are_isolated', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  writeHook = async (target) => {
    if (target.includes('.HANDOFF.md.')) throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
  };
  await h.run();
  expectNotice(h, 'warning', 'write_error');
  assert.ok(!(await exists('HANDOFF.md')));
  assert.equal((await listTmp()).length, 0);

  writeHook = async (target) => {
    if (target.includes('.implementation_plan.md.')) throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
  };
  h.state.complete = async () => modelResult(sectionBody(), [{ line: 1, text: '- [ ] Ship change', evidence: 'cargo build passed' }]);
  await h.run();
  expectNotice(h, 'warning', 'write_error');
  assert.equal(await read('implementation_plan.md'), PLAN_INITIAL);
  assert.ok(!(await exists('HANDOFF.md')));
  h.state.complete = async () => modelResult(sectionBody());

  writeHook = async (target) => {
    if (path.basename(target).startsWith('HANDOFF.2020')) throw Object.assign(new Error('read only'), { code: 'EPERM' });
  };
  await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
  const stale = new Date('2020-01-02T03:04:05.000Z');
  await fs.utimes('HANDOFF.md', stale, stale);
  await h.run();
  expectNotice(h, 'warning', 'archive_error');
  assert.equal(await read('HANDOFF.md'), 'Previous owner notes\n');
  writeHook = async () => {};
});

scenarios.set('notification_failures', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  h.state.hasUI = false;
  await h.run();
  assert.ok(await exists('HANDOFF.md'));
  assert.deepEqual(h.notices, []);

  await fs.rm('HANDOFF.md');
  h.state.hasUI = true;
  h.state.notifyThrows = true;
  await h.run();
  assert.ok(await exists('HANDOFF.md'));
  assert.deepEqual(h.notices, []);
});

scenarios.set('unborn_and_degraded_git', async (h) => {
  execFileSync('git', ['init', '-q'], { timeout: 5000 });
  await fs.mkdir('nested', { recursive: true });
  await h.run();
  const handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('(no commit yet)'));
  assert.ok(handoff.includes('(no commit)'));
  assert.ok(handoff.includes('unborn'));

  await fs.rm('HANDOFF.md');
  h.state.execOverride = (command, args) => (args[0] === 'rev-parse' && args[1] === '--show-toplevel' ? undefined : { stdout: '', code: 0, killed: true });
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('(unavailable)'));

  await fs.rm('HANDOFF.md');
  h.state.execOverride = (command, args) => {
    if (args[0] === 'rev-parse' && args[1] === '--show-toplevel') return undefined;
    throw new Error('git disappeared');
  };
  await h.run();
  assert.ok((await read('HANDOFF.md')).includes('(unavailable)'));

  await fs.writeFile('not-a-dir', 'regular file\n');
  h.state.execOverride = (command, args) => (args.join(' ') === 'rev-parse --show-toplevel' ? { stdout: 'not-a-dir', code: 0, killed: false } : undefined);
  await h.run();
  expectNotice(h, 'warning', 'unsafe_root');
  h.state.execOverride = null;
});

scenarios.set('upstream_and_detached_head', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  execFileSync('git', ['init', '-q', '--bare', 'remote.git'], { timeout: 5000 });
  git(['remote', 'add', 'origin', 'remote.git']);
  git(['push', '-q', '-u', 'origin', 'HEAD']);
  git(['commit', '--allow-empty', '-qm', 'later local change']);
  await h.run();
  let handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('Upstream: origin/'));
  assert.ok(handoff.includes('later local change'));

  git(['push', '-q']);
  h.state.sessionId = 'session-b';
  await h.run();
  handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('Upstream: origin/'));
  assert.ok(handoff.includes('(empty)'));

  git(['checkout', '-q', '--detach', 'HEAD']);
  h.state.sessionId = 'session-c';
  await h.run();
  handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('# Handoff — (empty) @ '));
  assert.ok(handoff.includes('(no upstream configured)'));
});

scenarios.set('model_response_shapes', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  let sawSummary = false;
  h.state.complete = async (model, input) => {
    const evidence = input.messages[0].content[0].text;
    assert.ok(evidence.includes('````text'), 'a quoted block containing backticks needs a longer fence');
    assert.ok(evidence.includes('## Previous compaction summary'));
    if (!sawSummary) assert.ok(evidence.includes('stale summary'), 'the previous summary is quoted');
    else assert.ok(evidence.includes('(none)'), 'a missing previous summary is marked');
    const body = `${sectionBody()}\n# Extra title\n\n## Archived — sneaky\n`;
    return { stopReason: 'stop', content: [{ type: 'thinking', thinking: 'hidden reasoning' }, { type: 'text', text: 'Here is the result:\n```json\n' + JSON.stringify({ handoff: body, completedTasks: [] }) + '\n```\n' }] };
  };
  await h.run({ preparation: { previousSummary: '```\nstale summary\n```' } });
  let handoff = await read('HANDOFF.md');
  for (const heading of sections) assert.ok(handoff.includes(heading), `handoff is missing ${heading}`);
  assert.ok(!handoff.includes('# Extra title'));
  assert.ok(handoff.includes('## Archived history — sneaky'));
  assert.ok(!handoff.includes('hidden reasoning'));

  sawSummary = true;
  await h.run({ preparation: { previousSummary: undefined } });
  handoff = await read('HANDOFF.md');
  assert.ok(handoff.includes('## Continue here'));
  assert.equal(handoff.split('## Archived — ').length - 1, 0, 'a repeated checkpoint in one session does not archive its own block');
});

scenarios.set('evidence_bounds', async (h) => {
  await initRepo();
  const planLines = Array.from({ length: 59 }, (_, index) => `- [ ] Task ${index + 1}`);
  planLines.push('- [ ] add ```fence');
  planLines.push('- [ ] Task 60');
  const plan = `${planLines.join('\n')}\n`;
  await fs.writeFile('implementation_plan.md', plan);
  await fs.writeFile('HANDOFF.md', 'z'.repeat(4000));
  h.state.branch = Array.from({ length: 30 }, (_, index) => ({
    id: `m${index}`,
    type: 'message',
    message: { role: 'user', content: [{ type: 'text', text: `${index === 0 ? 'first-marker' : index === 29 ? 'last-marker' : 'filler'}${'q'.repeat(1990)}` }] },
  }));
  let evidenceSeen = null;
  h.state.complete = async (model, input) => {
    evidenceSeen = input.messages[0].content[0].text;
    return modelResult(sectionBody());
  };
  await h.run();
  assert.ok(evidenceSeen.includes('60: - [ ] add ```fence'));
  assert.ok(!evidenceSeen.includes('61: - [ ] Task 60'), 'the plan excerpt stops at the line cap');
  assert.ok(evidenceSeen.includes('````text'));
  assert.ok(evidenceSeen.includes('characters truncated'));
  assert.ok(!evidenceSeen.includes('first-marker'), 'the transcript digest keeps the tail');
  assert.ok(evidenceSeen.includes('last-marker'));
  assert.equal(await read('implementation_plan.md'), plan);

  await fs.rm('HANDOFF.md');
  await fs.writeFile('implementation_plan.md', '# All done\n\n- [x] Done\n');
  h.state.branch = [
    { id: 'plain', type: 'message', message: { role: 'user', content: 'continue' } },
    { id: 'noc', type: 'message', message: { role: 'user' } },
    { id: 'parts', type: 'message', message: { role: 'assistant', content: [{ type: 'image', data: 'ignored' }, 'not-a-record', { type: 'text', text: 'visible text' }] } },
  ];
  await h.run();
  assert.ok(evidenceSeen.includes('(no unchecked checkbox lines)'));
  assert.ok(evidenceSeen.includes('[user] continue'));
  assert.ok(evidenceSeen.includes('[assistant]'));
  assert.ok(evidenceSeen.includes('visible text'));
  assert.ok(!evidenceSeen.includes('ignored'));

  await fs.rm('HANDOFF.md');
  h.state.branch = [];
  await h.run();
  assert.ok(evidenceSeen.includes('(no recent messages)'));
  assert.ok(evidenceSeen.includes('Message count: 0'));
});

scenarios.set('aborted_signal_is_respected', async (h) => {
  await initRepo();
  await fs.writeFile('implementation_plan.md', PLAN_INITIAL);
  const early = new AbortController();
  early.abort();
  await h.run({ signal: early.signal });
  assert.ok(!(await exists('HANDOFF.md')));
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));

  let sawAbortedSignal = false;
  h.state.execOverride = (command, args) => (args.join(' ') === 'rev-parse --show-toplevel' ? { stdout: process.cwd(), code: 0, killed: false } : undefined);
  h.state.complete = async (model, input, opts) => {
    sawAbortedSignal = opts.signal.aborted;
    return modelResult(sectionBody());
  };
  h.state.sessionId = 'session-b';
  const earlyAgain = new AbortController();
  earlyAgain.abort();
  await h.run({ signal: earlyAgain.signal });
  assert.ok(sawAbortedSignal, 'the model call sees the aborted deadline signal');
  expectNotice(h, 'warning', 'lgtm checkpoint skipped: unexpected_error');
  assert.ok(!(await exists('HANDOFF.md')));
  assert.ok(!(await exists('.lgtm-checkpoint.lock')));
  h.state.execOverride = null;
});

const scenario = scenarios.get(scenarioName);
assert.ok(scenario, `unknown scenario: ${scenarioName}`);
await scenario(createHarness());
console.log(`checkpoint scenario passed: ${scenarioName}`);
