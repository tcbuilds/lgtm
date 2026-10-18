//! CLI installation and pre-compaction lifecycle coverage for the global checkpoint.

use std::process::Command;

mod common;
use common::TempRepo;

const EXTENSION: &str = ".pi/agent/extensions/lgtm-checkpoint.ts";

#[test]
fn every_init_variant_installs_one_global_checkpoint() {
    let variants: &[&[&str]] = &[
        &["init", "--accept-guesses"],
        &["init", "--agent", "pi", "--accept-guesses"],
        &["init", "--agent", "codex", "--accept-guesses"],
        &["init", "--rules-only"],
        &["init", "--rules-only", "--agent", "pi"],
        &["init", "--rules-only", "--agent", "codex"],
        &["init", "--global"],
    ];
    for args in variants {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        for _ in 0..2 {
            let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
                .args(*args)
                .current_dir(repo.path())
                .env("HOME", home.path())
                .output()
                .expect("init executes");
            assert!(output.status.success(), "{args:?}: {output:?}");
            assert_eq!(
                home.read(EXTENSION),
                include_str!("../templates/pi/checkpoint.ts")
            );
            assert!(!repo.exists(EXTENSION));
        }
    }
}

#[test]
fn dry_run_and_failed_init_do_not_install_a_checkpoint() {
    for args in [
        vec!["init", "--dry-run"],
        vec!["init", "--global", "--dry-run"],
        vec!["init", "--accept-guesses"],
    ] {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        if !args.contains(&"--dry-run") {
            repo.write(".lgtm/config.json", "invalid json");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(&args)
            .current_dir(repo.path())
            .env("HOME", home.path())
            .output()
            .expect("init executes");
        assert_eq!(output.status.success(), args.contains(&"--dry-run"));
        assert!(!home.exists(".pi"));
    }
}

#[test]
fn checkpoint_install_preserves_custom_content() {
    let home = TempRepo::new();
    home.write(EXTENSION, "// personal checkpoint\n");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--rules-only"])
        .current_dir(home.path())
        .env("HOME", home.path())
        .output()
        .expect("init executes");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(home.read(EXTENSION), "// personal checkpoint\n");
}

#[cfg(unix)]
#[test]
fn checkpoint_install_rejects_symlinks_before_repository_writes() {
    let home = TempRepo::new();
    let repo = TempRepo::new();
    home.write("outside.ts", "// do not change\n");
    std::fs::create_dir_all(home.path().join(".pi/agent/extensions")).unwrap();
    std::os::unix::fs::symlink(home.path().join("outside.ts"), home.path().join(EXTENSION))
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--accept-guesses"])
        .current_dir(repo.path())
        .env("HOME", home.path())
        .output()
        .expect("init executes");
    assert!(!output.status.success());
    assert!(!repo.exists(".lgtm"));
    assert_eq!(home.read("outside.ts"), "// do not change\n");
}

#[test]
fn automatic_compaction_checkpoints_files_without_changing_pi_compaction() {
    let repo = TempRepo::new();
    repo.write(
        "checkpoint.ts",
        include_str!("../templates/pi/checkpoint.ts"),
    );
    repo.write(
        "exercise.mjs",
        r##"import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { stripTypeScriptTypes } from 'node:module';
const exec = promisify(execFile);
let action = 'normal';
globalThis.__checkpointFs = { ...fs, writeFile: async (path, ...args) => {
  await fs.writeFile(path, ...args);
  if (action === 'staging-conflict' && String(path).includes('.HANDOFF.md.') && String(path).endsWith('.tmp')) {
    await fs.writeFile('HANDOFF.md', 'Owner edit during staging\n');
  }
}};
const source = (await fs.readFile('checkpoint.ts', 'utf8')).replace(
  'import { lstat, open, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";',
  'const { lstat, open, readFile, realpath, rename, unlink, writeFile } = globalThis.__checkpointFs;'
);
const { default: checkpoint } = await import('data:text/javascript;base64,' + Buffer.from(stripTypeScriptTypes(source)).toString('base64'));
execFileSync('git', ['init', '-q'], { timeout: 5000 });
execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'initial'], { timeout: 5000 });
await fs.mkdir('nested');
const plan = '- [ ] Ship change\n- [ ] Still pending\n';
await fs.writeFile('implementation_plan.md', plan);
await fs.writeFile('HANDOFF.md', 'Previous owner notes\n');
const handlers = new Map();
const commands = new Map();
const notices = [];
let calls = 0;
let sessionId = 'current-session';
const headings = ['Mission context', 'What shipped this session', 'What is mid-flight', 'What was tried and rejected', 'Open decisions', 'Build and test state', 'Files of interest', 'Continue here'];
const body = headings.map(h => '## ' + h + '\nObserved session evidence.').join('\n\n');
const pi = {
  on: (name, handler) => handlers.set(name, handler),
  registerCommand: (name, handler) => commands.set(name, handler),
  exec: async (command, args, options) => {
    try { const r = await exec(command, args, options); return { ...r, code: 0, killed: false }; }
    catch (e) { return { stdout: '', code: 1, killed: false }; }
  }
};
const ctx = {
  cwd: process.cwd() + '/nested', hasUI: true,
  ui: { notify: message => notices.push(message) }, model: { id: 'fixture' },
  sessionManager: {
    getSessionId: () => sessionId,
    getBranch: () => [{id:'old', type:'message', message:{role:'assistant', content:[{type:'text',text:'cargo build passed; Ship change verified'}]}}, {id:'kept',type:'message',message:{role:'user',content:'continue'}}]
  },
  modelRegistry: {
    hasConfiguredAuth: () => true,
    complete: async (_model, input) => {
      calls++;
      assert.match(input.messages[0].content[0].text, /cargo build passed/);
      if (action === 'conflict') await fs.writeFile('HANDOFF.md', 'Concurrent owner edit\n');
      if (action === 'abort') controller.abort();
      if (action === 'malformed') return {stopReason:'stop',content:[{type:'text',text:'unusable JSON'}]};
      return {stopReason:'stop', content:[{type:'text',text:JSON.stringify({handoff:body,completedTasks:[
        {line:1,text:'- [ ] Ship change',evidence:'cargo build passed'},
        {line:2,text:'- [ ] Still pending',evidence:'invented success'},
        {line:2,text:'- [ ] Still pending',evidence:'- [ ] Still pending'}
      ]})}]};
    }
  }
};
checkpoint(pi);
let controller = new AbortController();
const event = () => ({reason:'threshold',signal:controller.signal,preparation:{tokensBefore:1000,settings:{keepRecentTokens:100},firstKeptEntryId:'kept'}});
const handler = handlers.get('session_before_compact');
assert.equal(await handler({...event(),reason:'manual'},ctx), undefined);
assert.equal(calls, 0);
assert.equal(await handler(event(),ctx), undefined);
assert.equal(calls, 1);
const handoff = await fs.readFile('HANDOFF.md','utf8');
assert.match(handoff,/Previous owner notes/);
assert.match(handoff,/<details>/);
assert.match(handoff,/# Handoff —/);
assert.match(handoff,/Resume in Pi/);
assert.equal(await fs.readFile('implementation_plan.md','utf8'),'- [x] Ship change\n- [ ] Still pending\n');
action = 'malformed';
await handler(event(),ctx);
assert.equal(await fs.readFile('HANDOFF.md','utf8'),handoff);
await commands.get('checkpoint-auto').handler('off',ctx);
await handler(event(),ctx);
assert.equal(calls, 2);
await commands.get('checkpoint-auto').handler('on',ctx);
action = 'normal';
sessionId = 'next-session';
const stale = new Date(Date.now() - 31 * 86400000);
await fs.utimes('HANDOFF.md',stale,stale);
await handler(event(),ctx);
const archives = (await fs.readdir('.')).filter(name => /^HANDOFF\.\d{4}-\d{2}-\d{2}\.md$/.test(name));
assert.equal(archives.length,1);
assert.match(await fs.readFile(archives[0],'utf8'),/Previous owner notes/);
if (process.platform !== 'win32') assert.equal((await fs.stat(archives[0])).mode & 0o077,0);
action = 'conflict';
await handler(event(),ctx);
assert.equal(await fs.readFile('HANDOFF.md','utf8'),'Concurrent owner edit\n');
action = 'staging-conflict';
await handler(event(),ctx);
assert.equal(await fs.readFile('HANDOFF.md','utf8'),'Owner edit during staging\n');
action = 'abort';
await handler(event(),ctx);
assert.equal(await fs.readFile('HANDOFF.md','utf8'),'Owner edit during staging\n');
assert.equal(await fs.stat('.lgtm-checkpoint.lock').catch(() => null),null);
console.log('checkpoint lifecycle checks passed');
"##,
    );
    let output = Command::new("node")
        .arg("exercise.mjs")
        .current_dir(repo.path())
        .output()
        .expect("Node executes");
    assert!(output.status.success(), "{output:?}");
}
