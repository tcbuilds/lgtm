# Remove automatic LGTM vetoes

## Approved direction

LGTM must help development, not control permission to develop.
The owner approved the four removal steps below. Do not add a permissive mode,
a new approval system, or another waiver layer.

Keep checks available through an explicit `lgtm check` command and optional CI.
A requested check may report failure and return a nonzero exit code. Automatic
agent hooks must not deny a tool, reject a commit, or prevent task completion.

This work starts from `main` at `00eaff6`. The repository already has unrelated
local changes. Preserve them, including `HANDOFF.md`, local rules, and untracked
agent configuration.

## 1. Remove automatic tool and commit denial

- [x] Remove command bans, edit-path denial, and commit interception from
  `src/hooks/pre_tool_use/`.
- [x] Keep useful guidance and change tracking only when they cannot deny work.
- [x] Remove commit-syntax restrictions from the automatic path. Normal Git
  commands must not need a special shell form to satisfy LGTM.

Check: existing hook integration tests must show that matching prohibited
commands, protected paths, compound commits, missing policy, and baseline errors
do not cause an LGTM permission denial. Do not execute destructive commands in
these checks; send hook requests and inspect the responses.

## 2. Remove automatic completion vetoes

- [x] Remove automatic `BlockStop` decisions from `src/hooks/stop.rs`.
- [x] Separate automatic hook reporting from explicit `lgtm check` exit results.
- [x] Do not run repository test, build, lint, or coverage commands merely because
  an agent finishes a turn. Run them only when the user or CI requests a check.

Check: automatic Stop and subagent-stop requests do not block completion or run
configured repository commands. Explicit checks still run selected commands,
report actual results, and return failure when a blocking check fails.

## 3. Remove Pi commit authorization machinery

- [x] Remove commit-specific runtime attestation, approval, and notice
  revalidation from the generated Pi extension.
- [x] Remove commit-specific checks for version hashes, session identity,
  cancellation support, and tool contracts when they act as permission gates.
- [x] Keep bounded tool execution, cancellation, output privacy, and useful
  advisory notices where they still serve a live feature.

Check: generated Pi hooks do not return `block: true` for development operations,
including commits, cancelled LGTM checks, stale runtime data, or heuristic secret
findings. A failure in LGTM must be visible without vetoing the underlying tool.

## 4. Delete obsolete gate support

- [x] Delete unreachable commit parsers, approval transactions, gate-only
  attestation helpers, and gate-only waiver plumbing after callers are removed.
- [x] Stop generating native Codex `forbidden` command rules. On normal managed
  refresh, retire only rules identified as LGTM-generated. Preserve user-owned
  Codex rules and the host's own permission settings.
- [x] Update existing integration tests, fixtures, and active documentation to
  describe the new behavior. Do not add unit tests.
- [x] Remove obsolete support rather than leave dormant code or compatibility
  switches that can restore automatic vetoes.

Check: the build and strict lint pass without dead gate code. Active docs do not
promise automatic tool, commit, or completion blocking. Explicit checking and CI
remain usable.

## Preserve

- Installer protection against overwriting unknown or user-modified files.
- Host-agent permissions and sandbox rules. LGTM does not replace or bypass them.
- Timeouts, bounded work, process cleanup, and honest check results.
- Secret redaction and privacy controls for output and optional Jev requests.
- Unrelated application controls, including any trading bot's own risk controls.

## Validation and publication

After each slice, inspect the exact diff and run focused behavior checks. Before
calling a slice complete, run formatting, relevant integration checks, a build,
and strict lint. Run independent review of the scoped change and resolve supported
regressions. Run the full affected suite after integration.

Do not claim that installed hooks changed merely because source code changed.
Installing or refreshing hooks, publishing a release, and changing another
repository are separate actions.

Rollback: revert the completed removal commits and regenerate installed hooks
only if the owner explicitly requests restoration of the old behavior.

## Progress

- Steps 1–3 are implemented in source: automatic tool, commit, and completion
  vetoes are removed. Automatic completion never starts configured checks.
- Explicit `lgtm check` still runs requested commands and returns exit 2 for
  actual error-level failures. Protected-rule configuration errors return
  nonzero. Unavailable checks remain visibly unverified.
- Shared adapters cannot express denial, approval, or completion-veto outcomes.
  Post-tool findings use nonblocking context.
- Step 4 code and integration migrations are implemented. The guarded-commit
  wrapper, staged-commit scanner, command parser, and approval interfaces are
  deleted. Old commit-reuse scenarios were removed with their feature.
- Existing explicit command, coverage, containment, redaction, and process
  cleanup checks remain. Shell uncertainty and unrelated-file audits still have
  coverage without using automatic completion as a verification trigger.
- Codex init no longer creates command rules. Init and managed refresh retire
  only LGTM-header-owned rules and preserve user rules and host settings.
- Optional Jev tools still need their bounded runtime identity and privacy
  helpers. A shared helper removed with commit code was restored after a real
  regression was found; all 12 Jev integration tests pass.
- Final parent validation: `cargo test --locked --all-targets --all-features
  --no-fail-fast -- --test-threads=4` passed with isolated HOME. This includes
  607 library tests and every integration target. No unit tests were added.
- Active guides and a new ADR describe observer hooks and explicit checks.
  Superseded ADR status fields point to that decision. Local Markdown links and
  whitespace checks passed; no Markdown LSP server is configured.
- Formatting, strict all-target/all-feature Clippy, build, CLI help, and embedded
  policy validation passed. Clippy found three redundant test struct updates;
  those were removed and the three affected existing tests passed again.
- The existing Jev/checkpoint JS coverage command passed at 97.82% lines and
  87.67% branches. Its 80% thresholds were not changed. The commit-observer
  fixture also proves that its request reached Rust tracking before asserting
  that no scanner, classifier, approval, or Git command ran.
- Sol 6.1 high and Astra high independently completed the full 65-file review.
  Both reported no remaining Critical, High, or Medium production regression.
  The initial review found an unsafe Codex retirement read; the bounded reader
  was restored and FIFO/oversized-file integration checks now pass.
- Astra's final Low finding was stale advice to retry automatic Stop. Three
  messages now direct users to explicit checks, with command/coverage/workspace
  assertions. Focused Astra-high verification confirmed the repair, and the
  complete all-feature suite passed again afterward.
- Retained reviewers were unavailable, so the final and focused checks used
  fresh same-model fallback runs. No provider or effort substitution occurred.
- Accepted pre-existing test-proof limits: a timeout may occur before its child
  readiness marker; some notice callbacks are not fully awaited; the hook-safety
  helper does not bound every possible pipe-stall case. No production cleanup
  change or failure was found. These are not claims of complete timeout,
  live-host, UI, or provider verification.
- After explicit owner approval, local activation updated only the installed
  binary and the recognized project/global Pi LGTM extensions. Canonical hashes,
  installed bytes, and Node syntax checks passed. Backups and a rollback receipt
  are under `$HOME/.local/state/lgtm/activation-backups/`. Thirteen protected
  settings, rules, and router paths were verified unchanged.
- Installed CLI smoke checks confirm that commit observation emits no permission
  response and automatic completion with `check: true` runs no verification.
  Pi requires `/reload` to replace its already-loaded extension. On-disk updates
  alone do not prove that the running session has reloaded.
- Generated-hook editor diagnostics are not clean: project/global TypeScript
  checks report missing Node typings and type annotations (497/499 diagnostics),
  and Biome reports four complexity findings in each. Node syntax and runtime
  fixtures passed. No checks were disabled or configuration changed to hide
  these diagnostics; this work does not claim a strict generated-TypeScript pass.
- The legacy installed gate blocked the first local commit before activation.
  After activation, the owner requested a normal commit retry. No bypass,
  release, version bump, push, or history rewrite was used.
  Unrelated local changes remain untouched.
