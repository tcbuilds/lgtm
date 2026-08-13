# Implementation Plan: Issue #40 — Make coverage thresholds enforce the Stop gate

## Issue

- Issue: #40, `[Improvement] Make coverage thresholds enforce the Stop gate`.
- Objective: make measured full-tier coverage threshold failures enter the same enforcement decision as required repository commands, so Stop summaries, evidence, hook responses, and CLI exit status agree.
- Source: GitHub issue acceptance criteria and reproduction; current code trace through `src/checks/commands/runner.rs::run_coverage`, `src/hooks/stop.rs::run_inner`, and `src/main.rs::run_check`.

## Current behavior

- V2 config loading already produces `CoverageCommand` values with bounded argv/cwd/timeout and optional line/branch thresholds.
- V2 loading flattens coverage commands, and the new projection currently executes/projects all configured coverage even when `--workspace` selects one workspace.
- `run_coverage` executes configured coverage commands only for a full-tier Stop/check path and returns `CoverageEvidence` with `passed`, `failed`, `unverified`, or `not_applicable` status.
- `run_inner` passes coverage only to `append_task_evidence`; it extends `results` with ordinary command results but never adds a coverage `EnforcementResult`.
- Stop blocking and summary counts inspect only failed/error-severity `EnforcementResult` values. Therefore below-threshold evidence can coexist with `failed=0`, a successful Stop, and exit status 0.
- Missing tools, non-zero/timeout execution, and output with no parseable metrics are already classified as `unverified` by the coverage runner; the fix must preserve that distinction.

## Desired behavior

- Each configured full-tier coverage outcome is represented in the enforcement result stream with the matching status; the existing no-coverage `not_applicable` sentinel remains evidence-only.
- No workspace argument executes/projects all configured coverage; `Some(id)` executes/projects only coverage matching `workspace_id == id` and never emits evidence/results for unselected coverage.
- A measured line or branch value below its configured threshold becomes a failed `required-repository-commands` result with default error severity, so full-tier Stop and `lgtm check --tier full` block/non-zero as existing command failures do.
- Passing coverage contributes a passed result; missing tools and unparsable output contribute unverified results and do not block.
- The existing serialized coverage evidence remains present and reports the same status as the corresponding configured-command enforcement result.
- Existing profile severity resolution, explicit overrides, waivers, bounded command execution, and fast-tier behavior remain unchanged.

## Constraints

- Change only the coverage-to-enforcement path required by issue #40; no adjacent refactor or new dependency.
- Select coverage by `workspace_id` before execution/projection; preserve the existing V2 argv/cwd/timeout trust boundary and restricted command environment from ADR-0009.
- Preserve `CoverageEvidence` fields and the `schemas/evidence.schema.json` coverage contract; no migration or new JSON fields are needed.
- Use the existing `required-repository-commands` rule ID and policy severity flow so profile/override/waiver handling remains consistent with ordinary repository gates.
- Convert coverage results before `apply_resolved_results`, `apply_results`, `waivers`, evidence serialization, and Stop failure filtering.
- Keep coverage execution limited to the existing full-tier path. Fast Stop must not start running coverage.
- Add deterministic regression coverage for the observable bug. Do not weaken or bypass repository/harness checks.
- `context/resources/` is absent in this worktree; no project resource notes were available.

## Affected areas

- `src/checks/commands/runner.rs::run_coverage` — retain threshold classification and evidence generation; prevent one metric from borrowing another metric's value while preserving the existing execution and evidence contract.
- `src/checks/commands/result.rs` / `src/checks/commands/mod.rs` — add the smallest result-construction/re-export seam needed to turn coverage statuses into `EnforcementResult` values under `required-repository-commands`.
- `src/hooks/stop.rs::run_inner` — apply the existing `--workspace` selection before full-tier coverage execution/projection, then extend the main `results` collection with coverage results before policy resolution and failure selection; continue passing coverage evidence to `append_task_evidence`.
- `src/checks/commands/tests.rs` — retain existing passing/no-config coverage tests and add boundary cases for below-line, below-branch, and unparsable output plus status projection as appropriate.
- `tests/commands.rs` — add end-to-end V2-config coverage scenarios covering passing, below-threshold, and unparsable output; exercise full-tier Stop and the `lgtm check --tier full` CLI path.
- Existing contracts to verify, not redesign: `src/checks/mod.rs::EnforcementResult`, `policy/profiles/*` handling of `required-repository-commands`, `schemas/evidence.schema.json`, and `.github/workflows/lgtm.yml`’s full check command.

## Implementation steps

### M1 — Full-tier coverage enforcement

- [x] [High] Project coverage status into the existing enforcement-result contract.
  - What: map each configured coverage evidence status to the matching `Status` (`passed`, `failed`, or `unverified`) and construct a stable, sanitized `required-repository-commands` result; keep the no-coverage `not_applicable` sentinel non-enforcing, and only measured threshold misses may map to `Failed`.
  - Where: `src/checks/commands/result.rs` / `src/checks/commands/mod.rs`, with only the minimal `runner.rs` adjustment required by the chosen return seam.
  - Why: coverage currently has evidence-only status, so Stop has no failure object to inspect.
  - Dependencies: existing `CoverageEvidence` classification and `EnforcementResult`/`result` helper; no schema or config change.

- [x] [High] Feed projected coverage results through full-tier Stop enforcement.
  - What: extend `results` from `src/hooks/stop.rs::run_inner` with the coverage results immediately after full-tier coverage execution and before profile severity resolution, overrides, waivers, evidence append, and failure filtering.
  - Where: `src/hooks/stop.rs::run_inner`; leave `append_task_evidence`’s separate coverage evidence field intact.
  - Why: the same result list drives policy adjustments, persisted rule counts, summary text, hook block response, and the exit code returned through `src/main.rs::run_check`.
  - Dependencies: coverage projection from the preceding step; existing full-tier selection and `required-repository-commands` policy.

- [x] [High] Preserve workspace-scoped coverage selection.
  - What: select coverage before execution/projection; without `--workspace`, include all configured coverage, and with `--workspace <id>`, include only matching `workspace_id` coverage with no evidence/result for unselected coverage.
  - Where: `src/hooks/stop.rs::run_inner` and its `select_coverage_commands` boundary, with regression coverage in `tests/commands.rs`.
  - Why: the flattened V2 coverage list currently allows selected-workspace runs to execute/project coverage from other workspaces.
  - Dependencies: existing `--workspace` selection and coverage projection; no new API, config field, schema field, dependency, or policy mechanism.

- [x] [High] Add regression tests for aligned coverage outcomes.
  - What: extend command-runner tests for above-threshold pass, line-threshold failure, branch-threshold failure, and no-parseable-metrics unverified behavior; add integration fixtures with a V2 coverage command that assert full Stop and `lgtm check --tier full` block/non-zero for a measured miss, while pass remains successful and unparsable output remains unverified/non-blocking. Assert both `results`/summary behavior and serialized `coverage` evidence.
  - Where: `src/checks/commands/tests.rs` and `tests/commands.rs`, following existing executable-script and `TempRepo` patterns.
  - Why: the issue’s false-success path is only proven fixed when threshold failure reaches both hook and CLI decisions, and the unverified guard prevents accidental hard failures for optional-tool degradation.
  - Dependencies: M1 enforcement wiring; no live tools, network, sleeps, or fabricated coverage data.

### M2 — Verification handoff

- [ ] [High] Run repository-required validation and inspect the final scope.
  - What: run the targeted coverage tests, then `cargo fmt --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo test --locked --all-targets --all-features`, `cargo build --locked`, `cargo run --locked -- --help`, `cargo run --locked -- compile --validate`, `shellcheck scripts/install.sh scripts/test-install.sh`, `scripts/test-install.sh`, and the full `lgtm check --tier full`/CI-equivalent check; inspect `git diff` and confirm no unrelated files or `.codegraph` data are included.
  - Where: repository root; no additional configuration or workflow file.
  - Why: these are the repository’s documented gates, and issue #40 changes the gate’s enforcement decision.
  - Dependencies: all implementation and regression tests complete.
  - Evidence: the integrated run observed exit 0 for formatting, Clippy, locked all-target/all-feature tests, build, CLI help, compile validation, ShellCheck, and installer tests. The full-tier policy check exited 2 with the same five baseline Semgrep findings as untouched baseline `add64cf` (2 `external-call-timeout`, 1 `public-input-validation`, 1 `sql-parameterization`, 1 `bounded-retries-loops`, 1 `destructive-operation-safeguards`); baseline equivalence is context, not a passing gate.

## Testing strategy

- Unit-level: table-driven coverage cases pin the threshold boundary and both dimensions; assert evidence status and projected `EnforcementResult.status` rather than only command execution.
- Integration-level: use deterministic executable scripts in `TempRepo` with V2 config and a full-tier payload. Assert:
  - passing metrics produce a successful Stop, `failed=0`, passed coverage evidence, and a passed result;
  - line or branch metrics below threshold produce a Stop block/exit 2 and a non-zero `lgtm check --tier full`, with failed result and failed coverage evidence;
  - workspace selection executes/projects all configured coverage without `--workspace`, and only matching `workspace_id` coverage with `--workspace <id>`; unselected coverage emits no evidence or result;
  - output without parseable metrics remains unverified, appears in the summary/evidence, and does not block;
  - existing no-coverage behavior still records `not_applicable` evidence and does not block;
  - evidence remains valid against `schemas/evidence.schema.json` through the existing end-to-end coverage.
- Repository verification: execute all existing Rust, installer, format, lint, build, compile-validation, and full-policy commands listed in M2; report only observed exit-0 results.

## Risks

- Repositories with thresholds intended only as informational will begin enforcing them under the default error policy; this is the stated issue tradeoff and remains configurable through existing policy severity controls.
- Adding one result per configured coverage command can change rule counts for configured coverage. Prevent duplicate or synthetic no-config results and assert counts/status alignment in integration tests.
- Failing to filter flattened coverage before execution/projection can cause cross-workspace false blocking when a selected workspace is affected by another workspace’s threshold miss; keep workspace selection explicit in regression coverage.
- Applying projection after overrides/waivers would bypass existing policy controls; ordering before those operations is required.
- Mapping missing/unparsable coverage to `Failed` would recreate the wrong hard-stop behavior for optional tools; explicit unverified cases must guard this.
- Including raw workspace/scope/config text in an agent-facing message could echo control characters or untrusted content; use existing sanitization or a fixed message shape.
- Coverage process execution, timeout, and shell-free trust behavior are existing risk surfaces; changing them is outside this fix and would expand regression scope.

## Non-goals

- Do not redesign metric parsing or change the meaning of existing coverage statuses beyond making them enforceable.
- Do not change V2 config validation, threshold fields, command timeouts, environment allowlisting, or fast-tier execution.
- Do not add a new rule ID, new policy profile, new waiver/override mechanism, evidence fields, schema migration, dependency, or CI workflow.
- Do not make missing tools or unparsable output hard failures.
- Do not modify unrelated check modules, reports, discovery, release files, or `.codegraph/`.

## Completion criteria

- [x] A measured line or branch threshold miss creates a failed error-severity enforcement result under `required-repository-commands` and blocks full Stop by default.
- [x] `lgtm check --tier full` exits non-zero for the same measured miss.
- [x] Full-tier Stop response, summary counts, enforcement results, and coverage evidence agree for pass, fail, and unverified cases.
- [x] Missing tools and unparsable output remain unverified and non-blocking.
- [x] Existing evidence schema and policy override/waiver behavior remain valid.
- [x] Existing `--workspace` selection limits full-tier coverage execution, evidence, and enforcement results to matching `workspace_id` values; no selector retains repository-wide coverage behavior.
- [ ] All M2 validation commands were executed; all other listed validations exited 0, while the full-tier policy check exited 2 on the same five baseline Semgrep findings as untouched baseline `add64cf` (baseline equivalence is context, not a passing gate); final diff contains only intended implementation/test/plan files for the implementation slice.

## Deferred / Out of scope (this iteration)

- Coverage parser redesign and richer threshold provenance fields — not required to close the evidence-to-gate gap.
- New informational-vs-enforcing coverage policy semantics — existing rule severity controls cover the stated tradeoff.
- CI/workflow redesign, migration tooling, new dependencies, and unrelated policy/reporting changes — no issue acceptance criterion requires them.
