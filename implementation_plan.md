# Implementation Plan: Issue #40 — Make coverage thresholds enforce the Stop gate

## Issue

- **Issue:** GitHub #40, `[Improvement] Make coverage thresholds enforce the Stop gate` (`priority:p1`).
- **Candidate baseline before test hardening:** branch `issue-40-coverage-thresholds`, HEAD `6f63fa57025a8260b80edbaa0a0b598adeddff97`, against `origin/main` (`5bfead7d3acf7e49f2a3798289b970eb5626aa09` when inspected). The parent records the final candidate OID in the delivery receipt.
- **Problem contract:** a valid V2 coverage command reporting 50% against an 80% threshold produced coverage evidence with `status: "failed"`, but `lgtm check --tier full` reported `failed=0` and exited 0 because coverage never entered the `EnforcementResult` failure stream.
- **Accepted outcome:** measured line or branch threshold misses must fail enforcement, full Stop must return its documented block response, `lgtm check --tier full` must exit non-zero, summary/result/evidence statuses must agree, and missing or unparsable coverage must remain `unverified` rather than fail.
- **Post-implementation review contract:** the issue comments additionally require coverage to honor `--workspace` before execution/evidence/projection and require `run_coverage` to remain within the repository function-size standard.
- **Evidence consulted:** complete issue body and owner comments preserved in the local GitHub session evidence; `AGENTS.md`, `CLAUDE.md`, ADR-0003/0007/0009/0011, current source and callers, policy/profile/override/waiver paths, evidence schema, workflow, changed tests, branch refs/reflogs, and recorded validation output.

## Current behavior

### `origin/main` behavior described by the issue

- `src/checks/commands/runner.rs::run_coverage` executed full-tier coverage and returned only `Vec<CoverageEvidence>`.
- `src/hooks/stop.rs::run_inner` serialized that separate coverage vector but derived summaries and blocking decisions only from `EnforcementResult` values.
- Consequently, measured coverage could be `failed` in evidence while Stop and `lgtm check --tier full` still reported no failures and exited successfully.
- Missing tools, timeouts/non-zero coverage processes, and unparseable output were already classified as `unverified`; that fail-open-for-availability distinction is required by ADR-0003 and ADR-0009.

### Review-candidate behavior at HEAD

- `src/checks/commands/result.rs::coverage_results` now projects each configured coverage evidence record into the existing `required-repository-commands` result contract:
  - `passed` → `Status::Passed`;
  - `failed` → `Status::Failed`;
  - `unverified` or an unknown status → `Status::Unverified`;
  - the synthetic no-coverage `not_applicable` record remains evidence-only.
- `src/hooks/stop.rs::run_inner` adds projected coverage results to `results` before profile severity resolution, overrides, waivers, evidence counts, and the error-severity failure filter. `src/main.rs::run_check` delegates directly to this Stop path, so the same result drives both hook and CLI exit behavior.
- Full-tier coverage is selected with `select_coverage_commands` before execution. No `--workspace` selector retains repository-wide behavior; a selector retains only exact matching `workspace_id` records, so unselected coverage produces neither evidence nor enforcement results.
- `src/checks/commands/runner.rs` separates execution, parsing, and status classification. A measured below-threshold metric wins over a missing companion metric; a configured metric that cannot be parsed remains unverified; an unconfigured optional metric is not required.
- Coverage remains full-tier only. Fast/targeted paths continue to emit the no-coverage `not_applicable` evidence sentinel and no coverage enforcement result.
- Unit and integration tests now cover passing, below-line, below-branch, partial/unparseable, no-config, Stop block, CLI non-zero, active-Stop summary, and selected-workspace behavior.

## Desired behavior

- Every configured **full-tier, selected-workspace** coverage execution has one aligned evidence status and one aligned enforcement result, except the no-coverage sentinel, which remains evidence-only.
- A successfully measured line or branch value below its configured threshold produces a failed `required-repository-commands` result. Under the default error policy this increments failed counts, blocks normal Stop with exit 2, and makes `lgtm check --tier full` non-zero.
- A metric exactly equal to its threshold passes.
- A passing configured metric remains passing when the other metric has no configured threshold.
- A configured metric that is absent/unparseable, a missing executable, timeout, wait failure, or non-zero coverage process remains `unverified`, visible, and non-blocking; LGTM must not guess success.
- Stop response, summary counts, serialized `results`, and serialized `coverage` must describe the same configured-command outcome.
- `--workspace <id>` must prevent other workspaces' coverage tools from executing or affecting evidence/results; no selector must continue to evaluate all configured coverage.
- Existing hook protocols, CLI arguments, evidence fields/schema, profile semantics, override/waiver ordering, V1 compatibility, and the ADR-0007/0009 command trust boundary must remain unchanged.

## Constraints

### Architecture and compatibility

- ADR-0007 requires workspace identity, repo-relative `cwd`, structured argv, bounded timeout, and no shell-string interpretation. Coverage must not bypass those boundaries.
- ADR-0009 requires coverage to use validated V2 argv, a restricted environment, regular/owned configuration, bounded subprocess execution, and honest `unverified` degradation.
- ADR-0011 makes full coverage a `lgtm check --tier full`/CI concern while normal Stop defaults to fast commands; this issue must not make fast Stop run full coverage.
- ADR-0003 requires unresolved error-severity MUST failures to block while missing-tool `unverified` outcomes remain non-blocking.
- Preserve `CoverageEvidence` and `schemas/evidence.schema.json`; do not add fields or require evidence migration.
- Preserve the existing `required-repository-commands` registry identity, default error severity, profile resolution, explicit override processing, and active-waiver processing. The rule is declared `overridable: false`; embedded profile behavior and existing waiver validation remain authoritative.
- V1 configurations have no structured coverage collection and must retain their current behavior.
- Do not change CLI flags, adapter response shapes, report/stats formats, policy profiles, workflow configuration, or dependencies.

### Security and reliability

- Execute argv directly through `std::process::Command`; do not introduce a shell or interpolate untrusted workspace/config text into executable command strings.
- Keep `PATH`, `HOME`, and `CI` as the only inherited environment entries used by the current command runner.
- Filter by exact `workspace_id` before process creation, not after evidence generation, to prevent cross-workspace execution and false blocks.
- Keep agent-facing coverage messages fixed/sanitized; do not echo raw tool output, config content, control characters, or paths into the Stop reason.
- Retain process timeout/process-group handling supplied by the existing runner. Aggregate command-count/deadline work is tracked separately by issue #42 and is not part of this branch.
- Do not weaken repository checks or treat a failed validation as passed merely because the same finding exists on the baseline.

### Scope and repository policy

- Change only the coverage-to-enforcement path, its workspace selection, the smallest classification refactor needed for correctness/function-size compliance, and deterministic regression tests.
- Do not modify production code or tests during this planning refresh; this file is the sole permitted planning artifact.
- `context/resources/` is absent, so no additional resource-note contract was available.

## Affected areas

### Changed in the candidate relative to `origin/main`

- `src/checks/commands/mod.rs` — crate-visible re-export of coverage result projection.
- `src/checks/commands/result.rs` — `CoverageEvidence` to `EnforcementResult` projection under `required-repository-commands`.
- `src/checks/commands/runner.rs` — coverage execution/classification split, threshold semantics, and metric-boundary parsing.
- `src/hooks/stop.rs` — full-tier workspace selection and insertion of coverage results into the main policy/result stream.
- `src/checks/commands/tests.rs` — unit regressions for projection and line/branch/partial/boundary/no-config semantics.
- `tests/commands.rs` — end-to-end Stop, CLI, evidence/count, active-Stop, and workspace-selection regressions.
- `implementation_plan.md` — local implementation/review roadmap and validation status.

### Production callers and consumers to verify

- `src/main.rs::run_check` — constructs a check payload and returns `stop::run`'s exit code.
- `src/hooks/stop.rs::run_repository_commands` — parallel structured-command selection behavior that coverage selection must match.
- `src/hooks/stop.rs::append_task_evidence` and `count_results` — serialize coverage separately while counting projected results.
- `src/hooks/stop.rs::write_summary` / `write_block_decision` — expose aligned result counts and block reasons.
- `src/policy/profile.rs::apply_resolved_results`, `src/policy/overrides.rs::apply_results`, and `src/policy/waivers.rs::apply` — must see coverage results before policy transformations.
- `src/checks/mod.rs::{Status, EnforcementResult::is_failure}` — normalized status and failure semantics.
- `templates/claude-rules/CLAUDE.md` / embedded rule files — `required-repository-commands` is an error-severity MUST, command-enforced, non-overridable rule.
- `schemas/evidence.schema.json` — existing coverage status/metric and normalized-result contracts.
- `.github/workflows/lgtm.yml` — invokes `cargo run --locked -- check --tier full` and enforces unresolved MUST failures.

## Ordered implementation and review steps

### 1. Project configured coverage into normalized enforcement results — implemented

- **What:** Map configured coverage `passed`, `failed`, and `unverified` statuses to one existing `EnforcementResult`; omit only the synthetic `not_applicable` record; use a fixed coverage label/message and the existing command remediation.
- **Where:** `src/checks/commands/result.rs`, re-exported crate-locally by `src/checks/commands/mod.rs`.
- **Why:** Stop, summary counts, evidence result counts, hook responses, and CLI status consume normalized results rather than `CoverageEvidence` directly.
- **Dependencies:** Existing `CoverageEvidence`, `Status`, `EnforcementResult`, `required-repository-commands`, and the result sanitizer.

### 2. Insert coverage before all policy and Stop decisions — implemented

- **What:** Extend the main `results` vector with coverage projections after full-tier execution but before profile resolution, overrides, waivers, evidence append/counting, and failure filtering.
- **Where:** `src/hooks/stop.rs::run_inner`.
- **Why:** One ordered result stream must govern policy transformation, persistence, summary text, block response, and the exit propagated by `src/main.rs::run_check`.
- **Dependencies:** Step 1; existing Stop result pipeline and adapter contract.

### 3. Preserve workspace isolation and tier compatibility — implemented

- **What:** Filter flattened V2 coverage commands by exact selected `workspace_id` before calling `run_coverage`; retain all coverage without a selector; keep coverage execution restricted to explicit full tier.
- **Where:** `src/hooks/stop.rs::select_coverage_commands` and its call in `run_inner`.
- **Why:** Running an unselected workspace's coverage can execute unintended code and falsely block the selected workspace, violating ADR-0007/0011.
- **Dependencies:** V2 loader-provided `workspace_id`; Step 2; existing CLI payload selection.

### 4. Make threshold classification explicit without changing the evidence contract — implemented

- **What:** Separate execution from pure status classification; parse line and branch values only from their own labeled region; require every configured metric for a pass; preserve any measured below-threshold failure even if another configured metric is absent; allow absent unconfigured metrics.
- **Where:** `src/checks/commands/runner.rs::{run_coverage, classify_coverage, classify_coverage_status, parse_metric}`.
- **Why:** Enforcement makes parser mistakes blocking, so cross-metric borrowing and partial-output ambiguity must not create false passes or hide measured failures. Extraction also keeps `run_coverage` below the repository function-size limit.
- **Dependencies:** Existing validated thresholds and bounded subprocess runner; no parser format or schema redesign.

### 5. Prove observable Stop/CLI/evidence behavior — implemented

- **What:** Keep deterministic executable fixtures for pass, threshold miss, unparseable output, active Stop recursion protection, and selected workspace; assert exit/decision, summary counts, projected result status, and coverage evidence status. Keep unit cases for exact boundary, line-only and branch-only thresholds, missing configured metrics, optional metrics, and `not_applicable`.
- **Where:** `src/checks/commands/tests.rs` and `tests/commands.rs`.
- **Why:** The original defect was an end-to-end false success, not merely a parser defect; both Stop and CLI decision paths require proof.
- **Dependencies:** Steps 1–4 and `tests/common/TempRepo`.
- **Added hardening:** `missing_coverage_executable_projects_to_unverified_without_failure` directly proves the unit-level missing-tool path, and `missing_coverage_executable_is_unverified_and_does_not_fail_stop` proves full Stop remains successful while recording visible unverified coverage.

### 6. Reconcile validation and review disposition — pending

- **What:** Re-run focused coverage tests and all repository-required checks on the final reviewed commit. Record exact exit codes. Either make the full policy check pass or obtain an explicit reviewer disposition that the unchanged baseline findings do not block this issue; never mark a failing command as passed. Confirm diff scope and that no `.codegraph/`, runtime `.pi/`, generated evidence, or unrelated files are included.
- **Where:** Repository root; final diff against `origin/main`.
- **Why:** Issue #40 changes a hard gate. A candidate is not fully complete while its documented full-policy command exits 2, even when comparison shows the same baseline findings.
- **Dependencies:** Steps 1–5, final branch identity, and reviewer/process decision on baseline findings.

## Testing strategy

### Focused unit coverage

- Run `cargo test --locked --lib checks::commands::tests`.
- Assert exact-threshold pass, line-only miss, branch-only miss, optional unconfigured metric pass, missing configured metric unverified, measured miss plus missing companion remains failed, unparseable output unverified, projection status/severity/message, and no-config evidence-only behavior.
- Add the residual missing-executable case and assert both evidence and projected result are `unverified` and non-failing.

### Integration coverage

- Run `cargo test --locked --test commands`.
- For full Stop:
  - pass → exit 0, `failed=0`, passed coverage evidence, passed projected result;
  - measured miss → exit 2 and documented JSON block response, failed evidence/result, failed count ≥ 1;
  - unparseable/missing tool → exit 0, visible unverified result/evidence, failed count 0;
  - `stop_hook_active=true` → exit 0 summary to avoid recursive blocking while retaining the failed count/evidence.
- For `lgtm check --tier full`, assert measured threshold miss is non-zero and carries the same rule/reason.
- For `--workspace selected`, assert only selected coverage executes/serializes/projects and an unselected failing workspace cannot block it. Retain a no-selector case or source assertion proving repository-wide selection remains unchanged.
- Validate a coverage-containing evidence record against `schemas/evidence.schema.json`; the repository has general evidence-schema tests in `tests/m1_e2e.rs` and `tests/codex_e2e.rs`, but the new coverage integration currently does not explicitly invoke the schema validator. This is a **low residual coverage gap**.

### Repository gates

Run from the exact issue worktree and report actual outcomes:

1. `cargo fmt --check`
2. `cargo clippy --locked --all-targets --all-features -- -D warnings`
3. `cargo test --locked --all-targets --all-features`
4. `cargo build --locked`
5. `cargo run --locked -- --help`
6. `cargo run --locked -- compile --validate`
7. `shellcheck scripts/install.sh scripts/test-install.sh`
8. `scripts/test-install.sh`
9. `cargo run --locked -- check --tier full`
10. Diff/status checks confirming only intended files, no whitespace errors, no staged files before handoff, and no runtime/generated artifacts in the candidate.

### Recorded validation status for HEAD

- This bounded test-hardening slice passes `cargo fmt --check`, the focused missing-executable unit test, and the focused missing-executable Stop integration test. The complete changed-test suite and final validation matrix remain pending after this slice.
- Exit 0 was recorded for Clippy, 564 locked all-target/all-feature tests across 27 suites, locked build, ShellCheck, installer tests, CLI help, and compile validation (71 rules).
- The issue owner handoff also records exit 0 for formatting; focused coverage tests and a mutation-style selector reversion were exercised, with the reversion causing the workspace regression to fail as expected (exit 101).
- `cargo run --locked -- check --tier full` exited **2**, reporting five unchanged baseline rule classes/six findings: `external-call-timeout` (2), `public-input-validation` (1), `sql-parameterization` (1), `bounded-retries-loops` (1), and `destructive-operation-safeguards` (1).
- Baseline equivalence is useful review evidence but is not an exit-0 validation. Step 6 and the final completion criterion remain open.

## Risks

- **Behavior change (intended):** repositories that treated configured thresholds as informational will now block under the default error policy. They must adjust thresholds or use an allowed existing profile/policy path; this branch does not add a new informational mode.
- **Cross-workspace execution/blocking:** filtering after execution would still run unselected tools and could block the wrong workspace. The filter must remain before `run_coverage`.
- **False failure from partial output:** a configured missing metric must be unverified unless another measured configured metric is already below threshold; tests must retain this precedence.
- **False pass from parser confusion:** similarly formatted line/branch text can cause one metric to borrow another. Metric-region parsing and dedicated unit cases guard this.
- **Policy bypass by ordering:** projection after profile/override/waiver application would skip established policy processing. Preserve current insertion order.
- **Evidence/result drift:** adding one result per configured coverage command changes counts. Do not add a result for the no-config sentinel or duplicate a configured outcome.
- **Prompt/control-character exposure:** coverage tools and config are repository-controlled. Keep raw output out of agent-facing messages and continue fixed/sanitized result text.
- **Schema range risk:** the simple parser can read out-of-range percentages that `schemas/evidence.schema.json` rejects. Parser hardening is outside issue #40, but a schema-validation regression would expose this existing residual risk.
- **Missing-tool behavior:** direct unit and Stop integration regressions now pin missing executable outcomes as visible, non-blocking `unverified`; other process-spawn/timeout/wait failures retain the existing bounded-runner behavior.
- **Aggregate runtime risk:** coverage commands remain sequential and the base branch lacks a shared aggregate deadline/count bound; issue #42 owns that separate trust-boundary improvement.
- **Baseline validation risk:** merging while the full policy check exits 2 requires an explicit process decision; silently relabeling it as a pass would violate repository evidence policy.

## Non-goals

- Redesigning coverage report formats, accepting arbitrary provider JSON, parsing decimals, or adding richer threshold provenance.
- Adding an informational-versus-enforcing coverage flag, a new rule ID, profile, override mechanism, or waiver mechanism.
- Changing V2 schema fields, validation/migration, command environment, timeout semantics, process-group handling, aggregate budgets, or command-count limits.
- Running coverage in fast or targeted Stop paths.
- Changing CLI arguments, adapter protocols, evidence schema fields, reports/stats, CI workflow, dependencies, or release metadata.
- Fixing the unchanged Semgrep baseline findings as part of issue #40.
- Modifying unrelated checks, discovery, init, policy bundles, `.codegraph/`, Git/GitHub/Orca state, labels, PRs, or generated evidence.

## Completion criteria

- [x] A measured line or branch threshold miss projects to a failed `required-repository-commands` enforcement result.
- [x] Under the default error policy, the same miss blocks normal full Stop with its documented response and makes `lgtm check --tier full` non-zero.
- [x] Summary counts, serialized normalized results, and serialized coverage evidence agree for pass, fail, and unverified outcomes.
- [x] Exact thresholds pass; missing configured metrics and unparseable output remain unverified; measured failures are not hidden by a missing companion metric.
- [x] No configured coverage produces only `not_applicable` coverage evidence and no synthetic enforcement result.
- [x] `--workspace` limits execution, evidence, and projection to exact matching coverage; no selector retains all-workspace behavior.
- [x] Coverage remains full-tier only and retains ADR-0007/0009 structured argv/cwd/timeout/environment behavior.
- [x] Existing evidence fields/schema, CLI surface, adapter responses, profile resolution, override/waiver ordering, and V1 behavior are unchanged.
- [x] `run_coverage` is decomposed to satisfy the repository function-size standard.
- [x] Passing, below-threshold, unparseable, Stop block, CLI failure, active-Stop, and workspace selection have deterministic regression coverage.
- [x] Add direct unit and Stop-level missing-coverage-tool regressions; coverage-containing evidence is parsed as JSON by the integration fixture, while explicit schema-validation coverage remains a residual.
- [ ] Re-run the final validation matrix after any review change and record actual exit codes.
- [ ] Resolve the full-policy exit-2 baseline disposition: either achieve exit 0 or obtain explicit reviewer acceptance without describing the command as passed.
- [ ] Final handoff confirms only intended implementation/test/plan files differ, no staged files exist, and runtime `.pi/`, `.codegraph/`, and generated evidence are excluded.

## Unresolved decisions

- **Review/process decision:** whether the five unchanged baseline Semgrep rule classes may be accepted for this issue despite the required full-policy command exiting 2. The evidence proves equivalence, not a passing gate.
- **Test-depth decision:** whether direct missing-tool unit coverage is sufficient or the acceptance clause should also be pinned through a Stop-level integration test. The safer recommendation is both.
- No product/API/schema decision is otherwise required for issue #40; the implemented design uses existing rule, policy, CLI, and evidence contracts.
