# lgtm — Engineering Harness for AI Coding Agents

**Status:** Finalized spec (refined 2026-07-11)
**Positioning:** Internal accelerator for the Golden Horizons portfolio. Standalone repo; `nautilus` (SDLC playbook) may reference it as its enforcement arm. No direct monetization planned — value is safer, faster agent output across every revenue project.

---

## One-Sentence Definition

**lgtm is an agent-neutral policy compiler and enforcement runtime, shipped as a single Rust binary, that converts coding standards into task-specific instructions, hooks, automated checks, and verifiable evidence for AI coding agents.**

The name is the point: the thing that makes "LGTM" actually mean something.

---

## Working Concept

Build a tool that converts a human-readable engineering standard into a compact, machine-enforceable coding harness for AI coding agents.

The tool does not rely on injecting a large Markdown standards document into every agent turn. Instead, it:

1. Represents engineering rules as structured data.
2. Selects only the rules relevant to the current task.
3. Enforces rules before, during, and after code changes.
4. Generates agent-specific configuration for Claude Code first, Codex and future agents later.
5. Produces evidence showing which rules were checked, passed, failed, skipped, or could not be verified.

The Markdown document (`codingStandards.md`) remains the source material for humans. The operational source of truth is a versioned policy registry (JSON) embedded in the binary, compiled into small agent instructions and executable checks.

---

## Problem

Large coding-standards files help agents reason, but they create several problems:

- They consume context on every turn.
- Most rules are irrelevant to any individual change.
- Agents may ignore rules buried deep in the document.
- Natural-language rules are difficult to enforce consistently.
- Different coding agents support different hooks, instructions, and tool lifecycles.
- Agents can claim compliance without running verification.
- Numeric guidance can be followed mechanically instead of intelligently.
- Repository-specific conventions may conflict with global standards.

The harness replaces passive instruction with selective policy loading and verifiable enforcement.

---

## Core Principle

Treat coding standards like a policy system, not a prompt.

The system separates:

- **Policy definition**: what the engineering organization requires.
- **Policy selection**: which rules apply to the current task.
- **Policy instruction**: what the agent needs to know before editing.
- **Policy enforcement**: what can be checked automatically.
- **Policy evidence**: what was actually verified.
- **Agent adaptation**: how each coding agent receives and executes the policy.

---

## Key Decisions (Resolved)

| Decision | Choice | Rationale |
|---|---|---|
| Name | `lgtm` | Short, memorable, ironic. |
| Revenue model | Internal accelerator | Force multiplier for all revenue repos; no direct monetization. |
| Relationship to nautilus | Standalone repo | Harness is runtime tooling; nautilus is process docs. Nautilus references lgtm. |
| Implementation | **Rust, single binary** | ~5ms hook startup vs ~80ms+ Python; zero venv/dependency setup in consumer repos; per-repo version pinning via one downloaded binary (rtk precedent). |
| Check engine | **Wrap existing tools** | gitleaks (secrets), ruff (Python lint/AST rules), semgrep (SQL, timeouts, validation patterns), git diff parsing native in Rust. lgtm orchestrates and normalizes to enforcement-result JSON. tree-sitter native checks post-MVP. |
| MVP language coverage | **Python only** | Prove the full loop (select → inject → check → evidence) on one language. TypeScript is fast follow. |
| Hook events (MVP) | **All five Claude Code events** | SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop. |
| Stop-gate strictness | **Hard block** | Stop hook exits 2 with precise repair instructions on unresolved MUST violations. This is the whole point. |
| Adoption | **`lgtm init`** | Binary on PATH (cargo install / GitHub release). `lgtm init` writes `.claude/settings.json` hook entries + `.lgtm/config.json`, detects languages and commands. |
| Policy registry location | **Embedded in binary + repo overrides** | Default rules compiled into binary, versioned with it. Consumer repo's `.lgtm/` holds only profile choice, overrides, commands. Upgrade rules = upgrade binary. |
| Task-context detection | **Deterministic only** | Derive from observables: file paths, extensions, diff content, imports, keyword match on prompt text. No LLM calls inside hooks. Predictable, testable. |
| Evidence storage | **`.lgtm/evidence/` gitignored** | Local JSONL per task. Attach to PRs later via flag. Zero commit noise. |
| Missing wrapped tools | **Degrade → `unverified`** | Never silently pass. Surfaced in evidence and Stop report. `lgtm doctor` lists missing tools with install commands. |
| Profiles (MVP) | **All four** | default, strict, prototype, infrastructure. |
| Waivers (MVP) | **None** | MUST = must. Waiver machinery post-MVP. |
| Dogfood target | **One active Python revenue repo** | e.g. internal-python-repo or alternate-python-repo as guinea pig. |
| Codex adapter | **Post-MVP** | Only after Claude Code loop proven. |

**Accepted risk:** hard block + no waivers means a legitimate MUST exception has no escape hatch in MVP. Fallback for genuine emergencies: `.lgtm/config.json` severity override (recorded in evidence, security-critical rules non-overridable). If this bites more than once during dogfooding, the waiver flow gets pulled forward.

---

## High-Level Architecture

```text
Human Standards (codingStandards.md)
      |
      v
Policy Registry (embedded rules.json)
      |
      v
Policy Compiler (in binary)
      |
      +------------------+
      |                  |
      v                  v
Agent Instructions   Enforcement Plan
      |                  |
      v                  v
Claude Adapter       Hook Runtime
Codex Adapter*       Wrapped Checks (gitleaks/ruff/semgrep)
Future Adapters*     Diff Checks (native Rust)
                     Test Commands
                     Evidence Report

* post-MVP
```

The policy registry is agent-neutral. Claude Code (and later Codex) receive generated adapters rather than separately maintained standards.

---

## Repository Layout

```text
lgtm/
├── README.md
├── idea.md
├── codingStandards.md          # human source material
├── Cargo.toml
├── src/
│   ├── main.rs                 # CLI: init, hook, doctor, compile, report
│   ├── policy/                 # rule model, registry loading, profiles, overrides
│   ├── select/                 # deterministic rule selection from task context
│   ├── compile/                # agent-context packet + enforcement plan generation
│   ├── context/                # task-context detection (paths, diff, imports, prompt keywords)
│   ├── checks/
│   │   ├── wrapped/            # gitleaks, ruff, semgrep runners + output normalizers
│   │   └── diff/               # native git-diff checks
│   ├── evidence/               # evidence ledger read/write
│   └── adapters/
│       ├── claude_code/        # settings.json hook generation, event handlers
│       └── shared/
├── policy/
│   ├── rules.json              # canonical registry, embedded at build time
│   ├── rule.schema.json
│   └── profiles/               # default, strict, prototype, infrastructure
├── schemas/
│   ├── task-context.schema.json
│   ├── enforcement-plan.schema.json
│   └── evidence.schema.json
├── examples/
│   └── python-service/
└── tests/
```

Consumer repo after `lgtm init`:

```text
consumer-repo/
├── .claude/settings.json       # hook entries pointing at lgtm binary (merged, not overwritten)
└── .lgtm/
    ├── config.json             # profile, languages, severity overrides, required commands
    └── evidence/               # gitignored JSONL, one file per task
```

---

## Canonical Rule Model

Each rule is a structured object rather than a paragraph in a prompt.

```json
{
  "id": "external-call-timeout",
  "title": "External calls require timeouts",
  "description": "Network, database, subprocess, lock, and external API operations must have explicit bounded timeouts.",
  "severity": "error",
  "level": "must",
  "category": "reliability",
  "applies_to": {
    "languages": ["python"],
    "domains": ["backend", "api", "worker", "infrastructure"],
    "file_patterns": ["**/*.py"]
  },
  "activation": {
    "change_types": ["create", "modify"],
    "signals": ["http-client", "database-client", "subprocess", "lock", "external-api"]
  },
  "instruction": "Add an explicit timeout and ensure cancellation or cleanup is handled.",
  "enforcement": {
    "mode": "hybrid",
    "checks": [
      "semgrep.external_call_timeout",
      "diff.external_call_added"
    ]
  },
  "overridable": false,
  "evidence": {
    "required": ["check_result", "changed_locations"]
  },
  "references": [
    "codingStandards.md#non-negotiable-rules"
  ]
}
```

`applies_to.languages` widens beyond Python as coverage grows; rule IDs stay stable.

---

## Rule Levels

### MUST

A change cannot be considered compliant without satisfying the rule. In MVP there are no waivers; the only relief valve is a repo-level severity override for rules marked `overridable: true`, recorded in evidence.

Examples:

- No secrets in code or logs.
- No swallowed errors.
- External calls require timeouts.
- Untrusted input must be validated.
- Destructive operations require safety controls.
- The agent must not claim checks passed unless they were run.

### SHOULD

Expected by default, but context may justify deviation.

Examples:

- Prefer typed domain objects over raw dictionaries.
- Prefer dependency injection for external services.
- Keep business logic out of controllers.
- Prefer guard clauses over deep nesting.

### REVIEW

Triggers inspection rather than automatic failure.

Examples:

- Function exceeds 50 lines.
- File exceeds 400 lines.
- Complexity exceeds a threshold.
- A new dependency is added.
- A new abstraction has only one implementation.

This prevents agents from blindly splitting code simply to satisfy metrics.

---

## Rule Enforcement Modes

Each rule declares how it can be enforced.

### Instruction

The rule is provided to the agent because automated verification is difficult.
Example: keep business rules out of route handlers.

### Static

The rule is checked via a wrapped tool (ruff, semgrep, gitleaks) or repository inspection.
Examples: bare exception handling, string-built SQL, committed secrets, missing timeout arguments.

### Command

The rule is enforced by running a repository command.
Examples: `ruff check`, `mypy --strict`, `pytest`.

### Diff

The rule examines the actual patch (native Rust, parsing `git diff`).
Examples: dependency added, tests removed, external call introduced, authentication code modified.

### Evidence

The agent must provide proof or an explicit unverified status.
Examples: migration rollback instructions, benchmark before/after, bug reproduction steps.

### Hybrid

Combines agent instruction, automated checks, and evidence. Most important engineering rules are hybrid.

---

## Task Context

Before selecting rules, the harness builds a compact task-context object — **deterministically**, from observables only. No LLM calls inside hooks.

```json
{
  "task_id": "local-or-generated-id",
  "agent": "claude-code",
  "intent": "bug-fix",
  "languages": ["python"],
  "domains": ["api", "database"],
  "files_touched": [
    "src/routes/events.py",
    "src/services/event_store.py",
    "tests/test_events.py"
  ],
  "risk_signals": [
    "database-write",
    "public-api",
    "authentication"
  ],
  "repository_commands": {
    "format": ["ruff format --check ."],
    "lint": ["ruff check ."],
    "types": ["mypy --strict src"],
    "tests": ["pytest tests/test_events.py"]
  }
}
```

Detection inputs:

- File extensions and paths (from tool-call payloads).
- Diff contents.
- Imported libraries in touched files.
- Keyword match on the user prompt (UserPromptSubmit provides prompt text) — `intent` is a keyword-derived label, nothing smarter in MVP.
- Repository metadata and framework signals (pyproject.toml, requirements, framework imports).
- Security-sensitive path patterns.
- Selected profile and repo-local config.

---

## Policy Selection

Example: a change to a Python FastAPI route that writes to PostgreSQL activates public input validation, authn/authz review, SQL parameterization, transaction handling, external-call timeout, structured errors, integration tests, regression-test requirement, type checking, no broad exception handling.

It does not activate React, Rust, Terraform, or CSS rules.

---

## Context Minimization

The harness generates a small instruction packet rather than passing the entire standards file.

```text
Applicable engineering constraints:

MUST
- Validate the public API request before domain logic.
- Use parameterized database operations.
- Add explicit timeouts to external operations.
- Do not catch and suppress unknown exceptions.
- Add or update a regression test for the reported failure.
- Preserve unrelated user changes.

REVIEW
- Keep route handlers thin.
- Avoid introducing a new abstraction unless an existing seam requires it.

Verification required:
- ruff check
- mypy --strict
- targeted pytest command
- diff review for secrets and unrelated changes

Do not claim a check passed unless it was executed successfully.
```

This packet is generated per task and refreshed when the touched-file set changes.

---

## Hook Lifecycle (Claude Code, MVP — all five native events)

### 1. SessionStart

- Detect repository type, languages, frameworks.
- Find repository-local instructions.
- Detect available build, lint, type, and test commands.
- Load the enforcement profile from `.lgtm/config.json`.
- Inject the persistent harness contract (see Claude Code Harness below).

### 2. UserPromptSubmit

- Classify task intent via keyword match on prompt text.
- Identify likely files and domains.
- Select applicable architectural and safety rules.
- Inject a small planning rule packet.

### 3. PreToolUse

- On Edit/Write: recompute rules based on target files, block prohibited paths if configured, capture a baseline for diff and verification.
- On Read/Search: no-op in MVP (context-inspection nudges post-MVP).

### 4. PostToolUse

- On Edit/Write: inspect changed files, run fast checks (secrets, diff, prohibited patterns, ruff on touched files).
- Detect newly activated rules.
- Return precise failures to the agent.
- Never dump the full policy into context.

### 5. Stop

- Run required repository commands.
- Verify claimed tests actually ran.
- Check that new behavior has tests.
- Inspect the final diff.
- Write the evidence record.
- **Hard block (exit 2) when unresolved MUST violations exist**, returning precise repair instructions.

### Final Report

The agent reports: files changed, behavior changed, checks run and results, checks not run and why, overrides applied and why, residual risks, required manual review.

---

## Enforcement Result

Every check returns structured output.

```json
{
  "rule_id": "external-call-timeout",
  "status": "failed",
  "severity": "error",
  "message": "HTTP request added without an explicit timeout.",
  "locations": [
    {
      "file": "src/client.py",
      "line": 84
    }
  ],
  "remediation": "Pass an explicit timeout and ensure cancellation is propagated.",
  "evidence": {
    "check": "semgrep.external_call_timeout",
    "tool_version": "semgrep 1.x"
  }
}
```

Allowed statuses: `passed`, `failed`, `warning`, `skipped`, `not_applicable`, `unverified`, `overridden`.

**Missing-tool behavior:** if a wrapped tool (gitleaks, ruff, semgrep) is not installed, affected rules report `unverified` — never a silent pass. `lgtm doctor` lists missing tools with install commands. Unverified MUST rules are surfaced prominently in the Stop report but do not hard-block in MVP (blocking on missing tooling would make fresh machines unusable).

---

## Evidence Ledger

Machine-readable record per task, stored as JSONL under `.lgtm/evidence/` (gitignored by `lgtm init`). Attachable to PRs later via a flag.

```json
{
  "task_id": "abc123",
  "agent": "claude-code",
  "profile": "strict",
  "commit": null,
  "rules": {
    "passed": 18,
    "failed": 0,
    "warning": 2,
    "unverified": 1,
    "overridden": 1
  },
  "commands": [
    {
      "command": "pytest tests/test_events.py",
      "exit_code": 0,
      "duration_ms": 1840
    }
  ],
  "overrides": [
    {
      "rule_id": "file-size-review",
      "from": "error",
      "to": "warning",
      "source": ".lgtm/config.json"
    }
  ]
}
```

---

## Agent Adapter Model

The core harness remains independent of any one coding agent. Each adapter translates the same lifecycle into the mechanisms supported by that agent.

```text
Canonical Policy
      |
      v
Adapter Interface
      |
      +-- Claude Code   (MVP)
      +-- Codex         (post-MVP, after Claude loop proven on dogfood repo)
      +-- Cursor        (future)
      +-- CI-only mode  (future)
```

Adapter interface:

```text
initialize_session()
inject_task_context()
before_tool_call()
after_tool_call()
before_edit()
after_edit()
before_completion()
format_feedback()
```

---

## Claude Code Harness (First Implementation)

The Claude adapter:

- Generates the smallest persistent repository instruction file.
- Registers all five lifecycle hooks in `.claude/settings.json` (merging, never clobbering existing entries).
- Calls the shared policy runtime (`lgtm hook <event>`) from those hooks.
- Provides concise failures back to Claude.
- Prevents completion when required checks fail.
- Stores evidence outside the model context.
- Recomputes applicable rules when files or task scope change.

The persistent Claude-facing instructions explain only:

- The harness is authoritative.
- Hook failures must be fixed.
- Verification claims require evidence.
- Repository-local conventions take precedence unless they violate MUST rules.
- The agent must not bypass or edit harness files unless the task explicitly concerns the harness.

All detailed rules stay in the policy registry.

---

## Codex Harness (Post-MVP)

Same policy registry and runtime; only the adapter changes. The Codex adapter generates Codex-specific repository guidance, wraps edit/command/completion workflows where possible, runs identical preflight/diff/verification/evidence checks, and preserves identical rule IDs and evidence schema.

The goal is not to make Claude and Codex behave identically — it is to make them subject to the same engineering policy and produce comparable evidence.

---

## Repository-Local Policy

Default rules ship embedded in the binary. A consuming repository holds only configuration:

```text
.lgtm/
├── config.json
└── evidence/          # gitignored
```

```json
{
  "profile": "strict",
  "languages": ["python"],
  "disabled_rules": [],
  "severity_overrides": {
    "file-size-review": "warning"
  },
  "required_commands": {
    "python": [
      "ruff check .",
      "mypy --strict src",
      "pytest"
    ]
  }
}
```

Rules marked `overridable: false` (security-critical) cannot be disabled or downgraded by repo config. Upgrading the rule set = upgrading the binary; per-repo version pinning is a version string in `config.json` checked by the binary at startup.

---

## Instruction Precedence

1. Security and data-protection requirements.
2. Explicit task acceptance criteria.
3. Repository-local architecture and instructions.
4. Organization policy.
5. Language and framework defaults.
6. Agent preferences.

Material conflicts are surfaced rather than silently resolved.

---

## Profiles (All Four in MVP)

Profiles modify severity and required evidence; they do not duplicate the rule set.

### Strict

Production services. All MUST rules enforced, full verification, evidence required.

### Default

Normal product work. MUST rules enforced, relevant test/lint commands required, REVIEW rules reported.

### Prototype

Experiments. Security and destructive-operation rules remain enforced; some documentation and coverage rules downgrade to warnings; temporary code still requires a deletion condition.

### Infrastructure

Adds plan review, rollback requirements, least-privilege checks, secret and state-file scanning, validation commands.

---

## Policy Compiler

```text
rules.json (embedded)
   |
   +-- selected-rules.json
   +-- agent-context packet (text)
   +-- enforcement-plan.json
   +-- generated hook configuration
   +-- CI configuration (post-MVP)
```

Responsibilities: validate rule schemas, resolve profiles and overrides, detect conflicting rules, select applicable rules, order checks by cost, generate compact instructions and executable enforcement plans, cache results when repository state has not changed.

---

## Check Execution Strategy

### Fast Checks (PostToolUse, after each edit)

Secret detection (gitleaks on touched files), diff inspection (native), prohibited patterns, ruff on touched files, schema validation.

### Targeted Checks (before a slice is considered complete)

Tests related to touched modules, type checking for touched packages, semgrep on changed surfaces.

### Full Checks (Stop gate / CI)

Full test suite, full lint and type checks, build.

This keeps the agent feedback loop fast without weakening final enforcement.

---

## Initial Rule Categories

Derived from `codingStandards.md`, grouped into: correctness, security, reliability, error handling, validation, architecture, dependencies, testing, observability, performance, documentation, refactoring, change management, AI-agent behavior, language-specific (Python first), infrastructure.

Each original standard maps to one or more stable rule IDs.

---

## MVP Scope

- **Rust single binary** (`cargo install` / GitHub release).
- **Python-only** enforced rules; TypeScript fast follow.
- **Claude Code adapter**, all five native hook events.
- Embedded JSON policy registry + `.lgtm/config.json` repo overrides.
- `lgtm init` (repo detection, hook registration, config scaffold, evidence gitignore).
- `lgtm doctor` (missing wrapped tools + install commands).
- Deterministic task-context detection.
- Post-edit fast checks; hard-blocking Stop verification gate.
- Evidence JSONL under `.lgtm/evidence/`.
- All four profiles.
- No waiver machinery (severity overrides on `overridable: true` rules only).

### First Enforceable Rules

1. No committed secrets. *(gitleaks)*
2. No swallowed errors. *(ruff/semgrep)*
3. No broad exception handling without rethrow or conversion. *(ruff)*
4. External operations require timeouts. *(semgrep)*
5. Public inputs require validation. *(semgrep + instruction)*
6. SQL must be parameterized. *(semgrep)*
7. No unbounded retries or loops. *(semgrep + instruction)*
8. Bug fixes require regression tests. *(diff + evidence)*
9. New behavior requires tests. *(diff)*
10. Do not claim unrun checks passed. *(evidence)*
11. Preserve unrelated user changes. *(diff)*
12. Required repository commands must run before completion. *(command)*
13. New dependencies trigger review. *(diff)*
14. Authentication and authorization changes trigger security review. *(diff)*
15. Destructive operations require explicit safeguards. *(semgrep + instruction)*

### MVP Execution Flow

```text
1. User gives Claude a task.
2. SessionStart: lgtm detects repo, loads profile, injects harness contract.
3. UserPromptSubmit: lgtm classifies task (keywords), injects compact rule packet.
4. PreToolUse (Edit/Write): recompute rules for target files, capture baseline.
5. Claude edits code.
6. PostToolUse: fast checks inspect the patch; failures returned as precise repair instructions.
7. Claude fixes violations.
8. Stop: required commands run, diff inspected, evidence.jsonl written.
9. Unresolved MUST violations → exit 2, Claude must repair before finishing.
10. Claude provides an evidence-based completion report.
```

### Rollout

Dogfood on **one active Python revenue repo** (candidate: internal-python-repo or alternate-python-repo). Codex adapter starts only after the Claude loop is proven there.

---

## Future Capabilities

- Waiver flow (`lgtm waive` with reason/owner/expiry) — pulled forward if the no-waiver MVP bites more than once.
- TypeScript rule coverage.
- Codex adapter, IDE integrations, CI enforcement, PR annotations.
- Native tree-sitter checks (reduce external tool dependency).
- Organization policy distribution, signed policy bundles, policy version pinning.
- Metrics on recurring agent violations; automatic rule recommendations from code-review findings.
- SARIF output; Open Policy Agent integration.
- Agent benchmarking across identical tasks; compliance scores by repo and agent.

---

## Non-Goals

- A new general-purpose linter.
- A replacement for language-native tooling.
- A giant permanent system prompt.
- An agent-specific collection of handcrafted prompt files.
- A framework that rewrites repositories to match one architecture.
- A system that claims semantic correctness from static checks alone.
- A tool that blocks all development because every ideal standard is mandatory.

lgtm coordinates existing tools, adds missing policy checks, selects relevant rules, and requires honest evidence.

---

## Design Constraints

- Agent-neutral core.
- Stable rule IDs.
- Deterministic policy selection.
- Compact agent-facing output.
- Human-readable failure messages; machine-readable evidence.
- No silent bypasses; missing tooling reports `unverified`, never `passed`.
- Security-critical rules are non-overridable.
- Repository conventions respected.
- Hooks fail safely and fast (single-binary startup, no interpreter).
- Enforcement is incremental (fast → targeted → full).
- The system distinguishes failure from lack of verification.
- A passing linter is never equated with correct behavior.

---

## Success Criteria

- Agents no longer need the full standards Markdown in context.
- Relevant rules load automatically per task.
- High-value violations are caught before completion.
- Agents stop claiming checks passed when they were not run.
- Each completed task has a structured evidence record.
- Repository-specific commands and conventions are preserved.
- The dogfood repo runs cleaner agent sessions than before adoption (measured by evidence records).
- Adding a new coding agent requires an adapter, not a rewritten policy set.
- Engineering standards become executable, measurable, and versioned.

---

## Open Questions

- **Dogfood repo final pick:** internal-python-repo vs alternate-python-repo (whichever has the most active Python agent work when build starts).
- **Binary distribution channel:** GitHub releases with an install script vs cargo-only — decide at first release.
- **Prompt-keyword intent taxonomy:** exact keyword → intent mapping table to be defined during build (bug-fix, feature, refactor, infra, docs).
