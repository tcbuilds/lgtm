---
description: LGTM engineering standards and agent behavior.
rules:
  [
    {
      "id": "preserve-unrelated-user-changes",
      "title": "Preserve unrelated user changes",
      "description": "Do not modify files outside the current task scope.",
      "severity": "error",
      "level": "must",
      "category": "change-management",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": []
      },
      "instruction": "Preserve unrelated work and restrict edits to files recorded for this task.",
      "enforcement": {
        "mode": "evidence",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      },
      "mechanism": "evidence",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: satisfy Preserve unrelated user changes; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop"
    },
    {
      "id": "required-repository-commands",
      "title": "Required repository commands pass",
      "description": "Repository-configured validation commands must pass before Stop completes.",
      "severity": "error",
      "level": "must",
      "category": "testing",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Run every configured repository validation command and fix failures.",
      "enforcement": {
        "mode": "command",
        "checks": [
          "command.required"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result",
          "command_result"
        ]
      },
      "mechanism": "command",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: satisfy Required repository commands pass; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop"
    },
    {
      "id": "evidence-claims-honest",
      "title": "Verification claims require evidence",
      "description": "Assistant verification claims must match current successful command evidence.",
      "severity": "error",
      "level": "must",
      "category": "ai-agent-behavior",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": []
      },
      "instruction": "Do not claim a command or tests passed unless current Stop evidence proves exit status 0.",
      "enforcement": {
        "mode": "evidence",
        "checks": [
          "transcript.claims"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "evidence",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: satisfy Verification claims require evidence; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop"
    },
    {
      "id": "ai-assisted-discipline",
      "title": "Review AI-assisted coding discipline",
      "description": "AI-assisted changes must stay within task scope, preserve unrelated work, avoid invented verification or unapproved deletion, and report residual/unrun risk.",
      "mechanism": "evidence",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: show touched files and executed checks; bad: invent a passing test or delete unapproved work",
          "schematic": true
        }
      ],
      "limitations": [
        "Evidence and diff checks cannot infer user intent or prove every generated name is non-generic."
      ],
      "enforcement_stage": "stop",
      "severity": "error",
      "level": "must",
      "category": "ai-agent-behavior",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": [
          "agent",
          "ai",
          "generated"
        ]
      },
      "instruction": "Keep changes task-scoped, preserve unrelated work, never invent verification or delete unapproved files, and report unrun checks and residual risk.",
      "enforcement": {
        "mode": "evidence",
        "checks": [
          "git.diff",
          "transcript.claims"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "changed_locations",
          "command_evidence",
          "transcript_claims"
        ]
      }
    },
    {
      "id": "commit-pr-evidence",
      "title": "Review commit and PR evidence",
      "description": "Completion summaries should state the problem, implementation, tests, security/performance, migration/rollback, screenshots, and residual risks without inventing evidence.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: list tests and residual risk; bad: claim green checks that did not run",
          "schematic": true
        }
      ],
      "limitations": [
        "The runtime does not push or message external systems; this is completion/PR guidance."
      ],
      "enforcement_stage": "report",
      "severity": "warning",
      "level": "review",
      "category": "change-management",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": [
          "commit",
          "pull-request",
          "release"
        ]
      },
      "instruction": "Summarize problem, implementation, tests, security, performance, migration, rollback, screenshots, and residual risks using only executed evidence.",
      "enforcement": {
        "mode": "instruction",
        "checks": []
      },
      "overridable": true,
      "evidence": {
        "required": [
          "review_result",
          "command_evidence"
        ]
      }
    },
    {
      "id": "justification-metadata",
      "title": "Require temporary-code justification",
      "description": "Temporary, TODO, disabled, or suppressed code needs a reason, owner, ISO expiry, and deletion condition.",
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: TODO reason=legacy owner=team expires=2099-01-01 delete=remove-after-migration; bad: TODO fix later",
          "schematic": true
        }
      ],
      "limitations": [
        "Existing debt is surfaced when touched; semantic completeness of a reason or deletion condition remains review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "error",
      "level": "must",
      "category": "refactoring",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "todo",
          "temporary",
          "disable",
          "suppress"
        ]
      },
      "instruction": "Temporary or disabled code must carry reason=, owner=, expires=YYYY-MM-DD, and delete=... metadata; expired markers fail the gate.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.justification"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    },
    {
      "id": "debugging-protocol",
      "title": "Follow the debugging protocol",
      "description": "Bug fixes should record reproduction inputs, environment and version, one hypothesis, a root-cause repair, a regression test, and removal or conversion of temporary diagnostics.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: reproduce, state one hypothesis, repair the cause, add a regression test; bad: patch symptoms and leave debug prints",
          "schematic": true
        }
      ],
      "limitations": [
        "The packet can request protocol evidence but cannot prove semantic root cause or reproduction quality."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "correctness",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "modify"
        ],
        "signals": [
          "bug-fix",
          "regression",
          "debug"
        ]
      },
      "instruction": "For bug fixes, state reproduction inputs/environment/version and one hypothesis; repair the root cause, add a regression test, and remove or convert temporary diagnostics.",
      "enforcement": {
        "mode": "instruction",
        "checks": []
      },
      "overridable": true,
      "evidence": {
        "required": [
          "review_result",
          "changed_locations"
        ]
      }
    }
  ]
---
<!-- lgtm-entry-document: standards-v1 -->
# Engineering Standards

Language-specific rules live in `.claude/rules/` and load automatically when you
touch a matching file. Do not read them manually.

<!-- lgtm-normative-headings: Review And Change Standards, Debugging Protocol, Quality Gates, AI-Assisted Coding Standards -->

## Language-Specific Standards

Language guidance is split by file type under `.claude/rules/`. Use the matching
language file and its pattern file when both exist.

## The Four Rules

**1. Think before coding.** State assumptions explicitly. If uncertain, ask. If
multiple interpretations exist, present them — do not pick silently. If a simpler
approach exists, say so. Push back when warranted.

**2. Simplicity first.** Minimum code that solves the problem. No features beyond
what was asked. No abstractions for single-use code. No flexibility that was not
requested. No error handling for impossible scenarios. If 200 lines could be 50,
rewrite.

**3. Surgical changes.** Touch only what you must. Do not improve adjacent code,
comments, or formatting. Do not refactor what is not broken. Match existing style
even where you would do it differently. Mention pre-existing dead code; do not
delete it unless asked. Every changed line must trace to the request.

**4. Goal-driven execution.** Turn tasks into verifiable goals: "add validation"
becomes "write tests for invalid inputs, then make them pass." For multi-step work,
state a brief plan with a verify check per step.

## The Ladder

Before writing code, walk this in order and stop at the first rung that works:

1. Does this need to exist at all?
2. Does it already exist in this codebase?
3. Does the standard library provide it?
4. Is it a native platform or framework feature?
5. Is it in an already-installed dependency?
6. Can it be one line?
7. Only now: the minimum viable implementation.

The ladder governs *scaffolding*. It never applies to input validation, error
handling, security, or accessibility — those are load-bearing and get written in
full every time. Skipping them is not minimalism, it is a defect.

## Non-Negotiable

- No secrets, tokens, private keys, or production credentials in code, logs,
  fixtures, screenshots, or commit history.
- No swallowed errors. If an error is deliberately ignored, document why.
- No unbounded queues, retries, caches, loops, tasks, threads, timers, or
  subscriptions.
- No network call, database call, subprocess, lock wait, or external API call
  without a timeout.
- No public API accepts unvalidated input.
- No string-built SQL, shell commands, HTML, URLs, or JSON where a safe builder
  exists.
- No disabled lint, type, security, or test rule without a justification comment
  at the suppression site.
- No "temporary" code without an owner, a date, and a deletion condition.
- No large feature merge without tests, run instructions, and rollback notes.

## Verification

Never state that a command succeeded unless you ran it and saw exit status 0.
Predictions are not results. If you did not run it, say so plainly.

Every bug fix carries a regression test in the same change. Write it first where
you can.

## Reject On Sight

- Vague names that hide domain meaning.
- Large functions mixing multiple abstraction levels.
- Boolean flags that create hidden modes.
- Shared mutable global state.
- Copy-pasted branches with tiny differences.
- Magic numbers or stringly-typed protocols.
- Catch-all error handlers.
- Comments explaining confusing code instead of simplifying the code.
- Assertions that code ran rather than what behavior occurred.
- Render paths recomputing heavy derived state.
- Synchronous slow work in request hot paths.
- Infrastructure changes without rollback or validation commands.

## Size Limits

Functions: aim 20–30 lines, split before 50. Files: review at 300 lines, split
before 500. Exceeding either requires a documented reason.

## Review And Change Standards

- Before a PR, run format, lint, type checks, tests, and the touched-area build; inspect the diff for debug code, dead code, unsafe logs, and actionable failures.
- A PR states the problem, implementation, test evidence, security/performance notes, screenshots for UI changes, and migration or rollback impact when relevant.

## Debugging Protocol

- Reproduce with the exact input, configuration, command, seed, timestamp, version, and environment; read the nearest code before changing it.
- State one hypothesis, repair the root cause, add a regression test, and remove temporary diagnostics or turn them into useful structured logs.

## Quality Gates

- A change is ready only when it builds, is formatted, passes linting and tests, covers new behavior and failure paths, and validates security-sensitive inputs.
- Report residual risk and unrun checks honestly; infrastructure changes include a validation command and rollback path.

## AI-Assisted Coding Standards

- AI-generated code meets the human bar: read surrounding code, keep patches small, use real APIs and files, preserve unrelated work, and never invent verification.
- Run relevant checks, replace generic generated names, remove scaffolding comments, verify security assumptions, and report residual or unrun risk.

<!-- lgtm-rule: preserve-unrelated-user-changes -->
#### Preserve unrelated user changes
<!-- lgtm-rule: required-repository-commands -->
#### Required repository commands pass
<!-- lgtm-rule: evidence-claims-honest -->
#### Verification claims require evidence
<!-- lgtm-rule: ai-assisted-discipline -->
#### Review AI-assisted coding discipline
<!-- lgtm-rule: commit-pr-evidence -->
#### Review commit and PR evidence
<!-- lgtm-rule: justification-metadata -->
#### Require temporary-code justification
<!-- lgtm-rule: debugging-protocol -->
#### Follow the debugging protocol
