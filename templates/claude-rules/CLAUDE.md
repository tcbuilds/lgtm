# Engineering Standards

Language-specific rules live in `.claude/rules/` and load automatically when you
touch a matching file. Do not read them manually.

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
