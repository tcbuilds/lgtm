# Coding Standards V2

These standards exist to prevent slop, slow code, hidden coupling, and hard-to-debug failures. They apply to all production code, tests, scripts, infrastructure, and generated code that is committed to the repository.

## Core Principles

1. Correctness beats cleverness.
2. Simplicity beats abstraction until repetition proves the abstraction.
3. Explicit data flow beats hidden global state.
4. Small, named concepts beat large anonymous blobs.
5. Failures must be observable, reproducible, and easy to isolate.
6. Performance work must be measured, not guessed.
7. Security is a design constraint, not a final checklist.

## Non-Negotiable Rules

- No secrets, tokens, private keys, or production credentials in code, logs, fixtures, screenshots, or commit history.
- No swallowed errors. If an error is intentionally ignored, document why.
- No unbounded queues, retries, caches, loops, goroutines, tasks, threads, timers, or subscriptions.
- No network call, database call, subprocess, lock wait, or external API call without a timeout.
- No public API accepts unvalidated input.
- No string-built SQL, shell commands, HTML, URLs, or JSON when safe builders exist.
- No disabled lint, type, security, or test rule without a local justification comment.
- No "temporary" code without an owner, date, and deletion condition.
- No large feature merge without tests, run instructions, and rollback notes.

## Code Organization

**Module boundaries**

- Each module owns one reason to change.
- Keep dependency direction obvious: UI -> domain -> infrastructure, not the reverse.
- Isolate external systems behind adapters: database, filesystem, HTTP, WebSocket, LLMs, queues, cloud APIs, OS services.
- Keep business rules out of controllers, route handlers, UI components, CLIs, and migration scripts.
- Avoid circular dependencies. If two modules need each other, extract the shared concept.

**Size limits**

- Function target: 20 to 30 lines. Hard limit: 50 lines unless it is a clear table, parser, or state machine.
- File target: under 300 lines. Review at 400 lines. Split before 500 lines.
- Class/struct target: under 200 lines. Hard limit: 300 lines.
- Function parameters: target 3 or fewer. Use a named options type after 4.
- Nesting depth: target 2 levels. Hard limit: 3 levels. Prefer guard clauses.
- Cyclomatic complexity: target 5 or lower. Hard limit: 10.

**File layout**

- Tests mirror source structure where practical.
- Keep domain types near domain logic.
- Keep generated files clearly marked and excluded from manual edits.
- Do not mix unrelated concerns because "the file already exists."

## Naming Standards

- Use full words except universal terms: ID, URL, API, HTTP, SQL, IP, CPU, GPU, UI.
- Booleans use predicate names: `isReady`, `hasGeo`, `canRetry`, `shouldFlush`.
- Functions are verb-first: `parseEvent`, `calculateScore`, `sendBatch`, `validateConfig`.
- Types name domain concepts, not implementation trivia: `EventBuffer`, not `DataManager`.
- Avoid vague names: `thing`, `stuff`, `data`, `payload2`, `helper`, `manager`, `processor`.
- Constants use the language's standard constant style and include units: `REQUEST_TIMEOUT_MS`, `maxRetries`, `cacheTtlSeconds`.
- Error names describe the failure: `ConfigMissing`, `InvalidSignature`, `StorageUnavailable`.

## Design For Debugging

Master-level code is easy to debug because it leaves a trail.

**Every failure should answer**

- What failed?
- Which input or entity failed?
- Where did it fail?
- Was it retryable?
- What should the operator or caller do next?

**Required debugging affordances**

- Structured logs with stable keys, not sentence-only logs.
- Request, trace, job, event, or correlation IDs at all async boundaries.
- Metrics for latency, throughput, error count, queue depth, retries, drops, and cache hit rate.
- Health checks for every long-running service.
- Debug endpoints or commands only when authenticated and safe.
- Deterministic repro instructions for every bug fix.

**Error message format**

```text
action failed: entity=<id> reason=<specific cause> retryable=<true|false>
```

Examples:

```text
event forward failed: event_id=abc123 target=http://127.0.0.1:8788/events reason=timeout retryable=true
config load failed: key=OPENROUTER_API_KEY reason=missing retryable=false
```

## Error Handling

- Validate at boundaries: API input, config, files, database rows, environment variables, queue messages.
- Convert unknown external errors into typed domain errors as soon as they enter the system.
- Include context before propagating errors. Never return a naked "failed" error.
- Log at the boundary that handles the error. Do not log and rethrow repeatedly.
- Use retries only for known transient failures. Add exponential backoff, jitter, caps, and cancellation.
- Make destructive operations idempotent or guarded by explicit confirmation.
- Prefer typed result/error values over exceptions for expected failures when the language supports it.

## Testing Standards

**Minimum expectations**

- Unit coverage target: 80 percent minimum, 90 percent preferred.
- Critical paths: 100 percent behavior coverage.
- Public APIs: integration tests.
- Bug fixes: regression test first or in the same change.
- Tests must be deterministic, isolated, and runnable locally.

**Test quality**

- Test behavior, not private implementation details.
- Use table-driven tests for parsers, classifiers, validators, and edge cases.
- Use property-based tests for serialization, parsing, scoring, normalization, and math-heavy logic.
- Use golden tests for stable text, JSON, CLI output, and generated artifacts.
- Use contract tests for service boundaries and cross-language schemas.
- Use fuzz tests for parsers, decoders, auth/token handlers, and anything that consumes untrusted input.
- Prefer real lightweight dependencies over excessive mocking. Mock only slow, flaky, paid, or external systems.

**Test naming**

- Python: `test_<behavior>_<condition>()`
- Rust: `fn parses_valid_nginx_line()`
- TypeScript: `it('renders reconnecting status after socket close', ...)`
- Go: `TestParserRejectsMalformedLine`
- Java/Kotlin/C#: `method_condition_expectedResult`

## Observability Standards

- Logs are for events. Metrics are for trends. Traces are for cross-service latency.
- Never log secrets, tokens, raw credentials, full cookies, private keys, or full auth headers.
- Redact sensitive fields by default.
- Log IDs and counts instead of entire large payloads.
- Add counters for dropped events, rejected input, retry exhaustion, and background task crashes.
- Add histograms for request latency, database latency, queue delay, and batch size.
- Alert on symptoms: user-facing errors, saturation, stale data, high latency, and data loss.

## Performance Standards

- Establish a baseline before optimization.
- Keep hot paths allocation-aware and I/O-aware.
- Batch high-frequency events before crossing expensive boundaries: React renders, database writes, network calls, logs, locks, and serialization.
- Prefer streaming for large data sets.
- Add pagination or windowing for lists over 100 items.
- Avoid N+1 database or network patterns.
- Cache only when invalidation is clear.
- Document Big O for non-trivial algorithms.
- Add load tests for services that process streams, queues, WebSockets, or large files.

**Performance workflow**

1. Define the user-visible symptom.
2. Measure with a profiler, trace, benchmark, or production metric.
3. Identify the bottleneck.
4. Make the smallest safe change.
5. Re-measure.
6. Keep the benchmark or metric if the path is important.

## Security Standards

- Treat all external input as hostile.
- Use allowlists over blocklists.
- Use parameterized SQL and safe ORM/query builders.
- Escape output for the target context: HTML, shell, URL, SQL, JSON, regex.
- Enforce authentication and authorization at the server, not only in the UI.
- Rate limit public endpoints and expensive internal endpoints.
- Use least privilege for service accounts, database users, tokens, and filesystem permissions.
- Pin or scan dependencies in CI.
- Require secure defaults: TLS, secure cookies, CSRF protection where applicable, safe CORS, and no debug mode in production.
- Store secrets in environment variables or secret managers. Rotate and document them.

## Dependency Standards

- Add dependencies only when they replace substantial, risky, or non-core code.
- Prefer boring, maintained, widely used libraries.
- Check license, maintenance activity, transitive dependency size, security posture, and bundle/runtime cost.
- Avoid adding a framework for one helper function.
- Wrap dependencies that are likely to change or that touch external systems.
- Keep dependency graphs shallow and acyclic.

## Documentation Standards

- README must explain purpose, quick start, test commands, configuration, and deployment basics.
- Public APIs need doc comments with behavior, errors, examples, and safety notes.
- Complex algorithms need comments explaining why, not line-by-line what.
- ADRs are required for major architectural decisions, migrations, protocols, and vendor choices.
- Runbooks are required for production services and recurring operational tasks.
- Comments must not lie. Update or delete stale comments during code changes.

## Review And Change Standards

**Before opening a PR**

- Run format, lint, type checks, tests, and build for touched areas.
- Review your own diff line by line.
- Remove debug prints, dead code, unused dependencies, and commented-out code.
- Confirm logs are useful and safe.
- Confirm failures are actionable.
- Confirm rollback or migration path for risky changes.

**PR requirements**

- Problem statement.
- Implementation summary.
- Test evidence.
- Screenshots or recordings for UI changes.
- Performance evidence for performance-sensitive changes.
- Security notes for auth, secrets, permissions, external inputs, or data exposure.
- Migration and rollback notes when applicable.

**Commit style**

- Use Conventional Commits: `feat(scope): description`, `fix(scope): description`, `test(scope): description`.
- Keep commits atomic.
- Keep subject lines under 72 characters.
- Do not mix refactors and behavior changes unless unavoidable.

## Refactoring Standards

- Refactor under tests.
- Separate mechanical moves from behavior changes.
- Make one dimension of change at a time: rename, extract, change behavior, optimize.
- Preserve public behavior unless the PR explicitly changes it.
- Delete obsolete code immediately after replacement.
- Prefer extraction when code repeats 3 times.
- Prefer composition when inheritance or framework magic hides control flow.

## Debugging Protocol

When something breaks:

1. Reproduce the failure locally or in a controlled environment.
2. Capture exact input, config, command, seed, timestamp, version, and environment.
3. Read the error and the nearest code before changing anything.
4. Form one hypothesis.
5. Add the smallest diagnostic needed to prove or disprove it.
6. Fix the root cause, not the symptom.
7. Add a regression test.
8. Remove temporary diagnostics or convert them into useful structured logs.

Do not shotgun changes. Do not "try stuff" without writing down the hypothesis.

## Anti-Slop Checklist

Reject code that has any of these traits:

- Vague names hiding domain meaning.
- Large functions with multiple abstraction levels.
- Boolean flags that create hidden modes.
- Shared mutable global state.
- Copy-pasted branches with tiny differences.
- Magic numbers or stringly typed protocols.
- Catch-all error handlers.
- Comments explaining confusing code instead of simplifying the code.
- Tests that only check that code ran, not what behavior occurred.
- UI code that recomputes heavy derived state on every render.
- Backend code that performs synchronous slow work in request hot paths.
- Infrastructure code without rollback or validation commands.

## Language-Specific Standards

### Rust

- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` must pass.
- Forbid `unsafe` unless approved by architecture review and documented with invariants.
- Avoid `unwrap()` and `expect()` in production paths. Use `?`, typed errors, or explicit handling.
- Use `thiserror` for libraries and domain errors; use `anyhow` at binary boundaries when appropriate.
- Prefer owned domain types at boundaries and borrowed values inside hot paths.
- Use `tracing` with structured fields.
- Use `tokio::time::timeout` around external async work.
- Keep `async` tasks cancellable and joinable.
- Use newtypes for IDs, units, and validated strings.
- Use property tests or fuzzing for parsers and codecs.

### Python

- Use Python 3.12+ features when they simplify code.
- `ruff check`, `ruff format --check`, `mypy --strict`, and `pytest` must pass.
- Type all function signatures.
- Use Pydantic or dataclasses for structured data.
- Avoid bare `dict` payloads after validation. Convert to typed objects.
- Avoid mutable default arguments.
- Use context managers for files, locks, database sessions, and network clients.
- Use explicit timeouts with `httpx`, database clients, and subprocesses.
- Avoid broad `except Exception` unless adding context and re-raising or converting.
- Prefer dependency injection for testable services.

### TypeScript And JavaScript

- `tsc --noEmit`, ESLint, formatter, and tests must pass.
- Strict TypeScript is mandatory.
- Avoid `any`. Use `unknown` at boundaries and narrow it.
- Model impossible states with discriminated unions.
- Keep React render paths pure and cheap.
- Batch high-frequency state updates.
- Memoize only when there is measured churn or stable identity is required.
- Never mutate React state in place.
- Validate API responses at runtime before using them.
- Prefer async/await with explicit cancellation or cleanup.
- Use error boundaries for UI surfaces that can fail independently.

### React

- Components should either orchestrate state or render UI. Avoid doing both heavily.
- Keep derived data outside hot render paths when it is expensive.
- Use stable keys from domain IDs, not array indexes, except static lists.
- Clean up subscriptions, timers, observers, sockets, and async effects.
- Avoid global singletons for UI state unless intentionally app-wide.
- Prefer controlled error and loading states over implicit null behavior.
- Use accessibility semantics: labels, roles, keyboard paths, focus management.

### Go

- `gofmt`, `go vet`, `staticcheck`, and `go test ./...` must pass.
- Always check errors.
- Wrap errors with context using `%w`.
- Accept `context.Context` as the first argument for request-scoped work.
- Keep interfaces small and consumer-owned.
- Do not start goroutines without cancellation and error reporting.
- Use table-driven tests.
- Avoid package-level mutable state.
- Prefer explicit structs over maps for domain data.

### Java

- Use modern Java LTS features where supported.
- Use immutable value objects for domain data.
- Avoid checked-exception noise at low levels by converting to meaningful domain errors.
- Use dependency injection without hiding all construction behind magic.
- Keep controllers thin and services cohesive.
- Use JUnit, AssertJ, SpotBugs/Error Prone, Checkstyle or equivalent gates.
- Avoid `null` as a control-flow mechanism. Use `Optional` at boundaries only.

### Kotlin

- Prefer non-null types and sealed classes for state.
- Use data classes for values and immutable collections by default.
- Avoid platform types leaking across boundaries.
- Use coroutines with structured concurrency.
- Use `Result` or sealed error types for expected failures.
- Run ktlint, detekt, and tests.

### C#

- Enable nullable reference types.
- Use async all the way for I/O paths.
- Avoid `.Result` and `.Wait()` in async code.
- Use records for immutable values.
- Use dependency injection with explicit lifetimes.
- Run `dotnet format`, analyzers, and tests.
- Include cancellation tokens for external and long-running work.

### C And C++

- Use sanitizers in CI where practical: ASan, UBSan, TSan.
- Compile with warnings as errors.
- Prefer RAII in C++ and explicit ownership conventions in C.
- Avoid raw owning pointers in C++.
- Bounds-check all buffers.
- Treat integer overflow, signed/unsigned mixing, and lifetime bugs as security issues.
- Use clang-format, clang-tidy, and static analysis.
- Fuzz parsers and binary input handling.

### SQL

- Use migrations for schema changes.
- Keep migrations reversible when practical.
- Use explicit column lists.
- Use indexes intentionally and verify query plans for hot queries.
- Avoid SELECT * in application code.
- Enforce constraints in the database, not only in application code.
- Use transactions for multi-step writes.
- Never construct SQL with string concatenation.

### Shell

- Prefer shell only for glue. Use a real language for complex logic.
- Start scripts with `set -euo pipefail` when compatible.
- Quote variables.
- Use `shellcheck`.
- Check command availability and required environment variables.
- Avoid parsing human-formatted command output when machine formats exist.
- Make scripts idempotent.

### HTML, CSS, And UI Styling

- Preserve semantic HTML.
- Use accessible contrast and focus states.
- Avoid layout shifts on load.
- Prefer design tokens for colors, spacing, typography, shadows, and z-index.
- Avoid one-off magic pixel values unless documented.
- Test responsive behavior at small, medium, and large viewports.

### Infrastructure As Code

- Run format and validation: `terraform fmt`, `terraform validate`, `tflint`, `yamllint`, or equivalents.
- Keep secrets out of state files and templates.
- Pin provider versions.
- Use least privilege IAM.
- Add outputs intentionally. Outputs can leak sensitive data.
- Use plan review before apply.
- Document rollback for risky infrastructure changes.

### YAML, JSON, And Config

- Validate config with schemas when possible.
- Keep environment-specific values outside shared templates.
- Include units in config names.
- Prefer explicit defaults in code and documented examples in `.env.example`.
- Avoid duplicate config keys across files.

## AI-Assisted Coding Standards

AI-generated code must meet the same bar as human-written code.

- Read surrounding code before generating changes.
- Prefer small patches.
- Do not invent APIs, files, commands, or configuration.
- Do not delete user changes without explicit instruction.
- Run relevant checks after edits.
- Explain residual risk and unrun checks.
- Replace generic generated names with domain names.
- Remove scaffolding comments such as "add your code here."
- Verify security assumptions manually.

## Master Techniques For Maintainable Systems

**Make illegal states unrepresentable**

- Use enums, sealed classes, discriminated unions, newtypes, and validators.
- Replace loose strings with typed values.
- Separate raw input types from validated domain types.

**Push complexity to the edge**

- Parse and validate at boundaries.
- Keep the core domain pure where possible.
- Isolate side effects in adapters.

**Prefer boring architecture**

- Use simple layers before introducing event sourcing, CQRS, microservices, custom DSLs, or plugin systems.
- Do not distribute a problem until one process is proven insufficient.

**Design seams for tests**

- Inject clocks, random generators, clients, and storage interfaces.
- Keep time, randomness, filesystem, network, and process state outside pure logic.

**Use progressive hardening**

- Start correct.
- Add tests.
- Add observability.
- Add limits.
- Add retries.
- Add performance optimizations only where measured.

**Leave the code easier to change**

- Every change should improve at least one of correctness, clarity, testability, safety, or performance.
- If a fix requires understanding too much unrelated code, create a seam first.

## Quality Gates

A change is not ready until:

- It builds.
- It is formatted.
- It passes linting.
- It passes type checks.
- It passes relevant tests.
- New behavior is tested.
- Failure paths are handled.
- Logs and errors are actionable.
- Security-sensitive inputs are validated.
- Performance-sensitive paths are measured or bounded.
- Documentation is updated when behavior, setup, config, or operations change.

