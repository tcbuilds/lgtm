---
paths:
  - "**/*.{java,kt,kts}"
---

# Java And Kotlin

## Java

- Use modern Java LTS features where supported.
- Use immutable value objects for domain data.
- Avoid checked-exception noise at low levels by converting to meaningful domain errors.
- Use dependency injection without hiding all construction behind magic.
- Keep controllers thin and services cohesive.
- Use JUnit, AssertJ, SpotBugs/Error Prone, Checkstyle or equivalent gates.
- Avoid `null` as a control-flow mechanism. Use `Optional` at boundaries only.

## Kotlin

- Prefer non-null types and sealed classes for state.
- Use data classes for values and immutable collections by default.
- Avoid platform types leaking across boundaries.
- Use coroutines with structured concurrency.
- Use `Result` or sealed error types for expected failures.
- Run ktlint, detekt, and tests.
