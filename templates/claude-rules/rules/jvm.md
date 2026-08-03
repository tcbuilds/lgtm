---
paths:
  - "**/*.{java,kt,kts}"
headings: ["Java", "Kotlin"]
rules:
  [
    {
      "id": "jvm-review",
      "title": "Review Java and Kotlin boundaries",
      "description": "JVM changes should use nullability, immutable domain values, controller boundaries, structured concurrency, and typed errors.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "java",
          "text": "good: typed domain error at the boundary; bad: nullable controller state leaks into infrastructure",
          "schematic": true
        }
      ],
      "limitations": [
        "Formatter, analyzer, nullability, and concurrency semantics depend on configured Gradle/Maven tools."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "java",
          "kotlin"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{java,kt,kts}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "java",
          "kotlin",
          "jvm",
          "controller",
          "coroutine"
        ]
      },
      "instruction": "Review nullability, immutable domain modeling, controller/infrastructure boundaries, structured concurrency, cancellation, and typed error conversion; run the workspace's configured Gradle/Maven gates.",
      "enforcement": {
        "mode": "instruction",
        "checks": []
      },
      "overridable": true,
      "evidence": {
        "required": [
          "review_result"
        ]
      }
    }
  ]
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

<!-- lgtm-rule: jvm-review -->
#### Review Java and Kotlin boundaries
