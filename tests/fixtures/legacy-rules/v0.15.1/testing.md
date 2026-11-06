---
description: LGTM testing rules.
paths:
  - "**/*.{py,rs,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hh,hpp,hxx}"
  - "**/test_*.py"
  - "**/*_test.{py,go,rs}"
  - "**/*.{test,spec}.{ts,tsx,js,jsx}"
  - "**/tests/**"
  - "**/__tests__/**"
headings: ["Testing Standards"]
rules:
  [
    {
      "id": "regression-test-required",
      "title": "Regression tests required",
      "description": "Observable bug fixes require regression coverage.",
      "severity": "error",
      "level": "must",
      "category": "testing",
      "applies_to": {
        "languages": [
          "python",
          "rust",
          "typescript",
          "javascript",
          "go",
          "java",
          "kotlin",
          "csharp",
          "c",
          "cpp"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.py",
          "**/*.rs",
          "**/*.ts",
          "**/*.tsx",
          "**/*.js",
          "**/*.jsx",
          "**/*.mjs",
          "**/*.cjs",
          "**/*.go",
          "**/*.java",
          "**/*.kt",
          "**/*.kts",
          "**/*.cs",
          "**/*.c",
          "**/*.cc",
          "**/*.cpp",
          "**/*.cxx",
          "**/*.h",
          "**/*.hh",
          "**/*.hpp",
          "**/*.hxx"
        ]
      },
      "activation": {
        "change_types": [
          "modify"
        ],
        "signals": [
          "bug-fix"
        ]
      },
      "instruction": "Add a deterministic regression test for observable bug fixes.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      },
      "mechanism": "review",
      "confidence": "medium",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy Regression tests required; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop",
      "language_implementations": {
        "python": {
          "mechanism": "review",
          "checks": [
            "git.diff"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "new-behavior-tests-required",
      "title": "New behavior tests required",
      "description": "Source behavior changes require corresponding tests.",
      "severity": "error",
      "level": "must",
      "category": "testing",
      "applies_to": {
        "languages": [
          "python",
          "rust",
          "typescript",
          "javascript",
          "go",
          "java",
          "kotlin",
          "csharp",
          "c",
          "cpp"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.py",
          "**/*.rs",
          "**/*.ts",
          "**/*.tsx",
          "**/*.js",
          "**/*.jsx",
          "**/*.mjs",
          "**/*.cjs",
          "**/*.go",
          "**/*.java",
          "**/*.kt",
          "**/*.kts",
          "**/*.cs",
          "**/*.c",
          "**/*.cc",
          "**/*.cpp",
          "**/*.cxx",
          "**/*.h",
          "**/*.hh",
          "**/*.hpp",
          "**/*.hxx"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Add deterministic tests for new or changed source behavior.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      },
      "mechanism": "review",
      "confidence": "medium",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy New behavior tests required; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop",
      "language_implementations": {
        "python": {
          "mechanism": "review",
          "checks": [
            "git.diff"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "test-naming-review",
      "title": "Review test names",
      "description": "Test names should describe the observable behavior under test instead of generic placeholders.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: rejects_expired_token; bad: test",
          "schematic": true
        }
      ],
      "limitations": [
        "Only generic parser symbols are flagged; framework-specific naming conventions remain review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "testing",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/test_*.py",
          "**/*_test.{py,go,rs}",
          "**/*.{test,spec}.{ts,tsx,js,jsx}",
          "**/tests/**",
          "**/__tests__/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "test",
          "spec"
        ]
      },
      "instruction": "Name tests after the observable behavior and expected outcome they verify.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.test-naming"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    },
    {
      "id": "determinism-review",
      "title": "Review test determinism",
      "description": "Unit tests should avoid real sleeps, unseeded randomness, live network calls, shared mutable fixtures, and paid external dependencies unless explicitly marked integration/e2e.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: inject a clock and seed randomness; bad: sleep and call a live API in a unit test",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical signals cannot prove order dependence or paid dependencies; explicit integration/e2e paths are allowed."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "testing",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/test_*.py",
          "**/*_test.{py,go,rs}",
          "**/*.{test,spec}.{ts,tsx,js,jsx}",
          "**/tests/**",
          "**/__tests__/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "test",
          "sleep",
          "random",
          "network"
        ]
      },
      "instruction": "Keep unit tests deterministic: inject clocks, seed randomness, avoid real sleeps/live network/paid dependencies, and isolate mutable fixtures; mark integration/e2e tests explicitly.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.determinism"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    },
    {
      "id": "behavior-test-quality",
      "title": "Review behavior-test assertions",
      "description": "Tests should assert observable outcomes rather than only running code or asserting an unconditional truth.",
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: assert_eq!(result, expected); bad: assert!(true)",
          "schematic": true
        }
      ],
      "limitations": [
        "Only high-confidence trivial assertions are flagged; semantic assertion strength remains review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "testing",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/test_*.py",
          "**/*_test.{py,go,rs}",
          "**/*.{test,spec}.{ts,tsx,js,jsx}",
          "**/tests/**",
          "**/__tests__/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "test",
          "assertion"
        ]
      },
      "instruction": "Assert observable outcomes and meaningful error cases; do not use smoke-only or unconditional truth assertions as proof.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result"
        ]
      }
    },
    {
      "id": "test-quality-guidance",
      "title": "Select appropriate test types",
      "description": "Choose test forms that match the changed behavior: table-driven and property tests for parsers/validators/classifiers, golden tests for stable generated output, contract tests at service/schema boundaries, and integration tests for public APIs.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: use a golden test for stable JSON output; bad: assert only that a function did not throw",
          "schematic": true
        }
      ],
      "limitations": [
        "Signals request review; they do not prove assertion strength or coverage percentage."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "testing",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/test_*.py",
          "**/*_test.{py,go,rs}",
          "**/*.{test,spec}.{ts,tsx,js,jsx}",
          "**/tests/**",
          "**/__tests__/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "parser",
          "validator",
          "classifier",
          "generated-output",
          "service-boundary",
          "schema",
          "public-api"
        ]
      },
      "instruction": "Match test style to the change: table-driven/property/fuzz tests for parsers and validators; golden tests for stable output; contract tests at service/schema boundaries; integration tests for public APIs.",
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

## Name the behaviour, not the function

The name should read as a claim about the system, so a failure line tells you what
broke without opening the file.

```
bad:   test_parse_date_2
good:  test_elapsed_expiry_does_not_invalidate_the_store
bad:   it('works')
good:  it('drops expired waivers and keeps current ones')
```

## Table-driven for anything with cases

Use table-driven tests for parsers, validators, and classifiers so each input and
expected outcome is visible in the failure.

## Test both directions of every guard

A test proving a check fires is half a test. The other half proves it does not fire
when it shouldn't — that is where false positives hide.

## Regression test names the bug

```rust
#[test]
fn accepts_new_file_inside_directories_that_do_not_exist_yet() { ... }
```

Write it before the fix and watch it fail. A regression test that has never failed
proves nothing.

## Tests are deterministic and order-independent

No shared mutable fixtures, no reliance on execution order, no real network, no
sleeps. Use unique temp directories per test and clean up. A flaky test is worse
than no test: it trains people to ignore red.

## Assert on values, not on logs

```python
# bad
assert "saved" in caplog.text

# good
assert store.get(key) == value
```

Log text is presentation. Asserting on it breaks when you improve a message.

# Testing Standards

## Minimum expectations

- Unit coverage target: 80 percent minimum, 90 percent preferred.
- Critical paths: 100 percent behavior coverage.
- Public APIs: integration tests.
- Bug fixes: regression test first or in the same change.
- Tests must be deterministic, isolated, and runnable locally.

## Test quality

- Test behavior, not private implementation details.
- Use table-driven tests for parsers, classifiers, validators, and edge cases.
- Use property-based tests for serialization, parsing, scoring, normalization, and math-heavy logic.
- Use golden tests for stable text, JSON, CLI output, and generated artifacts.
- Use contract tests for service boundaries and cross-language schemas.
- Use fuzz tests for parsers, decoders, auth/token handlers, and anything that consumes untrusted input.
- Prefer real lightweight dependencies over excessive mocking. Mock only slow, flaky, paid, or external systems.

## Naming

- Python: `test_<behavior>_<condition>()`
- Rust: `fn parses_valid_nginx_line()`
- TypeScript: `it('renders reconnecting status after socket close', ...)`
- Go: `TestParserRejectsMalformedLine`
- Java/Kotlin/C#: `method_condition_expectedResult`

<!-- lgtm-rule: regression-test-required -->
#### Regression tests required
<!-- lgtm-rule: new-behavior-tests-required -->
#### New behavior tests required
<!-- lgtm-rule: test-naming-review -->
#### Review test names
<!-- lgtm-rule: determinism-review -->
#### Review test determinism
<!-- lgtm-rule: behavior-test-quality -->
#### Review behavior-test assertions
<!-- lgtm-rule: test-quality-guidance -->
#### Select appropriate test types
