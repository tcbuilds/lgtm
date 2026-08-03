---
paths:
  - "**/*.rs"
headings: ["Rust"]
rules:
  [
    {
      "id": "rust-no-unsafe",
      "title": "Forbid unreviewed Rust unsafe",
      "description": "Rust unsafe requires approved invariants and architecture review.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "rust",
          "text": "good: use the supported pattern; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "The native check is lexical and requires review for complex syntax."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "should",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Rust unsafe requires approved invariants and architecture review.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.rust-no-unsafe"
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
      "id": "rust-no-unwrap-expect",
      "title": "Avoid Rust unwrap and expect",
      "description": "Production Rust paths should use typed error handling.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "rust",
          "text": "good: use the supported pattern; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "The native check is lexical and requires review for complex syntax."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "should",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Production Rust paths should use typed error handling.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.rust-no-unwrap-expect"
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
      "id": "rust-spawn-cancellation",
      "title": "Bound Rust spawned tasks",
      "description": "Spawned Rust tasks require cancellation and error reporting.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "rust",
          "text": "good: propagate cancellation and errors; bad: detach work",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common spawn/global syntax and requires review for wrappers and macros."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Spawned Rust tasks require cancellation and error reporting.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.rust-spawn-cancellation"
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
      "id": "rust-no-mutable-global",
      "title": "Avoid mutable Rust globals",
      "description": "Mutable Rust globals require explicit architecture review.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "rust",
          "text": "good: propagate cancellation and errors; bad: detach work",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common spawn/global syntax and requires review for wrappers and macros."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Mutable Rust globals require explicit architecture review.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.rust-no-mutable-global"
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
      "id": "rust-async-timeout-review",
      "title": "Review Rust external async timeouts",
      "description": "External Rust async work should use explicit timeout and cancellation boundaries.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "rust",
          "text": "good: make boundaries typed and cancellable; bad: pass loose strings or detached work",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic async and domain modeling proof is not claimed."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "External Rust async work should use explicit timeout and cancellation boundaries.",
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
    },
    {
      "id": "rust-id-unit-newtype-review",
      "title": "Review Rust IDs and units",
      "description": "Rust IDs, units, and validated strings should use domain newtypes at boundaries.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "rust",
          "text": "good: make boundaries typed and cancellable; bad: pass loose strings or detached work",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic async and domain modeling proof is not claimed."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "rust"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.rs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Rust IDs, units, and validated strings should use domain newtypes at boundaries.",
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

## Newtypes for identifiers and units

A function taking three `String` arguments accepts them in any order. A function
taking `UserId`, `TenantId`, `Email` does not.

```rust
// bad
fn transfer(from: String, to: String, amount: u64) { ... }

// good
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cents(u64);

fn transfer(from: &AccountId, to: &AccountId, amount: Cents) { ... }
```

Wrap units too. `Cents` and `Dollars` are not interchangeable, and `Duration`
beats a bare `u64` that might be seconds or milliseconds.

# Rust

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

<!-- lgtm-rule: rust-no-unsafe -->
#### Forbid unreviewed Rust unsafe
<!-- lgtm-rule: rust-no-unwrap-expect -->
#### Avoid Rust unwrap and expect
<!-- lgtm-rule: rust-spawn-cancellation -->
#### Bound Rust spawned tasks
<!-- lgtm-rule: rust-no-mutable-global -->
#### Avoid mutable Rust globals
<!-- lgtm-rule: rust-async-timeout-review -->
#### Review Rust external async timeouts
<!-- lgtm-rule: rust-id-unit-newtype-review -->
#### Review Rust IDs and units
