---
paths:
  - "**/*.go"
headings: ["Go"]
rules:
  [
    {
      "id": "go-ignored-error",
      "title": "Check Go ignored errors",
      "description": "Go errors should be checked or deliberately documented, not discarded.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "go",
          "text": "good: handle and wrap causes; bad: discard or detach errors",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common patterns and requires review for interfaces, generated code, and wrappers."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.go"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Go errors should be checked or deliberately documented, not discarded.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.go-ignored-error"
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
      "id": "go-goroutine-cancellation",
      "title": "Review Go goroutine cancellation",
      "description": "Go goroutines require cancellation and error reporting.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "go",
          "text": "good: handle and wrap causes; bad: discard or detach errors",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common patterns and requires review for interfaces, generated code, and wrappers."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.go"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Go goroutines require cancellation and error reporting.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.go-goroutine-cancellation"
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
      "id": "go-mutable-global",
      "title": "Review Go mutable globals",
      "description": "Go package-level mutable state requires explicit review.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "go",
          "text": "good: handle and wrap causes; bad: discard or detach errors",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common patterns and requires review for interfaces, generated code, and wrappers."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.go"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Go package-level mutable state requires explicit review.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.go-mutable-global"
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
      "id": "go-error-wrapping",
      "title": "Review Go error wrapping",
      "description": "Go wrapped errors should preserve causes with %w where appropriate.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "go",
          "text": "good: handle and wrap causes; bad: discard or detach errors",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common patterns and requires review for interfaces, generated code, and wrappers."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.go"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Go wrapped errors should preserve causes with %w where appropriate.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.go-error-wrapping"
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
      "id": "go-context-first-review",
      "title": "Review Go context placement",
      "description": "Request-scoped Go functions should accept context.Context as the first parameter.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "go",
          "text": "good: func Run(ctx context.Context, ...); bad: hide context in globals",
          "schematic": true
        }
      ],
      "limitations": [
        "Context placement is review guidance until grammar-backed analysis is available."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.go"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Review request-scoped Go functions for context.Context as the first parameter.",
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

## Wrap errors with `%w`, define sentinels for branchable failures

```go
var ErrNotFound = errors.New("not found")

func Load(id string) (*Rule, error) {
    row, err := db.Query(id)
    if err != nil {
        return nil, fmt.Errorf("loading rule %s: %w", id, err)
    }
    ...
}

// callers branch without string matching
if errors.Is(err, ErrNotFound) { ... }
```

Never `fmt.Errorf("...: %v", err)` — that severs the chain.

## Context first, and actually honour it

```go
func Fetch(ctx context.Context, url string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, fmt.Errorf("building request: %w", err)
    }
    ...
}
```

Never store a `context.Context` in a struct. Pass it as the first argument.

## Every goroutine has an owner and an exit

```go
// bad — fire and forget, no way to know it died
go process(items)

// good
g, ctx := errgroup.WithContext(ctx)
for _, item := range items {
    g.Go(func() error { return process(ctx, item) })
}
if err := g.Wait(); err != nil {
    return fmt.Errorf("processing: %w", err)
}
```

Ask of every `go` statement: who waits for it, and what happens when it fails?

# Go

- `gofmt`, `go vet`, `staticcheck`, and `go test ./...` must pass.
- Always check errors.
- Wrap errors with context using `%w`.
- Accept `context.Context` as the first argument for request-scoped work.
- Keep interfaces small and consumer-owned.
- Do not start goroutines without cancellation and error reporting.
- Use table-driven tests.
- Avoid package-level mutable state.
- Prefer explicit structs over maps for domain data.

<!-- lgtm-rule: go-ignored-error -->
#### Check Go ignored errors
<!-- lgtm-rule: go-goroutine-cancellation -->
#### Review Go goroutine cancellation
<!-- lgtm-rule: go-mutable-global -->
#### Review Go mutable globals
<!-- lgtm-rule: go-error-wrapping -->
#### Review Go error wrapping
<!-- lgtm-rule: go-context-first-review -->
#### Review Go context placement
