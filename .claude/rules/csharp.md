---
paths:
  - "**/*.cs"
headings: ["C#"]
rules:
  [
    {
      "id": "csharp-review",
      "title": "Review C# boundaries",
      "description": "C# changes should preserve nullable contracts, async cancellation, immutable values, and dependency-injection lifetime safety.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "csharp",
          "text": "good: pass CancellationToken and bound service lifetimes; bad: fire-and-forget async work with nullable state",
          "schematic": true
        }
      ],
      "limitations": [
        "Roslyn analyzers, nullable settings, and DI lifetime semantics depend on configured dotnet projects."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "csharp"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.cs"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "csharp",
          "dotnet",
          "async",
          "dependency-injection"
        ]
      },
      "instruction": "Review nullable contracts, cancellation tokens, immutable value types, async lifetime safety, and DI scopes; run configured dotnet format/build/test gates.",
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

# C#

- Enable nullable reference types.
- Use async all the way for I/O paths.
- Avoid `.Result` and `.Wait()` in async code.
- Use records for immutable values.
- Use dependency injection with explicit lifetimes.
- Run `dotnet format`, analyzers, and tests.
- Include cancellation tokens for external and long-running work.

<!-- lgtm-rule: csharp-review -->
#### Review C# boundaries
