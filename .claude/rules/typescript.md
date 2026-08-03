---
paths:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
headings: ["TypeScript And JavaScript"]
rules:
  [
    {
      "id": "typescript-no-any",
      "title": "Avoid TypeScript any",
      "description": "TypeScript boundaries should use unknown or a precise type.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "typescript",
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
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{ts,tsx,js,jsx,mjs,cjs}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "TypeScript boundaries should use unknown or a precise type.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.typescript-no-any"
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
      "id": "typescript-unsafe-unknown",
      "title": "Narrow external JSON",
      "description": "External JSON must be parsed as unknown and narrowed before use.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: validate at the boundary; bad: trust raw JSON",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common boundary calls and requires review for wrappers and schema libraries."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "validation",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{ts,tsx,js,jsx,mjs,cjs}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "External JSON must be parsed as unknown and narrowed before use.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.typescript-unsafe-unknown"
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
      "id": "typescript-api-response-validation",
      "title": "Validate API responses",
      "description": "API responses require explicit runtime validation before use.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: validate at the boundary; bad: trust raw JSON",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check identifies common boundary calls and requires review for wrappers and schema libraries."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "validation",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{ts,tsx,js,jsx,mjs,cjs}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "API responses require explicit runtime validation before use.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.typescript-api-response-validation"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result"
        ]
      }
    }
  ]
---

## Unknown at boundaries, never any

`any` disables checking silently and spreads. `unknown` forces a narrowing step at
the point where you actually know the shape.

```typescript
function handle(input: unknown) {
  if (typeof input === 'string') { ... }
}
```

# TypeScript And JavaScript

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

<!-- lgtm-rule: typescript-no-any -->
#### Avoid TypeScript any
<!-- lgtm-rule: typescript-unsafe-unknown -->
#### Narrow external JSON
<!-- lgtm-rule: typescript-api-response-validation -->
#### Validate API responses
