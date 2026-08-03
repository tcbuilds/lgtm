---
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Naming Standards"]
rules:
  [
    {
      "id": "naming-review",
      "title": "Review identifier naming",
      "description": "Use specific, verb-first names and avoid placeholder identifiers in production code.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: validate_request; bad: foo",
          "schematic": true
        }
      ],
      "limitations": [
        "Only clearly placeholder function names are flagged; naming quality and protocol fields remain review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "refactoring",
      "applies_to": {
        "languages": [
          "python",
          "rust",
          "typescript",
          "javascript",
          "go"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "function",
          "identifier"
        ]
      },
      "instruction": "Use domain-specific, verb-first names; avoid placeholder identifiers such as foo, bar, tmp, or thing.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.naming"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    }
  ]
---

# Naming Standards

- Use full words except universal terms such as ID, URL, API, HTTP, SQL, IP, CPU, GPU, and UI.
- Name booleans as predicates: `isReady`, `hasGeo`, `canRetry`, or `shouldFlush`.
- Use verb-first function names such as `parseEvent`, `calculateScore`, and `validateConfig`.
- Name types for domain concepts, not implementation trivia: `EventBuffer`, not `DataManager`.
- Avoid vague names such as `thing`, `stuff`, `data`, `payload2`, `helper`, `manager`, and `processor`.
- Give constants units where relevant: `REQUEST_TIMEOUT_MS`, `maxRetries`, or `cacheTtlSeconds`.
- Name errors for the failure: `ConfigMissing`, `InvalidSignature`, or `StorageUnavailable`.

<!-- lgtm-rule: naming-review -->
#### Review identifier naming
