---
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Error Handling"]
rules:
  [
    {
      "id": "destructive-operation-safeguards",
      "title": "Safeguard destructive operations",
      "description": "Recursive destructive operations require explicit safeguards.",
      "severity": "error",
      "level": "must",
      "category": "security",
      "applies_to": {
        "languages": [
          "python"
        ],
        "domains": [
          "backend",
          "api",
          "worker",
          "infrastructure"
        ],
        "file_patterns": [
          "**/*.py"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "destructive-operation"
        ]
      },
      "instruction": "Require explicit confirmation and validate the target before recursive deletion.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "semgrep.destructive-operation-safeguards"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy Safeguard destructive operations; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "post_tool",
      "language_implementations": {
        "python": {
          "mechanism": "native",
          "checks": [
            "semgrep.destructive-operation-safeguards"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "boundary-error-review",
      "title": "Review boundary error handling",
      "description": "External errors must be contextualized, converted, rethrown, or deliberately handled; empty exception paths are not acceptable.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "python",
          "text": "good: except ExternalError: raise DomainError('context'); bad: except Exception: pass",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical review covers clear empty Python and JavaScript-family handlers; typed conversion, cleanup, retries, and log duplication remain language-specific review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "error-handling",
      "applies_to": {
        "languages": [
          "python",
          "typescript",
          "javascript"
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
          "exception-handler",
          "catch",
          "boundary"
        ]
      },
      "instruction": "At boundaries, add context and convert or rethrow unknown errors; do not leave empty exception handlers.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.boundary-errors"
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
      "id": "public-input-validation",
      "title": "Validate public input",
      "description": "Public request input must be validated before use.",
      "severity": "error",
      "level": "must",
      "category": "validation",
      "applies_to": {
        "languages": [
          "python"
        ],
        "domains": [
          "backend",
          "api"
        ],
        "file_patterns": [
          "**/*.py"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "public-input"
        ]
      },
      "instruction": "Validate and normalize public input with an explicit schema before use.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "semgrep.public-input-validation"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy Validate public input; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "post_tool",
      "language_implementations": {
        "python": {
          "mechanism": "native",
          "checks": [
            "semgrep.public-input-validation"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "bounded-retries-loops",
      "title": "Bound retries and loops",
      "description": "Retry and worker loops must have explicit termination bounds.",
      "severity": "error",
      "level": "must",
      "category": "reliability",
      "applies_to": {
        "languages": [
          "python"
        ],
        "domains": [
          "backend",
          "api",
          "worker"
        ],
        "file_patterns": [
          "**/*.py"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "retry",
          "loop"
        ]
      },
      "instruction": "Add an explicit attempt, time, or cancellation bound.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "semgrep.bounded-retries-loops"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy Bound retries and loops; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "post_tool",
      "language_implementations": {
        "python": {
          "mechanism": "native",
          "checks": [
            "semgrep.bounded-retries-loops"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    }
  ]
---

# Error Handling

- Validate at boundaries: API input, config, files, database rows, environment variables, and queue messages.
- Convert unknown external errors into typed domain errors as soon as they enter the system.
- Add context before propagating errors; never return a naked `failed` error.
- Log at the boundary that handles the error. Do not log and rethrow repeatedly.
- Retry only known transient failures, with exponential backoff, jitter, caps, and cancellation.
- Make destructive operations idempotent or guard them with explicit confirmation.
- Prefer typed result or error values over exceptions for expected failures when the language supports them.

<!-- lgtm-rule: destructive-operation-safeguards -->
#### Safeguard destructive operations
<!-- lgtm-rule: boundary-error-review -->
#### Review boundary error handling
<!-- lgtm-rule: public-input-validation -->
#### Validate public input
<!-- lgtm-rule: bounded-retries-loops -->
#### Bound retries and loops
