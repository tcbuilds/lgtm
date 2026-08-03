---
paths:
  - "**/*.py"
  - "**/*.pyi"
headings: ["Python"]
rules:
  [
    {
      "id": "no-swallowed-errors",
      "title": "No swallowed errors",
      "description": "Errors must not be silently discarded. An intentionally ignored error must be documented with the reason, and broad exception handling must add context and re-raise or convert.",
      "severity": "error",
      "level": "must",
      "category": "error-handling",
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
          "exception-handler",
          "try-except",
          "bare-except"
        ]
      },
      "instruction": "Do not catch and suppress errors. Convert unknown external errors into typed domain errors, add context before propagating, and never leave a bare or empty except.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "ruff.check"
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
          "text": "good: satisfy No swallowed errors; bad: bypass it",
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
            "ruff.check"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "no-broad-exception-handling",
      "title": "No broad exception handling",
      "description": "Exception handlers must catch only the specific failures an operation can raise.",
      "severity": "error",
      "level": "must",
      "category": "error-handling",
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
          "exception-handler",
          "try-except",
          "bare-except"
        ]
      },
      "instruction": "Catch specific exception types. Do not use bare except or catch Exception without converting, contextualizing, or re-raising it.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "ruff.check"
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
          "text": "good: satisfy No broad exception handling; bad: bypass it",
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
            "ruff.check"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    },
    {
      "id": "external-call-timeout",
      "title": "External calls require timeouts",
      "description": "Network, database, subprocess, lock, and external API operations must have explicit bounded timeouts.",
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
          "http-client",
          "database-client",
          "subprocess",
          "lock",
          "external-api"
        ]
      },
      "instruction": "Add an explicit timeout and ensure cancellation or cleanup is handled.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "semgrep.external-call-timeout"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      },
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "python",
          "text": "good: satisfy External calls require timeouts; bad: bypass it",
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
            "semgrep.external-call-timeout"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    }
  ]
---

## Narrow exception handling with context

```python
# bad
except Exception:
    return None

# good
except json.JSONDecodeError as exc:
    raise ConfigInvalid(f"parsing {path}") from exc
```

`from exc` preserves the chain. Returning `None` on failure discards the reason
and pushes the bug downstream.

# Python

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

<!-- lgtm-rule: no-swallowed-errors -->
#### No swallowed errors
<!-- lgtm-rule: no-broad-exception-handling -->
#### No broad exception handling
<!-- lgtm-rule: external-call-timeout -->
#### External calls require timeouts
