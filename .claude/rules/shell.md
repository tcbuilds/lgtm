---
description: LGTM shell engineering rules.
paths:
  - "**/*.{sh,bash,zsh}"
headings: ["Shell"]
rules:
  [
    {
      "id": "shell-safety-review",
      "title": "Review shell safety",
      "description": "Quote variables, use safe parsing, and check command availability in shell glue.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "shell",
          "text": "good: validate and bound the change; bad: apply unreviewed mutable configuration",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic shell/IaC/config safety is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "infrastructure",
      "applies_to": {
        "languages": [
          "shell"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{sh,bash,zsh}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Quote variables, use safe parsing, and check command availability in shell glue.",
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
      "id": "shell-idempotency-review",
      "title": "Review shell idempotency",
      "description": "Shell automation should be idempotent and use bounded failure handling.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "shell",
          "text": "good: validate and bound the change; bad: apply unreviewed mutable configuration",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic shell/IaC/config safety is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "infrastructure",
      "applies_to": {
        "languages": [
          "shell"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{sh,bash,zsh}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Shell automation should be idempotent and use bounded failure handling.",
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

# Shell

- Prefer shell only for glue. Use a real language for complex logic.
- Start scripts with `set -euo pipefail` when compatible.
- Quote variables.
- Use `shellcheck`.
- Check command availability and required environment variables.
- Avoid parsing human-formatted command output when machine formats exist.
- Make scripts idempotent.

<!-- lgtm-rule: shell-safety-review -->
#### Review shell safety
<!-- lgtm-rule: shell-idempotency-review -->
#### Review shell idempotency
