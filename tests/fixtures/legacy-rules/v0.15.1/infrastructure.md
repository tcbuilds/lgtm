---
description: LGTM infrastructure engineering rules.
paths:
  - "**/*.{tf,tfvars}"
  - "**/Dockerfile*"
  - "**/docker-compose*.{yml,yaml}"
  - "**/.github/workflows/*.{yml,yaml}"
headings: ["Infrastructure As Code"]
rules:
  [
    {
      "id": "iac-validation-review",
      "title": "Review infrastructure validation",
      "description": "Infrastructure changes require format, validation, least privilege, and rollback evidence.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "terraform",
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
          "terraform"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tf,tfvars}"
        ,
          "**/Dockerfile*"
        ,
          "**/docker-compose*.{yml,yaml}"
        ,
          "**/.github/workflows/*.{yml,yaml}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Infrastructure changes require format, validation, least privilege, and rollback evidence.",
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

# Infrastructure As Code

- Run format and validation: `terraform fmt`, `terraform validate`, `tflint`, `yamllint`, or equivalents.
- Keep secrets out of state files and templates.
- Pin provider versions.
- Use least privilege IAM.
- Add outputs intentionally. Outputs can leak sensitive data.
- Use plan review before apply.
- Document rollback for risky infrastructure changes.

<!-- lgtm-rule: iac-validation-review -->
#### Review infrastructure validation
