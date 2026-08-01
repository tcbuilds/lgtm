---
paths:
  - "**/*.{tf,tfvars}"
  - "**/Dockerfile*"
  - "**/docker-compose*.{yml,yaml}"
  - "**/.github/workflows/*.{yml,yaml}"
---

# Infrastructure As Code

- Run format and validation: `terraform fmt`, `terraform validate`, `tflint`, `yamllint`, or equivalents.
- Keep secrets out of state files and templates.
- Pin provider versions.
- Use least privilege IAM.
- Add outputs intentionally. Outputs can leak sensitive data.
- Use plan review before apply.
- Document rollback for risky infrastructure changes.
