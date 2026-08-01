---
paths:
  - "**/*.{sh,bash,zsh}"
---

# Shell

- Prefer shell only for glue. Use a real language for complex logic.
- Start scripts with `set -euo pipefail` when compatible.
- Quote variables.
- Use `shellcheck`.
- Check command availability and required environment variables.
- Avoid parsing human-formatted command output when machine formats exist.
- Make scripts idempotent.
