---
paths:
  - "**/*.{yaml,yml,json,toml,ini,env}"
  - "**/.env.example"
---

# YAML, JSON, And Config

- Validate config with schemas when possible.
- Keep environment-specific values outside shared templates.
- Include units in config names.
- Prefer explicit defaults in code and documented examples in `.env.example`.
- Avoid duplicate config keys across files.
