---
paths:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
---

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
