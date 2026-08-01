---
paths:
  - "**/*.sql"
  - "**/migrations/**"
---

# SQL

- Use migrations for schema changes.
- Keep migrations reversible when practical.
- Use explicit column lists.
- Use indexes intentionally and verify query plans for hot queries.
- Avoid SELECT * in application code.
- Enforce constraints in the database, not only in application code.
- Use transactions for multi-step writes.
- Never construct SQL with string concatenation.
