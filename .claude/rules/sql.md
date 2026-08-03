---
paths:
  - "**/*.sql"
  - "**/migrations/**"
headings: ["SQL"]
rules:
  [
    {
      "id": "sql-migration-review",
      "title": "Review SQL migrations and queries",
      "description": "SQL changes need parameterized input, explicit columns, transaction and constraint review, reversible migrations, rollback evidence, and hot-query plan review.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "sql",
          "text": "good: explicit columns inside a transaction; bad: SELECT * and an irreversible migration with no rollback",
          "schematic": true
        }
      ],
      "limitations": [
        "Migration framework and query-plan semantics depend on configured SQL tooling and database evidence."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "sql"
        ],
        "domains": [
          "database"
        ],
        "file_patterns": [
          "**/*.sql"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "sql",
          "migration",
          "query",
          "database"
        ]
      },
      "instruction": "Use parameterized inputs and explicit columns; review transactions, constraints, reversibility, rollback, and hot-query plans with real database evidence.",
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

# SQL

- Use migrations for schema changes.
- Keep migrations reversible when practical.
- Use explicit column lists.
- Use indexes intentionally and verify query plans for hot queries.
- Avoid SELECT * in application code.
- Enforce constraints in the database, not only in application code.
- Use transactions for multi-step writes.
- Never construct SQL with string concatenation.

<!-- lgtm-rule: sql-migration-review -->
#### Review SQL migrations and queries
