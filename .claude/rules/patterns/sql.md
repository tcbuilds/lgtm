---
paths:
  - "**/*.sql"
  - "**/migrations/**"
  - "**/*.py"
rules:
  [
    {
      "id": "sql-parameterization",
      "title": "Parameterize SQL",
      "description": "SQL statements must not interpolate untrusted values.",
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
          "database-write",
          "database-client"
        ]
      },
      "instruction": "Use driver parameters for every dynamic SQL value.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "semgrep.sql-parameterization"
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
          "text": "good: satisfy Parameterize SQL; bad: bypass it",
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
            "semgrep.sql-parameterization"
          ],
          "limitations": [
            "Language-specific behavior may differ outside registered checks."
          ]
        }
      }
    }
  ]
---

# SQL Patterns

## Set-based, not row-by-row

One statement that expresses the whole change beats a loop issuing statements. The
loop is slower by orders of magnitude and is not atomic.

```sql
-- bad: application loops, one UPDATE per row
-- good:
UPDATE invoices
SET    status = 'overdue'
WHERE  status = 'unpaid'
AND    due_date < CURRENT_DATE;
```

## Keep predicates sargable

A function wrapped around an indexed column disables the index.

```sql
-- bad — cannot use an index on created_at
WHERE DATE(created_at) = '2026-08-01'

-- good — range scan on the index
WHERE created_at >= '2026-08-01'
AND   created_at <  '2026-08-02'
```

Same trap with leading wildcards (`LIKE '%foo'`) and implicit casts between a
text column and a numeric parameter.

## Explicit column lists everywhere

```sql
-- bad — breaks silently when a column is added or reordered
SELECT * FROM users;

-- good
SELECT id, email, created_at FROM users;
```

`SELECT *` in application code also drags large columns over the wire for no reason.

## Insert-or-update, atomically

```sql
INSERT INTO counters (key, value)
VALUES ($1, 1)
ON CONFLICT (key)
DO UPDATE SET value = counters.value + 1;
```

A `SELECT` followed by `INSERT` or `UPDATE` is a race. Let the database do it in
one statement.

## Constraints in the schema, not only in the app

```sql
ALTER TABLE waivers
    ADD CONSTRAINT waivers_expires_future CHECK (expires_at > created_at),
    ALTER COLUMN rule_id SET NOT NULL,
    ADD CONSTRAINT waivers_rule_fk FOREIGN KEY (rule_id) REFERENCES rules (id);
```

Application checks are advisory — anything with database credentials can bypass
them. Constraints are the only rule that always holds.

## Expand then contract for schema change

Code and schema do not deploy at the same instant. Split every breaking change:

1. **Expand** — add the new column as nullable, write to both, deploy.
2. **Backfill** — populate existing rows in batches.
3. **Contract** — once all readers are migrated, add `NOT NULL` and drop the old column.

Adding a `NOT NULL` column and the code that writes it in one deploy breaks every
instance still running the old build.

## Migrations are forward-only and reversible in practice

Give every migration a tested down path, or document explicitly why it is
irreversible. Never edit a migration that has run anywhere — write a new one.

## Batch large backfills

```sql
UPDATE invoices
SET    currency = 'USD'
WHERE  id IN (
    SELECT id FROM invoices WHERE currency IS NULL LIMIT 5000
);
```

A single unbounded `UPDATE` takes locks for its whole duration and can stall the
table. Loop in bounded chunks with a commit between.

## Indexes are deliberate, and verified

Add an index because a query plan showed a scan you cannot afford — then confirm
with `EXPLAIN (ANALYZE)` that the plan actually changed. Every index costs write
throughput and storage. Composite index column order matters: equality columns
first, range last.

## Transactions wrap multi-step writes, and stay short

```sql
BEGIN;
UPDATE accounts SET balance = balance - $1 WHERE id = $2;
UPDATE accounts SET balance = balance + $1 WHERE id = $3;
COMMIT;
```

Never hold a transaction open across a network call or user input. Lock ordering
must be consistent across code paths or you will deadlock.

## Parameters, never string building

```python
# bad
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# good
cursor.execute("SELECT id, email FROM users WHERE email = %s", (email,))
```

This is not a style preference. String-built SQL is the single most exploited
vulnerability class in existence.

## NULL is not a value

`NULL = NULL` is unknown, not true. Use `IS NULL`, and remember `NOT IN` against a
set containing `NULL` returns no rows at all.

<!-- lgtm-rule: sql-parameterization -->
#### Parameterize SQL
