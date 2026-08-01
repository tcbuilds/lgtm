---
paths:
  - "**/*.py"
  - "**/*.pyi"
---

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
