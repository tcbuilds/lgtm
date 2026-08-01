---
paths:
  - "**/test_*.py"
  - "**/*_test.{py,go,rs}"
  - "**/*.{test,spec}.{ts,tsx,js,jsx}"
  - "**/tests/**"
  - "**/__tests__/**"
---

# Testing

## Minimum expectations

- Unit coverage target: 80 percent minimum, 90 percent preferred.
- Critical paths: 100 percent behavior coverage.
- Public APIs: integration tests.
- Bug fixes: regression test first or in the same change.
- Tests must be deterministic, isolated, and runnable locally.

## Test quality

- Test behavior, not private implementation details.
- Use table-driven tests for parsers, classifiers, validators, and edge cases.
- Use property-based tests for serialization, parsing, scoring, normalization, and math-heavy logic.
- Use golden tests for stable text, JSON, CLI output, and generated artifacts.
- Use contract tests for service boundaries and cross-language schemas.
- Use fuzz tests for parsers, decoders, auth/token handlers, and anything that consumes untrusted input.
- Prefer real lightweight dependencies over excessive mocking. Mock only slow, flaky, paid, or external systems.

## Naming

- Python: `test_<behavior>_<condition>()`
- Rust: `fn parses_valid_nginx_line()`
- TypeScript: `it('renders reconnecting status after socket close', ...)`
- Go: `TestParserRejectsMalformedLine`
- Java/Kotlin/C#: `method_condition_expectedResult`
