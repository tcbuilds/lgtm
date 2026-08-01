---
paths:
  - "**/*.go"
---

# Go

- `gofmt`, `go vet`, `staticcheck`, and `go test ./...` must pass.
- Always check errors.
- Wrap errors with context using `%w`.
- Accept `context.Context` as the first argument for request-scoped work.
- Keep interfaces small and consumer-owned.
- Do not start goroutines without cancellation and error reporting.
- Use table-driven tests.
- Avoid package-level mutable state.
- Prefer explicit structs over maps for domain data.
