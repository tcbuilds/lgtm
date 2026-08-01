---
paths:
  - "**/*.go"
---

# Go Patterns

## Small, consumer-owned interfaces

Define the interface where it is used, not where it is implemented, and keep it to
the methods that caller needs.

```go
// bad — a wide interface in the producer package
type Storage interface {
    Read(string) ([]byte, error)
    Write(string, []byte) error
    List(string) ([]string, error)
    Delete(string) error
}

// good — declared by the consumer, one method
type reader interface {
    Read(key string) ([]byte, error)
}

func Sync(src reader) error { ... }
```

## Functional options for constructors

```go
type Option func(*Server)

func WithTimeout(d time.Duration) Option {
    return func(s *Server) { s.timeout = d }
}

func New(addr string, opts ...Option) *Server {
    s := &Server{addr: addr, timeout: 30 * time.Second}
    for _, opt := range opts {
        opt(s)
    }
    return s
}
```

Beats a config struct with a dozen zero-valued fields, and stays additive.

## Wrap errors with `%w`, define sentinels for branchable failures

```go
var ErrNotFound = errors.New("not found")

func Load(id string) (*Rule, error) {
    row, err := db.Query(id)
    if err != nil {
        return nil, fmt.Errorf("loading rule %s: %w", id, err)
    }
    ...
}

// callers branch without string matching
if errors.Is(err, ErrNotFound) { ... }
```

Never `fmt.Errorf("...: %v", err)` — that severs the chain.

## Context first, and actually honour it

```go
func Fetch(ctx context.Context, url string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, fmt.Errorf("building request: %w", err)
    }
    ...
}
```

Never store a `context.Context` in a struct. Pass it as the first argument.

## Every goroutine has an owner and an exit

```go
// bad — fire and forget, no way to know it died
go process(items)

// good
g, ctx := errgroup.WithContext(ctx)
for _, item := range items {
    g.Go(func() error { return process(ctx, item) })
}
if err := g.Wait(); err != nil {
    return fmt.Errorf("processing: %w", err)
}
```

Ask of every `go` statement: who waits for it, and what happens when it fails?

## Table-driven tests

```go
func TestParse(t *testing.T) {
    cases := []struct {
        name    string
        in      string
        want    Rule
        wantErr bool
    }{
        {name: "valid", in: "a=1", want: Rule{Key: "a", Value: 1}},
        {name: "missing value", in: "a=", wantErr: true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := Parse(tc.in)
            if (err != nil) != tc.wantErr {
                t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
            }
            ...
        })
    }
}
```

## `defer` immediately after acquiring

```go
mu.Lock()
defer mu.Unlock()

f, err := os.Open(path)
if err != nil {
    return fmt.Errorf("opening %s: %w", path, err)
}
defer f.Close()
```

Put the `defer` on the line after the acquire, before any early return can slip in
between.

## Accept interfaces, return structs

```go
func NewStore(db *sql.DB) *PostgresStore { ... }
```

Returning a concrete type lets callers use everything it offers; returning an
interface throws information away for no benefit.

## Zero values that work

Design structs so the zero value is usable. `var buf bytes.Buffer` is ready to go;
aim for the same.

## No naked returns in anything longer than a few lines

```go
// bad
func split(s string) (head, tail string, err error) {
    ...
    return
}
```

Name the results for documentation, but return them explicitly.
