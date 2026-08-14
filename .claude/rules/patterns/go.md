---
description: LGTM Go design patterns.
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
