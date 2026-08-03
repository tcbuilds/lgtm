---
paths:
  - "**/*.{rs,py,ts,tsx,js,jsx,go,java,kt,cs,rb,swift,scala}"
headings: ["Core Principles", "Refactoring Standards", "Master Techniques For Maintainable Systems"]
rules:
  [
    {
      "id": "refactor-discipline-review",
      "title": "Review refactor discipline",
      "description": "Refactors should separate mechanical and behavioral changes, retain tests, remove obsolete duplicates, and preserve public behavior unless evidence proves the change.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: split mechanical and behavioral commits; bad: replace code and leave duplicate paths",
          "schematic": true
        }
      ],
      "limitations": [
        "Architectural duplication and public-behavior preservation require review and tests."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "refactoring",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{rs,py,ts,tsx,js,jsx,go,java,kt,cs,rb,swift,scala}"
        ]
      },
      "activation": {
        "change_types": [
          "modify",
          "delete"
        ],
        "signals": [
          "refactor",
          "rename",
          "replace",
          "deprecate"
        ]
      },
      "instruction": "Keep mechanical and behavioral changes separable; add behavior tests, remove obsolete duplicates, and preserve public behavior with evidence.",
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
    },
    {
      "id": "contextual-design-guidance",
      "title": "Apply contextual maintainability design guidance",
      "description": "When a task touches domain models, boundaries, or architecture, prefer illegal-state prevention, validated-domain conversion, pure cores with side-effect edges, explicit data flow, dependency injection for external effects, and simple designs before distributed abstractions.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: parse raw input into a validated domain type before a pure core; bad: pass unvalidated maps through side effects",
          "schematic": true
        }
      ],
      "limitations": [
        "This is contextual review guidance; semantic architecture and illegal-state proofs are not automated."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "architecture",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{rs,py,ts,tsx,js,jsx,go,java,kt,cs,rb,swift,scala}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "domain",
          "boundary",
          "architecture",
          "dependency-injection",
          "refactor"
        ]
      },
      "instruction": "Model illegal states out of existence; convert raw input to validated domain values; keep pure core logic separate from side effects; make data flow explicit; inject time, randomness, network, and filesystem dependencies; avoid premature distributed or abstract architecture.",
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
# Core Patterns

Language-agnostic shapes. Apply them in the idiom of the file you are editing.

## Parse, don't validate

Validate once at the boundary and return a type that cannot be invalid. Downstream
code should not re-check what the type already guarantees.

```python
# bad — every caller must remember to re-check
def send(email: str) -> None:
    if "@" not in email:
        raise ValueError("bad email")
    ...

# good — invalid values cannot reach send()
@dataclass(frozen=True)
class Email:
    value: str
    def __post_init__(self) -> None:
        if "@" not in self.value:
            raise ValueError(f"invalid email: {self.value!r}")

def send(email: Email) -> None: ...
```

If you find yourself writing the same guard in three functions, the guard belongs
in a type.

## Make illegal states unrepresentable

A struct with optional fields whose validity depends on a flag is a bug waiting to
happen. Use a sum type so the compiler enforces the combinations.

```typescript
// bad — four representable states, two of them nonsense
type Request = {
  loading: boolean
  data?: User
  error?: Error
}

// good — three states, all meaningful
type Request =
  | { status: 'loading' }
  | { status: 'ok'; data: User }
  | { status: 'failed'; error: Error }
```

Ask: how many combinations does this type allow, and how many are real? If those
numbers differ, reshape it.

## Functional core, imperative shell

Keep decisions pure and push I/O to the edges. Pure logic is testable without
mocks, and mocks are where test suites go to die.

```go
// bad — logic and I/O fused, needs a fake DB and a fake clock to test
func ExpireSessions(db *sql.DB) error {
    rows, _ := db.Query("SELECT id, expires FROM sessions")
    for rows.Next() { /* decide and delete inline */ }
}

// good — decide purely, act at the edge
func expired(sessions []Session, now time.Time) []ID { ... }  // trivially testable

func ExpireSessions(db *sql.DB, now time.Time) error {
    sessions, err := loadSessions(db)
    if err != nil { return err }
    return deleteByID(db, expired(sessions, now))
}
```

## Guard clauses over nesting

Handle the exits first. The happy path belongs at the leftmost indentation.

```rust
// bad
fn process(order: &Order) -> Result<Receipt, Error> {
    if order.is_valid() {
        if let Some(payment) = &order.payment {
            if payment.is_settled() {
                return Ok(build_receipt(order, payment));
            } else { Err(Error::Unsettled) }
        } else { Err(Error::MissingPayment) }
    } else { Err(Error::Invalid) }
}

// good
fn process(order: &Order) -> Result<Receipt, Error> {
    if !order.is_valid() {
        return Err(Error::Invalid);
    }
    let payment = order.payment.as_ref().ok_or(Error::MissingPayment)?;
    if !payment.is_settled() {
        return Err(Error::Unsettled);
    }
    Ok(build_receipt(order, payment))
}
```

## No boolean parameters

A bare `true` at a call site carries no meaning. Use an enum, or split the function.

```typescript
// bad — what is true?
createUser(name, email, true, false)

// good
createUser(name, email, { role: 'admin', notify: 'silent' })
```

Rule of thumb: if the argument is a literal at every call site, it should be part
of the function name or an enum.

## Exhaustive matching, never a silent default

A `default` branch that swallows unknown variants hides every future addition.
Prefer exhaustiveness so adding a variant produces a compile error.

```typescript
function label(s: Status): string {
  switch (s.kind) {
    case 'loading': return 'Loading'
    case 'ok': return 'Done'
    case 'failed': return 'Failed'
    default: {
      const never: never = s   // adding a variant fails the build here
      throw new Error(`unhandled: ${never}`)
    }
  }
}
```

Reserve `default` for input you genuinely do not control, and log it there.

## Errors carry context, and are values

Wrap with what you were doing; never discard the cause. Catch-alls that log and
continue turn one failure into a mystery three layers up.

```python
# bad
try:
    charge(order)
except Exception:
    logger.error("something failed")

# good
try:
    charge(order)
except PaymentDeclined as exc:
    raise CheckoutFailed(f"charging order {order.id}") from exc
```

## Name the domain, not the shape

`data`, `info`, `handle`, `manager`, `process`, `temp` say nothing. If the best
name you can think of is generic, the function is probably doing several things.

```
bad:  processData(items)        good:  settleExpiredInvoices(invoices)
bad:  UserManager               good:  UserDirectory / UserRepository
bad:  const result = ...        good:  const unpaidTotal = ...
```

## Prefer data over branching

Long if/else ladders over a fixed set of cases usually want a table.

```python
# bad
if kind == "csv": return parse_csv(raw)
elif kind == "tsv": return parse_tsv(raw)
elif kind == "json": return parse_json(raw)

# good
PARSERS = {"csv": parse_csv, "tsv": parse_tsv, "json": parse_json}
parser = PARSERS.get(kind)
if parser is None:
    raise UnsupportedFormat(kind)
return parser(raw)
```

Tables are easier to extend, test, and read than branches.

## Accept the narrowest type, return the most specific

Take an iterable, return a concrete list. Take an interface, return a struct.
Callers gain flexibility going in and information coming out.

## Core Principles

- Correctness beats cleverness; simplicity beats abstraction until repetition proves it; explicit data flow beats hidden global state.
- Failures stay observable, reproducible, and easy to isolate; performance claims are measured; security is a design constraint.

## Refactoring Standards

- Refactor under tests and separate mechanical moves from behavior changes; preserve public behavior unless the change explicitly requires otherwise.
- Delete obsolete code after replacement, extract repeated logic only when repetition is real, and leave the code easier to change.

## Master Techniques For Maintainable Systems

- Make illegal states unrepresentable, validate at boundaries, and keep pure domain logic separate from side effects behind explicit seams.
- Prefer boring architecture and progressive hardening; inject time, randomness, filesystem, and network effects so behavior stays testable.

<!-- lgtm-rule: refactor-discipline-review -->
#### Review refactor discipline
<!-- lgtm-rule: contextual-design-guidance -->
#### Apply contextual maintainability design guidance
