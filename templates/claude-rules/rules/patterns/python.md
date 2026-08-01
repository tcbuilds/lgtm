---
paths:
  - "**/*.py"
  - "**/*.pyi"
---

# Python Patterns

## Typed values at the boundary, plain objects inside

Parse untrusted input once into a model, then pass the model. Do not thread raw
dicts through the call stack.

```python
# bad — every layer re-reads keys that may not exist
def handle(payload: dict) -> None:
    user_id = payload["user"]["id"]
    charge(payload["amount"], payload.get("currency", "USD"))

# good
class Charge(BaseModel):
    user_id: UserId
    amount: Decimal
    currency: Currency = Currency.USD

def handle(payload: dict) -> None:
    charge(Charge.model_validate(payload))
```

Use `Decimal` for money. `float` for currency is a defect, not a style choice.

## Frozen dataclasses for values

```python
@dataclass(frozen=True, slots=True)
class Waiver:
    rule_id: str
    owner: str
    expires: date
```

`frozen=True` makes it hashable and safe to share; `slots=True` cuts memory and
catches typo'd attribute assignment.

## `match` over isinstance ladders

```python
# bad
if isinstance(event, Created):
    ...
elif isinstance(event, Deleted):
    ...

# good
match event:
    case Created(id=id):
        ...
    case Deleted(id=id, reason=reason):
        ...
    case _:
        raise UnhandledEvent(event)
```

## Context managers for anything paired

If you write "open ... close", "acquire ... release", or "start ... stop", it
belongs in a context manager so the error path cannot skip cleanup.

```python
@contextmanager
def timed(name: str) -> Iterator[None]:
    started = time.monotonic()
    try:
        yield
    finally:
        logger.info("%s took %.3fs", name, time.monotonic() - started)
```

Note `time.monotonic()` for durations — never `time.time()`, which can jump.

## Generators for streams, lists for results

Return an iterator when the caller may not need everything, or when the data does
not fit comfortably in memory.

```python
def read_records(path: Path) -> Iterator[Record]:
    with path.open() as handle:
        for line in handle:
            yield Record.parse(line)
```

Do not return a generator from a function whose caller must know the count — that
forces a hidden second pass.

## Protocols over ABCs

Structural typing avoids forcing inheritance on implementers, including ones you
do not own.

```python
class Storage(Protocol):
    def read(self, key: str) -> bytes: ...
    def write(self, key: str, value: bytes) -> None: ...

def sync(source: Storage, target: Storage) -> None: ...
```

## Keyword-only arguments for options

```python
def connect(host: str, *, timeout: float, retries: int = 3) -> Connection: ...
```

Positional booleans and bare numbers at call sites are unreadable. The `*` forces
callers to name them.

## Narrow exception handling with context

```python
# bad
except Exception:
    return None

# good
except json.JSONDecodeError as exc:
    raise ConfigInvalid(f"parsing {path}") from exc
```

`from exc` preserves the chain. Returning `None` on failure discards the reason
and pushes the bug downstream.

## Never mutate default arguments

```python
# bad — the list is shared across every call
def add(item: str, into: list[str] = []) -> list[str]: ...

# good
def add(item: str, into: list[str] | None = None) -> list[str]:
    into = [] if into is None else into
```

## Comprehensions for shape changes, loops for side effects

```python
# good
active = [w for w in waivers if w.expires > today]

# bad — a comprehension executed for its side effects
[logger.info(w.rule_id) for w in waivers]
```

## `pathlib` over string paths

```python
config = root / ".lgtm" / "config.json"
if config.is_file():
    data = json.loads(config.read_text())
```

## Injection over module-level singletons

Module globals are invisible dependencies and make tests order-sensitive. Pass
collaborators in, default them at the composition root.

```python
def build_service(clock: Clock = SystemClock()) -> Service:
    return Service(clock=clock)
```

Inject the clock. Code that calls `datetime.now()` internally cannot be tested
without freezing global time.
