---
paths:
  - "**/test_*.py"
  - "**/*_test.{py,go,rs}"
  - "**/*.{test,spec}.{ts,tsx,js,jsx}"
  - "**/tests/**"
  - "**/__tests__/**"
---

# Testing Patterns

## Arrange, act, assert — with the act on one line

```python
def test_expired_waiver_is_inactive() -> None:
    store = Store(waivers=[waiver(expires=date(2000, 1, 1))])   # arrange

    active = load_active(store, today=date(2026, 8, 1))          # act

    assert active == []                                          # assert
```

If the act step needs several lines, the API is probably too hard to use.

## One behaviour per test

Multiple assertions are fine when they describe one behaviour. Multiple *acts* are
not — the second one is a different test wearing the same name, and it never runs
after the first assertion fails.

## Table-driven for anything with cases

```rust
#[test]
fn calendar_validation_rejects_impossible_dates() {
    let cases = [
        ("1970-01-01", true),
        ("2027-02-29", false),
        ("2028-02-29", true),
    ];
    for (input, valid) in cases {
        assert_eq!(parse_date(input).is_ok(), valid, "input: {input}");
    }
}
```

Always include the input in the failure message; otherwise a table failure tells
you nothing about which row broke.

## Fakes over mocks

A mock asserts on calls and couples the test to the implementation. A fake behaves
like the real thing and lets you assert on outcomes.

```python
# bad — breaks when the implementation changes how it saves
store.save.assert_called_once_with(user)

# good
assert fake_store.get(user.id) == user
```

Reserve mocks for things you cannot run: payment providers, email, paid APIs.

## Inject time, randomness, and IO

```python
def test_session_expires() -> None:
    clock = FixedClock(datetime(2026, 8, 1, tzinfo=UTC))
    assert is_expired(session, clock=clock)
```

Anything calling `now()` or `random()` internally is untestable without global
patching. Pass them in.

## Test the boundary, not just either side of it

Two tests that sit far away from a threshold prove nothing about the threshold.

```rust
// bad — both cases survive flipping `>` to `>=`
expires: "2000-01-01"   // long past
expires: "2999-12-31"   // long future

// good — pins the comparison itself
expires: today          // does an expiry landing exactly now count?
expires: today + 1
```

Every `>` you write is a decision between `>` and `>=`. If no test fails when
you swap them, you have not tested the decision — only the easy cases either
side of it.

## Mutation testing measures whether tests would notice

Coverage says a line ran. It does not say a test would fail if that line were
wrong. Mutation testing changes the code on purpose — `>` to `>=`, `&&` to `||`,
deleting a statement — and reruns the suite. A mutant the suite still passes is
code with no real test on it.

```sh
cargo mutants --file src/policy/waivers.rs   # Rust
mutmut run --paths-to-mutate src/pricing.py  # Python
npx stryker run                              # TypeScript
```

Worth the time on comparisons, boundaries, predicates, permission and policy
decisions, and anything guarding a destructive action. Not worth it on glue.

Read survivors one at a time; do not chase a score. Equivalent mutants — edits
that cannot change observable behavior — survive forever and are noise. Scope to
changed files, because the suite reruns once per mutant.

This is the check that catches a test written to pass rather than to detect.
Coverage rises by touching a line; mutation score rises only by writing a test
that fails when the code is broken.

## Property tests for round trips and invariants

```python
@given(st.text())
def test_encode_decode_round_trips(raw: str) -> None:
    assert decode(encode(raw)) == raw
```

Best value on parsers, serialisers, normalisers, and anything with a mathematical
invariant. One property replaces dozens of examples.

## Golden tests for stable output

Pin exact bytes for CLI output, generated files, and wire formats. When a golden
test fails, review the diff and update deliberately — never regenerate blindly to
make it green, which defeats the purpose.

## Fixture data is not production code

Fixture trees hold deliberately-invalid input; that is their purpose. Never point
linters, formatters, or coverage gates at them.
