---
paths:
  - "**/*.{tsx,jsx}"
---

# React Patterns

## Derive, don't synchronise

Most `useState` + `useEffect` pairs are a computed value in disguise. Extra state
can disagree with its source; a derived value cannot.

```tsx
// bad — two sources of truth, one render behind
const [full, setFull] = useState('')
useEffect(() => { setFull(`${first} ${last}`) }, [first, last])

// good
const full = `${first} ${last}`
```

Reach for `useMemo` only when profiling shows the computation is expensive.

## Effects are for external systems only

An effect synchronises React with something outside React: a subscription, a
timer, the DOM, an analytics call. Anything else belongs in render or an event
handler.

```tsx
// bad — this is an event, not a synchronisation
useEffect(() => {
  if (submitted) { postOrder(order) }
}, [submitted])

// good
function handleSubmit() {
  postOrder(order)
}
```

## Lift state only as far as it is shared

State belongs at the lowest node that needs it. Hoisting everything to a top-level
store re-renders the world and turns local concerns into global ones.

## Custom hooks named as domain verbs

```tsx
// bad
const data = useFetch('/api/invoices')

// good
const { invoices, isLoading, error } = useUnpaidInvoices(customerId)
```

A hook should express a domain capability, not restate its implementation.

## One state object over correlated fields

```tsx
// bad — these can contradict each other
const [loading, setLoading] = useState(false)
const [data, setData] = useState<User>()
const [error, setError] = useState<Error>()

// good
const [state, setState] = useState<Fetch>({ status: 'idle' })
```

Same discriminated-union reasoning as everywhere else — make the impossible
combinations unrepresentable.

## Stable identities for anything passed down

```tsx
// bad — new object every render, defeats memo on the child
<Chart options={{ smooth: true }} data={points} />

// good
const options = useMemo(() => ({ smooth: true }), [])
```

Only matters when the child is memoised or the prop feeds a dependency array.
Otherwise it is noise.

## Controlled inputs own their value

```tsx
<input value={query} onChange={(e) => setQuery(e.target.value)} />
```

Mixing controlled and uncontrolled inputs produces warnings and cursor jumps. Pick
one per field and stay with it.
