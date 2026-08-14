---
description: LGTM TypeScript design patterns.
paths:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
---

# TypeScript Patterns

## Discriminated unions for anything with states

```typescript
// bad — 8 representable combinations, 3 valid
interface Fetch { loading: boolean; data?: User; error?: Error }

// good
type Fetch =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ok'; data: User }
  | { status: 'failed'; error: Error }
```

Narrowing on `status` gives you the right fields for free, and the compiler stops
you reading `data` before it exists.

## Exhaustive switch with a `never` guard

```typescript
function render(f: Fetch): ReactNode {
  switch (f.status) {
    case 'idle': return null
    case 'loading': return <Spinner />
    case 'ok': return <Profile user={f.data} />
    case 'failed': return <Error error={f.error} />
    default: {
      const unreachable: never = f
      throw new Error(`unhandled state: ${JSON.stringify(unreachable)}`)
    }
  }
}
```

Adding a state now breaks the build at the exact place that needs updating.

## Branded types for identifiers

```typescript
type Brand<T, B extends string> = T & { readonly __brand: B }
type UserId = Brand<string, 'UserId'>
type OrderId = Brand<string, 'OrderId'>

const asUserId = (raw: string): UserId => raw as UserId

// passing an OrderId where UserId is expected is now a type error
```

## Validate at the edge, trust inside

Every `fetch` response and every request body is `unknown` until parsed. Type
assertions are not validation — they are a promise you cannot keep.

```typescript
// bad
const user = (await res.json()) as User

// good
const User = z.object({ id: z.string(), email: z.string().email() })
const user = User.parse(await res.json())
```

## `satisfies` to keep literal types

```typescript
// bad — widens to Record<string, string>, losing the keys
const routes: Record<string, string> = { home: '/', profile: '/me' }

// good — checked against the constraint, keys preserved
const routes = { home: '/', profile: '/me' } satisfies Record<string, string>
type Route = keyof typeof routes   // 'home' | 'profile'
```

## Options objects over positional flags

```typescript
// bad
createUser('ada', 'ada@example.com', true, false, 3)

// good
createUser({ name: 'ada', email: 'ada@example.com', admin: true, retries: 3 })
```

## Readonly by default

```typescript
function total(items: readonly LineItem[]): Cents { ... }
```

Signals you will not mutate, and stops accidental in-place edits of a caller's array.

## Prefer `type` for unions, `interface` for extensible object contracts

Do not agonise. Use `type` unless you need declaration merging or `implements`.

## Async: no floating promises, always handle cancellation

```typescript
// bad — errors vanish, and nothing waits
void loadUser(id)

// good
const controller = new AbortController()
try {
  const user = await loadUser(id, { signal: controller.signal })
} finally {
  controller.abort()
}
```

## Narrow with type predicates, not casts

```typescript
function isOk(f: Fetch): f is Extract<Fetch, { status: 'ok' }> {
  return f.status === 'ok'
}

const users = results.filter(isOk).map((r) => r.data)   // typed, no cast
```

## Nullish coalescing, not `||`

```typescript
// bad — 0 and '' fall through to the default
const limit = input.limit || 100

// good
const limit = input.limit ?? 100
```
