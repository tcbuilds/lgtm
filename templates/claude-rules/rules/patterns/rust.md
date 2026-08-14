---
description: LGTM Rust design patterns.
paths:
  - "**/*.rs"
---

# Rust Patterns

## Smart constructors

Keep the inner field private and validate on construction. Once built, the value
is known good everywhere.

```rust
pub struct Slug(String);

impl Slug {
    pub fn new(raw: &str) -> Result<Self, SlugError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(SlugError::Invalid(trimmed.to_string()));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

## Typed errors with `thiserror`, context at the boundary

Libraries define their error enum. Binaries add context. Never stringly-type a
failure that callers might want to branch on.

```rust
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("waiver store is malformed: {0}")]
    Malformed(String),
    #[error("waiver store exceeds {limit} bytes")]
    TooLarge { limit: u64 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

`#[from]` gives you `?` for free. `#[error(transparent)]` forwards a cause without
inventing a new message.

## Let-else for the unhappy path

Flattens the common "extract or bail" shape.

```rust
// bad
let parent = match path.parent() {
    Some(parent) => parent,
    None => return Err(Error::NoParent),
};

// good
let Some(parent) = path.parent() else {
    return Err(Error::NoParent);
};
```

## Iterator chains over index loops

Chains say what you are computing; loops say how. Reach for a loop when you need
early exit with side effects, not by default.

```rust
// bad
let mut active = Vec::new();
for waiver in &waivers {
    if waiver.expires > today {
        active.push(waiver.clone());
    }
}

// good
let active: Vec<_> = waivers.iter().filter(|w| w.expires > today).cloned().collect();
```

## RAII guards for anything that must be undone

If cleanup depends on remembering to call it, it will be forgotten on the error
path. Put it in `Drop`.

```rust
struct TempFile {
    path: PathBuf,
    committed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
```

## Borrow at the boundary, own in the struct

Take `&str` and `&[T]` in function arguments; store `String` and `Vec<T>` in
structs. Avoid lifetimes in public types until measurement says you need them.

```rust
// good — callers can pass anything string-like
pub fn find(rules: &[Rule], id: &str) -> Option<&Rule> { ... }
```

## `impl Trait` for arguments, concrete types for returns

```rust
pub fn write_all(items: impl IntoIterator<Item = Rule>) -> Vec<RuleId> { ... }
```

Returning `impl Trait` from public API locks you out of naming the type later;
prefer a concrete type or a named struct unless the type is genuinely unnameable.

## Make invalid state unrepresentable with enums

```rust
// bad — is_active and expires_at can disagree
struct Waiver {
    is_active: bool,
    expires_at: Option<Date>,
}

// good
enum Waiver {
    Active { expires_at: Date },
    Expired { expired_at: Date },
}
```

## Exhaustive matches, no catch-all on your own types

Never write `_ => {}` over an enum you control. When someone adds a variant, you
want a compile error, not silence. Reserve `_` for foreign enums marked
`#[non_exhaustive]`.

## Derive the obvious set

`#[derive(Debug)]` on everything. Add `Clone`, `PartialEq`, `Eq`, `Hash` when the
type is a value. `Copy` only for small plain-data types. `Debug` on error types is
required for `?` to be useful in tests.

## `#[must_use]` on anything ignorable by mistake

```rust
#[must_use]
pub fn with_timeout(self, timeout: Duration) -> Self { ... }
```

Builder methods and pure transformations should shout when discarded.
