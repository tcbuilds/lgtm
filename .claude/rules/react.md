---
paths:
  - "**/*.{tsx,jsx}"
headings: ["React"]
rules:
  [
    {
      "id": "react-no-state-mutation",
      "title": "Do not mutate React state",
      "description": "React state must be updated through setters, never mutated in place.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: use the supported pattern; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "The native check is lexical and requires review for complex syntax."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tsx,jsx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "React state must be updated through setters, never mutated in place.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.react-no-state-mutation"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result"
        ]
      }
    },
    {
      "id": "react-unstable-key",
      "title": "Use stable React keys",
      "description": "React list keys should use stable domain IDs rather than indexes.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: use the supported pattern; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "The native check is lexical and requires review for complex syntax."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tsx,jsx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "React list keys should use stable domain IDs rather than indexes.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.react-unstable-key"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result"
        ]
      }
    },
    {
      "id": "react-effect-cleanup",
      "title": "Review React effect cleanup",
      "description": "React effects must clean up subscriptions, timers, observers, sockets, and async work.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: make the state explicit; bad: rely on implicit null behavior",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic UI quality is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tsx,jsx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "React effects must clean up subscriptions, timers, observers, sockets, and async work.",
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
      "id": "react-error-loading-states",
      "title": "Review React error and loading states",
      "description": "Interactive React surfaces should expose explicit loading and failure states.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: make the state explicit; bad: rely on implicit null behavior",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic UI quality is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tsx,jsx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "Interactive React surfaces should expose explicit loading and failure states.",
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
      "id": "react-accessibility-review",
      "title": "Review React accessibility semantics",
      "description": "React components should use semantic labels, keyboard paths, focus management, and accessible states.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "typescript",
          "text": "good: make the state explicit; bad: rely on implicit null behavior",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic UI quality is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{tsx,jsx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "React components should use semantic labels, keyboard paths, focus management, and accessible states.",
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

## Every subscription cleans up

```tsx
useEffect(() => {
  const controller = new AbortController()
  loadUser(id, { signal: controller.signal }).then(setUser).catch(ignoreAbort)
  return () => controller.abort()
}, [id])
```

Timers, sockets, observers, and in-flight requests all need the cleanup return.
Without it you get state updates on unmounted components and leaked connections.

## Keys from domain identity, never array index

```tsx
// bad — reorder or delete and React reuses the wrong DOM node
{items.map((item, i) => <Row key={i} item={item} />)}

// good
{items.map((item) => <Row key={item.id} item={item} />)}
```

Index keys are acceptable only for lists that never reorder, filter, or delete.

## Explicit loading and error states

Never render `undefined` as if it were empty. Distinguish "no data yet" from "no
data exists" — they read identically to the user and mean opposite things.

## Accessibility is not optional polish

Label every input, keep focus visible, make custom controls keyboard-operable, and
give interactive elements real roles. A `<div onClick>` is not a button.

```tsx
// bad
<div onClick={submit}>Save</div>

// good
<button type="button" onClick={submit}>Save</button>
```

# React

- Components should either orchestrate state or render UI. Avoid doing both heavily.
- Keep derived data outside hot render paths when it is expensive.
- Use stable keys from domain IDs, not array indexes, except static lists.
- Clean up subscriptions, timers, observers, sockets, and async effects.
- Avoid global singletons for UI state unless intentionally app-wide.
- Prefer controlled error and loading states over implicit null behavior.
- Use accessibility semantics: labels, roles, keyboard paths, focus management.

<!-- lgtm-rule: react-no-state-mutation -->
#### Do not mutate React state
<!-- lgtm-rule: react-unstable-key -->
#### Use stable React keys
<!-- lgtm-rule: react-effect-cleanup -->
#### Review React effect cleanup
<!-- lgtm-rule: react-error-loading-states -->
#### Review React error and loading states
<!-- lgtm-rule: react-accessibility-review -->
#### Review React accessibility semantics
