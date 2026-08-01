---
paths:
  - "**/*.{tsx,jsx}"
---

# React

- Components should either orchestrate state or render UI. Avoid doing both heavily.
- Keep derived data outside hot render paths when it is expensive.
- Use stable keys from domain IDs, not array indexes, except static lists.
- Clean up subscriptions, timers, observers, sockets, and async effects.
- Avoid global singletons for UI state unless intentionally app-wide.
- Prefer controlled error and loading states over implicit null behavior.
- Use accessibility semantics: labels, roles, keyboard paths, focus management.
