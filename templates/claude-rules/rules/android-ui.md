---
description: Android and Material guidance for mobile app UI.
paths:
  - "**/android/**/*.{kt,java,xml,js,jsx,ts,tsx,dart}"
  - "**/*.android.{js,jsx,ts,tsx}"
---

# Android UI

Apply only to Android phone/tablet UI, including that target in cross-platform
code; do not copy these conventions into iOS, desktop, TV, or automotive UI.

- Prefer Android/Material components and adaptive navigation over iOS imitations.
- Preserve system Back and predictive back behavior; distinguish Back from Up.
  Do not intercept system gestures to implement custom navigation.
- Provide touch targets of at least 48 × 48 dp with room between controls.
- Use scalable text (sp), support system font scaling, and expose meaningful
  TalkBack semantics with logical focus order; avoid redundant decorative labels.
- Draw edge-to-edge while applying system bar, gesture, and keyboard insets to
  interactive content. Keep focused fields and actions visible.
- Respect system light/dark themes and animation settings. Verify large text,
  TalkBack, gesture/button navigation, and supported window sizes on devices.

Sources: [Accessibility](https://developer.android.com/design/ui/mobile/guides/foundations/accessibility),
[Predictive back](https://developer.android.com/design/ui/mobile/guides/patterns/predictive-back),
[Edge-to-edge](https://developer.android.com/design/ui/mobile/guides/layout-and-content/edge-to-edge).
