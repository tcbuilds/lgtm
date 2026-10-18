---
description: Shared mobile UI design guidance.
paths:
  - "**/{ios,iosApp}/**/*.{swift,m,mm,h,storyboard,xib,js,jsx,ts,tsx,dart}"
  - "**/*.ios.{js,jsx,ts,tsx}"
  - "**/android/**/*.{kt,java,xml,js,jsx,ts,tsx,dart}"
  - "**/*.android.{js,jsx,ts,tsx}"
  - "**/{mobile,react-native}/**/*.{js,jsx,ts,tsx,dart}"
  - "**/*.native.{js,jsx,ts,tsx}"
---

# Mobile UI

Apply only to phone/tablet UI, not backend, desktop, or web code that happens to
share these paths. In shared code, preserve each target platform's conventions.

- Make primary actions clear and reachable; use familiar navigation and controls.
- Adapt to screen size, rotation, text scaling, safe areas, and the keyboard;
  keep focused fields and actions visible without clipping content.
- Label controls for screen readers; keep logical focus order and sufficient
  contrast. Never communicate status through color, sound, or gestures alone.
- Respect light/dark appearance and reduced-motion preferences.
- Design loading, empty, error, offline, and permission-denied states. Preserve
  input during recovery; request permissions in context and explain their use.
- Verify on target devices or simulators with large text and assistive technology;
  injected guidance is not proof of accessibility or platform compliance.

Sources: [Apple HIG](https://developer.apple.com/design/human-interface-guidelines),
[Android accessibility](https://developer.android.com/design/ui/mobile/guides/foundations/accessibility).
