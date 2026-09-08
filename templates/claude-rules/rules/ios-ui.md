---
description: Apple HIG guidance for iOS app UI.
paths:
  - "**/{ios,iosApp}/**/*.{swift,m,mm,h,storyboard,xib,js,jsx,ts,tsx,dart}"
  - "**/*.ios.{js,jsx,ts,tsx}"
---

# iOS UI

Apply only to iOS/iPadOS UI, including that target in cross-platform code; do not
copy these conventions into Android or desktop UI.

- Prefer system controls, navigation stacks, tab bars, sheets, and alerts over
  imitations. Preserve expected back navigation and swipe gestures.
- Use 44 × 44 pt as the default touch target; allow spacing between controls.
- Use system text styles with Dynamic Type; keep layouts usable at accessibility
  text sizes. Provide VoiceOver labels, values, traits, and logical reading order.
- Respect safe areas and keyboard changes; keep essential controls reachable.
- Use semantic colors and adaptable assets for light/dark appearance; respect
  Reduce Motion instead of making animation essential to understanding an action.
- Test navigation, large text, VoiceOver, and appearance on supported iOS versions.

Sources: [Designing for iOS](https://developer.apple.com/design/human-interface-guidelines/designing-for-ios),
[Accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility).
