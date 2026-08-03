---
paths:
  - "**/*.{html,htm,tsx,jsx,css,scss,sass,less}"
headings: ["HTML, CSS, And UI Styling"]
rules:
  [
    {
      "id": "ui-accessibility-review",
      "title": "Review UI accessibility signals",
      "description": "Semantic HTML and UI components need image alternatives and accessible labels or roles.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "html",
          "text": "good: <img alt=\"Map\">; bad: <img src=\"map.png\">",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical checks cover common missing-alt/label patterns; keyboard, contrast, and visual semantics remain review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "html",
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{html,htm,tsx,jsx,css,scss,sass,less}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "ui",
          "html",
          "react",
          "accessibility"
        ]
      },
      "instruction": "Use semantic elements and provide accessible labels, roles, focus states, and image alternatives; verify rendered behavior.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.ui-review"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    },
    {
      "id": "ui-responsive-review",
      "title": "Review responsive UI signals",
      "description": "UI changes should avoid brittle fixed styling and be checked at small, medium, and large viewports.",
      "mechanism": "native",
      "confidence": "low",
      "examples": [
        {
          "language": "css",
          "text": "good: use responsive tokens; bad: fixed !important dimensions everywhere",
          "schematic": true
        }
      ],
      "limitations": [
        "Static signals cannot prove layout stability or visual quality; screenshot evidence remains optional review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "html",
          "css",
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{html,htm,tsx,jsx,css,scss,sass,less}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "ui",
          "css",
          "responsive",
          "layout"
        ]
      },
      "instruction": "Prefer design tokens and responsive layout; verify accessibility and visual behavior at configured small/medium/large viewports.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.ui-review"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    }
  ]
---

# HTML, CSS, And UI Styling

- Preserve semantic HTML.
- Use accessible contrast and focus states.
- Avoid layout shifts on load.
- Prefer design tokens for colors, spacing, typography, shadows, and z-index.
- Avoid one-off magic pixel values unless documented.
- Test responsive behavior at small, medium, and large viewports.

<!-- lgtm-rule: ui-accessibility-review -->
#### Review UI accessibility signals
<!-- lgtm-rule: ui-responsive-review -->
#### Review responsive UI signals
