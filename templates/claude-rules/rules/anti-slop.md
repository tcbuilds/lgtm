---
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Anti-Slop Checklist"]
rules:
  [
    {
      "id": "anti-slop-checklist",
      "title": "Review anti-slop checklist signals",
      "description": "Remove debug output, scaffolding, broad suppressions, and temporary code from diffs.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: ship focused code; bad: leave debug output or temporary suppressions",
          "schematic": true
        }
      ],
      "limitations": [
        "The diff check covers high-confidence lexical signals only; architectural slop remains review."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "refactoring",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": []
      },
      "instruction": "Review the diff for debug prints, scaffolding, broad suppressions, and temporary code.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
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

# Anti-Slop Checklist

Reject code with any of these traits:

- Vague names hiding domain meaning.
- Large functions with multiple abstraction levels.
- Boolean flags creating hidden modes.
- Shared mutable global state.
- Copy-pasted branches with tiny differences.
- Magic numbers or stringly typed protocols.
- Catch-all error handlers.
- Comments explaining confusing code instead of simplifying it.
- Tests that only check that code ran, not what behavior occurred.
- UI code recomputing heavy derived state on every render.
- Backend code doing synchronous slow work in request hot paths.
- Infrastructure code without rollback or validation commands.

<!-- lgtm-rule: anti-slop-checklist -->
#### Review anti-slop checklist signals
