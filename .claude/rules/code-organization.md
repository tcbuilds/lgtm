---
description: LGTM code organization rules.
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Code Organization"]
rules:
  [
    {
      "id": "function-size",
      "title": "Review oversized functions",
      "description": "Functions over 50 lines require extraction or a documented parser/table/state-machine exemption.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: split cohesive responsibilities; bad: grow one multi-concern function",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical spans do not prove semantic cohesion; untouched legacy debt is not baselined yet."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "architecture",
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
          "modify"
        ],
        "signals": []
      },
      "instruction": "Keep functions near 20–30 lines and split before 50 unless a documented exemption applies.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.function-size"
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
      "id": "file-size",
      "title": "Review oversized files",
      "description": "Files over 300 lines require review and should be split before 500 lines.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: keep one abstraction level; bad: combine unrelated branches",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical metrics are review signals; generated code and legacy baselines need repository policy."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "architecture",
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
          "modify"
        ],
        "signals": []
      },
      "instruction": "Files over 300 lines require review and should be split before 500 lines.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.file-size"
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
      "id": "function-complexity",
      "title": "Review function complexity",
      "description": "Functions should keep parameters, nesting, and cyclomatic complexity bounded.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: keep one abstraction level; bad: combine unrelated branches",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical metrics are review signals; generated code and legacy baselines need repository policy."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "architecture",
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
          "modify"
        ],
        "signals": []
      },
      "instruction": "Functions should keep parameters, nesting, and cyclomatic complexity bounded.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.function-complexity"
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
      "id": "module-boundary-review",
      "title": "Review module boundaries",
      "description": "Modules should not form deterministic dependency cycles; domain code should remain separated from infrastructure concerns.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: depend through an adapter; bad: module A imports B while B imports A",
          "schematic": true
        }
      ],
      "limitations": [
        "Only relative source imports visible in the bounded touched-file graph are analyzed; architectural layering remains review guidance."
      ],
      "enforcement_stage": "post_tool",
      "severity": "error",
      "level": "must",
      "category": "architecture",
      "applies_to": {
        "languages": [
          "python",
          "rust",
          "typescript",
          "javascript"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "import",
          "module"
        ]
      },
      "instruction": "Avoid dependency cycles and keep domain code behind explicit adapter seams.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.module-boundaries"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result",
          "changed_locations"
        ]
      }
    }
  ]
---

# Code Organization

**Module boundaries**

- Each module owns one reason to change.
- Keep dependency direction obvious: UI -> domain -> infrastructure, not the reverse.
- Isolate external systems behind adapters: database, filesystem, HTTP, WebSocket, LLMs, queues, cloud APIs, and OS services.
- Keep business rules out of controllers, route handlers, UI components, CLIs, and migration scripts.
- Avoid circular dependencies. If two modules need each other, extract the shared concept.

**Size limits**

- Keep functions near 20 to 30 lines and split before 50 unless a clear table, parser, or state machine needs more.
- Keep files under 300 lines when practical; review at 400 and split before 500.
- Keep classes and structs under 200 lines and use named options after three function parameters.
- Keep nesting at two levels where practical and cyclomatic complexity at five or lower.

**File layout**

- Mirror tests to source structure where practical and keep domain types near domain logic.
- Mark generated files clearly and exclude them from manual edits.
- Do not mix unrelated concerns because a file already exists.

<!-- lgtm-rule: function-size -->
#### Review oversized functions
<!-- lgtm-rule: file-size -->
#### Review oversized files
<!-- lgtm-rule: function-complexity -->
#### Review function complexity
<!-- lgtm-rule: module-boundary-review -->
#### Review module boundaries
