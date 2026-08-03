---
paths:
  - "**/*.{c,h,cc,cpp,cxx,hpp,hxx}"
headings: ["C And C++"]
rules:
  [
    {
      "id": "cpp-review",
      "title": "Review C and C++ safety",
      "description": "C and C++ changes require warnings, ownership/bounds review, overflow awareness, sanitizers, and fuzz coverage where risk warrants.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "cpp",
          "text": "good: enable warnings and sanitizers; bad: unchecked pointer arithmetic without a regression or fuzz case",
          "schematic": true
        }
      ],
      "limitations": [
        "Compiler, sanitizer, and fuzz semantics depend on configured CMake/Meson/Make tooling."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "language-specific",
      "applies_to": {
        "languages": [
          "c",
          "cpp"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{c,h,cc,cpp,cxx,hpp,hxx}"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "c",
          "cpp",
          "pointer",
          "buffer",
          "sanitizer"
        ]
      },
      "instruction": "Review warnings-as-errors, ownership and bounds, overflow, sanitizer, and fuzzing coverage; run configured CMake/Meson/Make gates without inventing tools.",
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

# C And C++

- Use sanitizers in CI where practical: ASan, UBSan, TSan.
- Compile with warnings as errors.
- Prefer RAII in C++ and explicit ownership conventions in C.
- Avoid raw owning pointers in C++.
- Bounds-check all buffers.
- Treat integer overflow, signed/unsigned mixing, and lifetime bugs as security issues.
- Use clang-format, clang-tidy, and static analysis.
- Fuzz parsers and binary input handling.

<!-- lgtm-rule: cpp-review -->
#### Review C and C++ safety
