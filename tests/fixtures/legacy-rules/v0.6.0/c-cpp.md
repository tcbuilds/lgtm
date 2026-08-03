---
paths:
  - "**/*.{c,h,cc,cpp,cxx,hpp,hxx}"
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
