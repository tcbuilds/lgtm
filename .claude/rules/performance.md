---
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Performance Standards"]
rules:
  [
    {
      "id": "performance-review",
      "title": "Review performance-sensitive changes",
      "description": "Hot paths and performance work require a baseline and remeasurement, with review for N+1 queries, unpaginated lists, unbounded caches/queues, synchronous slow work, and repeated heavy renders.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: measure before and after a bounded query; bad: optimize a hot path without a baseline",
          "schematic": true
        }
      ],
      "limitations": [
        "Performance semantics require measured evidence; static guidance cannot prove latency or throughput."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "performance",
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
        "signals": [
          "performance",
          "hot-path",
          "latency",
          "query",
          "render"
        ]
      },
      "instruction": "For performance work, capture a baseline and remeasurement; review N+1/unpaginated work, unbounded caches/queues, synchronous slow calls, and repeated heavy renders.",
      "enforcement": {
        "mode": "instruction",
        "checks": []
      },
      "overridable": true,
      "evidence": {
        "required": [
          "review_result",
          "measurement"
        ]
      }
    }
  ]
---

# Performance Standards

- Establish a baseline before optimizing and keep the measurement that proves the result.
- Keep hot paths allocation-aware and I/O-aware.
- Batch high-frequency work before crossing expensive boundaries such as renders, database writes, network calls, logs, locks, and serialization.
- Prefer streaming for large data sets.
- Add pagination or windowing for lists over 100 items.
- Avoid N+1 database and network patterns.
- Cache only when invalidation is clear.
- Document Big O for non-trivial algorithms.
- Add load tests for services that process streams, queues, WebSockets, or large files.

**Performance workflow**

1. Define the user-visible symptom.
2. Measure with a profiler, trace, benchmark, or production metric.
3. Identify the bottleneck.
4. Make the smallest safe change.
5. Re-measure.
6. Keep the benchmark or metric when the path is important.

<!-- lgtm-rule: performance-review -->
#### Review performance-sensitive changes
