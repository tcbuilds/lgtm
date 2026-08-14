---
description: LGTM observability rules.
paths:
  - "**/*.{rs,py,pyi,ts,tsx,js,jsx,mjs,cjs,go,java,kt,kts,cs,c,cc,cpp,cxx,h,hpp,sql,sh,bash,zsh,html,css,scss,sass,less,tf,tfvars}"
headings: ["Design For Debugging", "Observability Standards"]
rules:
  [
    {
      "id": "sensitive-logging-review",
      "title": "Review sensitive logging",
      "description": "Logs must not expose passwords, tokens, cookies, auth headers, raw payloads, or PII.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: redact auth headers before logging; bad: logger.info('token=%s', token)",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical signals are review findings; wrapper output is sanitized and no secret value is echoed."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "security",
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
          "logging",
          "auth",
          "credential",
          "payload"
        ]
      },
      "instruction": "Redact or remove credentials, auth headers, cookies, PII, and raw payloads from logs; never echo secret values in findings.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.sensitive-logging"
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
      "id": "structured-observability-review",
      "title": "Review structured service observability",
      "description": "Long-running services and workers should expose structured logs, correlation IDs, health checks, and metrics for latency, errors, queues, retries, and drops.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: correlate request logs and measure queue latency; bad: emit unstructured messages with no health signal",
          "schematic": true
        }
      ],
      "limitations": [
        "Static analysis does not prove semantic observability coverage; this rule only requests focused review."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "observability",
      "applies_to": {
        "languages": [],
        "domains": [
          "service",
          "worker",
          "queue"
        ],
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
          "service",
          "worker",
          "queue",
          "long-running"
        ]
      },
      "instruction": "Review structured log keys, correlation IDs, health checks, and metrics for latency, errors, queue depth, retries, and drops; do not claim static proof.",
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
    },
    {
      "id": "error-contract-review",
      "title": "Review boundary error contracts",
      "description": "Boundary failures should expose an action, entity, specific reason, and retryability instead of opaque messages.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: config load failed: entity=config reason=missing retryable=false; bad: failed",
          "schematic": true
        }
      ],
      "limitations": [
        "The lexical check reviews newly added failure strings; it cannot prove every runtime boundary or typed error conversion."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "error-handling",
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
          "error",
          "exception"
        ]
      },
      "instruction": "At system boundaries, include action, entity, specific reason, and retryable=true|false in failure output.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result"
        ]
      }
    }
  ]
---

# Design For Debugging

Master-level code leaves a useful trail.

**Every failure should answer**

- What failed, which input or entity failed, where it failed, whether it is retryable, and what the operator or caller should do next.

**Required debugging affordances**

- Use structured logs with stable keys, not sentence-only logs.
- Carry request, trace, job, event, or correlation IDs across async boundaries.
- Measure latency, throughput, errors, queue depth, retries, drops, and cache hits.
- Expose health checks for long-running services.
- Keep debug endpoints and commands authenticated and safe.
- Record deterministic reproduction instructions for every bug fix.

Use this failure shape:

```text
action failed: entity=<id> reason=<specific cause> retryable=<true|false>
```

# Observability Standards

- Logs are for events, metrics are for trends, and traces are for cross-service latency.
- Never log secrets, tokens, raw credentials, full cookies, private keys, or full auth headers.
- Redact sensitive fields by default and log IDs and counts instead of large payloads.
- Count dropped events, rejected input, retry exhaustion, and background task crashes.
- Measure request latency, database latency, queue delay, and batch size.
- Alert on user-facing errors, saturation, stale data, high latency, and data loss.

<!-- lgtm-rule: sensitive-logging-review -->
#### Review sensitive logging
<!-- lgtm-rule: structured-observability-review -->
#### Review structured service observability
<!-- lgtm-rule: error-contract-review -->
#### Review boundary error contracts
