---
paths:
  - "**/*"
headings: ["Non-Negotiable Rules", "Security Standards"]
rules:
  [
    {
      "id": "no-committed-secrets",
      "title": "No committed secrets",
      "description": "Secrets, tokens, private keys, or production credentials must never appear in code, logs, fixtures, screenshots, or commit history.",
      "severity": "error",
      "level": "must",
      "category": "security",
      "applies_to": {
        "languages": [],
        "domains": [
          "backend",
          "api",
          "worker",
          "infrastructure"
        ],
        "file_patterns": [
          "**/*"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "credential",
          "token",
          "private-key",
          "env-file"
        ]
      },
      "instruction": "Do not add secrets, tokens, private keys, or credentials to tracked files. Load them from environment variables or a secret manager.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "gitleaks.detect"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: satisfy No committed secrets; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "post_tool"
    },
    {
      "id": "auth-change-security-review",
      "title": "Review auth and security changes",
      "description": "Authentication and security-sensitive changes require focused review.",
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
          "authentication",
          "authorization"
        ]
      },
      "instruction": "Perform a focused authentication, authorization, and sensitive-data review.",
      "enforcement": {
        "mode": "diff",
        "checks": [
          "git.diff"
        ]
      },
      "overridable": false,
      "evidence": {
        "required": [
          "check_result"
        ]
      },
      "mechanism": "review",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: satisfy Review auth and security changes; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop"
    },
    {
      "id": "endpoint-controls-review",
      "title": "Review endpoint security controls",
      "description": "Public and expensive routes need input validation, server-side authorization, rate limiting, secure cookies/CORS/CSRF, and non-debug defaults.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: validate, authorize, rate-limit; bad: trust raw public input and ship debug mode",
          "schematic": true
        }
      ],
      "limitations": [
        "Framework-specific auth, rate-limit, cookie, CORS, and CSRF semantics remain review unless a registered checker proves them."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "security",
      "applies_to": {
        "languages": [
          "python",
          "typescript",
          "javascript"
        ],
        "domains": [
          "api"
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
          "endpoint",
          "route",
          "api",
          "public",
          "auth"
        ]
      },
      "instruction": "For each public or expensive route, document runtime validation, server-side authentication/authorization, rate limiting, secure cookies/CORS/CSRF, and non-debug defaults; report unknown semantics as review.",
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
      "id": "auth-input-enforcement",
      "title": "Enforce public endpoint controls",
      "description": "Detected public endpoints require runtime input validation, server-side authentication and authorization, rate limiting, secure cookies/CORS/CSRF, and non-debug defaults.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: validate and authorize at the route boundary; bad: trust raw public input",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical signals cannot prove runtime authorization, rate-limit policy, cookie flags, CORS, CSRF, or debug configuration; complete signals remain unverified."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "security",
      "applies_to": {
        "languages": [
          "python",
          "typescript",
          "javascript"
        ],
        "domains": [
          "api"
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
          "endpoint",
          "route",
          "api",
          "public",
          "auth",
          "input"
        ]
      },
      "instruction": "For each public or expensive route, prove boundary validation, server-side authorization, rate limiting, secure cookie/CORS/CSRF settings, and non-debug defaults with runtime evidence; static signals never claim semantic proof.",
      "enforcement": {
        "mode": "hybrid",
        "checks": [
          "native.auth-input-enforcement"
        ]
      },
      "overridable": true,
      "evidence": {
        "required": [
          "check_result",
          "runtime_security_evidence"
        ]
      }
    },
    {
      "id": "public-endpoint-review",
      "title": "Review public endpoint controls",
      "description": "Detected public endpoints require boundary validation, server-side authentication/authorization, rate limits, and secure cookie/CORS/CSRF/debug defaults.",
      "mechanism": "native",
      "confidence": "medium",
      "examples": [
        {
          "language": "all",
          "text": "good: validate and authorize at the route boundary; bad: expose raw request data with debug defaults",
          "schematic": true
        }
      ],
      "limitations": [
        "Signals cover common FastAPI, Express, and Next-style routes; unknown frameworks remain unverified rather than silently passing."
      ],
      "enforcement_stage": "post_tool",
      "severity": "warning",
      "level": "review",
      "category": "security",
      "applies_to": {
        "languages": [
          "python",
          "typescript",
          "javascript"
        ],
        "domains": [
          "api"
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
          "endpoint",
          "route",
          "api",
          "public"
        ]
      },
      "instruction": "For public endpoints, require boundary validation, server-side auth/authorization, rate limits for expensive/public routes, secure cookies/CORS/CSRF, and non-debug defaults.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.public-endpoints"
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
      "id": "safe-construction-review",
      "title": "Review safe construction boundaries",
      "description": "Avoid concatenating untrusted values into shell, HTML, URL, JSON, regex, or SQL strings; use contextual builders and escaping.",
      "mechanism": "native",
      "confidence": "high",
      "examples": [
        {
          "language": "all",
          "text": "good: parameterized query/argv builder; bad: 'SELECT ' + user_input",
          "schematic": true
        }
      ],
      "limitations": [
        "Lexical checks cover common concatenation shapes; framework-specific builders and semantic escaping remain review."
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
          "shell",
          "html",
          "url",
          "json",
          "regex",
          "sql",
          "input"
        ]
      },
      "instruction": "Use parameterized SQL, argv/builders, contextual HTML/URL escaping, and typed serializers; do not concatenate untrusted values into boundary strings.",
      "enforcement": {
        "mode": "static",
        "checks": [
          "native.safe-construction"
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

# Non-Negotiable Rules

- Never commit secrets, tokens, private keys, or production credentials in code, logs, fixtures, screenshots, or history.
- Never swallow errors or leave unbounded queues, retries, caches, loops, tasks, threads, timers, or subscriptions.
- Put explicit timeouts around network, database, subprocess, lock, and external API work.
- Validate public API input before use and use safe builders instead of string-built SQL, shell commands, HTML, URLs, or JSON.
- Do not disable lint, type, security, or test rules without a local justification comment.
- Give temporary code an owner, date, and deletion condition.
- Ship large features with tests, run instructions, and rollback notes.

# Security Standards

- Treat all external input as hostile and use allowlists over blocklists.
- Use parameterized SQL and safe ORM or query builders.
- Escape output for the target context: HTML, shell, URL, SQL, JSON, or regex.
- Enforce authentication and authorization at the server, not only in the UI.
- Rate-limit public endpoints and expensive internal endpoints.
- Use least privilege for service accounts, database users, tokens, and filesystem permissions.
- Pin or scan dependencies in CI.
- Require secure defaults such as TLS, secure cookies, applicable CSRF protection, safe CORS, and no production debug mode.
- Store secrets in environment variables or secret managers; rotate and document them.

<!-- lgtm-rule: no-committed-secrets -->
#### No committed secrets
<!-- lgtm-rule: auth-change-security-review -->
#### Review auth and security changes
<!-- lgtm-rule: endpoint-controls-review -->
#### Review endpoint security controls
<!-- lgtm-rule: auth-input-enforcement -->
#### Enforce public endpoint controls
<!-- lgtm-rule: public-endpoint-review -->
#### Review public endpoint controls
<!-- lgtm-rule: safe-construction-review -->
#### Review safe construction boundaries
