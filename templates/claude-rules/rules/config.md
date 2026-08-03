---
paths:
  - "**/*.{yaml,yml,json,toml,ini,env}"
  - "**/.env.example"
  - "**/{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,pyproject.toml,requirements.txt,Gemfile,Podfile}"
  - "**/README.md"
  - "**/docs/**"
headings: ["YAML, JSON, And Config", "Dependency Standards", "Documentation Standards"]
rules:
  [
    {
      "id": "new-dependency-review",
      "title": "Review new dependencies",
      "description": "Dependency changes require focused risk review.",
      "severity": "warning",
      "level": "review",
      "category": "dependencies",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{yaml,yml,json,toml,ini,env}"
        ,
          "**/.env.example"
        ,
          "**/{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,pyproject.toml,requirements.txt,Gemfile,Podfile}"
        ,
          "**/README.md"
        ,
          "**/docs/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "dependency"
        ]
      },
      "instruction": "Review necessity, license, maintenance, transitive size, and security posture.",
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
          "text": "good: satisfy Review new dependencies; bad: bypass it",
          "schematic": true
        }
      ],
      "limitations": [
        "Automated checks cover only registered patterns; review other implementations."
      ],
      "enforcement_stage": "stop"
    },
    {
      "id": "config-schema-review",
      "title": "Review configuration schemas",
      "description": "YAML, JSON, and shared configuration should use schemas and avoid duplicate keys or secret outputs.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {
          "language": "yaml",
          "text": "good: validate and bound the change; bad: apply unreviewed mutable configuration",
          "schematic": true
        }
      ],
      "limitations": [
        "This is review guidance; semantic shell/IaC/config safety is not claimed as static proof."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "infrastructure",
      "applies_to": {
        "languages": [
          "yaml",
          "json"
        ],
        "domains": [],
        "file_patterns": [
          "**/*.{yaml,yml,json,toml,ini,env}"
        ,
          "**/.env.example"
        ,
          "**/{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,pyproject.toml,requirements.txt,Gemfile,Podfile}"
        ,
          "**/README.md"
        ,
          "**/docs/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": []
      },
      "instruction": "YAML, JSON, and shared configuration should use schemas and avoid duplicate keys or secret outputs.",
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
      "id": "documentation-change-review",
      "title": "Review documentation and rollout changes",
      "description": "Setup/config/operations changes need README or runbook updates, public API docs, ADRs for irreversible decisions, and rollback/migration notes for risky changes.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: document config and rollback; bad: change deployment behavior with no operator notes",
          "schematic": true
        }
      ],
      "limitations": [
        "Documentation completeness is contextual review; UI screenshots are requested only when configured."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "documentation",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{yaml,yml,json,toml,ini,env}"
        ,
          "**/.env.example"
        ,
          "**/{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,pyproject.toml,requirements.txt,Gemfile,Podfile}"
        ,
          "**/README.md"
        ,
          "**/docs/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify",
          "delete"
        ],
        "signals": [
          "config",
          "deploy",
          "operation",
          "api",
          "migration"
        ]
      },
      "instruction": "Update README/setup, public API docs, ADRs, runbooks, rollback/migration notes, and configured UI evidence when behavior or operations change.",
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
      "id": "dependency-change-review",
      "title": "Review dependency changes",
      "description": "Dependency changes need direct/transitive delta, license, source, pinning, maintenance/security evidence, runtime impact, and adapter review for volatile APIs.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {
          "language": "all",
          "text": "good: pin and record license/source impact; bad: add an unreviewed volatile dependency",
          "schematic": true
        }
      ],
      "limitations": [
        "Offline environments and package ecosystems vary; missing evidence remains unverified."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "dependencies",
      "applies_to": {
        "languages": [],
        "domains": [],
        "file_patterns": [
          "**/*.{yaml,yml,json,toml,ini,env}"
        ,
          "**/.env.example"
        ,
          "**/{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,pyproject.toml,requirements.txt,Gemfile,Podfile}"
        ,
          "**/README.md"
        ,
          "**/docs/**"
        ]
      },
      "activation": {
        "change_types": [
          "create",
          "modify"
        ],
        "signals": [
          "dependency",
          "package",
          "manifest",
          "lockfile"
        ]
      },
      "instruction": "Review direct/transitive delta, license, source, pinning, maintenance/security evidence, runtime impact, and adapter seams for volatile dependencies.",
      "enforcement": {
        "mode": "instruction",
        "checks": []
      },
      "overridable": true,
      "evidence": {
        "required": [
          "review_result",
          "dependency_delta"
        ]
      }
    }
  ]
---

# YAML, JSON, And Config

- Validate config with schemas when possible.
- Keep environment-specific values outside shared templates.
- Include units in config names.
- Prefer explicit defaults in code and documented examples in `.env.example`.
- Avoid duplicate config keys across files.

## Dependency Standards

- Add dependencies only when they replace substantial, risky, or non-core code; prefer maintained libraries with shallow, acyclic graphs.
- Review license, maintenance, transitive size, security posture, runtime cost, and adapter seams before adding or upgrading a dependency.

## Documentation Standards

- README files explain purpose, quick start, tests, configuration, and deployment basics; public APIs and complex algorithms need honest docs.
- Record major architectural decisions in ADRs and keep runbooks, rollback notes, and comments current with behavior.

<!-- lgtm-rule: new-dependency-review -->
#### Review new dependencies
<!-- lgtm-rule: config-schema-review -->
#### Review configuration schemas
<!-- lgtm-rule: documentation-change-review -->
#### Review documentation and rollout changes
<!-- lgtm-rule: dependency-change-review -->
#### Review dependency changes
