# Adapter contract

Adapters may parse harness-specific input, but they must preserve LGTM’s
decision semantics and evidence path:

| Result | JSON contract | Meaning |
| --- | --- | --- |
| block | `{ "decision": "block", "reason": "..." }` | unresolved error-severity MUST result |
| deny | Claude `PreToolUse` envelope | edit denied before execution |
| context | Claude `UserPromptSubmit` envelope | compact task policy context |

Validate adapter responses against `schemas/adapter.schema.json`. Adapters may
not turn `unverified`, `warning`, or `review` into a block, invent a passed
status, bypass waivers, or skip evidence persistence. Harnesses without a
matching lifecycle event should call `lgtm check --tier full` and document that
limitation.
