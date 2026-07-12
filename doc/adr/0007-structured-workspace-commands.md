# ADR-0007: Structured workspace commands for config V2

- Status: Accepted
- Date: 2026-07-12

## Context

V1 stores repository gates as shell command strings at the repository root.
That shape cannot describe nested workspaces, their working directories, or
safe argument boundaries. It also tempts discovery to invent commands for a
monorepo and makes shell operators part of the policy surface.

## Decision

Config V2 represents each workspace explicitly with an `id`, `language`,
repo-relative `root`, and an ordered list of command records. A command record
stores `argv` as an array (never a shell string), a bounded timeout, execution
tier, purpose, source, and confidence. Commands run with the workspace as
their `cwd`; shell operators and implicit shell expansion are rejected.

V1 remains readable for one migration cycle. `lgtm init` writes a validated
backup before converting known V1 commands into V2 records, preserving user
overrides and disabled rules. Ambiguous or malformed V1 values remain
untouched and produce repair instructions. V2 writes are staged atomically and
repeated initialization is idempotent.

## Consequences

Nested Python, TypeScript, and Rust projects can use their own tool
configuration without root/cwd leakage. Structured argv is safer to validate
and evidence can record exact cwd and arguments. The config schema is more
verbose, and migration must remain conservative when a V1 shell string cannot
be represented without interpretation.
