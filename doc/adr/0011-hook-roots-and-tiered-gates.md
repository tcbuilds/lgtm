# ADR-0011: Hook roots and tiered repository gates

## Status

Accepted

## Decision

Resolve hook `cwd` upward to the nearest real repository marker (`.git/HEAD`,
worktree `.git` file, or `.lgtm/config.json`). Accept absolute Edit/Write paths
only after proving they resolve inside that root. Fresh init and legacy V1
migration use detected workspace-scoped V2 commands. Stop hooks run `fast`
commands by default; a Git `pre-push` hook or CI invokes
`lgtm check --tier full` for the complete gate. Commands run only for
workspaces touched by the current session.

## Rationale

Claude Code supplies absolute file paths and may invoke hooks from nested
workspaces. Treating either as the repository root caused every edit to be
denied or caused root-level commands to run in the wrong environment. Full test
suites and production builds are valid CI gates but are too expensive for every
conversation stop.

## Trade-offs

Fast Stop can defer full test/build failures; the pre-push hook and CI provide
the final full gate. Existing hand-authored V2 configs remain authoritative;
legacy V1 configs are replaced with detected workspace commands during init.
