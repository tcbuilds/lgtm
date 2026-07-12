# ADR-0009: Structured command trust boundary

## Status

Accepted

## Decision

Repository commands are executed only from validated V2 argv arrays with repository-relative working directories, bounded timeouts, no shell operators, and regular-file configuration. Coverage commands use the same boundary. The runner records workspace, argv, cwd, exit status, duration, and provenance metadata. Environment is limited to an explicit allowlist. Config ownership and permission hardening remains a follow-up because cross-platform metadata behavior must be specified before enforcement.

## Rationale

Shell strings and ambient configuration create injection and workspace-leakage risk. Explicit argv and cwd make the command surface reviewable and deterministic. Missing optional tools remain `unverified`; LGTM never guesses a successful check.

## Trade-offs

Some repositories need environment variables or wrapper scripts. They must expose those through an explicit executable or repository-local configuration rather than relying on hidden shell behavior. Permission checks remain an open compatibility-reviewed change.
