# ADR-0010: Organization policy bundle integrity

## Status

Accepted

## Decision

Support opt-in repository-local organization policy at `.lgtm/org-policy.json` with a pinned SHA-256 digest in `.lgtm/org-policy.sha256`. The embedded policy floor loads first, the pinned organization layer may only strengthen known rules, and the repository overlay applies last under its existing non-weakening rules.

## Rationale

Digest pinning is deterministic, offline, cross-platform, and has no hidden network trust. It provides integrity for a reviewed bundle but is not a cryptographic signature or identity system; deployments needing signer identity must add a separately reviewed signing adapter.

## Evidence

Evidence records the embedded source plus organization version and digest when the layer is active. Missing or mismatched pins fail closed before checks run.
