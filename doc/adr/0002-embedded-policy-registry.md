# ADR-0002: Embedded policy registry with repo-local overrides

## Status

Accepted

## Date

2026-07-11

## Context

The operational source of truth for `lgtm` is a versioned policy registry (`policy/rules.json`) derived from the human-readable `codingStandards.md`. Every consuming repository needs access to the default rule set to select, instruct on, and enforce policy. The question is where that registry physically lives and how it is distributed and upgraded across many repos.

The spec resolves this by versioning the default registry with the binary: the default rules are compiled into the binary, and consuming repos hold only configuration and overrides, not a copy of the rules. Upgrading the rule set means upgrading the binary. This keeps rule authorship and distribution tied to the single artifact already established in ADR-0001, consistent with the zero-setup, fast-failing-hook posture.

## Decision

Embed the default policy registry in the harness binary, versioned with it, and let each consuming repo hold only repo-local overrides.

- Default `rules.json` is compiled into the binary at build time. Upgrading the rule set means upgrading the binary (this is the same version lever as ADR-0001).
- A consumer repo's `.lgtm/config.json` holds only the profile choice, severity overrides, disabled rules, languages, and required commands — not a copy of the rules.
- Rules marked `overridable: false` (security-critical) cannot be disabled or downgraded by repo config.
- Per-repo version pinning is a version string in `config.json` checked by the binary at startup.

## Consequences

- Version drift of the rule set is eliminated: every repo running a given binary version enforces the same rules, and a repo pins to a known version deliberately.
- Consumer repos stay minimal — configuration only — with no rule text to maintain or accidentally edit.
- There is no runtime dependency on a central policy service and no network call to fetch rules, preserving fast, self-contained hook execution.
- Rule authorship and rule distribution are coupled to the binary release cycle: a rule change requires a binary rebuild and release, not a config edit. This is an accepted trade-off in exchange for eliminating drift.
- Repos can still tailor enforcement locally through severity overrides and disabled rules, bounded by the non-overridable security-critical set, so legitimate per-repo variation is expressible without forking the registry.
- Organization policy distribution, signed policy bundles, and policy version pinning are noted as future capabilities in the spec; if central distribution is ever adopted it would warrant a superseding ADR.
