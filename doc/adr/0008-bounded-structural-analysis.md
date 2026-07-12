# ADR-0008: Bounded structural analysis before AST-dependent rules

- Status: Accepted
- Date: 2026-07-12

## Context

Size, complexity, naming, and React/Rust structure rules need symbols and
spans. Regex-only checks can provide useful review signals, but claiming AST
confidence from them would overstate enforcement and can hang on hostile input.

## Decision

LGTM introduces a bounded structural-analysis boundary. Every analyzer receives
explicit byte, line, token, and elapsed-work limits. It returns either metrics,
an explicit unsupported result, or `unverified` on malformed/partial input;
parse failure never becomes a pass. Generated, vendor, minified, and excluded
paths are filtered before analysis and reported when skipped.

The first implementation is a deterministic lexical substrate with stable
function spans and nesting/complexity counters. Language-specific AST grammars
may replace it behind the same interface later; callers must not infer AST
confidence from the lexical tier.

## Consequences

Hooks remain bounded and fail-safe while structural work lands incrementally.
Metrics are useful for high-confidence size limits, but semantic rules remain
review-only until a grammar-backed implementation is available. The interface
keeps that limitation visible in evidence and coverage rather than hiding it.
