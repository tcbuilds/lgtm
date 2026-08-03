# ADR-0013: Rule files as the single source of rules

## Status

Accepted

## Date

2026-08-02

## Supersedes

ADR-0002 (Embedded policy registry with repo-local overrides).

## Context

ADR-0002 established a derivation chain: a human standards document was the
source, a separate JSON registry was derived from it, and the
registry is compiled into the binary. Two facts have since invalidated the
shape of that chain, though not its intent.

First, the derivation is maintained by hand. 72 rule `references` entries and
33 `source_anchor` values bind the registry to that document, several by line
number. Nothing detects divergence; a prose edit and a registry edit can
disagree indefinitely.

Second, Claude Code now loads `.claude/rules/*.md` natively, selecting files by
a `paths:` frontmatter glob against the file actually being opened. Measured on
Claude Code 2.1.220 in an isolated repository: the injected content is the body
only, `paths:` is parsed into a structured `globs` field, unrecognized
frontmatter keys are dropped without error, and the record carries an explicit
`contentDiffersFromDisk: true`. A second session asked directly for a
frontmatter key's value answered `NOT_PRESENT`. Frontmatter is therefore a
machine-readable channel on the same file, at zero context cost.

Against that, LGTM's own guidance selection is weaker than the platform's.
`UserPromptSubmit` derives its candidate file set from `likely_files(prompt)`,
which splits the user's prompt on whitespace and keeps tokens ending in a known
extension. It never consults the filesystem and cannot know which file the
agent will open. A prompt that names no source file selects no rules; the same
repository and the same task produce full guidance or none depending on whether
the sentence happened to contain a path.

Enforcement does not share this weakness. `PostToolUse` reads the edited path
from the tool event, `PreToolUse` reads the pending command, and `Stop` reads
the transcript's real commands and exit statuses. Only the pre-emptive guidance
hook guesses.

## Decision

Make the rule files the single source, and never derive a path that can be
observed.

- A rule file carries YAML frontmatter for machine fields (`paths:` plus a
  `rules:` array of `id`, `level`, `severity`, `overridable`, `checks`) and
  prose in the body. The separate JSON registry and prior standalone standards
  document are retired entirely.
- The rule files remain compiled into the binary at build time and versioned
  with it. Every guarantee ADR-0002 made about distribution survives: no
  network call at hook time, no central policy service, consuming repos hold
  configuration and overrides only, and rules marked `overridable: false`
  cannot be disabled or downgraded by repo configuration.
- Enforcement reads the binary's embedded copy, never the installed
  `.claude/rules/` files. The installed files are guidance. They are editable
  by design and are not authoritative for any enforcement decision, even though
  they are byte-identical to the embedded copy at install time.
- Guidance selection is delegated to the harness where the harness does it
  natively. Claude Code loads `.claude/rules/` itself; LGTM does not inject
  guidance there. `likely_files` and prompt-text path derivation are removed.
- Where a harness has no native path-scoped loading (Codex, OpenCode, Pi),
  LGTM injects rule bodies through the shared service in M20, matching against
  the path extracted from the pending tool call. Prompt text is not a path
  source for any harness.

## Consequences

- One artifact holds each rule's text and its machine fields, so the 105
  hand-maintained cross-references disappear rather than being repointed, and
  registry-versus-prose drift becomes unrepresentable.
- Guidance for Claude Code becomes strictly more accurate: rules load on the
  file actually opened rather than on whether the user typed its name.
- Two copies of the rules now exist in the same format — embedded and
  installed — distinguished only by which one enforcement trusts. This is a
  new opportunity for misreading and must be stated explicitly in user-facing
  documentation. Editing an installed rule file changes guidance and changes
  nothing about enforcement.
- The frontmatter-stripping behavior is observed, not documented by Anthropic.
  A future Claude Code release could inject frontmatter into context. A test
  asserts that injected content excludes frontmatter so the regression surfaces
  on the version that introduces it rather than in production.
- The always-loaded entry document competes for a documented 200-line budget.
  Sections that nothing triggers must be compressed or scoped to a glob; the
  budget is a real constraint on how much process guidance can be always-on.
- LGTM's guidance-selection code is retained rather than deleted, because three
  supported harnesses still require it. It is now reached only through observed
  paths, which is the same correctness standard enforcement already met.
