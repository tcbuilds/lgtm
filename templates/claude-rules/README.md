# Claude rules templates

A binary-free way to carry these standards into a repository. Copy the files in,
and Claude Code loads them with no install step.

## Install

```sh
cp templates/claude-rules/CLAUDE.md /path/to/repo/CLAUDE.md
cp -r templates/claude-rules/rules /path/to/repo/.claude/rules
```

`CLAUDE.md` loads at the start of every session. Each file under `.claude/rules/`
declares a `paths:` glob in YAML frontmatter and loads only when Claude reads a
file matching it, so a Python change never pulls in the Rust or Terraform rules.

## Two layers

- `rules/*.md` — the gate checklist per language: what must pass, what is banned.
  Short, scannable, no code.
- `rules/patterns/*.md` — craft patterns with bad/good code pairs: how to shape
  the code you are about to write.

Both load for a matching file. Editing `store.rs` pulls in `rules/rust.md` and
`rules/patterns/rust.md`; editing `store_test.rs` adds `rules/patterns/testing.md`
on top. Drop the `patterns/` directory if you only want the checklists.

Confirm what loaded with `/context` in a session; the files appear under
**Memory files**.

## Codex

Codex reads `AGENTS.md` rather than `CLAUDE.md`, and has no equivalent of
path-scoped rules. Concatenate instead:

```sh
cat templates/claude-rules/CLAUDE.md templates/claude-rules/rules/*.md > /path/to/repo/AGENTS.md
```

That loses lazy loading — every language's rules are present in every session.

## What this does and does not do

These files are guidance. Claude Code's own documentation is explicit that
memory files are "context, not enforced configuration"; the model reads them and
generally follows them, but nothing stops it from doing otherwise.

Anything that must hold regardless of what the model decides — no committed
secrets, no claiming a command succeeded without evidence, no merging source
changes with no accompanying test — needs the hooks that `lgtm init` installs.
The two are complementary: rules shape behavior, hooks enforce it.

## Source

Derived from `codingStandards.md` at the repository root. Edit that file first,
then update these templates so the two do not drift.
