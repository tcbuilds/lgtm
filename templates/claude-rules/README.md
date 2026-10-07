# Claude rule files

These files are the human-readable and machine-readable source for LGTM's
engineering rules. Claude Code loads the Markdown bodies; lgtm embeds the
frontmatter rules for enforcement.

## Install

With the CLI, registering no hooks:

```sh
lgtm init --rules-only
```

Everything lands under `.claude/rules/`, so an existing `CLAUDE.md` is never
touched. The entry document is written as `.claude/rules/standards.md` with no
`paths:` frontmatter, which Claude Code loads every session. Re-running is safe:
files matching the shipped template are reported unchanged, and files you have
edited are kept as they are.

The shipped entry document contains the exact marker
<!-- lgtm-entry-document: standards-v1 -->. The UserPromptSubmit hook
suppresses fallback guidance only when .claude/rules/standards.md contains that
marker. Removing it is an explicit opt-out from the installed entry document;
an unrelated or locally authored standards.md continues to receive fallback
guidance.

This installs guidance only. No hooks are registered, no `.lgtm/` directory is
created, and nothing is enforced.

Without the CLI at all:

```sh
curl -fsSL https://github.com/tcbuilds/lgtm/archive/refs/tags/v0.6.0.tar.gz \
  | tar -xz --strip-components=3 -C .claude 'lgtm-0.6.0/templates/claude-rules'
```

Create `.claude/rules/` first and copy `CLAUDE.md` to
`.claude/rules/standards.md` with every file under `rules/` beside it.

`CLAUDE.md` loads at the start of every session. Each file under `.claude/rules/`
declares a `paths:` glob in YAML frontmatter and loads only when Claude reads a
file matching it, so a Python change never pulls in the Rust or Terraform rules.

## File layout

- `standards.md` is always loaded and carries workflow guidance that has no safe
  file glob.
- `rules/*.md` contains path-scoped standards and language checklists.
- `rules/patterns/*.md` contains path-scoped craft patterns with bad/good pairs.

Both rule layers load for a matching file. Editing `store.rs` pulls in the Rust
and core patterns; editing `store_test.rs` also loads the testing rules.

Confirm what loaded with `/context` in a session; the files appear under
**Memory files**.

## Mobile design guidance

`mobile-ui.md` carries shared accessibility, layout, feedback, and state guidance.
`ios-ui.md` adds Apple HIG conventions; `android-ui.md` adds Android/Material
conventions. These are prose-only guidance, not new enforcement checks or a claim
of HIG, Material, or accessibility compliance.

The defaults deliberately use mobile path hints, not language detection:

| Source location | Mobile guidance loaded |
| --- | --- |
| UI source under `ios/` or `iosApp/`, or `*.ios.{js,jsx,ts,tsx}` | Shared + iOS |
| UI source under `android/`, or `*.android.{js,jsx,ts,tsx}` | Shared + Android |
| JS/TS/Dart under `mobile/` or `react-native/`, or `*.native.{js,jsx,ts,tsx}` | Shared only |
| Arbitrary `.swift`, `.kt`, `.dart`, or `.tsx` elsewhere | None |

Paths match at the repository root and inside monorepos; exact extension lists
are in each template's `paths:` frontmatter. A matching path is only a hint: apply
these rules to actual phone/tablet UI, never unrelated server, web, or desktop
code in the same directory. Shared Flutter/React Native code does not reveal the
active target; check each target's conventions explicitly rather than assuming
both platform rule files loaded.

For other layouts (such as root `app/src/`, Expo `app/`, or Flutter `lib/`), narrow
installed Claude rules to the project's actual mobile UI paths. Re-running init
preserves these local edits. Pi's LGTM adapter uses the embedded catalog, not the
installed Claude copies: editing their frontmatter does not change Pi injection.
For unmatched Pi paths, supply the target guidance through agent-supported
project instructions. Codex receives all three bodies in `AGENTS.md`; their
explicit platform conditions still apply without lazy loading.

Run `cargo test --test mobile_guidance` to verify scope and installation behavior.
To remove the Claude guidance, delete these three installed files; a later init
will reinstall missing templates. Pi's bundled guidance changes with the binary.

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

## Source and placement

Each file carries prose in its body and, where the enforcement registry needs
it, machine fields in frontmatter. Installed files are guidance; enforcement
uses the same source files embedded in the binary.

Path-scoped guidance belongs beside the file types it describes. The broad
source glob in `patterns/core.md` carries Core Principles, Refactoring Standards,
and Master Techniques because they shape implementation craft. The config file
also covers manifests and docs/README paths, so Dependency Standards and
Documentation Standards load where their triggers live. Review, debugging,
quality-gate, and AI workflow guidance stays in `standards.md` because no file
type reliably triggers it. Design For Debugging and Observability share a broad
source-scoped rule file.

Edit the rule-file body and its frontmatter together, then run the policy and
template tests. Keep the always-loaded entry document below 200 lines.
