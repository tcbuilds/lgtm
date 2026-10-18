# Changelog

User-visible changes to LGTM, newest first. Links open the detailed release
notes, including verification, limits, upgrade steps, and rollback guidance.
Dates below are GitHub publication dates, in UTC. This index starts at v0.1.2;
earlier tags are not reconstructed here.

## Unreleased

Add changes here under **Features**, **Improvements**, **Bug fixes**,
**Security**, or **Breaking changes**, as needed. Include migration steps for
changes that require user action. Do not list planned work as a shipped feature.
At release time, move these entries into a dated version section and link its
notes in `doc/releases/`.

## [v0.13.1](doc/releases/v0.13.1.md) — 2026-10-18

### Bug fixes

- Fix valid Jev request reads rejected after Pi guidance hooks drop structured
  content. Accept only a complete visible text block that matches the existing
  read digest. Removed or changed text still fails closed; no raw reread occurs.
- Recognize the exact v0.13.0 Pi hook templates during upgrade. Create a backup
  if none exists; preserve an existing canonical backup. Custom hooks remain protected.
- Update managed Pi extensions with `lgtm update`, then run `/reload` or restart
  each running Pi session to load the fix.

## [v0.13.0](doc/releases/v0.13.0.md) — 2026-10-18

### Features

- Add six optional Jev tools for file questions, review flags, scope and claim
  advice, diagnostic triage, compaction advice, and untrusted-text warnings.
  Managed Pi setup includes them; startup makes no classifier call.

### Breaking changes

- Earlier advisory API drafts used inline bodies; now pass a bounded workspace
  JSON file through `requestPath`.
  Keep `preview` and `allowSend` in outer arguments. Review still accepts `{}`.
- Prepare private requests outside recorded tool arguments. References cannot
  erase earlier logs, and rejected inline calls may already be recorded by Pi.

### Improvements

- Preserve lazy native context fields and structured governed results. Accept
  fractional classifier scores, bound pending operations, and respect cancellation.
- Measure rendered JavaScript execution for coverage and share privacy code.
- Correct CI's MUST-only gate to evaluate failed/error results from one valid
  evidence record. Warning reviews remain visible; malformed evidence blocks.

### Security and bug fixes

- Inspect complete structured Git output and separate NUL-delimited paths;
  disable rename detection and external/text diff drivers to catch private origins.
- Consume governed read output only, reject missing or redirected bindings,
  and keep source previews metadata-only. Redact credentials and owned nested
  errors before provider transport or journaling; redaction remains a heuristic.

### Upgrade notes

- Run `lgtm update`, then `/reload` or restart each Pi session. Update draft tool
  callers to the reference-input API. Jev advice never grants permission or
  replaces deterministic enforcement. See the detailed release notes for limits
  and rollback guidance.

## [v0.12.6](doc/releases/v0.12.6.md) — 2026-10-17

### Bug fixes

- Accept Pi's current and legacy built-in tool paths, safe schema annotations,
  reordered required fields, and added optional inputs. These compatible changes
  no longer cause false tool-verification failures.
- Keep late failures from an old session out of the new session's warning state.

### Improvements

- Show hook warnings once per reason per session, with a reason code and repair
  guidance. Continue attempts to record every failure in session evidence.
- Recognize v0.12.5 and the earlier compatibility-build hooks during refresh.
  Preserve strict tool-origin checks, Bash-result tracking, and tool-call IDs.

### Upgrade notes

- Run `lgtm update`, then `/reload` or restart each running Pi session. Loaded
  hooks do not change when a file on disk changes. No Pi package update is needed.

## [v0.12.5](doc/releases/v0.12.5.md) — 2026-10-14

### Features

- Track shell-made file changes, including redirects, scripts, deletions,
  renames, and executable-bit changes, without requiring an Edit or Write event.

### Bug fixes

- Route Pi Bash results with native tool-call IDs. Add Claude Bash success and
  failure hooks so shell changes reach Stop checks.
- Migrate the old Claude matcher once without repeatedly restoring an owner-removed
  failure hook. Do not claim unchanged pre-existing dirty files as new edits.

## [v0.12.4](doc/releases/v0.12.4.md) — 2026-10-12

### Features

- Add Pi package defaults for web search, GitHub PR status, and explicit goal
  sessions. Packages still need their own credentials and user setup.

### Improvements

- Use unpinned Pi package names so old project defaults do not block updates.
  Keep custom versions, package filters, and other owner settings.

### Breaking changes

- Init and refresh remove the exact old LGTM package pins shipped through
  v0.12.3, even if an owner independently selected the same version. Other pins
  remain. Unpinned packages can receive breaking updates: review changes, run
  `pi update --extensions` in the project, then reload Pi.

## [v0.12.3](doc/releases/v0.12.3.md) — 2026-10-12

### Features

- Adopt known older hooks at the standard global Pi path during update, without
  a prior registry entry. Custom hooks and untracked projects are not adopted.
- Share managed engineering guidance between global Codex and Pi instructions.
- Enable Pi codemode beside existing tools while preserving explicit opt-outs.

### Security

- Reject uncertain Stop evidence reuse and keep staged-commit assessments fresh.
- Bound Ruff scans, version probes, output capture, and process cleanup. Report
  uncertain cleanup or unsupported containment as unverified, not as a clean pass.

## [v0.12.2](doc/releases/v0.12.2.md) — 2026-09-30

### Features

- Refresh registered managed rules, guidance, installed hooks, Codex execpolicy,
  and Pi configuration after `lgtm update`. Add `lgtm refresh` for manual binary
  replacement; keep `refresh-pi` as an alias.

### Upgrade notes

- Installations from v0.12.1 or earlier need one matching init registration.
  Register only the adapters in use; reload running agents afterward. Customized,
  repointed, removed, or disabled integrations remain protected during refresh.

## [v0.12.1](doc/releases/v0.12.1.md) — 2026-09-29

### Improvements

- Remove the 512-file source-scan cap and exclude runtime artifacts from its
  budget. Keep traversal and execution limits.

### Bug fixes

- Terminate active Pi hook processes on cancellation or session shutdown.
- Correct Pi pre-tool timeout margins and refresh missing rule descriptions.

### Breaking changes

- LGTM's shipped rule filenames become managed output: init backs up and replaces
  edits to those files. Keep custom guidance in separately named files. Preview
  replacements with `--dry-run`; review backups before committing them.

## [v0.12.0](doc/releases/v0.12.0.md) — 2026-09-08

### Features

- Add scoped shared-mobile, iOS, and Android design guidance for accessibility,
  layout, navigation, input, loading, errors, offline states, and permissions.
- Deliver the guidance through Claude rules, Pi's embedded catalog, and Codex's
  combined instructions. These are design instructions, not compliance checks.

## [v0.11.1](doc/releases/v0.11.1.md) — 2026-09-07

### Bug fixes

- Remove the ten-minute Pi runtime-attestation expiry. Otherwise valid long
  sessions no longer become unverified merely because time passed.
- Repair runtime-marker lookup and filter unsupported tools. Keep integrity,
  trust, policy, session-identity, and future-timestamp checks.

## [v0.11.0](doc/releases/v0.11.0.md) — 2026-08-28

### Features

- Configure Claude language-server plugins and protected-file permissions at init.
- Configure Pi project packages and language-server routes while preserving
  existing package choices, filters, routes, timeouts, and explicit disablements.

### Bug fixes

- Validate managed JSON before writing files. Recognize Pi 0.84.3 descriptive
  array metadata and safely upgrade v0.10.1-generated Pi extensions.

## [v0.10.1](doc/releases/v0.10.1.md) — 2026-08-27

### Improvements

- Add bounded `.gitignore` pattern handling for nested workspace discovery.
- Keep warning-level post-tool feedback non-blocking and show coverage evidence
  in human-readable reports. Improve path and endpoint signal boundaries.

### Security

- Strengthen bounded downloads, atomic updater replacement, external-process
  cleanup, and output capture for update and scanning operations.

### Bug fixes

- Correct a macOS locking-test assumption that blocked publication of v0.10.0.
  This is the published release of the v0.10 hardening changes.

## [v0.9.0](doc/releases/v0.9.0.md) — 2026-08-19

### Features

- Add Pi 0.84.2 adapter support, project/global installation, built-in tool
  verification, runtime attestation, and session-bound evidence.
- Add path-scoped guidance after verified Pi reads while preserving tool results.
  Custom tools and direct-first-edit guidance are not claimed as verified.

## [v0.8.9](doc/releases/v0.8.9.md) — 2026-08-19

### Features

- Add `lgtm init -g` for global Claude/Codex hooks and guidance, with a dry run.
  Merge managed content without replacing unrelated user hooks or instructions.

## [v0.8.8](doc/releases/v0.8.8.md) — 2026-08-18

### Features

- Publish the v0.8 feature set: session-deduplicated path guidance, workspace-scoped
  coverage gates, tooling guidance, and structural JavaScript script discovery.

### Security

- Bound command work and current-task evidence. Enforce workspace command paths
  and report incomplete policy, module, or coverage evidence as unverified.

### Bug fixes

- Handle macOS `/var` and `/tmp` aliases in persistent path-guidance state.
  Include the portability repairs from the unpublished v0.8.0–v0.8.7 tags.

## [v0.7.3](doc/releases/v0.7.3.md) — 2026-08-12

### Improvements

- Make Stop use targeted checks by default. Move full checks to intercepted
  direct commits, explicit full checks, pre-push, and CI.
- Reuse successful full evidence only while its session and content inputs match.

## [v0.7.2](doc/releases/v0.7.2.md) — 2026-08-12

### Bug fixes

- Keep chat-only Stop events quiet and bound non-actionable output.
- Record edited files directly and restore omitted full-tier Stop checks.
  v0.7.3 later changes the default Stop tier to targeted.

## [v0.7.1](doc/releases/v0.7.1.md) — 2026-08-03

### Security

- Fix Codex rules generated with invalid `decision="deny"`, which caused Codex
  to discard the whole file. Emit `forbidden` and regenerate owned rule files.
  Affected Codex projects must rerun `lgtm init --agent codex`.

## [v0.7.0](doc/releases/v0.7.0.md) — 2026-08-03

### Features

- Install rule guidance during normal init. Expand changed-test association to
  seven language packs and keep rule prose beside its machine-readable fields.

### Security

- Match prohibited command shapes across equivalent flag spellings and wrappers.
  Redact wrapper-carried values from denial messages.

### Bug fixes

- Tighten test-pass claim matching and allow safe symlinked repository ancestors.

### Breaking changes

- Retire checked-in `policy/rules.json` and the aggregate standards document.
  Checkout consumers must use `templates/claude-rules/rules/`; policy export
  still produces a derived `rules.json`.
- A missing source/test association becomes advisory `unverified`, not a hard
  Stop failure. Users who relied on that blocking behavior must adjust their gate.

## [v0.6.0](doc/releases/v0.6.0.md) — 2026-08-02

### Bug fixes

- Install the default destructive-command policy and route Claude Bash calls
  through it before execution. Existing policy files stay unchanged.
- Make Codex rules-only init write `AGENTS.md`, not Claude-only rule files.
  Existing users need to rerun the matching init command to receive these repairs.

## [v0.5.0](doc/releases/v0.5.0.md) — 2026-08-01

### Features

- Add `lgtm init --rules-only` to install Claude guidance without hooks or
  repository enforcement configuration.

## [v0.4.0](doc/releases/v0.4.0.md) — 2026-08-01

### Features

- Add copyable, binary-free Claude rule templates. Guidance is not enforcement.

### Bug fixes

- Treat expired waivers as inactive instead of invalidating the whole waiver file.
- Allow writes within new directories, reduce false verification claims, and
  exclude fixture/testdata trees from workspace discovery.

## Earlier published releases

| Version and notes | Published (UTC) | Category | Summary |
| --- | --- | --- | --- |
| [v0.3.1](doc/releases/v0.3.1.md) | 2026-07-13 | Features | Add Codex permission/subagent hooks, stable binary paths, and a documented execution-path capability matrix. |
| [v0.3.0](doc/releases/v0.3.0.md) | 2026-07-13 | Features | Add native Codex hook setup, event adapters, and optional execpolicy output. |
| [v0.2.6](doc/releases/v0.2.6.md) | 2026-07-12 | Bug fixes | Repair older generated V2 configs containing obsolete legacy keys after schema validation. |
| [v0.2.5](doc/releases/v0.2.5.md) | 2026-07-12 | Bug fixes | Stop adding legacy fields to valid V2 configs and preserve their bytes on re-init. |
| [v0.2.4](doc/releases/v0.2.4.md) | 2026-07-12 | Bug fixes | Stop treating operational LGTM notes as repository test claims. |
| [v0.2.3](doc/releases/v0.2.3.md) | 2026-07-12 | Bug fixes | Correct macOS canonical-path assertions and clarify the README's enforcement flow. |
| [v0.2.1](doc/releases/v0.2.1.md) | 2026-07-12 | Bug fixes | Detect declared Python tools without guessing unrelated commands. |
| [v0.2.0](doc/releases/v0.2.0.md) | 2026-07-12 | Features | Add policy authoring, pinned organization bundles, workspace/coverage support, and local evidence statistics. |
| [v0.1.4](doc/releases/v0.1.4.md) | 2026-07-12 | Features | Add checksum-verified atomic self-update, read-only update checks, and version selection. |
| [v0.1.3](doc/releases/v0.1.3.md) | 2026-07-12 | Bug fixes | Use portable Linux musl downloads to avoid the `GLIBC_2.39 not found` startup failure. |
| [v0.1.2](https://github.com/tcbuilds/lgtm/releases/tag/v0.1.2) | 2026-07-11 | Historical record | Only a comparison link is retained in its GitHub release; detailed notes are unavailable here. |

## Tags without a published release

The following tags have source notes but no published GitHub release in the
release list used for this index. Keep them separate from shipped releases.
Some early notes describe planned success that later release jobs did not reach;
see v0.8.8 and v0.10.1 for the published follow-ups.

| Tag and source notes | Status / follow-up |
| --- | --- |
| [v0.10.0](doc/releases/v0.10.0.md) | macOS release tests failed; published as v0.10.1 after repair. |
| [v0.8.7](doc/releases/v0.8.7.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.6](doc/releases/v0.8.6.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.5](doc/releases/v0.8.5.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.4](doc/releases/v0.8.4.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.3](doc/releases/v0.8.3.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.2](doc/releases/v0.8.2.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.1](doc/releases/v0.8.1.md) | Unpublished portability attempt; included in v0.8.8. |
| [v0.8.0](doc/releases/v0.8.0.md) | Feature release attempt; published with fixes in v0.8.8. |
| [v0.2.2](doc/releases/v0.2.2.md) | Source notes retained; no published GitHub release listed. |
