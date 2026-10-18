# Pi adapter contract evidence

This document records the Pi facts used by the M23 adapter work. The lifecycle
contract remains pinned to the Pi 0.84.2 matrix; built-in tool provenance was
re-probed against Pi 0.84.3 after its edit schema gained descriptive metadata.
This is a capability record, not a claim that Pi enforcement is installed. The
checked-in matrix is `tests/fixtures/pi/0.84.2/capability_matrix.json`; every
matrix claim below is tied to source or live evidence. The 0.84.2 capture
manifest and source excerpts remain under `tests/fixtures/pi/0.84.2/`; the
current built-in tool capture is
`tests/fixtures/pi/0.84.3/tool_provenance.json`.

## Verified event contract

- `session_start` is emitted after extension binding and before resource discovery
  (`session-start`, source fixture `source-session-start-types-0.84.2`).
- `before_agent_start` exposes the expanded prompt and current system prompt. Its
  result can provide a custom message or a replacement system prompt
  (`before-agent-start`, source fixture `source-before-agent-start-types-0.84.2`).
- `tool_call` runs before execution and can return `{ block, reason }`. Its input
  is mutable in Pi, so LGTM must treat it as read-only
  (`tool-call-block`, source fixture `source-tool-call-types-0.84.2`).
- `tool_result` runs after execution and can patch `content`, `details`, `isError`,
  and `usage`. It runs before `tool_execution_end` and final tool-result message
  events (`tool-result-feedback`, source fixture `source-tool-result-types-0.84.2`).
- `tool_execution_end` exposes the completed result and error flag but has no
  typed replacement result (`tool-execution-end`, source fixture
  `source-tool-execution-end-types-0.84.2`).
- `agent_end` may be followed by retry, compaction, or queued continuation;
  `agent_settled` means those automatic continuations are finished. Neither
  event declares a blocking response (`agent-end`, `agent-settled`).
- A global or CLI extension can decide project trust with `yes` or `no`; the
  first decided result wins. Both decisions were exercised in a temporary
  runtime probe (`project-trust-yes-no`, fixture `live-project-trust-yes-no-001`).

## Discovery and failures

Pi resolves project extensions from the startup cwd's `.pi/extensions/` directory,
then global extensions from `~/.pi/agent/extensions/`. The loader does not walk
ancestors for project extensions. A live loader probe recorded project-before-
global order at repository-root startup and global-only loading from a nested cwd
(`project-global-discovery-root`, `project-global-discovery-nested`; fixture
`live-discovery-root-order-001` and `live-discovery-nested-global-only-001`).

A module without a default factory is reported as a load error and skipped while
other discovered extensions continue (`malformed-extension`, fixture
`live-malformed-extension-001`). Extension modules run with the user's full
permissions; only trusted extension sources may be installed.

## Tool provenance

The live SDK captures in the versioned `tool_provenance.json` files record
`pi.getAllTools()` output, including parameter schemas and `sourceInfo`, for
built-in `read`, `bash`, `edit`, and `write` (`builtin-read-provenance`,
`builtin-bash-provenance`, `builtin-edit-provenance`,
`builtin-write-provenance`; fixtures `live-sdk-builtins-001` and
`live-sdk-builtins-0.84.3-001`). Pi 0.84.3 added a human-readable `description`
to the `edit.edits` array without changing its type, required fields, item schema,
or built-in provenance. The current matcher checks the capabilities LGTM uses,
not the exact captured schema. It accepts these compatible changes:

- Built-in paths in either `builtin:read` or legacy `<builtin:read>` form, with
  the matching tool name and `sourceInfo.source` equal to `builtin`.
- A different order for required fields.
- Schema annotations: `description`, `title`, `$comment`, `examples`, `default`,
  `deprecated`, `readOnly`, and `writeOnly`.
- Added optional inputs, or removal of a known optional input. A known optional
  input must keep its expected type if it is present.

Required fields, their types, and the `edit.edits` item contract must still match.
Unknown structural schema keys, new required inputs, and non-built-in origins
remain unverified. This does not promise support for every future Pi change.
The `PI_VERSION` wire label remains the legacy attestation profile; the extension
does not compare it to the installed Pi package version as an eligibility test.

A live SDK probe against installed Pi 1.1.0 confirmed that all four built-ins
pass with the `builtin:` path form. A same-name SDK `read` replacement reported
`sourceInfo.source: sdk` and failed verification. The integration test
`generated_hook_accepts_compatible_pi_changes_without_hiding_failures` also
checks compatible schema changes, rejected origins and structural changes, and
warning deduplication.

A project extension replacing `read` reports non-builtin
project source metadata (`same-name-read-override`; fixture
`live-sdk-override-001`). The override is deliberately **unverified** for built-in
enforcement. Custom, MCP, provider, and schema-mismatched tools remain
unverified (`custom-tool-provenance`; fixture
`unverified-custom-tool-provenance`). Tool names alone do not establish
provenance.

## Repeated unverified warnings

An unverified warning means that LGTM could not prove a check ran correctly. It
is not a policy violation or a successful check. The warning includes a bounded
reason code, such as `tool_provenance_unverified`. LGTM attempts to record every
failure in Pi session entries with custom type `lgtm`. Persistence is best effort
if Pi rejects the entry.

Without standalone Jev auto, each loaded extension shows a warning once per
reason per session. With Jev auto, the same metadata-only notice can be recorded
silently or shown as a nonblocking warning. A new session, `session_start`, or
shutdown resets the bounded presentation state. Failure records and deterministic
enforcement decisions are not suppressed. See [Jev auto](../jev-auto.md).

For `tool_provenance_unverified`, check whether another extension replaced a
built-in tool. If Pi changed its API, update LGTM, run `lgtm refresh`, then use
`/reload` or restart Pi. `project_untrusted` requires a project trust decision;
`policy_unverified` requires valid `.lgtm` policy files. Refresh does not grant
trust or repair invalid owner policy. A direct commit still requires current
runtime evidence and the existing commit-gate checks.

## Installation and rollback

Project setup uses `lgtm init --agent pi`. It writes the owned extension to
`.pi/extensions/lgtm.ts`, merges unpinned project package defaults into
`.pi/settings.json`, and merges the configured language-server routes into
`.pi/pi-lsp.json`. Init and refresh remove only the exact old pins shipped by
LGTM through v0.12.3. Other version choices and all package filters remain.
Package identity is compared without its npm version to avoid adding a second
entry for the same package.
Existing top-level Pi settings, timeout values, and named LSP server routes are
also preserved. Pi loads these project resources only after project trust; its
package manager, not LGTM, installs missing packages. Neither LGTM nor pi-lsp
installs language-server executables.

Global setup uses the existing `lgtm init -g` command and writes the owned
extension to `~/.pi/agent/extensions/lgtm.ts` alongside the other global harness
files. Both generated extension files embed the absolute executable path, are
upgraded only when their LGTM ownership markers match, and keep one
collision-safe `.bak` copy before a first upgrade. A user-authored extension at
either path is preserved. Remove the owned extension and its backup to roll back
that scope. For project package or LSP rollback, remove only the generated entries
and preserve unrelated JSON settings. No repository `.lgtm` configuration is
written by global init.

A project-root Pi session uses the project extension. When Pi starts in a nested
cwd, the project extension is not discovered, so the global extension prefers the
nearest root with a regular `.lgtm/config.json`; partial `.lgtm` markers are only
a fallback when no initialized config exists. The global extension is inert when
no marker exists and skips a root-start session when the current cwd contains the
owned project extension.

## Automatic upgrade refresh

Project/global init, rules-only init, and verified Pi session starts register
managed installations in `$HOME/.local/state/lgtm/pi-installations/` (the registry
retains its original directory name). Registration is outside repository tracking.
LGTM does not search the disk for repositories.

`lgtm update` invokes the newly installed executable to refresh all tracked managed
files: rules, guidance, installed hooks, generated Codex execpolicy, Pi extensions,
and installed Pi package/LSP configuration. An already-current update also refreshes
them. Only canonical Pi extensions pointing to that executable are changed;
customized, repointed, missing, or disabled extensions are preserved. Existing
hook events are reconciled without re-adding removed events, except for the
one-time Claude failure-hook migration described in
[shell change tracking](../shell-change-tracking.md). Repo policy and
command configuration, owner settings, and custom files remain untouched. Edited
shipped rules are backed up using the existing init backup behavior.

Existing backup collisions fail visibly without overwriting owner content. If
refresh fails after binary installation, repair the reported problem and run
`lgtm refresh`; the updater reports that the binary was already installed.

**Older installations:** refresh also checks the standard global hook path,
`~/.pi/agent/extensions/lgtm.ts`. It can adopt a known LGTM template at that path
if the hook points to the running executable. It replaces the old active hook and
keeps the existing backup policy. It does not search for other repositories or
adopt custom hooks. Untracked project installations still need
`lgtm init --agent pi` once. Versions through v0.12.1 do not run refresh after an
update; run `lgtm refresh` after that first upgrade. A verified session start also
registers its Pi installation.

**Running sessions still need `/reload` or a restart.** Updating a file on disk
cannot replace an extension already loaded in Pi. Automatic refresh does not
claim native UI approval verification or re-enable disabled integrations. If you
replace the binary outside `lgtm update`, run `lgtm refresh` afterward.
`refresh-pi` remains a compatibility alias.

Pi lifecycle hooks use a 10-second transport deadline. Bash pre-tool calls use a
310-second transport deadline because they may run the Pi-specific pre-commit gate;
that gate has a fixed 300-second total budget, including bounded checks and evidence
persistence, and denies on aggregate exhaustion. Claude and Codex keep their
existing full-gate budget.

## User guide: installation records and test isolation

The installation registry is a list of locations to refresh. It is not a list of
running agents. Tests that run init or verified Pi session-start hooks must set
the child process's `HOME` to a test-owned temporary directory. The temporary
fixture removes that directory and its registry when the test ends. Do not change
process-wide `HOME` in parallel Rust tests; use an isolated CLI child instead.

To check for leaks, run the full suite with a separate temporary HOME and an
isolated build directory. Keep Cargo and Rustup paths explicit so the test can
still use the installed toolchain. After the suite, verify that the outer test
HOME has no installation records. Records inside individual test fixtures are
expected; records in the outer HOME show a missing isolation boundary.

Refresh reports missing managed project roots for the current binary as stale
registrations. It skips those projects without deleting records or recreating
hooks. All directory entries still count toward the 4,096-entry scan limit,
including stale and unrelated records. The 30-second budget also remains in force.
The errors distinguish a full registry from a timeout.

If the registry is full, inspect the records and move only confirmed stale ones
to a backup directory outside the registry. Keep real installations and do not
use a temporary-path prefix alone as proof that a record is stale. Then run
`lgtm refresh`. There is no `lgtm repair` command. If the error is a timeout,
retry once and inspect the registry and storage if it persists.

## User guide: package updates

Pi project settings take precedence over global settings for the same package.
An old project pin can therefore keep a package old even when its global entry
has no version. LGTM no longer adds these version pins. The default list includes
`pi-web-search`, `@narumitw/pi-github-pr`, and `@narumitw/pi-goal`.

Run `lgtm update` to update LGTM and refresh registered project declarations.
Then run `pi update --extensions` in the project to update its installed packages.
Reload Pi after the update. LGTM does not run npm or download these packages.
Global init still manages guidance, the hook, and codemode; it does not add the
project package list to global settings.

Migration uses an exact list of the old LGTM specifications. If you chose the
same exact version yourself, LGTM cannot tell that choice from its old default
and removes that pin too. Different custom versions remain. Object-form settings
keep their resource filters and other fields when their source is migrated.

Unpinned packages can receive breaking changes. Extensions run with your user
permissions. Review updates before you trust them. Web search needs a supported
provider and its credentials. Installing goal support does not start a goal.
To roll back a package, select a tested version in Pi settings and reconcile the
installation with Pi. An exact old LGTM default will be migrated again on refresh.

## User guide: shared guidance and codemode

Run `lgtm init -g` to set up global guidance. LGTM puts the same engineering
standards in `~/.codex/AGENTS.md` and `~/.pi/agent/AGENTS.md`. Each file has an
LGTM-managed section. LGTM changes only that section. It does not copy your
private Codex instructions into Pi or remove your Pi preferences.

On update, older global installations get the Pi section once. After this step,
removal of the section is an opt-out. Update does not add it again.

Global setup also adds `+codemode` to `~/.pi/agent/settings.json`. Project Pi setup
adds it to `.pi/settings.json`. This enables codemode beside the existing tools.
Codemode lets the agent use a script to find tools and call them. It does not
change the selected chat model. It does not enable a classifier account or force
the agent to use a classifier.

LGTM preserves your tool list and codemode mode. An empty tool list,
`-codemode`, or `-builtin:codemode` is an explicit opt-out. LGTM does not override
those settings. Existing Pi settings get the same merge on refresh while the
LGTM hook is present. A removed settings file stays removed after migration.

To check the change:

1. Run `lgtm refresh`.
2. Open the two global `AGENTS.md` files. Check their managed sections.
3. Open the Pi settings file. Check `defaultTools` for `+codemode`.
4. Restart Pi, or use `/reload` to load the changed files.

To disable codemode, add `-codemode` to the tool list. To stop guidance refresh,
remove the LGTM-managed section after migration. Keep your personal text. To
restore setup, run `lgtm init -g` again. Explicit codemode opt-outs remain in force;
remove them yourself before setup if you want codemode enabled again.

A refreshed hook is not proof that every Pi version or tool is supported. If Pi
still reports an unverified hook, check its runtime evidence. Do not remove the
warning or mark the hook verified without that check. In particular, codemode
calls are not a new claim of verified LGTM enforcement.

## Jev advisory tools and request privacy

Managed project/global init includes six advisory Jev tools, exposed through
native codemode. Startup makes no classifier call and needs no extra key. Explicit
judgments use Pi's native OpenRouter `~typesafe/jev-latest` classifier and its
existing auth. Missing APIs, model, or provider return `unavailable`; deterministic
LGTM enforcement remains authoritative.

### Breaking draft API change: file references

The repaired API ships in **v0.13.0**. Earlier PR drafts
accepted inline excerpts, questions, claims, and state. These inputs now use a
bounded JSON request file. Only `requestPath` and the documented boolean controls
belong in tool arguments. Review flags still use an empty argument object.

**Why:** Pi records nested tool arguments before a tool runs. Redacting a result
or an `lgtm-jev` entry cannot remove an earlier argument record. With a valid
reference call, that record contains a path and controls, not the request body.
Pi can still record malformed inline arguments before Jev rejects them. Do not
put private data into any tool argument, including `write.content`, a command
literal, or a codemode script literal.

Prepare request files in an owner-approved editor or with a local command that
reads an approved file and writes JSON **without printing its contents**. Do not
copy raw logs through a model-facing tool result to build a request. Keep private
request files out of Git, give them owner-only permissions, and delete them when
finished. File references do not erase earlier logs or protect files left on disk.

Request files must be workspace-contained, regular, single-link UTF-8 files of at
most 32 KiB and 1,500 lines (a trailing LF counts as another line). Symlinks, private locations, prohibited paths, changed reads, malformed
JSON, and missing native read permission are rejected. Reads pass through Pi's
governed `read` path. The JSON body must match the selected tool's schema. The owned read-result hook
must be active in an initialized project; missing or changed read metadata fails
closed. A path digest observes the executed read arguments, not an unforgeable
authority token. Cooperative path redirects are rejected rather than followed
with a raw read of the original path.

| Tool | JSON request body | Outer controls |
| --- | --- | --- |
| `lgtm_jev_files` | `paths`, `questions` | `preview` |
| `lgtm_jev_scope` | `scope`, `claims`, optional `revision` | none |
| `lgtm_jev_triage` | `command`, `exitCode`, `excerpt`, optional `cwd`, `finding` | `allowSend` |
| `lgtm_jev_compaction` | optional `changedPaths`, `unfinished`, `constraints`; at least one item | none |
| `lgtm_jev_untrusted` | `source`, `excerpt` | `allowSend` |

`preview` and `allowSend` are not JSON-body fields. Body text cannot grant upload
permission. Redaction is a conservative heuristic, not proof that arbitrary
source has no secrets. It handles quoted JSON credential names, common config
assignments and token forms, emails, home paths, and IPs. Private-key blocks are
rejected. Common credential files such as `.npmrc`, `.netrc`, `.aws/`, and
`.ssh/` are denied. Unknown formats can escape a heuristic: review selected
inputs before sending them. Results do not create permission or verification. Jev keeps at most 64 active or
settling invocation IDs; overload returns `advisory_busy` without a new request.
Owned nested native errors are replaced with fixed text before Pi's error
journal sees them, including late errors after advisory cancellation. Deterministic
post-tool checks still run. Normal tool calls outside Jev are unchanged. Native
events or other trusted in-process extensions can still observe data; this is
not a sandbox against extensions or same-user filesystem changes.

## Jev file questions

Put one to eight `paths` and one to four typed `questions` in the request file.
For example, an approved request can contain:

```json
{
  "paths": ["src/checks/auth.rs"],
  "questions": {
    "lexical_check": {
      "type": "bool",
      "instructions": "Does this file check lexical signals rather than prove runtime authorization?",
      "criteria": {"true": "Lexical review signals", "false": "No such check"}
    }
  }
}
```

Use the path to that file, not its contents:

```js
const preview = await tools.lgtm_jev_files({requestPath: "advice-request.json", preview: true});
text(preview);
const judged = await tools.lgtm_jev_files({requestPath: "advice-request.json"});
text(judged);
```

Each source file is at most 16 KiB and 1,500 lines. The batch source budget is
64 KiB. File judgments have five-second deadlines inside a twenty-second total
budget, including request loading. Files are read sequentially, with at most one
classifier call per file. Preview reads its request file, but checks only metadata for selected source
files. It reads no selected-source bytes and makes **zero classifier calls**.
Its call/byte counts and eligibility labels are estimates, not content or native
read-permission proofs.

The tool rejects private/credential-bearing content and unsafe or filtered reads.
It consumes only final governed text, never raw source snapshots or a discarded
field. If a guidance hook adds text and Pi drops `structuredContent`, Jev can use
a complete visible text block whose SHA-256 matches the read binding. It does not
combine blocks, strip guidance, or recover removed text. Replaced structured text,
changed bindings, and removed or altered file blocks still fail closed. This
applies to request files and selected source files. Metadata changes cause `stale` or unavailable outcomes.
Metadata checks are not byte-identity or race-proof guarantees. Bool answers retain probabilities. Choice labels outside the offered
criteria become explicit no-match. Scores are finite expected level indices in
`[0, criteria.length - 1]`, including fractional values such as `1.5`.
Malformed, missing, or out-of-range answers are unavailable, not negative matches.

Results contain typed judgments, safe question IDs/types, file metadata,
coverage/status, and reported usage. `hashKind: "governed_output"` labels the
SHA-256 of the authorized returned text, not a proven on-disk file hash;
`coverage: "governed"` makes that scope explicit. They do not contain source or rubric bodies.
Use ordinary reads before editing or quoting. Request files and chosen source
files can contain sensitive data that heuristics cannot recognize; approval of
the input remains the caller's responsibility.

### Replay and coverage checks

`tests/fixtures/pi/jev_replay_corpus.json` retains the hand-labeled public-source
corpus and rubric `lgtm-pi-jev-replay-v1`. The offline preflight uses a scripted
provider to check transport, bounds, stale input, hostile-text handling, and
typed results. It is marked `semanticQuality: "not-evaluated"`; scripted agreement
is not classifier accuracy. The older live result in
[the replay record](../jev-replay-results.md) is historical evidence, not a fresh
live verification of the reference-input API.

Run `cargo test --test jev_pi` for generated-extension integration checks. Run
`node scripts/jev-coverage.cjs` with Node 24 and Rust installed to measure their
execution against the original JS fragments. The loader verifies each rendered
fragment byte-for-byte, then executes it under its original source filename.
Pinned c8 writes real LCOV to `target/jev-coverage/lcov.info`. Coverage
includes every Jev template, including unexecuted files. CI imports that report
into SonarCloud; fixture files are classified as tests, not production sources.
No coverage exclusions or fabricated counts replace missing execution.

A live replay needs separate owner approval and a bounded call/cost budget.
Record source identities, model alias/version, failures, abstentions, elapsed
time, and actual cost. Compare against grep or CodeGraph. No advantage over grep
is claimed by the old small corpus, and no paid replay runs during init or tests.

## Jev diff review flags

`lgtm_jev_review` uses fixed read-only Git calls through Pi's native Bash tool.
It validates complete structured output and a separate NUL-delimited name list.
It disables rename detection and external/text-conversion drivers for both Git
operations, so old private rename endpoints remain visible. It checks the path
list again after reading the patch. Truncated native output,
changed path lists, private paths, and recognized sensitive content are rejected
before classification. A clean worktree makes no classifier call.

```js
text(await tools.lgtm_jev_review({}));
```

Input is capped at 200 files and 192 KiB of complete diff before the UTF-8-safe
48 KiB clip. Clipping is reported as partial coverage. Hunk text is never used
as returned filename metadata. Four independent flags cover auth/permissions,
data loss, public interfaces, and state/concurrency complexity. There is no
aggregate risk score. Missing answers remain unknown. These flags never change
a gate, grant permission, or create passed-command evidence.

## Jev scope and claim advice

A scope request file holds a 512-character `scope`, one to eight bounded
`claims`, and an optional 40-hex `revision`. The tool reads the revision and
complete NUL-delimited changed paths through native Bash. It rejects private or
incomplete path lists and bounds the list to 200 paths.

```js
text(await tools.lgtm_jev_scope({requestPath: "scope-request.json"}));
```

A revision mismatch is `stale`; no changes is `empty`. Both make zero classifier
calls. Per-claim verdicts are supported, unsupported, contradicted, unclear,
missing, or invalid. These are advice, not verification; deterministic Stop
claim checks remain authoritative. Claim and scope bodies are not returned.

## Jev diagnostic triage

A triage request file holds `command`, integer `exitCode`, and an already-minimized
`excerpt`, plus optional `cwd` and `finding`. The tool reads that request file,
not a full log. It redacts metadata and excerpt before the 8 KiB byte clip.
Private keys in any field reject the request, including preview.

```js
text(await tools.lgtm_jev_triage({requestPath: "triage-request.json"}));
// Send only after the owner has approved the selected input and preview.
text(await tools.lgtm_jev_triage({requestPath: "triage-request.json", allowSend: true}));
```

Only outer `allowSend: true` permits a classifier call. Preview and advice return
safe facts, counts, clipping information, and a bounded cause category: code,
tool, environment, or unknown. They do not return the excerpt or suggest/apply a
repair. Unavailable advice does not prevent normal log inspection.

## Jev compaction advice

A compaction request file contains bounded `changedPaths`, `unfinished`, and
`constraints` lists. It reads no transcript and cannot compact anything.

```js
text(await tools.lgtm_jev_compaction({requestPath: "compaction-request.json"}));
```

The result contains a recommendation and a sanitized preservation checklist.
Private-key state is rejected. Missing answers remain partial or unavailable.
Use Pi's own `/compact`; its summary format, cut safety, settings, and tool/result
pair handling stay in control.

## Jev untrusted-output advice

An untrusted request file holds bounded `source` and `excerpt` fields. Both are
sanitized before preview, transport, return, or optional session metadata.
Private-key content in either field is rejected. The excerpt is clipped to
8 KiB on a UTF-8 boundary, with provided/inspected coverage reported.

```js
text(await tools.lgtm_jev_untrusted({requestPath: "untrusted-request.json"}));
// Send only after reviewing the selected input and redacted preview.
text(await tools.lgtm_jev_untrusted({requestPath: "untrusted-request.json", allowSend: true}));
```

The result has a suspicious flag and an instruction-injection, exfiltration,
benign-quoting, or unclear category. **This is not a security boundary.** A clean
inspected span says nothing about unseen text. Advice never overrides trusted
instructions, permissions, or deterministic checks. No raw excerpt is returned.

## Answer caching for explicit advisory tools

The six explicit advisory tools do not cache answers. Standalone
[Jev auto](../jev-auto.md) separately retains one transient routing hint and bounded
notice-presentation deduplication; neither stores approval or command evidence.
No persistent answer cache ships. The decision rule is measurement first: caching is
only justified when repeat queries of the same identity actually reuse answers
enough to beat the cost and risk it adds. The offline preflight makes no live
calls by design, and the live replay has no measured repeat reuse, so there is no
net benefit to claim. Adding storage now would create stale-answer risk for a
cheap decision without evidence.

If a future live replay shows real reuse, a cache may be added only with a
bounded, private design: identity covers the exact input, questions, provider and
model, policy, and source freshness; a moving alias like `~typesafe/jev-latest`
must resolve to a concrete version before reuse; errors are never cached as
negative judgments; expiry and size limits are enforced; corrupt state fails
closed; and cancellation never writes. Do not add a database or service to cache
these decisions.

## Finding approval capability

The canonical extension now advertises `lgtm-pi-heuristic-notices` version 1.
Eligible staged heuristics become nonblocking typed notices, with presentation
handled by standalone [Jev auto](../jev-auto.md). No native confirmation is asked.
The extension performs a fresh deterministic reassessment after presentation;
changed or hard findings remain denied. Missing Jev produces a warning, not a
new prompt or a passed check.

The paragraphs below describe the retained **legacy client**
`lgtm-pi-finding-approval` v1 contract. Rust still preserves that capability only
when its exact `{name, version: 1}` object is present. The new extension does not
advertise it and rejects a legacy challenge rather than opening a dialog. Missing,
malformed, or unknown capabilities cannot select the new notice policy.
Only a direct staged `git commit` whose complete fresh gitleaks assessment contains
eligible built-in `generic-api-key` findings can produce the redacted approval
challenge. Provider credentials, private keys, custom rules, mixed findings, and
scanner or repository errors remain hard denials.

The challenge binds the canonical repository and Git state, session and adapter,
normalized commit argv, scanner/config/ignore/waiver and policy identities, scanner
and Git executable identities, and the complete finding set. The extension may ask
for native confirmation only in Pi `tui` mode with verified current runtime
attestation and UI availability. Approval authority is local to one invocation,
never persisted, and invalidated by session generations and shutdown. Before a new
direct commit attempt, the live extension revalidates its executable, template,
project trust, and all built-in tool contracts, then records fresh runtime evidence.
This lets a repaired hook failure recover in the same session without deleting
failure history or restoring an earlier approval. Failed re-attestation denies.
The extension rechecks the canonical template and trusted executable after confirmation, performs
one bounded fresh reassessment, and allows only an identical pending assessment or
a clean pass. Cancellation, timeout, UI absence, changed findings/configuration,
stale attestation, executable/template mutation, malformed responses, and failed
reassessment deny. Finding display is redacted to rule, path/location, and a
non-secret candidate identifier; no secret value or scanner description is shown.
These checks narrow, but cannot eliminate, same-user TOCTOU mutation between
revalidation and child execution; Pi extensions are not an operating-system
security boundary.

The bounded full-repository source scan preserves `.pi/extensions/`,
`.pi/settings.json`, and `.pi/pi-lsp.json`. It excludes only the known runtime
subtrees `.pi/orca-recovery/`, `.pi/subagents/`, `.pi/subagent-output/`,
`.pi/npm/`, and the root `.killer-whale/`. A real source-path limit remains a
source-scan failure; it is not reported as aggregate-budget expiry.

## Path-scoped guidance

For a verified built-in `read` result, the Pi extension validates the result
shape, safely resolves the path against the event cwd, verifies repository
containment, and forwards only the normalized path and session identity to the
shared M20 path-injection service. The service performs frontmatter matching,
body extraction, ordering, bounds, and persistent per-session deduplication.
Matching bodies are returned as additional text after the original `content`
array; `details`, `isError`, and `usage` are preserved. Malformed results,
unsafe paths, and degraded shared state remain bounded unverified outcomes.
This path is guidance only and does not change tool input or enforcement results.

Pi cannot provide verified context before a direct `edit` or `write` call through
the current event contract. Such calls remain enforced by the pre-tool policy,
but path-scoped guidance is unsupported/unverified for that direct-first-edit
case. A preceding `read` is the supported guidance path.

The supported built-in input paths captured by the fixture are:

| Tool | Required input | Optional input |
| --- | --- | --- |
| `read` | `path` | `offset`, `limit` |
| `bash` | `command` | `timeout` |
| `edit` | `path`, `edits[].oldText`, `edits[].newText` | none |
| `write` | `path`, `content` | none |

## Deferred claims

M23.2 does not claim a hard Stop gate, provider payload coverage, or interception
of custom/MCP/overridden tools. M23.7 does not claim direct pre-execution
path-scoped context for `edit` or `write`; a preceding verified `read` result is
required. The `agent_settled` notification writes current Pi enforcement evidence
through the existing evidence JSONL path; `agent_end` and Stop remain
non-blocking. The adapter preserves original `tool_result` fields and fails open
with an explicit unverified marker when provenance, schema, trust, runtime
loading, or shared guidance state is not proven.
