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

Each loaded extension shows a warning once per reason per session. A new session,
`session_start`, or shutdown resets this limit. Warning state holds at most 32
reason codes. Repeated warnings are suppressed; failure records and enforcement
decisions are not suppressed.

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

## Jev file questions

Managed project/global init includes `lgtm_jev_files`, available by default
through native codemode. Init makes no classifier call and requires no key.
The operation uses Pi's native OpenRouter `~typesafe/jev-latest` classifier;
there is no separate client or credential store. Older Pi versions without
the native classifier/nested-tool API return `unavailable`. Ordinary tools and
LGTM enforcement continue working when Jev, authentication, or the provider
is unavailable.

```js
const result = await tools.lgtm_jev_files({
  paths: ["src/checks/auth.rs"],
  questions: {
    lexical_check: {
      type: "bool",
      instructions: "Does this file check lexical signals rather than prove runtime authorization?",
      criteria: { true: "Lexical review signals", false: "No such check" },
    },
  },
});
text(result);
```

The operation accepts one to eight files, each up to 16 KiB and 1,500 lines, one
to four boolean/choice/score questions, and a five-second request deadline
inside a twenty-second aggregate budget. It reads files one at a time, so a
batch makes at most one classifier call per judged file and never carries more
than one file in a request. It rejects workspace escapes, symlinks/hardlinks,
prohibited paths, common credential paths/content, non-text input, duplicate
paths, oversized input, and total volume above 64 KiB. Content checks reduce
risk; they do not prove that arbitrary source has no secrets. The file read
passes through Pi's normal tool handlers. A filtered source block is not
silently replaced with raw bytes. Source changes make the answer stale.

Set `preview: true` to inspect the scope with **zero classifier calls**: it
reports eligible and skipped paths, stable item IDs, planned questions, the
declared bounds, and labeled call/byte estimates. Preview does not read file
content, so content-level rejection surfaces during classification. Every
answer is validated against the offered criteria: a choice label outside the
criteria is an explicit no-match, an out-of-range score or missing answer is
`unavailable`, and failed or unread files are `unavailable`, never negative
matches. Batch results keep per-file coverage, content hashes, and a
`partial` status when only some files were judged.

```js
const preview = await tools.lgtm_jev_files({ paths: ["src/a.rs", "src/b.rs"], questions, preview: true });
text(preview);
const judged = await tools.lgtm_jev_files({
  paths: ["src/a.rs", "src/b.rs"],
  questions: {
    risky: { type: "bool", instructions: "Does this file touch auth?", criteria: { true: "Auth", false: "No auth" } },
    layer: { type: "choice", instructions: "Which layer?", criteria: { domain: "Domain", api: "API" } },
    quality: { type: "score", instructions: "Rate validation.", criteria: ["none", "partial", "strong"] },
  },
});
text(judged);
```

### Replay procedure

`tests/fixtures/pi/jev_replay_corpus.json` is a versioned, hand-labeled corpus of
real public LGTM source. It records the rubric (`lgtm-pi-jev-replay-v1`), model
identity, byte bound, questions, and per-case labels for useful, irrelevant,
negation, held-out, and hostile text.

`tests/fixtures/pi/jev_replay.cjs` runs the offline preflight. It validates the
corpus, then drives the generated tool with a **scripted** provider to prove
transport and validation contracts: one call per case, raw source never returns,
preview makes zero calls, unmapped choices become explicit no-match, out-of-range
scores become `unavailable`, changed inputs become `stale`, hostile text is
carried as data only, and denied paths never reach the provider. It prints a JSON
report marked `semanticQuality: "not-evaluated"`. Offline preflight needs no key
and makes no classifier call. Run it with the other Pi integration checks.

Only a **live** replay measures semantic quality. Ask the owner first, then run a
small, bounded set: at most 64 calls, 16 KiB of public committed source per call,
and a hard cost cap. Record the question and policy version, source identities,
reported model (an unresolved alias is not a pin), failures, misses, false
positives, abstentions, main-model context, elapsed time, and total cost. Compare
against CodeGraph or grep alone. Unknown cost stays unknown, and publishing no
benefit is the expected outcome when Jev adds nothing.

Results contain judgments, source hashes, coverage/status, and reported usage,
not file text. They are advisory; probabilities are not correctness proofs.
Use ordinary reads before editing or quoting. Failure diagnostics and session
metadata omit raw provider errors, question bodies, and source. Your existing
`jev-auto.ts`, active tools, chat model, and deterministic checks are unchanged.

## Jev diff review flags

Managed init also registers `lgtm_jev_review`, available by default through
native codemode. It obtains the current diff with a fixed read-only
`git diff` call through Pi's own bash tool, bounds the patch to 48 KiB and 200
files, and returns **four independent** boolean flags: authentication and
permissions, data loss, public interfaces, and state or concurrency complexity.

```js
const review = await tools.lgtm_jev_review({});
text(review);
```

There is no aggregate risk score, because one cannot cancel a security flag.
Each flag carries its own probability, an `unknown` marker, and the same evidence
ID. A missing or malformed answer leaves that flag `unknown` and the rest intact;
the overall status is `partial` or `unavailable`, never a clean result. Empty,
oversized, credential-bearing, or private-path diffs are `empty`/`rejected` and
make no classifier call. The tool never writes, never runs a repository command
other than the fixed read-only diff, and never creates command evidence or
changes a gate. Use ordinary review and the deterministic gates for decisions;
this only focuses attention.

## Jev scope and claim advice

`lgtm_jev_scope` compares a declared scope and final claims against the current
changed paths at an explicit completed-slice check. It reads the revision and
paths with fixed read-only `git` calls, bounds the inputs (512-character scope,
one to eight claims, 200 paths), and returns an advisory verdict per claim:
`supported`, `unsupported`, `contradicted`, `unclear`, `missing`, or `invalid`.

```js
const advice = await tools.lgtm_jev_scope({
  scope: "documentation only, no production code",
  claims: ["Only markdown changed"],
  revision: "<40-hex HEAD>",
});
text(advice);
```

A revision that does not match `HEAD` is `stale`; no changes is `empty`; both
make no classifier call. Advice is not verification. This tool never creates
`Passed` command evidence, never changes `lgtm` gate decisions, and never edits
`src/checks/claims.rs` or `src/hooks/stop.rs` behavior. The deterministic Stop
claims check remains authoritative, and a missing answer stays `missing` rather
than becoming a clean or contradicted result.

## Jev diagnostic triage

`lgtm_jev_triage` returns one bounded cause category for a caller-minimized
diagnostic excerpt: `code`, `tool`, `environment`, or `unknown`. The caller
supplies the excerpt; the tool never reads a log, runs a command, stores
evidence, installs anything, or suggests a repair.

```js
const preview = await tools.lgtm_jev_triage({ command: "cargo test", exitCode: 101, excerpt });
text(preview); // redaction and clipping plan only; no classifier call
const triage = await tools.lgtm_jev_triage({ command: "cargo test", exitCode: 101, excerpt, allowSend: true });
text(triage);
```

Redaction runs before the 8 KiB clip, and clipping is always reported. Regex
redaction is not permission to upload: without `allowSend: true` the tool returns
a `preview` with zero calls. Home paths, emails, IPs, and credential-like tokens
become markers; a private-key block is `rejected` outright and never transported
or logged. Command, cwd, exit code, and an existing LGTM finding remain facts
after the same redaction; a private-key value in any field is `rejected` before
transport or persistence. Bounds count UTF-8 bytes, so multi-byte text cannot
exceed the clip. When Jev is unavailable, inspect the raw log normally; the tool
never replaces that.

## Jev compaction advice

`lgtm_jev_compaction` advises whether the current point is a task boundary and
lists what to preserve before Pi's **own** `/compact`. It reads no transcript and
compacts nothing; it only accepts bounded caller state and returns advice.

```js
const advice = await tools.lgtm_jev_compaction({
  changedPaths: ["src/init/pi.rs"],
  unfinished: ["wire refresh path"],
  constraints: ["keep owner edits"],
});
text(advice);
```

The recommendation is `compact_now`, `compact_after_finishing`, `stay_put`, or
`unclear`; unfinished state is a separate flag. The result echoes the caller's
paths, unfinished work, and constraints as a preservation checklist. Missing
answers leave advice `partial` or `unavailable`, never a clean result. It cannot
change Pi compaction settings, delete transcript, or drop a tool/result pair;
Pi's native summary format and cut safety stay in control. When Jev is
unavailable, `/compact` works exactly as before.

## Jev untrusted-output advice

`lgtm_jev_untrusted` warns when an approved, bounded external excerpt tries to
redirect an agent or leak data. The caller supplies the excerpt and its source;
the tool redacts then clips, reports inspected versus provided coverage, and
returns a `suspicious` flag plus a `kind` (`instruction_injection`,
`exfiltration_attempt`, `benign_quoting`, `unclear`).

```js
const preview = await tools.lgtm_jev_untrusted({ source: "issue comment", excerpt });
text(preview); // redaction/coverage plan; no classifier call
const warning = await tools.lgtm_jev_untrusted({ source: "issue comment", excerpt, allowSend: true });
text(warning);
```

This is **not a security boundary**. A clean inspected span never proves unseen
text is safe, and clipping is always reported as partial coverage. Bounds count
UTF-8 bytes, not characters. It never
overrides trusted instructions, permissions, or deterministic checks, never reads
files, and never runs commands. A private-key block is `rejected`; missing answers
stay `partial` or `unavailable`. A harmless quoted or test example is
`benign_quoting`, not an injection.

## Answer caching: not needed

No bounded answer cache ships. The decision rule is measurement first: caching is
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

The canonical extension advertises the strictly versioned
`lgtm-pi-finding-approval` capability on Bash tool calls. Rust preserves that
capability only when its exact `{name, version: 1}` object is present; missing,
malformed, unknown, or old callers receive the ordinary `{block, reason}` denial.
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
