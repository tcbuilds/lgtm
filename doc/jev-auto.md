# Jev auto: routing and quiet gate notices

Jev auto helps select tools before each assistant model request. It also sorts
LGTM's already-nonblocking heuristic notices. It does not approve an operation,
change a test result, or create command evidence.

## Per-step routing

The native Pi `context` event runs before each model call. The router uses:

- A short, sanitized user task, with credential-shaped text removed.
- Recent tool names, error flags, and numeric exit codes.
- Tool names, bounded descriptions, and exposure settings.

It does not send tool inputs, commands, tool output, file contents, or the full
conversation. Only the last 32 context messages are inspected. The starting task
is retained for longer runs. Code fences in the task stop task-text collection.
Redaction is a heuristic, not proof that arbitrary prose has no private data.
Do not include private credentials in prompts or tool descriptions.

At the first recognized credential assignment, the router removes the rest of the
bounded text. It does not try to guess where a quoted credential ends. This can
remove useful task detail, but prevents a second quoted segment from leaking.
Tool-name copies in classifier inputs, generated hints, and status messages use
the same redaction before their length limit. Original tool names stay local for
ranking and activation. Native Pi tool declarations and existing conversation
messages are not rewritten; they are outside this extension's redaction scope.

The router keeps existing active tools. Pi snapshots the tool loadout before the
`context` hook, so newly enabled direct tools take effect on the **next model
turn**, not the request being routed. The hint states this limit. Current requests
must use already-declared tools or an already-callable codemode tool.
Hidden tools are excluded. Codemode tools
stay callable through scripts instead of becoming direct tool declarations.
At most eight suggestions are shown at the initial relevance cutoff of 0.65.
The score is not a calibrated probability of success or permission to call a tool.

An unchanged sanitized task/result/catalog signature reuses the last hint without
another classifier call. A changed result can cause a new route during the same
user task. Old transient Jev hints are replaced, not added to an ever-growing
context. File classification remains an explicit on-demand tool.

Status notifications show `routed`, `skipped-unchanged`, or `unavailable`, with the
model, scores, tool counts, activation details, and elapsed time. Use
`/jev-auto status`, `/jev-auto off`, or `/jev-auto on` for local control.

## Quiet gate notices

The updated LGTM extension advertises `lgtm-pi-heuristic-notices` version 1.
This is a separate protocol from the old native finding-confirmation protocol.
It means that deterministic policy permits an operation with review notices.
It does not mean that Jev approved the operation.

Only these findings can enter this channel:

- A complete staged scan containing only eligible built-in `generic-api-key`
  findings, after the full deterministic commit gate has run.
- Existing warning-level review findings from post-tool checks.
- Presentation-only hook diagnostics. Their original error and gate decision
  remain unchanged.

Known provider credentials, private keys, custom scanner rules, mixed hard and
heuristic findings, prohibited actions, required-command failures, and unverified
required checks cannot be downgraded by a Jev answer. Touched-file secret scans
still keep their existing hard feedback; the staged scanner's stronger eligibility
partition is not guessed from a message or a filename.

LGTM sends a typed notice through the in-process `jev-auto:gate` event bus. Jev
receives only notice kind, safe rule ID, and a broad path class such as `test` or
`source`. No paths, candidate hashes, source, secret values, command output, or
scanner descriptions go to the classifier.

- Noise score at least 0.90: record silently.
- Other valid score: record and show a nonblocking warning.
- Missing model, timeout, malformed answer, busy provider, or spent budget:
  record unknown and warn without a confirmation dialog.

The 0.90 cutoff controls display only. It is an initial product setting, not a
measured accuracy guarantee. A `test` path is not proof of safety. Each outcome is
recorded as compact metadata in `jev-auto-gate` session entries. Repeated notice
identities are not sent, recorded, or shown again while retained in the bounded
session window. At capacity, the oldest identity is evicted; new notices are
still recorded and warned when their status is unknown.
Warnings are grouped per batch rather than shown as one dialog per finding.

After awaiting staged notice presentation, LGTM rechecks the live runtime and
performs one fresh deterministic reassessment. Only the identical notice set or
a clean result allows the commit. A new hard finding, changed identity, stale
session, cancelled operation, malformed response, or failed reassessment denies.
Jev's cached display decision is never cached permission.

The new extension does not fall back to the legacy confirmation dialog. An old
binary returning a legacy challenge is denied with a refresh instruction. Older
clients retain their existing v1 behavior. Claude and Codex behavior is unchanged.

## Bounds and failure behavior

- Routing: at most 256 tools, eight suggestions, one unresolved classifier call,
  64 attempts per session, and a one-second deadline.
- Gate notices: at most 32 notices per event, 16 classified per batch, one
  unresolved classifier call, 20 attempts per session, and a one-second deadline.
- Routing keeps one last hint. Gate deduplication holds at most 256 identities.
- Session changes clear local decisions. Late replies cannot activate tools or
  notify a new session. A provider that ignores abort still occupies its slot.
- There are no retries, persistent answer database, extra model turns, or new
  requests for human approval. No real model calls run in integration tests.

Jev auto cannot intercept every UI dialog from another extension. LGTM uses the
explicit notice handoff. A hard denial from any extension remains a hard denial.
If Jev auto is not loaded, LGTM warns once and preserves deterministic decisions.

## Repair required-command failures without a waiver loop

A required test or build failure is not a heuristic notice. The agent must inspect
the failure, repair the cause within the approved task, and rerun the check. A
routine repair does not require a new owner decision. Do not ask for a waiver
that cannot clear a protected gate, or repeatedly ask the same question.

Containment checks look for child processes left behind by a command. A command
can exit successfully while a child remains. On Linux, even an exited child can
remain as a zombie until its parent collects its exit status. The gate rejects
these leftovers; Jev cannot turn that result into a pass.

LGTM's own timeout fixtures exposed this problem. The test-mode runner used its
whole deadline for execution, then had no time left to reap the killed child.
Other fixtures deliberately orphaned processes without an isolated reaper. The
repair reserves cleanup time and uses the existing isolated test helper. It does
not relax containment, accept incomplete evidence, or change approval policy.

Use the normal command gate after the repair. Passing tests alone do not prove
that no child processes were left behind. Ask the owner only when the repair
needs new authority or a real product decision, not merely because a check failed.

<a id="install-and-verify-without-a-release"></a>

## Install and verify

Requirements: Pi 1.3.0, Node 24 for the local checks, and authenticated access to
`openrouter/~typesafe/jev-latest`. Missing classifier access is nonblocking.

The LGTM binary embeds both Jev auto source files. You do not need a source
checkout or manual file copies. Every successful CLI `lgtm init` variant installs
this global bundle:

```text
~/.pi/agent/extensions/jev-auto/index.ts
~/.pi/agent/extensions/jev-auto/jev-auto-gates.ts
```

`lgtm update` and `lgtm refresh` also install it on a fresh HOME, even when there
are no registered project hooks. An already-current update still refreshes the
bundle. `lgtm update --check` and init dry-runs do not write files. These commands
do not call the classifier or change provider credentials.

After installation, use `/reload`, then `/jev-auto status`. Routing notices appear
when Pi prepares model steps, not while the CLI updater runs. The directory
layout keeps the helper from loading as a second extension. Jev auto is global;
it is not a separate copy in each project.

LGTM tracks the exact installed file hashes in
`~/.local/state/lgtm/jev-auto/receipt.json`. Unchanged managed copies can upgrade.
Edited files are preserved as a complete pair and reported as not upgraded.
Refresh also preserves a deliberately removed managed component; explicit init
can restore it only when surviving files are still recognized. Disable the
extension in Pi settings for a persistent runtime opt-out.

An exact canonical legacy pair at `extensions/jev-auto.ts` and
`extensions/jev-auto-gates.ts` can migrate automatically. Backups stay outside
Pi's extension discovery directory. Unknown legacy entrypoints, orphan helpers,
and invalid management receipts produce an actionable collision error rather
than being overwritten or duplicated. Move a confirmed custom legacy setup to
a backup outside the extensions directory before choosing managed installation.

Publication is staged and checked for detected concurrent edits, but the two
files and receipt are not one filesystem transaction. Follow any partial-write
recovery message; do not replace a management receipt to claim custom files are
owned. Keep your own matching files before a downgrade: an older binary may not
manage this bundle. Restore those files or disable the directory, then reload Pi.

Run the offline checks from the repository:

```sh
node --experimental-strip-types tests/fixtures/pi/jev_auto.cjs templates/pi/jev-auto.ts
cargo test --test jev_pi --test init_pi --test pi_adapter --test commit_secret_scope
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build
```

Verify in a throwaway trusted project: a second assistant step routes, an unchanged
step skips, a heuristic notice does not call native confirmation, and a hard
finding still blocks. Check session entries for silent outcomes. Local verification
does not itself publish a release or replace your installed production binary.
