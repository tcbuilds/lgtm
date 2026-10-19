# Automatic Pi checkpoints

Every successful `lgtm init` command installs a personal Pi extension at
`~/.pi/agent/extensions/lgtm-checkpoint.ts`. This includes Claude, Codex, Pi,
global, rules-only, and config migration commands. `--dry-run` reports the
planned installation without writing it. Reload or restart Pi after installation.

This is separate from the LGTM enforcement extension. It can write documents in
any active Git repository, even one without LGTM policy. Checkpointing does not
perform Jev routing. CLI init installs the separate embedded global Jev auto pair
alongside the checkpoint; see [Jev auto setup](jev-auto.md#install-and-verify).

## What happens before automatic compaction

1. Find the active Git worktree root, even from a nested directory.
2. Read local Git state, the recent Pi conversation, the previous compaction
   summary, and the existing handoff and plan.
3. Ask the current model for a short handoff. This is an extra model request and
   can add cost. It uses the same provider as the active conversation.
4. Update `HANDOFF.md`. Keep the earlier handoff in collapsed history. Move
   history older than 30 days, or history that exceeds the inline limit, to a
   dated `HANDOFF.YYYY-MM-DD.md` file. Existing archives are never overwritten.
5. Check an existing plan task only when the model supplies a matching line and
   a supporting quote from the supplied evidence. Do not create a missing plan.
6. Let Pi perform its normal compaction.

Manual `/compact` does not write a checkpoint. The extension does not change
Pi's summary, commit files, push changes, run a build, or run model-chosen shell
commands. Build and test claims remain unverified unless the captured session
contains their results. Model judgment about task completion can still be wrong;
review checked tasks before treating them as final acceptance.

## Handoff contents

The document follows the session handoff skill:

- Mission context: why the work exists.
- What shipped, with observed commit evidence.
- Work still in progress, uncommitted files, and stashes.
- Tried and rejected approaches.
- Open decisions and questions.
- Observed build and test state.
- Files to read first.
- Exact next actions and Pi resume instructions.

This version reads the current Pi branch instead of a Claude session log. It
uses bounded excerpts, not the full transcript. It does not run the skill's
build commands because a pre-compaction hook must stay short and predictable.
A repeated checkpoint in the same session replaces that session's current block.

## Controls and failure behavior

Use `/checkpoint-auto off`, `/checkpoint-auto on`, or `/checkpoint-auto status`.
The toggle applies to the loaded extension runtime. Reloading restores the default
of on. To disable it persistently, exclude the extension in Pi settings or move
it out of the extensions directory. Remove the file to uninstall it; another
`lgtm init` will install it again. `lgtm update` does not manage this file yet.

The checkpoint uses a 55-second cancellation deadline, a 45-second model timeout,
and a five-second timeout for each fixed Git command. Files and model input have
size limits. Non-Git directories are skipped. Symlinks and special document files
are rejected. A repository lock prevents two checkpoints from running together.
If Pi crashes, check that no checkpoint is active before removing the leftover
`.lgtm-checkpoint.lock` from the repository root.

A failed checkpoint warns and lets compaction proceed. An unusable model response
preserves an existing handoff. If no handoff exists, it can write an observed Git
snapshot instead. Detected concurrent document edits prevent replacement; the
extension checks again after it stages the new content. Archives and new documents
use owner-only permissions. Each replacement is atomic, but the handoff and
plan are not one filesystem transaction. Filesystem checks do not protect against
a hostile process racing a path change. Checkpoints are not backups or a security
boundary. Do not put secrets in conversation text or these documents.

## Validate and roll back

Run `cargo test --test checkpoint` to exercise CLI installation and the extension's
compaction callback. The callback check uses a deterministic model stand-in and real Git/filesystem
operations. It makes no provider call and does not certify live provider behavior.

For a live check, reload Pi in a disposable Git repository with an existing plan.
Let automatic compaction occur. Inspect both documents and the checkpoint notice.
Do not use manual `/compact` for this check: it intentionally skips checkpointing.

To roll back, remove `~/.pi/agent/extensions/lgtm-checkpoint.ts`, reload Pi, and
restore document contents from Git or the dated handoff archives as needed.
Locally edited extension files are preserved by subsequent init commands.
