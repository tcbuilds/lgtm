# How LGTM tracks shell changes

## The problem

A shell command can change files without using an Edit or Write tool. For example,
a Python script can update several source files. Older LGTM hooks did not record
these changes. Stop could then report: “Diff includes files not recorded in this
session.”

## What happens now

1. Before a shell call, LGTM saves the initial dirty-file list and a bounded
   snapshot of dirty files.
2. After the call, LGTM compares file content hashes and executable bits.
3. LGTM records files that changed during that matched call. It includes new
   files, deleted files, and both paths of a rename.
4. Existing files receive fast checks. Stop runs its normal checks. Deleted paths
   take part in diff checks, but are not sent to content scanners.

An unchanged dirty file is not recorded as a shell edit. The initial baseline
still protects that file as pre-existing work. A changed dirty file is recorded.
This is file-level tracking. It does not prove that every pre-existing line was
preserved.

LGTM stores paths, hashes, and call identities. The snapshot does not store file
contents or command text. Direct commits keep their separate, fresh staged gate.

## Install the fix

Run `lgtm update`, then restart your agent. Registered installations receive
managed updates. For an unregistered project, run the appropriate `lgtm init
--agent pi` or `lgtm init --agent claude` once.

Pi passes the same native call ID through its call and result hooks. Failed
results are included. Claude uses both `PostToolUse` and `PostToolUseFailure`.
The old managed Claude success matcher is the one-time migration boundary for
the new failure hook. An existing failure-event key is preserved. After migration,
removing that event remains an opt-out on refresh.

This change does not establish native Pi version compatibility or codemode
enforcement. Existing runtime verification checks remain in place.

## When tracking stays unverified

LGTM does not guess when an event is missing, an ID does not match, calls overlap,
HEAD changes, or a read fails. Known outstanding calls remain recorded across
session changes. Their matching results must arrive before a new session can
start a clean tracking window. A later successful call does not erase an earlier
tracking warning in the same session.

After an interrupted agent process, first confirm that all shell processes have
ended. Start a new session only after resolving the outstanding tracking state.
If no result can arrive, preserve the evidence for review, remove only
`.lgtm/evidence/shell-tracking.json`, and start a new session. Do not clear state
while another agent or shell command is active. The new session treats existing
dirty files as pre-existing work; it does not verify the interrupted work.

## Limits

- Tracking uses Git's staged, unstaged, and non-ignored untracked file lists.
  Ignored files are outside this tracking scope.
- Snapshot limits are 4,096 paths, 8 MiB per file, 128 MiB of reads per capture,
  and a 10-second snapshot deadline. At most 512 changed paths are recorded.
- Symlinks, special files, and submodules remain unverified rather than being
  followed. Tracking requires Unix evidence locking.
- A missing call identity, more than 64 outstanding calls, or a repeated
  outstanding identity leaves
  tracking unverified until an operator reviews and resets it.
- Snapshots are observations, not an operating-system sandbox. They cannot prove
  which process made a change. Unhooked concurrent editors and background writes
  after a result remain limitations. Use separate worktrees for parallel agents.

## Verify and roll back

Run `cargo test --test shell_tracking --test init_pi` to exercise CLI tracking,
real Stop checks, managed migration, and generated Pi event handling.

For rollback, restore the previous binary and its matching managed hook backup.
Do not pair an old binary with new hook behavior. Keep current-task evidence
until the interrupted or completed work has been reviewed.
