# ADR-0016: Contain configured-command descendants

## Status

Accepted

## Date

2026-08-14

## Context

Configured repository commands are synchronous authorization gates. Placing a
command in its own process group lets the runner terminate ordinary children,
but a descendant can call `setsid`, enter a new process group/session, close the
captured pipes, and outlive a successful parent. Such a descendant could replace
and stage `.lgtm/config.json` after the gate's final digest comparison but before
the authorized `git commit` executes.

A pidfd can address PID-reuse races for a process already known to the runner,
but does not discover detached descendants. Recursively sampling `/proc` lineage
before the parent exits has reparenting races. A cgroup would provide the
strongest kernel boundary, but ordinary unprivileged hooks cannot assume cgroup
v2 delegation or a systemd user manager. Requiring either would silently disable
configured commands in otherwise supported Linux environments.

## Decision

On Linux, the configured-command runner makes the hook process a child
subreaper with `PR_SET_CHILD_SUBREAPER` before spawning a command. When any
intermediate parent exits, session-escaped descendants are therefore reparented
to the hook rather than to PID 1. After the direct child and captured pipes have
been handled, the runner retains the existing process-group kill and also reads
`/proc/self/task/<pid>/children`, identifies children created after containment
began by PID plus `/proc/<pid>/stat` start time, sends each `SIGKILL`, and reaps
it. It repeats until no command-created child remains, so killing an intermediate
process also exposes and terminates descendants reparented on that iteration.

Configured-command executions are serialized within the hook process. Children
that already existed when containment began are recorded as a baseline and are
not attributed to the command. This matches the hook architecture: repository
commands execute synchronously and the hook does not independently launch
concurrent subprocess work.

Cleanup has a separate bounded two-second proof window so timeout cleanup can
still terminate a descendant after the command deadline itself expires. Failure
to enable subreaping, inspect Linux process state, or reach an empty descendant
set is an unverified configured-command result, stops all later configured work,
and cannot authorize a gate. The caller still checks the aggregate monotonic
budget after cleanup, so cleanup cannot turn a deadline-expired command into a
pass.

On non-Linux platforms, configured commands are not started because this
repository has no equivalent kernel-backed descendant-containment
implementation. Their results explicitly say descendant containment is
unavailable and remain unverified. Process-group behavior remains in place for
non-authorization subprocess helpers, but is not misrepresented as sufficient
for configured-command authorization.

## Consequences

A successful Linux gate returns only after every process causally adopted from
the configured command has been killed and reaped, including a double-forked
`setsid -f` descendant. Ordinary foreground commands and existing aggregate and
per-command deadlines keep their result semantics. Linux environments without
usable procfs fail closed, and non-Linux configured-command gates conservatively
remain unavailable until a platform-specific containment primitive is added.
