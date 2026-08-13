# ADR-0016: Isolate configured-command descendant containment

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
v2 delegation or a systemd user manager.

Linux `PR_SET_CHILD_SUBREAPER` can discover detached descendants, but it is a
process-wide setting. Enabling it in the hook or in an embedding application can
adopt unrelated concurrent children and can steal their owner's ability to wait
for them. A mutex and a baseline child snapshot cannot make that global state
safe because unrelated children may start or exit while a configured command is
running.

## Decision

Every configured repository command executes through a dedicated `lgtm`
supervisor subprocess. The existing multithreaded Rust process is never forked
and never becomes a subreaper. The parent uses a hidden internal CLI boundary,
passes a bounded structured request, and accepts only a bounded structured
response from the exact current executable.

On Linux, the short-lived supervisor verifies procfs access, enables
`PR_SET_CHILD_SUBREAPER` only in itself, and then spawns the configured command
in a new process group with bounded stdout and stderr capture. It reserves time
inside the parent's absolute deadline for cleanup. After the direct command
exits (or is killed at its execution cutoff), the supervisor repeatedly inspects
its direct children, sends `SIGKILL`, and reaps them until the child set remains
empty for a quiescence interval. Since the dedicated supervisor creates no
other process, every adopted child belongs to that one configured command.

A descendant which outlives the direct command and has to be terminated is a
containment violation, not successful command evidence. Inability to enable the
subreaper, inspect children, finish cleanup, reap the direct child, drain output,
or decode the supervisor response is unverified. A violation or unproven
containment stops later configured work. Precommit converts these results to a
protected denial, persists nonpassing evidence, and never reuses it.

Reusable full-gate evidence records the OS/architecture platform and a stable
containment implementation version. Reuse requires exact equality with the
current runtime, in addition to the existing policy, binary, config, touched
file, command, and coverage bindings. Evidence produced by Linux containment
therefore cannot authorize a non-Linux run, and a containment implementation
change invalidates older evidence.

On non-Linux platforms, fresh configured commands are not started because this
repository has no equally strong descendant-containment implementation. Their
results explicitly report containment as unavailable and remain unverified.
Process-group behavior remains available for non-authorization subprocess
helpers but is not treated as sufficient authorization containment.

## Consequences

Session-escaped descendants, including `setsid -f` double forks, are killed and
reaped without changing child-reparenting semantics in the hook or embedding
process. Unrelated concurrent children survive and remain waitable by their
owner. Commands that leave descendants are denied even when the direct command
returns zero, so evidence accurately records the containment defect rather than
silently authorizing it.

Supervisor startup and cleanup consume a small reserved portion of each command
and aggregate deadline. The boundary adds one exec per configured command and a
versioned evidence field, but avoids process-global synchronization, unsafe
post-fork Rust execution, and broad platform claims that the implementation
cannot prove.
