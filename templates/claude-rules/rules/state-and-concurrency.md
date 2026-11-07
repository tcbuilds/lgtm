---
description: LGTM state, concurrency, and distributed-consistency rules.
paths:
  - "**/{state,states,workers,worker,jobs,tasks,queues,queue,consumers,consumer,events,webhooks,webhook,sagas,workflows,workflow,schedulers,scheduler,outbox,inbox}/**/*.{rs,py,ts,tsx,js,jsx,mjs,cjs,go,java,kt,cs,rb,swift,scala}"
  - "**/*{state,State,status,Status,transition,Transition,workflow,Workflow,saga,Saga,fsm,FSM,reconcil,Reconcil}*.{rs,py,ts,tsx,js,jsx,mjs,cjs,go,java,kt,cs,rb,swift,scala}"
  - "**/*{worker,Worker,job,Job,queue,Queue,consumer,Consumer,subscriber,Subscriber,webhook,Webhook,event,Event,outbox,Outbox,inbox,Inbox}*.{rs,py,ts,tsx,js,jsx,mjs,cjs,go,java,kt,cs,rb,swift,scala}"
  - "**/*{_lock,-lock,Lock,_mutex,Mutex,_lease,-lease,Lease,fencing,Fencing,retry,Retry,retries,Retries,poll,Poll,scheduler,Scheduler,idempot,Idempot}*.{rs,py,ts,tsx,js,jsx,mjs,cjs,go,java,kt,cs,rb,swift,scala}"
headings: ["State And Concurrency"]
rules:
  [
    {
      "id": "state-machine-review",
      "title": "Make implicit state machines explicit",
      "description": "When changed code branches on status fields, flag combinations, or lifecycle steps, identify the implicit state machine and define its valid states, allowed transitions, and invariants in one place.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {"language": "all", "text": "good: one transition table rejects shipped -> pending; bad: scattered status assignments that allow any jump", "schematic": true}
      ],
      "limitations": [
        "Recognizing an implicit state machine is semantic review; no check extracts states or transitions.",
        "Native loading uses path-name hints, so state logic in files without those hints may not receive this guidance."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "correctness",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["state", "status", "transition", "workflow", "lifecycle"]},
      "instruction": "Name the states, list the allowed transitions, route every status change through one transition function that rejects invalid moves, and state the invariant each state guarantees.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    },
    {
      "id": "check-then-act-atomicity",
      "title": "Make check-then-act sequences atomic",
      "description": "A decision based on a read must not be applied by a separate write that another actor can interleave; time-of-check/time-of-use gaps need an atomic primitive or a lock held across both steps.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {"language": "sql", "text": "good: UPDATE seats SET holder = $1 WHERE id = $2 AND holder IS NULL, then check the row count; bad: SELECT to see the seat is free, then UPDATE it", "schematic": true}
      ],
      "limitations": [
        "Interleavings are not detected statically; this is instruction guidance.",
        "Native loading uses path-name hints, so check-then-act code in files without those hints may not receive this guidance."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "should",
      "category": "correctness",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["race", "lock", "concurrency", "toctou"]},
      "instruction": "Collapse check-then-act into one atomic step: conditional update or compare-and-set, unique constraint, create-new file open, atomic rename, or a lock held across both the check and the act.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    },
    {
      "id": "cross-system-idempotency",
      "title": "Make cross-system operations idempotent and recoverable",
      "description": "Operations that span a database and an external service, queue, or file store must be safe to retry and must leave a recoverable record when they fail partway.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {"language": "all", "text": "good: persist a pending payment row, charge with the order ID as idempotency key, then mark it settled; bad: charge, crash before saving, and charge again on retry", "schematic": true}
      ],
      "limitations": [
        "Idempotency and recovery paths are not verified automatically; review the retry and failure behavior.",
        "Native loading uses path-name hints, so cross-system code in files without those hints relies on the error-handling guidance."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "should",
      "category": "reliability",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["retry", "idempotency", "external-api", "queue", "webhook"]},
      "instruction": "Give each cross-system operation a stable idempotency key, record intent before the external call, make the receiver dedupe on that key, and give partial failure a resume or compensation path instead of a silent half-commit.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    },
    {
      "id": "lease-fencing-review",
      "title": "Fence writes from stale lease holders",
      "description": "Distributed locks and leases can expire while their holder keeps running; writes they protect must carry a fencing token or lease epoch that the resource checks.",
      "mechanism": "review",
      "confidence": "low",
      "examples": [
        {"language": "all", "text": "good: storage rejects a write with token 33 after accepting token 34; bad: a worker resumes after a pause and writes because it still believes it holds the lock", "schematic": true}
      ],
      "limitations": [
        "Fencing is a design property of the lock service and the protected resource; it is not detected statically.",
        "A single-process mutex does not need fencing; apply this only to locks or leases shared across processes or hosts."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "review",
      "category": "reliability",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["lock", "lease", "leader-election", "distributed-lock"]},
      "instruction": "Issue a monotonically increasing fencing token or epoch with each lease, send it with every protected write, and have the resource reject tokens older than the newest it has accepted; never rely on lease timing alone.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    },
    {
      "id": "event-ordering-duplicates",
      "title": "Define event ordering and duplicate handling",
      "description": "Consumers of events, messages, jobs, and webhooks must state which ordering they rely on and how they handle duplicate, late, and out-of-order delivery.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {"language": "all", "text": "good: skip event version 41 for order 7 because version 42 is already applied; bad: apply webhooks in arrival order and credit twice on redelivery", "schematic": true}
      ],
      "limitations": [
        "Delivery guarantees depend on the transport and are not inferred; review the consumer contract."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "should",
      "category": "reliability",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["event", "message", "queue", "webhook", "consumer"]},
      "instruction": "Assume at-least-once, possibly reordered delivery unless the transport guarantees more; dedupe on a stable event ID, check per-entity sequence or version before applying, and define the handling of late, duplicate, and poison messages.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    },
    {
      "id": "state-failure-path-tests",
      "title": "Test invalid transitions, concurrency, retries, and partial failure",
      "description": "Changes to stateful, concurrent, or retried code need tests for rejected transitions, competing callers, repeated delivery, and failure between steps, not only the happy path.",
      "mechanism": "instruction",
      "confidence": "low",
      "examples": [
        {"language": "all", "text": "good: run two reserve calls concurrently and assert exactly one succeeds; bad: test only one successful reserve call", "schematic": true}
      ],
      "limitations": [
        "Test presence is not mapped to these failure modes automatically; review the test plan."
      ],
      "enforcement_stage": "prompt",
      "severity": "warning",
      "level": "should",
      "category": "testing",
      "applies_to": {"languages": [], "domains": [], "file_patterns": []},
      "activation": {"change_types": ["create", "modify"], "signals": ["test", "state", "retry", "concurrency"]},
      "instruction": "Add deterministic tests asserting that invalid transitions are rejected, concurrent callers cannot double-apply, retries and duplicate deliveries are idempotent, and a failure between steps leaves a recoverable state.",
      "enforcement": {"mode": "instruction", "checks": []},
      "overridable": true,
      "evidence": {"required": ["review_result"]}
    }
  ]
---

# State And Concurrency

Apply only to code that owns state, coordinates concurrent actors, or crosses
system boundaries. A matching file name is a hint, not proof.

- Treat a status field, a set of flags, or a sequence of lifecycle steps as a state machine: name its states, its allowed transitions, and the invariant each state guarantees, and keep them in one place.
- Route every state change through one transition function that rejects invalid moves; do not assign status fields directly from callers.
- Close time-of-check/time-of-use gaps with one atomic step: conditional update, compare-and-set, unique constraint, create-new open, atomic rename, or a lock held across check and act. SQL specifics are in `patterns/sql.md`.
- Make cross-system operations idempotent and recoverable: stable idempotency keys, intent recorded before the external call, receiver-side dedupe, and a resume or compensation path for partial failure.
- Fence writes protected by distributed locks or leases with a monotonically increasing token or epoch that the resource checks; lease expiry alone does not stop a paused holder.
- State the ordering each consumer relies on and handle duplicate, late, out-of-order, and poison messages explicitly; assume at-least-once delivery unless the transport guarantees more.
- Test invalid transitions, concurrent callers, retries and duplicate delivery, and failure between steps.

## Shapes

```python
# bad: two callers can both see the seat as free
if db.fetch_holder(seat_id) is None:
    db.set_holder(seat_id, user_id)

# good: the database decides atomically; zero rows means someone else won
claimed = db.execute(
    "UPDATE seats SET holder = %s WHERE id = %s AND holder IS NULL",
    (user_id, seat_id),
).rowcount == 1
```

```python
# good: one owner of the lifecycle; invalid moves fail loudly
TRANSITIONS = {
    OrderState.PENDING: {OrderState.PAID, OrderState.CANCELLED},
    OrderState.PAID: {OrderState.SHIPPED, OrderState.REFUNDED},
}

def transition(order: Order, target: OrderState) -> Order:
    if target not in TRANSITIONS.get(order.state, set()):
        raise InvalidTransition(order.id, order.state, target)
    return replace(order, state=target)
```

```python
# good: the resource rejects a stale lease holder in one conditional write
def write(key: str, value: bytes, fencing_token: int) -> None:
    if not store.put_if_token_at_least(key, value, fencing_token):
        raise StaleLeaseHolder(key, fencing_token)
```

<!-- lgtm-rule: state-machine-review -->
#### Make implicit state machines explicit
<!-- lgtm-rule: check-then-act-atomicity -->
#### Make check-then-act sequences atomic
<!-- lgtm-rule: cross-system-idempotency -->
#### Make cross-system operations idempotent and recoverable
<!-- lgtm-rule: lease-fencing-review -->
#### Fence writes from stale lease holders
<!-- lgtm-rule: event-ordering-duplicates -->
#### Define event ordering and duplicate handling
<!-- lgtm-rule: state-failure-path-tests -->
#### Test invalid transitions, concurrency, retries, and partial failure
