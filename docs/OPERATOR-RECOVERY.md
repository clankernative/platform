# Operator recovery boundary

Ambiguous external writes cannot be repaired by retrying blindly. Retain the
artifact-bound invocation evidence, identify whether the provider committed the
effect, and reconcile using the provider's admitted contract. Revocation prevents
new authority; it does not prove an already dispatched effect never happened.

## Abandoning work that will never finish

Two kinds of pending invocation never finish on their own:

- **Blocked.** An authority change (a policy or binding change, an expired
  resource grant, the effect horizon, an exhausted budget) blocks pending work
  permanently. The invocation stays pending, never runs a business phase again,
  and only settles evidence for external attempts admitted before the block.
- **Orphaned request.** In an ordinary store with a non-rolling profile, a
  direct request admitted a query or a page load, and the serving process
  stopped before finishing it, for example when maintenance stopped the app
  mid-request. Only that request was running it: that scheduler resumes
  commands, never queries or pages, and a page load's identity is random, so no
  later request repeats it. It stays pending until the next migration abandons
  it (below); an operator does not. A rolling profile drains queries and pages
  too, so nothing there is orphaned; a native-storage app is not supported.

### A migration abandons its orphaned requests

Every activation of a new image migrates the store after the app stops:

```
day2 migration-apply INSTANCE APP TARGET PLAN_FILE LOCAL_OPERATOR
```

The migration holds the migration exclusion: the operation lease and the
exclusive serving lock, which no `day2-serve` (or runtime-pair executor) can
hold beside it. A request cut off by that stop, or by any earlier stop or crash,
is then provably over, so the migration abandons it itself instead of refusing
the store with `migration_requires_drained_invocations`:

- It abandons exactly the orphaned requests: pending, unblocked invocations
  that a direct request admitted (`trigger` `request`), of an operation the
  store's scheduler never resumes, in an ordinary non-rolling store. A command
  never qualifies: the scheduler resumes it, and a client may retry it under
  its key. Neither does work that a schedule, a command request, ingress, a
  delegation or a credential started.
- It abandons under `LOCAL_OPERATOR`, who must be an instance operator or a
  policy administrator when there is something to abandon
  (`recovery_operator_required`). A GKE maintenance session passes its request's
  operator, who already needs that standing to activate.
- The abandonments commit in the migration's own transaction. Work the
  scheduler finishes, such as an accepted command, must still drain first: the
  migration is then refused as before, and any refusal changes nothing.
  Replaying a recorded migration still abandons a request orphaned since, so
  its activation can proceed.
- Blocked work, including a blocked request, is left for an operator.
- Each one is recorded like an operator's, with cause `orphaned_request`, the
  operator as audit actor, `request_id` `migration:` plus the invocation id (a
  prefix operator requests may not use) and a reason saying no server held the
  store. `day2 migration-apply` lists their receipts under `abandoned`.
- The store must already hold `day2_abandonments`, which every runtime from
  `3a29178b` on creates.

GKE activation migrates a copy of the store before its confirmation and
journals that copy's list as `rehearsal-abandoned`, printing any it finds. The
copy taken once the app has stopped lists what the live migration will abandon;
the earlier copy taken while the source still serves also lists reads that
were then in flight and finished there.

`day2 activate` and `day2 platform authority activate` refuse while any
runnable work is pending (`activation_precondition_failed`), orphaned requests
included. GKE activation always migrates first. Elsewhere, run `day2
migration-plan` and `day2 migration-apply` onto the target before activating,
and the migration abandons them.

The lock is what keeps servers off the store, so this holds only for processes
that take it. `day2 serve-local`, `day2 invoke`, `day2 resume` and the local
development server do not: never migrate a store one of them is using.

### Abandoning blocked work

A local operator ends blocked work explicitly, as one list of up to 16
invocations:

```
day2 recovery-abandon INSTANCE APP LOCAL_OPERATOR REQUESTS_JSON
```

The operator must be an instance operator or an administrator in the app's
policy. Each request names `request_id` (the operator's idempotency key),
`invocation`, `expected_artifact` (the artifact that admitted it) and `reason`
(at most 200 bytes, no control characters). Each `request_id` and each
invocation appears once. Repeating a request returns its original receipt, with
cause `blocked`; reusing its `request_id` for a different request is refused.

- The list is all or nothing. One transaction decides every item, and one
  refusal leaves every listed invocation as it was.
- Only a pending, blocked invocation qualifies, including one admitted by an
  earlier artifact. Anything else is refused with
  `recovery_requires_blocked_invocation`, an orphaned request included: the
  next migration abandons it.
- An invocation is abandoned at most once.
- Each abandonment finishes the invocation as a failure (`invocation_abandoned`),
  appends a `day2_abandonments` row (operator, reason, the active authority
  stamp and policy, evidence, the request, and the receipt with its cause) and
  records a `recovery` audit event naming the operator. The reason stays in the
  abandonment row, not the event stream.
- A block row stays. Receipts, execution, duplicate requests and cross-app
  status report the abandonment (`invocation_abandoned`, or `refused` across
  apps) under their usual owner, authority and artifact checks; work from an
  artifact the runtime no longer serves still reads as `artifact_binding_changed`.
- A dispatch permit that has not started its provider call is refused. The
  provider was never called, so that attempt and its budget reservation settle as
  not dispatched. An attempt already in flight may finish; its result is recorded
  as evidence and never runs completion.
- The receipt classifies each claimed external effect: never admitted (no
  attempt), known result (the effect's result is recorded and its usage known),
  or unknown outcome (an attempt was admitted and the effect is unresolved, or
  its usage is unknown). Abandoning releases no budget: each reservation stays as
  the attempt left it. Reconcile unknown outcomes with the provider as above. The
  receipt describes the moment of abandonment; a permit refused afterwards is
  recorded on its attempt.
- It never retries, never cascades to the command requests the invocation made
  (the receipt lists them) and never edits business rows.

Running blocked work again, as a fresh invocation or as the same run under current
authority, is not implemented.

On GKE, run it with the app stopped through `day2 platform maintain
recovery-abandon REQUEST_JSON_FILE` (see [deploy/gke](../deploy/gke/README.md),
"Maintenance"). The request file lists the requests under `abandon` and is checked
before anything stops. The session takes a verified backup, asks for a typed
`abandon` that names each invocation, runs `day2 recovery-abandon` in
the maintenance pod with the request's operator, then restores the app. After a
refusal or an interrupted session, rerun the same request file in a new session:
committed requests return their receipts, and a request changed in any field
under the same `request_id` is refused with `recovery_request_conflict`. The
store must already hold `day2_abandonments`, which every runtime from
`3a29178b` on creates, and the tooling image must be a build with this command,
which may be newer than the running app's.

The current runtime does not provide a universal operator command to rewrite
business workflow states. Company-specific recovery policies and runbooks belong
in the private application/instance repository. Do not bypass journals or edit
business tables to force a workflow to appear complete.

See [command execution and recovery](COMMAND-RUNTIME.md),
[secret lifecycle](RUNTIME-SECRET-LIFECYCLE.md) and
[release workflows](RELEASE-WORKFLOW.md) for implemented contracts.
