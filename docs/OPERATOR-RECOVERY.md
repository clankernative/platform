# Operator recovery boundary

Ambiguous external writes cannot be repaired by retrying blindly. Retain the
artifact-bound invocation evidence, identify whether the provider committed the
effect, and reconcile using the provider's admitted contract. Revocation prevents
new authority; it does not prove an already dispatched effect never happened.

## Abandoning blocked work

An authority change (a policy or binding change, an expired resource grant, the
effect horizon, an exhausted budget) blocks pending work permanently. The
invocation stays pending, never runs a business phase again, and only settles
evidence for external attempts admitted before the block. A local operator ends
it explicitly, one invocation at a time:

```
day2 recovery-abandon INSTANCE APP LOCAL_OPERATOR REQUEST_JSON
```

The operator must be an instance operator or an administrator in the app's
policy. The request names `request_id` (the operator's idempotency key),
`invocation`, `expected_artifact` (the artifact that admitted it) and `reason` (at
most 200 bytes, no control characters). Repeating a request returns its original
receipt; reusing its `request_id` for a different request is refused.

- Only a pending, blocked invocation qualifies, including one admitted by an
  earlier artifact. An invocation is abandoned at most once.
- One transaction finishes it as a failure (`invocation_abandoned`), appends a
  `day2_abandonments` row (operator, reason, the active authority stamp and
  policy, evidence) and records a `recovery` audit event naming the operator.
  The reason stays in the abandonment row, not the event stream.
- The block row stays. Receipts, execution, duplicate requests and cross-app
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

The current runtime does not provide a universal operator command to rewrite
business workflow states. Company-specific recovery policies and runbooks belong
in the private application/instance repository. Do not bypass journals or edit
business tables to force a workflow to appear complete.

See [command execution and recovery](COMMAND-RUNTIME.md),
[secret lifecycle](RUNTIME-SECRET-LIFECYCLE.md) and
[release workflows](RELEASE-WORKFLOW.md) for implemented contracts.
