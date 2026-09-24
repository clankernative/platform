# Secret-dependent release workflow

This is a private control-plane workflow, not an application SDK. The bounded
contract prepares one immutable secret dependency and one inactive deployment
candidate, then commits the approved active pointer. Provider implementations in
the lab are synthetic; this is not yet a GCP deployment command.

## Start with these files

- `ops/Release.roc`: pure step selection from persisted phase and logical occurrence.
- `crates/day2-control/src/release_recipe.rs`: runs the checked compiled Roc recipe.
- `crates/day2-control/src/release_execution.rs`: typed effects, durable steps,
  leases, provider validation, outbox, and the Temporal activity backend.
- `crates/day2-control/src/release.rs`: exact Git/build approval, secret readiness,
  desired generation, cancellation/revocation, and atomic activation guards.
- `crates/day2-control/src/simulation/`: independent provider state, fault
  schedules, per-step assertions, and replay.

## Decisions and authority

The normal path is:

```text
approved candidate
  -> prepare dependency
  -> observe exact secret version (wait until usable)
  -> prepare inactive deployment
  -> observe that deployment (wait until ready)
  -> activate under current authority
```

Roc selects one operation per advance. It receives only the phase and logical
step number. Rust independently checks the allowed predecessor, company, pinned
recipe and provider bindings, current approval, and exact provider receipt. A
recipe cannot skip preparation by returning `activate` early.

The approved candidate identifies an exact successful build, source commit,
policy and immutable secret version. Approval evidence comes from a trusted host
adapter; a digest is an identity, not authentication of a forge. The qualified
production forge adapter must verify protected merge and exact-candidate checks.
No apply-first/merge-later path is authorized by this workflow. Secret material
is never included in source, the Roc decision input, or simulation traces.
Release admission also requires an explicit runtime-secret binding and atomically
reserves a protected consumer. A retirement barrier blocks new reservations and
pending activation, including through another app alias of the same version.

## Persistence and recovery

`provider_evidence.rs` separates equality-only opaque tokens, ordered revisions
within one identified stream, effect acknowledgments, and qualified read barriers.
A barrier binds the trusted adapter authority, exact resource and (for deployment
readiness) the original preparation effect. A receipt digest is not proof of
provider consistency. An adapter must qualify its protocol before issuing barriers.

Weak secret reads are recorded in workflow evidence but cannot advance the
qualified frontier or grant readiness. A qualified incomparable revision or
contradictory same-revision state records durable uncertainty and invalidates old
ready handles without inventing an ordering. Clearing a same-stream contradiction
requires qualified evidence newer than both the prior state and the conflict.
Incomparable streams and opaque revision changes remain blocked pending an
explicit reviewed resynchronization capability, which this increment does not
implement. Repeated same-state reads may have new receipts
without inventing a new state revision.

Deployment preparation records its physical controller incarnation. Qualified
readback must follow that exact preparation; incarnation drift blocks activation.
These contracts do not turn an empty Kubernetes inventory into a drain proof.
Nonempty legacy journals with untyped evidence fail closed and require an explicit
reviewed migration. Verification never rewrites user journals to bypass this check.

Release execution admission records its dispatch intent in the same SQLite
transaction. The existing Temporal adapter delivers only the execution identity;
the activity reloads persisted state and runs the pinned recipe. Polls and
retries do not depend on an in-memory Roc process or a retained readiness handle.

The release-step journal is additive. The existing build workflow keeps its
three single-use effect kinds. Release steps instead identify a logical name and
occurrence within a pinned execution. Retries reuse that identity; a new completed
observation advances the occurrence. Lease epochs fence journal completions, not
remote requests already sent by another worker.

Provider I/O happens outside SQLite transactions. After an ambiguous mutation,
the next attempt reconciles its exact identity. Mere absence from an eventually
consistent list is not proof that a mutation was never applied. An unresolved
outcome must remain explicit instead of permitting a blind second mutation.

Activation rechecks current desired generation and readiness. The active pointer,
activation receipt, workflow completion, consumer protections and audit are committed together.
Superseded or revoked candidates cannot take over, and replaying an old receipt
does not restore an old active pointer.

These deployment-proof and workflow-completion guarantees apply to releases
enrolled in this workflow. The older native `Journal::activate_release` primitive
remains for unenrolled secret-readiness guard fixtures; it refuses enrolled
releases. It is not an app SDK or an alternative production deployment entrypoint.

## Qualification boundary

The lab must demonstrate both safety and progress: no unauthorized or stale
activation at any boundary, and actual activation of the newest eligible release
after finite recoverable faults stop. Missing prerequisites and genuinely unknown
mutation outcomes require explicit durable waiting/intervention states, not a
successful-looking runner exit.

Provider facts are observations, not omniscience. A secret revocation that has
not yet been observed cannot be made atomic with SQLite activation. Real adapters
need qualified readback and, where available, provider-side conditional writes.
The simulator separates external secret availability from a watcher delivering
that metadata into the journal. Delivered changes must invalidate stale readiness;
unacknowledged provider reads are not treated as delivered evidence.
The current active pointer is not an atomic cloud traffic switch, nor a guarantee
that an externally disabled incumbent secret remains usable. Destructive shared
resource transitions now have a separate [protected-retirement contract](RUNTIME-SECRET-LIFECYCLE.md).
Routing activation, general cleanup/compensation, irreversible destruction and
broader secret-manager semantics still need contracts and conformance tests.

See [the lab guide](DETERMINISTIC-LAB.md) for campaign/replay commands and
[verification coverage](VERIFICATION-COVERAGE.md) for the remaining legacy suite
porting obligation. Small real-provider conformance sandboxes come before Linux
deployment qualification and the disposable GCP canary.
