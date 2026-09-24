# Deterministic control-plane lab

This is the first bounded shared-world campaign, not a replacement for provider
qualification or a claim that RADICAL's entire simulation milestone is complete.
It runs without Temporal, Docker, cloud credentials, or provider network access.
The normal Cargo and pinned Roc toolchains are still needed to build the runner.

## The boundary being tested

The lab runs the production `ExecutionHost`, `ReleaseExecutionHost`, control
guards, and on-disk SQLite `Journal`. The release host invokes the checked,
compiled `ops/Release.roc` recipe used by the live Temporal backend. Live hosts
and the scheduler share three boundaries:

1. `claim_at`: validate company and pinned capabilities, then commit a lease.
2. `perform`: call the provider outside the journal transaction.
3. `settle_at`: atomically record the observation, state transition, and audit.

The scheduler can interleave different executions between those boundaries.
It does not expose uncommitted SQLite writes to another operation or implement a
second copy of the operational state machines. Reopening storage exercises durable
recovery, but is not a substitute for process-kill, power-loss, disk-full, or
filesystem conformance tests.

The simulated providers retain their own state independently of the journal.
In particular, publishing a check and observing its receipt are separate facts.
A lost acknowledgement or temporarily invisible receipt cannot authorize a
second publication. Expired leases fence journal completion, not a remote API
request already sent by the old worker.

## First shared world

The bounded world has competing revisions of one company's app and another
company's app. It exercises source snapshots, verification, check publication,
cancellation, retries, lease expiry, delayed observations, and host restart.
Release admission and secret readiness share the same real control journal.

The [secret-dependent release workflow](RELEASE-WORKFLOW.md) now drives dependency
preparation, secret observation, inactive deployment preparation/readback, and
activation through those guards. Provider implementations remain synthetic, not
qualified cloud-deployment adapters:

- Exact successful build and Git approval evidence authorize a desired revision.
- Company, environment, app, source binding, and immutable secret references are
  explicit. Secret material never enters the lab or its trace format.
- Readiness captures an observation revision; activation rechecks current desired
  state, approval, secret state, access, and projection in one transaction.
- Deployment evidence belongs to the exact candidate and secret readiness proof.
  A refreshed proof requires new deployment preparation/readback.
- Supersession, revocation, cancellation, and stale observations cannot activate a
  pending revision. They do not silently roll back or delete the incumbent.

The secret model records per-version enabled/access/projection metadata, missing
metadata, delayed visibility, and synthetic unavailable probes. It is not a full
Secret Manager emulator for absent containers, containers without versions,
destroyed versions, provider error semantics, or IAM behavior.
The host distinguishes ordered revisions in one identified stream from opaque
equality-only tokens. Weak reads cannot grant readiness; qualified incomparable
or conflicting state blocks old ready handles without advancing the frontier.
The synthetic provider's private history positions are not an ordering for ETags.

Approval metadata is a **trusted adapter input**, not authenticated merely because
it has a digest. A production forge adapter must independently verify protected
merge and exact-candidate checks before constructing that input. Likewise, actual
provider readiness must be observed by a trusted adapter. Apps cannot call these
private host APIs. There is no apply-first-then-merge path.

Preserving the active pointer does not guarantee continued health after an
external actor disables an incumbent secret, nor make destructive shared-resource
changes safe. Those require operational recovery and explicit transition policies.

Legacy guard-only secret actions and workflow-provider secret actions cannot
drive the same reference in one scenario. Admission rejects that unsupported
mixture rather than combining unrelated synthetic revision counters. The workflow
watcher and workflow reads do share one provider history.

## Campaign and replay

`ops/Simulation.roc` owns the private campaign recipe: run each committed schedule
and replay its trace, then do the same for bounded generated schedules. Roc verification and
CI recipes invoke it. Native capabilities execute one bounded schedule at a time
and require a complete campaign before issuing evidence.

```text
cargo run --locked -p xtask -- simulate-control
cargo run --locked -p xtask -- simulate-control 42 32
cargo run --locked -p xtask -- replay-control TRACE.json
```

Generated scenarios use format 4 with explicit request admission, weak-provider events and shared-secret
lifecycle actions; existing regressions retain format 1's preadmitted starting
state. Formats 2 and 3 retain their earlier bounded input catalogs. Traces use format 5 and
include the pinned compiled recipe and the generated-schedule/recovery boundary.
Virtual time, scheduler choices, provider
outcomes, and logical state fingerprints are recorded; temporary paths and real
timestamps do not participate in replay identity. Replaying compares observations
and state fingerprints, not just a final success flag. Reviewed regressions live
in `fixtures/control-simulation/`; generated evidence lives under
`artifacts/control-simulation/`.

[Stateful generation](STATEFUL-SIMULATION.md) separates typed operation intents
from worker scheduling, faults and delivery. Campaign receipts recompute witnessed
coverage from traces and require generated progress before recovery. Handwritten
regressions cannot substitute for an inert generated campaign. Failed typed
histories receive bounded, fingerprint-preserving semantic reduction and private
original/reduced replay evidence.

Safety assertions run during the schedule. A bounded fair recovery phase checks
build-journal progress after finite injected faults stop; it is not a proof of progress during
permanent outages or arbitrary sustained overload. A publication claim abandoned
before the simulated provider receives it can remain explicitly intervention-needed:
the production journal cannot distinguish that from an accepted but unobserved
request. The campaign checks this conservative outcome separately from successful
drain, rather than inventing a receipt or silently retrying the mutation.
Release schedules also drive the same compiled recipe through its production
host. They check per-step safety and bounded recovery toward actual activation
of the newest eligible candidate. Missing prerequisites remain explicitly waiting;
unresolved mutation outcomes cannot be counted as successful activation. Provider
availability is separate from watcher-delivered metadata and successful workflow
observations. Provider state remains separate from the journal, and restart reconstructs release execution
state from disk instead of preserving readiness handles in the scheduler.
Property-test shrinking helps
find smaller failing schedules. A reviewed minimized scenario belongs in the
committed corpus, never an automatically approved source change.

## What comes next

The world now includes [runtime-secret rollover and protected disable](RUNTIME-SECRET-LIFECYCLE.md).
Extend it next with ownership changes and additional qualified provider semantics.
Each new capability needs independent invariants,
generation/shrink rules and observed-coverage requirements; adding a successful
handwritten sequence is not sufficient. The current catalog still bounds the
world to six candidate identities, two companies, three app targets and four worker slots.

1. Add semantic provider conformance: exact source/check identity, ambiguous
   mutations, secret container/version states, IAM delay, and unavailable or stale
   observations against small real-provider sandboxes. A simulator passing its own
   assumptions is not evidence that GCP, GitHub, or another provider obeys them.
2. Cover admission queues, bursts, overload/backpressure, global capacity, and
   fairness across more operation types and exact instance compositions.
3. Complete Linux runtime and deployment qualification, then run a disposable GCP
   canary with explicit credentials, scope, cleanup, and incumbent checks.

Temporal remains the durable scheduling adapter for live control workflows. Fast
simulation calls the same host below it; separate real-Temporal restart/history
tests qualify that adapter. This increment does not create a new execution engine,
implement Okta/Entra/IAP, or qualify AWS/on-prem deployments.
