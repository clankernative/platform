# Typed app calls on normal hosts

Apps call their generated `ImportedContracts` functions. Input/result types and
operation digests come from the caller's exact build imports. There is no app API
for selecting a peer URL, signing a request or choosing an actor. The host resolves
one current resource grant; the receiver separately authorizes the inherited actor.
Nominal root records are generated once per type ID. Unsupported nested nominal
codec dependencies fail the build rather than being erased to structural types.

The container entrypoint accepts `day2-serve INSTANCE APP --edge --app-calls HOST_JSON`.
Private POST endpoints `/_platform/app-issue` and `/_platform/app-query` require
exactly one IAP workload assertion. Human/browser capacity is separate from the
private admission pools. Issuance has four permits, query/send execution six and
status reconciliation two, behind sixteen bounded body readers. A call never
queues while holding a business transaction or browser permit. Bodies, proof lifetimes, response
bytes, deadlines and peer/key counts are bounded. Unsupported paths, redirecting
transports, unknown fields and unauthenticated claims are refused.

`day2-control::app_host::Configuration` is infrastructure bootstrap, not company
business policy. It fixes one installation/environment/app, workload identity,
managed signing-key files, public peer trust keys, gate audiences, peer URLs and
GKE serving bindings. Grants remain in activated instance authority. The issuer
reopens the durable invocation, checks its current authority and exact imported
grant, verifies the root IAP account binding and only then signs the request.
The receiver checks IAP, both signatures, the current selected serving generation,
its loaded artifact and its own current operation/row policy.

The first release supports human-rooted calls in one installation/environment.
Other origin families require their admitted ingress. App reentry and chains
deeper than four hops are refused. Query admission never accepts a command as a
read. Human root evidence is durably inherited by each receiver; background
command execution never manufactures a service origin.

Each human root starts with 256 call credits. The source reserves disjoint child
subtrees under its SQLite writer lock; the receiver inherits only that child's
allowance. Every first dispatch consumes one credit and reserves its descendants,
and retries reuse the same reservation. Diamonds cannot duplicate an ancestor's
budget. Existing operation grants can impose smaller call limits.

## Commands and receipts

Each imported command generates `<operation>_send : Input -> Effects(Receipt)`
and `<operation>_status : Receipt -> Observe(Status)`. Receipts are nominal per
operation. Sends return durable acceptance, not a completed business result.
Statuses are pending, success, refused, blocked or unknown. Unknown never means
that an earlier mutation did not occur; status exposes no receiver result payload.

The source persists its original delivery fence before dispatch. A stable identity
binds source scope/security epoch, invocation, effect step and receiver scope.
The receiver inserts the inbox and ordinary invocation atomically, binding the
payload, actor, operation, contract and human origin. Duplicate delivery returns
the same receipt; conflicting reuse is rejected. A replacement receiver with no
original inbox cannot accept an old uncertain call as a new mutation.

Uncertain sends leave the effect pending. The ordinary effect scheduler releases
workers and transactions, retries the same identity at bounded intervals and
parks work after four attempts or one hour. Each attempt consumes its grant's
request allowance. An exhausted grant or budget durably blocks an uncertain send
earlier. Revocation blocks new
dispatch and completion; an already issued proof has a maximum 30-second in-flight
window. Settlement records evidence without authorizing further writes.

Inbox, outgoing and call-allocation ledgers each have a hard 10,000-record bound. Compact receipts
remain available after invocation-result compaction. Capacity exhaustion refuses
new acceptance; the host never forgets a live uncertain identity into a new mutation.
Terminal or permanently blocked source records may compact after the one-hour
retry horizon plus the maximum 60-second proof lifetime. Terminal or permanently
blocked receiver mappings may compact after 24 hours. Live runnable acceptances
remain pinned. A compacted status returns unknown, which never authorizes another
business mutation. Normal admission reclaims expired mappings before enforcing
the bound; sustained live or retained work applies backpressure.
Supported restore disables authority and changes its epoch. Historical inbox
receipts may be inspected after fresh authority activation; old pending work is
not automatically resumed. Restore also records a receiver cutoff in the same
transaction: a missing inbox cannot accept a send first issued at or before
that cutoff, even if the StatefulSet identity did not change. Sends begun in the
same clock second as restore are conservatively refused. A missing original
receiver fence remains unresolved.

Accepted invocations stay pinned to their original artifact. Artifact activation
requires runnable work to drain; explicit authority changes durably block old
pending work. Keep the addressed artifact and database together for inspection
and backups. A new artifact never silently executes an old accepted invocation.

## GKE deployment

The `app-edge` root's optional `app_calls` creates two distinct protected backends,
routes only the exact private paths to them and publishes their resolved audiences.
The issuer backend grants only its own workload; the receiver grants explicitly
selected incoming workloads. Neither uses the human backend's domain membership.
The runtime KSA impersonates its bound GSA using Workload Identity. That GSA can
sign JWTs only as itself and discover clusters; namespace RBAC permits `get` of
only the exact StatefulSet, ordinal-zero pod and runtime service account. An explicit
network policy permits HTTPS to the selected Kubernetes serving API CIDR.

The `day2-app` root's optional `app_calls` renders the bootstrap file and mounts
two exact Secret Manager versions through CSI. A fixed file-install init container
copies keys into a memory volume as UID 10001, mode 0400. The serving container
mounts it read-only. Include these secret IDs in `app-edge.runtime_secret_ids`.
Private key bytes never enter OpenTofu state. Independent issuer/workload keys
and public trust sets permit explicit rotation; a missing key fails startup.
Publish the new public key to each verifier first, restart the source on its exact
new managed secret version, then remove the old trust key after the maximum
60-second proof lifetime. Removing a key immediately rejects its outstanding
proofs. Rotate issuer and workload keys independently; each is scoped to the
configured source and audience. This release has explicit operator rotation,
without automatic hot reload or issuer-key recovery from application state.

Both the StatefulSet and pod declare installation/environment/app/artifact.
`DAY2_EXPECTED_ARTIFACT` fences actual host loading. The authenticated GKE probe
checks cluster CA, controller UID/generation, ready revision, pod ownership,
running pinned image, artifact environment and KSA-to-GSA binding before and
after the call. Request claims are never substituted for provider observations.

The release host exports active selectors atomically using
`day2-serving-snapshot JOURNAL TARGETS_JSON OUTPUT`. Targets are an exact bounded
JSON array of release targets in one installation/environment. The exported file
contains only checked active serving selections, never the control journal.
Publish those bytes as `serving.json` in the configured serving-snapshot ConfigMap
when releases activate or change. Its directory mount follows atomic ConfigMap
updates without rolling the app workload. The mount may initially be absent so
the workload can become ready before activation; calls fail until a matching
selector exists. The host rereads selection and fresh provider evidence around
every call. Publication is part of deployment integration, not an app-maintained
operation/type catalog.

The local HTTP/provider fixtures establish protocol and host wiring. They do not
establish real cluster authentication or production readiness.

## Recorded qualification profiles

The native Linux recipe builds the typed delegation examples, Stock Ledger,
Request Desk, App Ownership and Notifications. It runs their native HTTP
business and fault campaigns, then qualifies containment, restart, authority
revocation and supported restore. Its scoped receipt records the exact platform,
toolchain, runtime and app artifacts; it excludes the complete platform gate and
broader production certification. The complete local gate remains required.

Notifications imports the exact `app_ownership.check` query to authorize its
configuration reads, previews and saves using the inherited human. Ownership
administration is a separate, unexported command restricted by instance policy.
Each operation checks current ownership; revocation and receiver failure refuse
new work. The business configuration remains local and revision-checked, with
atomic actor-attributed changes. Notifications also accepts owner-authorized,
versioned publications and continues them through the ordinary command runtime to
its operator-bound Slack channel. Retained publication identities cannot resend an
uncertain provider attempt, and command status remains separately actor-scoped.
See the
[Ownership source](../examples/app-ownership/README.md) and
[Notifications source](../examples/notifications/README.md) for the source
oracles, bounds and the remote-authorization race boundary.

The October 2, 2026 GKE canary used runtime source `f53742d` with separate
`request_desk` and `stock_ledger` workloads, managed keys and independent IAP
gates. A human signed into Request Desk and submitted two requests for 30. Both
reservations succeeded; Stock Ledger's independent public query returned
`available: 40`, `reserved: 60`, `count: 2`, matching the recorded actions.
This was a manual browser campaign, with operator-published selectors from actual
StatefulSet identities. It establishes real authentication for those pinned
canary images; it does not qualify a production GKE release publisher or a later
runtime revision. Screenshots and artifact-bound evidence stay in protected
operator storage, without browser credentials or signing-key contents.
