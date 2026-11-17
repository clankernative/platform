# Online runtime and SDK upgrades: implementation plan

Status: proposed runtime-pair protocol. R0 preparation, online preflight rehearsal
and backup/release operation exclusion are described in
[shared activation preparation and recovery](ACTIVATION-RECOVERY.md). The final
checkpoint and repeated rehearsal remain exclusive; preflight never replaces
the checkpoint of later writes. R1 now provides the preparation contract below;
runtime-pair activation remains blocked pending R2 and qualification.
Source baseline: `bd96d438b666bddd0c37a13f6f4f8e79ae7f585d`.

The goal is to keep an authenticated, writable application available while its
runtime changes. App-artifact rolling qualification alone does not establish
that property. This plan covers ordinary SQLite on one retained, same-node RWO
claim. Native storage, OAuth and other deployment profiles require their own
protocol and qualification. Same-node overlap provides no node-failure HA.

## R1 preparation contract

The existing release journal now records two closed software generations, each
containing artifact, runtime identity (SDK inventory and native executable/image
evidence), effective parsed-instance digest and immutable deployment image. A
same-artifact runtime change therefore has distinct source and target generations.
The raw target instance digest separately binds the operator's exact input bytes.
All app-artifact consumers use this record in place; there is no dual-read format.
An installed runtime that cannot read this journal still needs the explicit
bootstrap decision described below.

`runtime-pair-protocols INSTANCE APP` computes the current private SQLite shape
in memory, excluding the app's tables and their indexes from the reusable digest.
The manifest also versions serving/operation/execution leases, release journal,
authority, invocation/effect receipts, web tickets, worker protocol and artifact
catalog. Per-app preparation compares the complete actual business/private shape;
the native campaign must prove semantics beyond those format versions.

`runtime-pair-prepare INSTANCE APP CANDIDATE REQUEST RECEIPT OPERATOR` is a narrow
native preparation transaction. REQUEST is a closed record of `id`, immutable
`source_image`/`target_image` and the operator-reviewed `receipt_digest`. The receipt
is a closed, directed source/target manifest pair with verifier/recipe digests,
complete mandatory checks and feature profile. This reuses the existing trusted
local-operator evidence model; it is not signed provenance or app authority. No
native pair campaign or production receipt is produced by this command.

The initial `sqlite_local_v1` class keeps the app artifact and effective instance
unchanged. It rejects native storage, provider/credential/OAuth access, ingress,
schedules, unknown top-level SQLite stores and changed artifact-catalog shapes.
R3 must qualify richer profiles before they can serve installed apps using those
features. Shared pair evidence contains no app artifact, instance, business model
or controller identities; compilation and qualification remain reusable per pair
and profile, with installed state checked separately.

Preparation holds the per-app release lock and captures current authority in the
same SQLite transaction as the journal write. Schema compilation happens before
taking the business writer. It changes no active selection/security requirements.
The incumbent stays ready; actual business work still requires its measured source
supervisor/launcher and current authority. Artifact equality cannot transfer that
work to a target host. Any authority revision invalidates the prepared pair.
Preparation retries require the same request; a second unsettled release refuses.
Abort preserves accepted source work, including same-artifact work.

R1 **refuses candidate startup and every runtime-pair promotion transition**.
The app-artifact operational recipe also refuses to resume a runtime-pair record.
R2 must implement captured generation ownership, source executor recovery,
LB-health promotion/drain and durable operation/backup exclusion before removing
those guards. Local two-connection SQLite/serde tests and synthetic receipt
negatives establish the preparation contract only; they do not qualify two native
runtime binaries, live ingress availability or zero-downtime runtime activation.

## R2a executor ownership

Ordinary RWO accepted work now captures a host-runtime generation separately from
its app artifact. The existing rollout journal owns an immutable generation
catalogue, one active runtime selection and an invocation-to-generation row.
The installed runtime identity is reused when an app artifact changes; it is not
reconstructed from the next app build's SDK inventory. Retained worker selection
keeps the process's original runtime selection.

The actual accepting executor measures its supervisor/launcher and binds the
initial selection under the same transaction as input, authority stamp and work
ownership. Existing app-artifact rollout admission allows an unchanged-runtime
candidate to accept the first work too; an unadmitted artifact cannot bootstrap. A process keeps that choice after a rollback; retry can recreate only
that exact selection. Reopen compares actual code with the durable selection.
A JSON generation ID, SDK label or artifact ID alone cannot admit another binary.
Unqualified development harnesses may have no Linux launcher; qualified Linux
requirements still require the exact launcher digest. This measurement is trusted
host code identity, not hostile-host attestation or image identity proof.

Decision, observation, child request, dispatch and commit guards check both current
authority and captured executor ownership. A duplicate pending request remains
owned by its original executor. Queue selection filters owners before loading
retained workers. Child commands inherit their parent's owner; external effects
inherit through their invocation. Completed receipts still use the existing
current-authority result guard and do not rerun a retired worker.

Settlement of an already-performed effect checks the original process selection,
actual measured code and original invocation/stamp. Revocation or a changed active
selection can prevent fresh work without discarding known provider results.
Settlement does not authorize a new dispatch or business completion. Ownership
rows are immutable; missing rows are refused rather than backfilled.

This slice does not admit a second runtime or remove R1's startup/promotion guards.
Only the active generation may execute pending work until the later R2 slice adds
qualified source retention, target admission and source-executor recovery. Policy-only
revisions keep runtime identity but continue to fence accepted work; exclusive
artifact/restore binding changes and native security rebinds clear the active
selection without transferring captured owners. In particular, an explicitly
approved replacement supervisor can bootstrap after offline activation even when
the app artifact is unchanged. Native storage and non-RWO profiles retain their existing execution
protocols and are outside this runtime-overlap class.

Do not adopt this preparation/ownership slice as the complete serving bridge.
The remaining R2 work must bind actual deployment/image identity, keep or recover
source executors, implement actual LB-health promotion/drain and share the native
operation lease with backups. R3–R5 still precede live app adoption. These ownership
tables change the private SQLite contract in place; they supply no legacy-owner
migration or permission to execute unowned historical work.

## R2b isolated candidate and source recovery

The runtime-pair journal now has a required closed executor state: unadmitted,
or admitted source/candidate generation IDs and a candidate-check attempt. The
release-journal protocol is version 3. Old records are not upgraded or backfilled.
Ordinary target serving and every public promotion transition still refuse.

The actual RWO serving process registers its runtime generation after native
executable admission and before HTTP/pump startup. Operator inspection never
registers itself as the app executor. `runtime-pair-admit INSTANCE APP ID OPERATOR`
requires the existing exact `rollout-bind` placement, a registered source matching
its qualified supervisor/launcher, current authority and unchanged actual store
shape. It shares the native backup/release operation lease for this transaction.
Unknown side stores or retained credential/OAuth history refuse the local-only
profile. Admission records expected target code without changing the active
runtime, native security requirements, source readiness or replica count.

A closed executor selection carries the release ID, source/candidate role, exact
recorded placement and immutable image. Instance/artifact/scope are checked from
the loaded runtime against the same durable release. Selection files are bounded,
regular files and cannot follow symlinks. Placement/image facts are host/operator
DATA, not pod attestation; actual supervisor and launcher bytes must independently
match the qualified role. The remaining controller recipe must collect and
revalidate the real Kubernetes observations. A selection, label or receipt alone
cannot supply those observations or admit different executable bytes.

Both execution modes run from the qualified **day2-serve** binary, so an operator
CLI cannot impersonate the pinned supervisor:

- `day2-serve INSTANCE APP --runtime-candidate SELECTION EVIDENCE_DIRECTORY` starts
  a standby listener after schema admission and app-owned property checks on one
  complete bounded read snapshot. Properties have no effect interpreter. Their
  worker evaluation runs outside the business transaction; failed app checks keep
  artifact-bound replay evidence in the supplied protected directory. Only health
  endpoints exist. `/health/candidate` describes the current admitted check;
  `/health/ready` and all app routes return unavailable. No HTTP/pump for business
  work is constructed, and candidate startup runs no initialization DDL.
- `--runtime-candidate-check SELECTION EVIDENCE_DIRECTORY` performs the same
  bounded candidate check and exits, using the same supervisor executable.
- `--runtime-source-executor SELECTION BUDGET` runs one bounded headless source
  drain tick. It holds the ordinary shared serving/kernel lease, admits only the
  exact source code/placement and executes work through the existing current
  authority, captured owner and kernel execution-stripe guards. It accepts no new
  HTTP root requests. A fresh source process reads the original durable owner;
  a candidate never substitutes its runtime for that work. Source recovery also
  remains available after an abort while the original authority/binding remains
  current. Revocation or restore fences old selections.

A new candidate check clears the old positive before snapshot/evaluation. Its
monotone attempt and complete release binding are compared again before publishing
success. A failed/crashed check stays unready; competing or stale completions
cannot win, and the exact successful completion can be recovered after a lost
response. Check digests contain no model/provider values. A candidate observation
never authorizes public serving, a business write, or a later promotion.
Executor process failures use one fixed refusal label; source output contains
only the bounded settlement count, with raw failed-check evidence kept private.

This is the executor primitive layer, not a Kubernetes deployment recipe or a
native pair qualification receipt. Local SQLite/model/HTTP-refusal tests establish
its guard semantics; actual two-image Linux startup, source death, recovery and
availability still require the R3 campaign. R2 must still implement atomic public
promotion with source retention, real LB health/drain and durable controller
recovery/backup coordination. Promotion stays blocked until those exist. Nothing
here changes an installed app, controller, PVC safeguard or data. Compiled runtime
and app artifacts remain reusable; no app deployment rebuilds Platform for this
protocol.

## R2c online runtime handoff

`day2 platform maintain runtime-rollout REQUEST_JSON_FILE` is the runtime-only
lane in the existing `ops/Maintain.roc` recipe. App-code-only delivery continues
through `maintain rollout`; it refuses runtime-pair records. This code supplies
controller/kernel guards. R3 native qualification and R4–R5 delivery/adoption
remain prerequisites for live use; local SQLite, metadata and scripted adapter
tests do not establish two-binary or real-ingress qualification.

The request keeps the existing source/target immutable images, same compiled
artifact, effective instance, exact controller/PVC UID and incumbent node. It adds
one closed `runtime_pair` record with `receipt`, `receipt_digest`, `project`,
`backend_service`, Kubernetes `service` and both measured image compositions. The receipt pins the exact directed
qualified pair and local-only profile. No app deployment compiles Platform or its
SDK/operator tooling. The local-only profile rejects provider/OAuth/native-store,
sidecar and credential initialization combinations; unsupported shapes refuse
while Source serves. Existing protocol-3 installations require the explicit
bootstrap decision; no journal migration or stopped fallback is supplied.

The native protocol now versions the release journal at 5 (R3 composition binding) and serving, operation
and execution leases at 2. The same journal records bound, promoted, withdrawing,
quiesced and complete handoff states. Actual measured Source and Target code
remain separate execution approvals; the artifact's original SDK/security
prerequisites are still validated independently. No authority document, invocation
owner or effect owner is rewritten to make the target impersonate Source.

The recipe first obtains a verified offsite checkpoint and a private local copy
under the shared operation lease. It prepares a disposable SQLite copy, then
starts the target's actual candidate-check binary with **no live PVC mounted**.
After that rehearsal and operator confirmation, it claims the original Deployment
and prepares live admission. Preparation leaves Source ready. A per-release
immutable ConfigMap binds the instance, role selections and original/target
pod templates. An independently managed ReplicaSet starts Target on the same
node using scheduler affinity in every existing placement term. Target is owned
by that ConfigMap until adoption, so the Source Deployment cannot scale it away.

Target first exposes standby health only. Native promotion atomically selects
its execution generation and retains Source; the same process then opens the
ordinary Edge server. Its own pump executes the app-owned business probe.
Public readiness stays false until the probe succeeds. Current policy, captured
execution ownership and measured code are enforced on business requests, separate
from the health cache.

Withdrawal requires Google's real backend endpoint health, matched to the exact
Service/NEG, project, backend ID/configuration, attached HTTP `/health/ready`
check, target Pod/ReplicaSet UID, actual image ID, node and PVC UID. The initial
adapter supports one global HTTP backend and one zonal IPv4 NEG; other topologies
refuse. Pod Ready, `LoadBalancerNegReady`, an aggregate healthy backend or the
absence of a health check is insufficient. Backend health and NEG membership
come from separate bounded, read-only provider observations. Each transition
uses a fresh native observation round and current authority stamp.

After withdrawal Source stays able to finish requests while the controller waits
for its original endpoint to leave the NEG and for a full configured connection
drain interval. The interval is monotonic and starts again after controller loss.
A fresh allowlisted `/health/drain` observation must report zero in-flight
requests and streams under Source's original generation. Native quiescence then
blocks new Source roots; accepted work and children retain Source ownership.
The ordinary server observes that state, drains HTTP and exits successfully.
The controller records the actual original Pod's graceful stop in the canonical
journal **before** it may retire that Pod. A historical successful termination
beside a currently running container is insufficient.

Adoption pauses the original Deployment, installs the exact Target template,
compare-and-swaps the running ReplicaSet's owner from ConfigMap to Deployment,
and unpauses. It retains the running Target instead of asking Kubernetes to make
another target surge. Every mutation tests current UID, resourceVersion and
template, and rechecks Target backend health. Source's stopped public Pod may
then release its CPU slot. Bounded headless executors using the exact original
Source image recover its remaining accepted work on the same PVC/node. No work
is transferred to Target. Completion requires Source backlog zero, no Source
public Pods and a healthy adopted Target. The reviewed backup CronJob then selects
Target's image/instance under the same exclusion protocol.

A controller restart uses the same exact request, immutable blueprint and
canonical journal. It reaps only its own previous helper/checkpoint Pods under
UID preconditions, waits for its prior bounded backup Jobs to settle, and keeps
a headless Source recovery Pod available for reconciliation. Reaping a keeper
does not release a borrowing child's actual locked descriptor. A policy-aborted,
never-public candidate is removed only after native inspection proves original
Source is still active; its Deployment claim is then cleared without stopping
Source. Lost responses reconcile rather than repeat app writes or
invent completion. Pending runtime admission blocks fresh backups and offline
maintenance even after the keeper dies; the Deployment claim also prevents an
offline recipe from stopping the app before that refusal. Shared-claim backups
must use a qualified member of this pair and the operation-lock contract.
Interrupted source recovery remains bounded and retains original owners.
No step deletes a PVC or restores a checkpoint over live writes.

Ordinary-RWO readiness uses a dedicated metadata-only SQLite observer, outside
the business SQL admission queue. HTTP probes use its bounded fresh cache rather
than enqueue SQL. Busy/locked observations retain at most five seconds of prior
health; invalid binding/metadata clears it. A single owned sampler is joined at
shutdown. Source quiescence is irreversible for that process. Native-store health
keeps its existing protected path.

This is a planned-deploy bridge, not node-failure HA. Before Target is healthy,
Source remains the only available backend. After Source is quiesced, a Target or
node failure can still interrupt service. R3/R5 must exercise those failure
windows, authenticated ingress, long responses/streams, backup exclusion,
source/target deaths and exact retained receipts. Richer artifact/runtime pairs
and restore under fresh runtime authority remain explicitly unqualified.

## Current mechanisms

- [Maintain.roc](../ops/Maintain.roc) prepares artifacts and a sized helper while
  the source serves, takes and rehearses an online snapshot under native backup
  exclusion, then stops and rechecks the storage bound. The final backup
  and admission rehearsal before the *migration fence* still occur after the
  application has stopped.
- [Session::stop](../crates/day2-ops/src/maintenance.rs) scales non-rolling
  workloads to zero. `Operation::Rollout` alone keeps the incumbent serving.
- [maintenance_lease](../crates/day2/src/deployment.rs) requires the exclusive
  store lease before maintenance initialization. Sharing an RWO volume does not
  make concurrent maintenance safe.
- [rollout preparation](../crates/day2/src/rollout.rs) requires a new artifact,
  equal operational contracts and equal platform inventories. It compares the
  instance after normalizing only artifact identities. Runtime-only changes,
  including the same artifact on a new runtime, are outside that protocol.
- The release record denies unknown fields. In the app-artifact lane, retained work is identified by app
  artifact; retaining its worker does not prove that another host runtime can
  safely execute that work.

Removing an inventory comparison, skipping maintenance admission, returning a
literal readiness success, or allowing a stopped-maintenance fallback would not
provide the required protocol.

## Separate build identity from serving identity

Classify the actual software and state transition before selecting activation:

| Change | Required behavior |
| --- | --- |
| Tooling/SDK selection with identical admitted serving software and effective instance/security requirements | Record the checked build/provenance; preserve the running software and deployment selection. No activation or restart. |
| App artifact changes within the existing runtime/instance contract | Existing qualified app-artifact rollout. |
| Runtime executable or runtime-only image changes, with unchanged durable formats and supported execution protocols | New qualified runtime-pair rollout described below. It must admit a same-artifact runtime change. |
| Business schema, private format, provider-store format, execution ABI or instance change outside the qualified pair | Refuse automatic promotion while the incumbent serves. Explicit maintenance remains separate until an online protocol for that exact change exists. |

An SDK version string never determines this classification. Compare immutable
runtime/package identities, artifact, effective instance/security requirements
and operator-approved evidence. A changed security requirement cannot take the
no-op path merely because executable bytes match. Reuse a package keyed by
those software inputs instead of rebuilding an equivalent wrapper per source
commit. Keep build receipts separate from installed-deployment provenance.

## Runtime-pair admission

R3 image composition separates the registry descriptor used by Kubernetes,
the exact native builder image witness recorded by qualification, the canonical OCI
configuration digest, and the application artifact. The fixed app Dockerfile adds one artifact layer to the
qualified runtime. After pushing that image, an operator runs:

```console
build-out/bin/xtask verify-runtime-image BASE_IMAGE@sha256:DIGEST QUALIFIED_BASE_ID APP_IMAGE@sha256:DIGEST ARTIFACT_DIRECTORY NEW_DIRECTORY
```

`QUALIFIED_BASE_ID` is the exact image identity in the shared native qualification
receipt. It must be a measured root, native manifest or configuration node of the
base OCI graph; the deployment independently requires that exact approved value.
The private `RuntimeImage.roc` recipe measures the resolved image configurations,
the inherited OCI layer descriptors, and the added layer's actual bytes.
A root or manifest witness binds the inherited blob addresses directly. A
configuration witness also requires measuring the base layers against its DiffIDs. It refuses
changed execution settings, additional layers, links, whiteouts, extended
permissions, writable files, extra paths and missing or altered artifact files.
`composition.json` binds both immutable image references, the qualified native base identity, both native manifests and OCI configurations,
the exact artifact/tree/layer, and verifier/recipe identities. It grants no
qualification or pod attestation. The operator reviews and pins this DATA in the
maintenance request as `runtime_pair.source_composition` and
`runtime_pair.target_composition`. Both must bind the same unchanged artifact and
their selected app images. Journal admission and every later read retain those
bindings and require the native base identity from the exact qualification receipt.
Pod image observations must match the pinned root or its one measured native
manifest; a configuration digest or unrelated manifest is refused.

This verifier consumes the existing compiled workflow runner and never builds
Platform or the runner. Its temporary saved-image archive is bounded and removed
after successful measurement. Compiled SDK production and runtime-pair native
qualification remain shared platform-release operations. This first R3 slice
does not produce native/strict/pair qualification or enable installed apps.
The closed journal protocol is now version 5; both runtimes in a future qualified
pair must understand the composition fields. Older receipts are refused.

Publish an operator-owned transition receipt for one exact source and target
runtime pair. A target runtime's native and strict receipts, or an app rolling
receipt on the source runtime, are insufficient. The pair must bind:

- both runtime image/executable identities and qualified SDK references;
- serving lease, release-journal, authority, invocation/effect receipt, web ticket
  and worker-protocol formats; lock paths and cross-process exclusion semantics;
- complete business/private SQLite shapes and every auxiliary store's format,
  lifecycle and backup/restore policy;
- supported provider/resource/credential features, with exact bindings checked
  again on the installed application;
- coexistence and recovery results, the verifier/recipe identities and the
  complete mandatory negative-case campaign.

The native verifier calculates these identities. Apps cannot assert
`compatible=true`, choose a transition receipt, or authorize a runtime upgrade.
Receipt lookup requires exact source and target identities, not an ordering
claim such as “newer than.” Qualification runs once per supported runtime pair
and feature profile; per-app admission still checks the actual state and scope.
Ordinary application CI reuses the compiled SDK and published evidence.

An ABI-preserving runtime upgrade can reuse the checked app artifact. Target
runtime admission, required app checks/rehearsal and the installed-app probe still
run; reuse does not authorize skipping them or repeating Platform compilation.

The first supported class changes no durable schema or codec during overlap.
Startup opens and admits existing stores without initialization DDL, conversion
or cleanup that invalidates the source. A schema match alone is insufficient:
wire formats, locking and command/effect semantics must also be proved.

## One release state machine

Extend the existing native release state and Roc operational composition, rather
than adding a shell driver or an app-facing operational SDK. Represent source
and target *software generations* explicitly: runtime identity plus artifact and
effective instance identity. Artifact ID alone cannot distinguish a runtime-only
upgrade. Keep one canonical on-disk record and closed transition types.

1. **Prepare while serving.** Check current authority, exact controller/PVC/node,
   pair receipt, same-node capacity, scratch/disk bounds, backup exclusion and
   source/target image availability. Acquire a per-app release-operation lease.
   Back up online and verify the offsite checkpoint. Rehearse on an isolated copy.
   A refusal at this stage changes no serving replica or readiness state.
2. **Admit the pair.** Persist the exact request, target instance, source/target
   generations, current authority epoch, placement and checkpoint identities.
   Revalidate after the copy rehearsal; a snapshot is not authority over later
   writes. Permit overlap only under this durable, exact-pair admission.
3. **Start and probe the candidate.** Keep the source serving. Candidate startup
   may not mutate a durable format. Use isolated probes before public admission,
   then the supported release probe. Enforce current business authority at every
   decision/commit/result boundary; target seed grants never restore old policy.
4. **Promote with source service retained.** A compare-and-set publishes the
   target generation while continuing to admit the source generation under its
   exact native requirements. Target public readiness can now become eligible.
   Source readiness stays valid while target NEG/LB health converges. Do not
   assume the old and new native security requirements are interchangeable.
5. **Withdraw and drain the source.** Observe the target endpoint as healthy in
   the actual load balancer before withdrawing the source endpoint. Wait for
   connection draining, in-flight requests and captured source work. A Kubernetes
   Ready condition without a health-checked LB endpoint does not satisfy this.
6. **Complete.** Retire the source only after its finite backlog is settled and
   the target remains healthy. Publish the installed selection and align the
   scheduled backup. Reconciliation must preserve the released pod template.

Promotion is not permission to restart a pre-upgrade runtime against an
unqualified store. Abort is limited to an unpromoted pair with compatible writes;
after promotion resume the exact durable transaction or perform a separately
admitted reverse transition. There is no implicit image rollback.
Read/write coexistence proof does not by itself authorize a reverse deployment;
that direction needs its own receipt and admission against current state.

### Retained work and process death

Default to executing accepted source work on its original host-runtime
generation. Do not substitute a target host merely because the old worker
artifact is retained. Keep or restart the exact source generation off service
until that work settles, under current authority and the qualified pair. Source
process loss must not cause provider effects to be delivered twice or retried
after an ambiguous result. Cross-runtime execution needs its own explicit proof.

Allow only one unsettled runtime pair per app. Reserve capacity for source,
candidate and helper; replacing a lost source executor must fit that reservation.
Exceeding a drain budget blocks completion while a healthy generation serves;
it does not force deletion of pending work or the only healthy backend.

Operator death at any stage is recoverable from the durable request. Recovery
must discover the actual DB generation, controller/PVC/pod UIDs and LB health.
It cannot reconstruct authority from current CI defaults or rely on process-local
destructors. Lost promotion responses must not publish another transition.

### Readiness, backups and auxiliary state

Ready means this exact process generation holds current serving admission and
can receive traffic. Rechecking a contended business SQLite connection on every
probe can withdraw all backends during an ordinary write or backup. Design a
bounded, generation-bound serving observation with explicit invalidation/freshness
rules, and independently enforce current authority on actual requests. A cached
success must never admit an invalidated/restored generation.

Scheduled backup, rollout and exclusive activation share a native per-app
operation lease, in addition to SQLite transactions and serving leases. CronJob
`Forbid` alone is insufficient. A hung backup must delay/refuse a new transition
before stopping the source. Declare every auxiliary database; either include its
consistent recovery semantics or prove that its cold reconstruction is safe.
Unknown side stores or unversioned format drift refuse the transition.

## Bootstrap and format-changing upgrades

An old runtime cannot be assumed to read an extended release record: the current
record rejects unknown fields. A one-replica exclusive serving lease also cannot
silently become shared. The first runtime containing this protocol and the
controller/profile handoff therefore need an explicit bootstrap decision.

Prove an online bootstrap on the exact old runtime if the existing wire/store
contract can express it without changing that runtime's admitted inputs. Otherwise
combine the bridge runtime, required probe operations, final resource profile and
controller conversion in one reviewed maintenance window. Do not advertise that
window as zero downtime. Do not counterfeit the old inventory to hide the change.
This limitation applies to currently installed runtimes, not just future SDKs.

This first protocol does not solve arbitrary format-changing upgrades. Supporting
those without an outage needs a separate transactional state-handoff design:
source remains the writer during snapshot/replay, a complete committed-write
journal catches the target up, and a fenced ownership transfer changes the sole
writer only after target admission. Authority revisions, effects, all side stores
and recovery must move consistently. HTTP acknowledgment must wait for the real
commit; queued acceptance or read-only service is not write availability. This
requires a new bounded protocol and qualification, not a migration shim in the
same-file overlap lane. Until then, refuse it in automatic delivery and keep the
incumbent serving; an explicit maintenance decision is still required.

## Implementation slices and exit criteria

| Slice | Concrete changes | Required evidence |
| --- | --- | --- |
| R0: shorten and recover exclusive activation | `ops/Maintain.roc`, native maintenance session and existing release journal: prepare images/helper/capacity and rehearse online before stop; persist stop/fence/recovery intent; distinguish pre-fence restore from post-fence target-only recovery | Fail/suspend/kill every preparation step while source continues; pre-fence loss restores the original UIDs/replicas. Preparation snapshots never replace the final consistent checkpoint or lose intervening writes. This slice still has downtime. |
| R1: define the bridge contract | Runtime/store/authority/rollout code: closed software-generation identity, pair admission, protocol manifest and source/target executor ownership | Real SQLite conformance in both directions; same-artifact runtime change; unknown pair/schema/ABI/lock namespace refused without writes; strict current-authority negatives |
| R2: implement the online recipe | Extend the Roc maintenance/release recipe and narrow native capabilities; actual LB-health observation, operation lease, durable recovery and generation drain | No source scale-to-zero; candidate faults, LB delay, source death and lost promotion responses; exact request resume and no duplicate provider effects |
| R3: publish qualified compiled outputs | Native/strict receipts plus directed runtime-pair evidence and immutable SDK/operator artifacts | Linux/native campaign; correct SDK closure, source/target image and recipe binding; no per-app Platform rebuild |
| R4: wire instance delivery | Classify no-op/app rollout/runtime-pair/explicit-maintenance-required before activation; retain release-managed Deployment and backup selection | Unsupported runtime changes stop before selection/stop; no stopped fallback; unchanged software avoids activation; prepared artifacts survive retry without rebuilding |
| R5: qualify an installed-app-shaped canary | Same provider, auxiliary-store and resource features as the intended app; restored data, scope and current authority; real ingress and LB observations | Continuous authenticated read/write, session/assets/provider-backed reads; exact retained IDs/counts; zero availability failures; offsite restore; final no-change infrastructure plan |

R0 can land independently; R1–R3 can use disposable fixtures before any installed
controller conversion. R4–R5 precede enabling automatic runtime upgrades. The
format-changing state-handoff protocol is a subsequent required slice before
claiming that *all* runtime upgrades are online. Every implementation follows the
repository's scoped checks, full verification and native qualification rules.

## Qualification matrix

Include at least: same artifact/new runtime; new artifact/new runtime; unsupported
source pair; private/auxiliary schema mismatch; worker and ticket incompatibility;
pending local/child/provider work; policy revoke and restore epoch changes;
concurrent scheduled backup; scratch/CPU exhaustion; candidate kill; source kill;
operator kill before/after promotion; LB health delayed or never established;
slow SQLite writes; old forms/assets during drain; target backup and source
checkpoint restore. Record failures as well as successful repeats.

For a live transition require zero failed valid observer cycles, no no-backend
LB errors, and a healthy target endpoint before source withdrawal. Do not retry,
drop busy cycles, infer LB health from pod Ready, or subtract baseline 5xx errors.
Baseline failures must be resolved before the campaign can pass. These are
acceptance criteria; this document supplies no implementation or live receipt.

## Provider references

GKE documents a [NEG readiness race](https://docs.cloud.google.com/kubernetes-engine/networking/docs/known-issues#neg_readiness_gate_race_condition)
that can report ready before backend health is established. Its
[Ingress draining guidance](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/ingress-configuration#connection_draining_timeout)
also requires keeping the process alive through draining and endpoint removal.
Use actual endpoint health and observed drain completion as release evidence;
a readiness reason or a configured BackendConfig alone is insufficient.
