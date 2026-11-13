# Online runtime and SDK upgrades: implementation plan

Status: proposed runtime-pair protocol. The first R0 increment is described in
[shared activation preparation and recovery](ACTIVATION-RECOVERY.md); it remains
exclusive activation, with online backup/rehearsal and operation exclusion still
required before R0 is complete. No runtime-pair upgrade support is implemented.
Source baseline: `bd96d438b666bddd0c37a13f6f4f8e79ae7f585d`.

The goal is to keep an authenticated, writable application available while its
runtime changes. App-artifact rolling qualification alone does not establish
that property. This plan covers ordinary SQLite on one retained, same-node RWO
claim. Native storage, OAuth and other deployment profiles require their own
protocol and qualification. Same-node overlap provides no node-failure HA.

## Current mechanisms

- [Maintain.roc](../ops/Maintain.roc) prepares artifacts and a sized helper while
  the source serves, then stops and rechecks the storage bound. The final backup
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
- The release record denies unknown fields. Retained work is identified by app
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
