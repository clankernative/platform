# Shared activation preparation and recovery

`day2 platform maintain activate REQUEST.json` uses the same Roc recipe and
native admission for every app. There is no app-name selection or Home-specific
implementation. This is the first R0 increment in
[the online-runtime plan](ONLINE-RUNTIME-UPGRADES.md): it shortens exclusive
activation and makes interrupted preparation and stop intent recoverable. It
does not implement runtime-pair overlap or claim zero-downtime activation.

## Preparation while serving

The source remains at its original replica count while the operator fetches
digest-verified artifacts, measures store file sizes, schedules the sized helper,
pulls its image and copies/verifies artifacts and instance files. A running
source's helper also pulls the exact target app image in an init container and
runs `day2-health --help`, without any state-volume mount. This checks image
availability and binary startup, not store admission or app readiness. A target
image without this command is refused during preparation. A running
source must have exactly one Ready, controller-owned pod using the reviewed RWO
claim and source image. StatefulSets and Deployments use the same protocol.

The helper uses the incumbent's exact node through scheduler node affinity, so
normal CPU, memory, ephemeral-storage and volume admission still run. It does
not match a Service. Preparation only reads filesystem size metadata on the
live claim; it never opens SQLite or takes a serving/maintenance store lease.
The native host refuses store workflows before the stop and final size check.
Failure, suspension or operator death during preparation leaves the source
serving. A dead operator's helper can occupy resources until explicit recovery.

Immediately before stopping, the host rechecks the source controller UID and
pod template, instance bytes, PVC UID, original pod UID, node and readiness.
A controller compare-and-set publishes the stopped checkpoint and changes
replicas together. Replacement resources or a concurrent change refuse the stop.
Once stopped, file sizes are checked again against the helper's reservation.
Outgrown scratch is refused before any database is opened; the pre-fence source
is restored after helper cleanup. Preparation measurements are not a backup and
do not discard writes committed while the helper was starting.

The final consistent backup, target migration/admission rehearsal, confirmation
and real mutation still run exclusively. Moving the backup and rehearsal online,
and coordinating scheduled backups through native operation exclusion, remain
required follow-on R0 work. The runtime-pair protocol remains R1–R3.

## Durable intent

`day2.dev/activation` on the original workload records a closed checkpoint:
the unique owner, exact request and target-instance digests, original controller,
template, source-instance and PVC identities, original replicas, helper name/UID and
phase. It lives outside the pod template and does not itself restart the source.
The shared app stack retains the checkpoint for managed and direct deployments
and refuses plans while it is active or unrecognized. Keep infrastructure applies
serialized with activation: a previously saved plan is not an activation lease.
Concurrent maintenance cannot replace an active activation. The stop and fence
use API resource-version compare-and-set operations. A lost fence response is
treated as possibly committed; the old runtime is never automatically restarted.

The private format-2 session journal preserves the exact request and target
instance bytes beside the existing backup. Each update is written atomically,
with the file and parent directory synced. Keep that journal with the private
release evidence. It contains deployment configuration and must not be published
as a shared SDK receipt. Recovery survives operator process death with the saved
journal available; it does not reconstruct missing inputs after host/disk loss.

## Recover an interrupted operator

Run the same compiled tooling against its saved journal:

```text
day2 platform maintain recover /private/backups/SESSION.session.json
```

Roc orders checkpoint claim, helper cleanup and restore. Native admission checks
the saved request, target instance, workload template, source instance and claim
against the actual cluster checkpoint. It rejects stale or modified evidence and
replacement resources. The original request/target files need not still exist.
The recovery claim prevents the old operator from crossing the mutation fence.
Only the recorded helpers are removed, with UID-preconditioned graceful deletion
and termination observation; no volume is deleted and no force deletion is used.

Before the fence, recovery restores the original replica count and waits for
controller readiness. An already completed restore can be repeated safely.
After the fence, recovery cleans up but returns `target_only: true` and leaves
the old runtime stopped. Resume the exact saved target activation, or its
`mark-activated` recovery when applicable, after fixing the reported failure.
Recovery never chooses a different target, restores seed grants, rolls an old
runtime onto potentially changed stores, or treats a preparation copy as the
final recovery checkpoint. A runtime-only target still requires its own
activation/admission; an artifact ID alone cannot vouch for another runtime.

## Qualification and adoption

Mocked operator tests cover preparation refusal, source identity changes, growth,
controller kinds, operator loss and lost responses. They do not establish live
GKE/LB availability, native runtime-pair compatibility or offsite restore.
Adopt the shared app infrastructure revision containing checkpoint retention and
admission before using the new operator; older pinned stacks do not know this
guard. Qualify the resulting compiled SDK against each supported storage/provider
profile, then select that shared SDK for existing apps and future defaults.
Application CI reuses the compiled tooling; this change adds no per-app Platform
build. Publishing the implementation does not change a live app's selection.
