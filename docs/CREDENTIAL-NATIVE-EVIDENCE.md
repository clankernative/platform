# Private native Controller observations

The real `day2-epoch-controller` executor writes bounded historical observations
to its private container stderr. There is no diagnostic HTTP endpoint, synthetic
serving request, replay command or receipt-to-authority constructor. Health still
returns lifecycle DATA only.

Each complete line starts with `day2-native-controller-evidence ` followed by one
JSON object. `format` is `day2_native_controller_evidence_v1`; `sequence` starts
at one. `selection` commits to the complete selected bootstrap policy and epoch
store. `controller_incarnation` is the historical commitment from the actual
successful enrollment. These commitments contain no raw configuration, process
paths, account names, tokens, keys or provider errors. A failure before selection
or enrollment has null commitments for the unavailable context.
The selection commitment describes the selected input; enrollment alone does
not establish that the file, first-holder or epoch-store joins succeeded.

The closed `observation.event` values are:

| Event | Actual completed boundary | Maximum records |
| --- | --- | --- |
| `enrolled` | The final owning Controller thread completed native enrollment. | 1 |
| `first_holder_durability_completed` | The real original file/PD/ext4 and authenticated first-holder exchange completed the selected conditional durability checks and retained activation continuity. `seed` and `holder` are commitments only. | 1 |
| `bootstrap_completed` | One actual reserve, dispatch or settle finished its known result, peer acknowledgement, original checks and release. `step` is one of the six fixed steps; `operation`, `request` and `snapshot` are commitments to the exact request and resulting versioned observation. | 6 |
| `activation_completed` | Both three-step operations completed; the exact activated snapshot and operation were retained. | 1 |
| `first_serving_release` | The first real Controller-side App or Shell operation completed consumer acknowledgement, final provider reobservation, physical/peer checks and release. `role`, actual request `binding` and final `snapshot` identify that historical operation. | 2, one per role |
| `refused` | An actual error stopped the executor. `at` is a fixed phase label, never the error text. A possibly attempted or unknown effect is not reported as completed. | 1 |

The bootstrap `step` order is exactly `create_reserve`, `create_dispatch`,
`create_settle`, `activate_reserve`, `activate_dispatch`, `activate_settle`.
Each record is at most 2,048 bytes including prefix and newline; the exporter
writes at most twelve records (24 KiB) per process. Repeated serving operations
do not grow the transcript. A partial/failed export stops the executor and cannot
be followed by another purported complete evidence record. OS logging can block
or perturb another executor's existing deadline; neither an elapsed-time bound
nor a deadline extension is implied.

## Collect an exact running executor's transcript

The operator first selects the actual Controller Pod and retains its UID,
container ID, image ID and restart count alongside the exact source/image being
qualified. Do not select an arbitrary replacement Pod by label and combine its
logs with a prior executor's transcript. The container is `epoch-controller`.

```sh
umask 077
kubectl logs --namespace "$CANARY_NAMESPACE" "$CONTROLLER_POD" \
  --container epoch-controller --timestamps=false > controller-private.log
sed -n 's/^day2-native-controller-evidence //p' controller-private.log \
  > controller-native-evidence.jsonl
```

This only collects the ordinary private Pod logs; it invokes no native action
or cloud mutation. Keep both files private. A separate `--previous` collection,
if needed to diagnose refusal, belongs to that previous container incarnation
and must not be merged into the current transcript. Treat missing, incomplete,
out-of-order or mixed-incarnation records as incomplete evidence, not success.

Nine contiguous startup records cover enrollment, first holder, the six steps
and activation. Subsequent first-release records cover only those particular
real Controller-side consumers. The first App operation can be initial Runtime
admission rather than a human connection or response. Join its exact binding
with the actual consumer-side evidence before claiming a particular consumer
scope completed. A known native read or key retrieval can also be followed by
product-level refusal; release and acknowledgement do not mean OAuth approval
or authentication acceptance. Retain the actual product outcome separately.
Bindings identify selected purpose/original DATA, not unique native phase or
invocation IDs. Equal hashes alone cannot establish that two records describe
the same request; retain the actual consumer original/connection evidence and
executor context for any such claim.
The App storage binding wraps the original serving binding and
completion request under `day2-current-active-app-storage-v1`; the Shell uses its
actual serving request binding directly. All final snapshot commitments reuse
`security_epoch::journal::snapshot_digest`, including all four provider version
tokens. The Shell does not receive a provider snapshot and must not fabricate
one from its channel binding.

These are observations from trusted running code and private operator-collected
logs, not independently signed attestations, transferable permissions, current
leases, general SQLite-writer fences, future readiness or proof that every
serving request completed. Retained App file/process continuity does not grant
current epoch authority. Actual current checks remain mandatory at security
consumers. Conditional PD/ext4 durability and accepted provider/governance trust
limits remain unchanged. The S1 supplier qualification, actual App/Shell consumer
settlement and end-to-end Google campaign remain separately required.

### Preparation refusal details

A refusal at `preparation` or `holder_listener` additionally exports a closed `preparation` record:
`{"step":"claim_binding","category":"permission_denied"}` is an example.
The step is the innermost annotated actual boundary, including its existing
pre/post checks; it does not establish that a request was sent or a filesystem
operation completed. It distinguishes the role-stage acquisition, selected
profile/CA/credentials, fixed provider joins, block/mount checks, private-directory
creation, memory-image admission and original-file preparation/retention.
At `holder_listener`, fixed `holder_*` steps separately identify acquisition of
the next role, current-file phase, owner capture, projection, interval narrowing,
transport binding and final checks. An existing more specific inner boundary
retains precedence. Thus a later listener failure does not relabel a completed
original preparation, and a missing historical category must not be inferred.
Desired instance/artifact admission runs before enrollment, so a preparation
refusal there can have no Controller incarnation or preceding `enrolled` event.
That admission is DATA only; no native acquisition, original seed or file owner
exists yet. Native image initialization and file retention still use the same
original bounded phase. The ordering does not assert a latency cause or a later
successful preparation.

When available, `progress` contains fixed optional `acquired_us`, `image_us`,
`prepared_us` and `last_checked_us` fields. Each copies cumulative microseconds
from an already successful sample of the same original acquisition. Recording
them reads no clock and changes no validity flag or deadline. A failed or expired
sample is not included, so the values are not exact boundary times, operation
durations or current remaining time. Missing values stay absent. Retention can
identify `original_retention_before`, `original_retention_owner` or
`original_retention_after`, while preserving any more specific inner boundary.
The progress is emitted only with the existing refusal after unwinding; there is
no extra in-phase log I/O or successful-preparation receipt.

When an HTTP send fails, optional `request` is
`[last_sampled_elapsed_us, selected_timeout_us, is_timeout]`. The elapsed sample
and timeout were already selected before that send; exporting them reads no
clock or private error text. The first element can be `null`. These historical
values do not prove transmission, remote effects or exact expiry. The native
postcheck still runs, and its refusal remains terminal even when the original
request failure takes precedence in the diagnostic.

Categories are a fixed allowlist: clock expired or rewound, acquisition refused,
transport unavailable, response status or bound, admission rejected, known OS
error categories, or `other`. The combined response category does not reveal or
prove a particular HTTP status; transport unavailability does not itself prove
a timeout. Unknown causes are never formatted or exported. The original error
and existing refusal remain intact internally. The same twelve-record and
2,048-byte record ceilings apply; no request, check, deadline, retry, adoption or
permission is added. These details diagnose a stopped attempt only; they are
neither authority nor a successful preparation receipt.

The fixed Compute instance GET requests only
`id,name,selfLink,status,disks(source,deviceName,type,mode,boot)` using Google's
[partial-response fields parameter](https://docs.cloud.google.com/compute/docs/api/how-tos/performance).
Every attachment remains present for the unchanged complete-list, ambiguity,
32-attachment and read/write joins. The 65,536-byte response ceiling, exact
resource selection, authenticated transport and original acquisition are
unchanged. This avoids unrelated instance metadata; it does not filter disks,
truncate a response, retry a failed read or establish the cause of a prior
refusal.

## Purpose and original-lifetime boundaries

Ordinary Current, serving, Shell and human-original consumers retain their
five-second stage. Initial first-holder admission retains its separate
10-second purpose. Neither purpose can substitute for the other.

Only the six fixed Controller storage-bootstrap operations and their exact
retained App responder select `storage_bootstrap`, with a nominal 30-second
original interval. The App selects it from its local `Bootstrapping` owner,
never from a received purpose label. Role exchange and complete Google/Kubernetes
authentication must both finish by that same original origin plus five seconds.
The actual successful authentication child is consumed before a fresh I/O view
is derived from its retained parent; the five-second child is never widened.
Configured, file and signed shorter ceilings continue to tighten the interval.
Each provider HTTP request remains bounded by five seconds and the actual
remaining original time. No retry, renewal or ambiguous-effect resend is added.

The Controller-only operator diagnostic has the distinct signed purpose
`storage_metadata_observation`. Its metadata-read facade cannot create a
Controller writer facade, storage peer, initial file, original, active serving
phase or consumer. Its separate nominal ceiling remains ten seconds. Even a valid signed non-Current purpose with a short interval
is refused by ordinary consumers. The nominal ceiling does not establish a
complete-path timing margin or successful native qualification. On 2026-10-23,
the ten-second bootstrap attempt spent 7.718 seconds before writer preparation
and then refused there after all three provider rounds, before the first
counter read. The user approved thirty seconds per bootstrap action to qualify
the unmeasured tail. Require repeated complete actions within 24 seconds before
claiming margin; neither this ceiling nor successful DATA tests establish it.

The subsequent thirty-second attempt refused during its counter read: the
inclusive counter phase took 18.732 seconds, including 17.968 seconds of native
checks and 14.317 seconds of nested authentication checks. These durations
overlap. The timed Firestore read and rollback themselves totalled 0.126 seconds;
that is not the complete transport/authority cost. Three pure response-decoding
checkpoints now sample only the SAME retained original native clock, behind the
same refusal gate and local file/process/thread liveness checks. They return
budget DATA only. Full current file, peer, role and authentication checks still
run at budget/context issuance, every HTTP pre/post boundary, observation
consumption and final lifecycle transfer. No successful native check is cached,
no initial-image read guard is removed, and no deadline is widened. A separate
allocation-free canonical decimal check preserves the fresh `/proc` parser's
previous integer range and spelling rules. Actual savings and complete-path
margin still require new native measurements.

## Preparation timing diagnosis

`day2-epoch-controller --observe-preparation-read-only INSTANCE APP` is a closed,
one-process diagnostic for the actual enrolled Controller. It performs the
ordinary artifact/instance admission, role-stage exchange, complete Controller
authentication and three fresh rounds of selected provider-metadata checks under
one original `storage_metadata_observation` interval. The origin precedes the
role RPC. Role and full provider authentication share its first five seconds;
provider I/O then spends the remainder of that same nominal 10-second parent.
All rounds share the same genuine authenticated reader; none starts another
stage or renews its acquisition.
Each round validates the current claim, volume, node, disk and instance responses.
Attachment checks remain strict: a detached or changed disk refuses. It opens
neither `/state` nor a block-device descriptor,
and performs no mount acquisition or current-volume checks. It returns before seed,
private-directory, initial-file, first-holder, bootstrap or serving construction.
It never opens the existing native SQLite file or writes provider/control state.
Run it only with the actual source/image/profile bindings and preserve any first
refusal. It is not permission to retry a failed original. After either outcome
all role/storage owners have dropped and the command remains ownerless for a
fixed five-minute hold, without another observation, provider call or listener.
For this operator-only Deployment run, disable liveness/startup probes, keep
readiness failing and stop/scale it to zero before that hold ends. There is no
once-across-restarts or hard OS scheduling guarantee; forced replacement or
letting the hold expire can cause Kubernetes to start another process.

Its `preparation_read_only_observed` record contains the fixed
`frontier: "auth_three_provider_rounds"`, `completed: true`, `expected_rounds: 3`
and a `bootstrap` snapshot with
`scope: "provider_read_only_storage_metadata"`, `purpose_limit_us: 10000000` and
`provider_rounds: [3, 3]`. The limit is nominal purpose DATA, not effective
remaining time or permission. This is a different signed purpose from the
earlier Current diagnostic; do not relabel either result as the other.
Completion requires all three rounds and the final
reader/guard postchecks to return successfully. It establishes no filesystem
observation, bootstrap completion, readiness or current permission. It excludes
App concurrency, physical/file checks, fsync, peer exchange and writer work, so
it supplies no complete-path timing margin.

The first failed round stops the command and emits the ordinary single refusal
with its original boundary, request tuple when present, and scoped snapshot of
attempted versus fully validated rounds. It never restarts authentication or
repeats that failed round. An export failure remains terminal and does not
replace an earlier native error. Separately, ordinary initial preparation caches
its own preparation summary into its existing first-holder or first refusal
record, including a later listener/holder refusal. The twelve-record and
2,048-byte bounds remain unchanged; logging does not run inside the measured
original phase.

Each timing row is `[fixed_operation, [calls, total_us, max_us]]`. Durations come
from separate diagnostic Linux boot-clock reads, never from cached successful
authority samples. They are **inclusive**: for example `volume_acquisition`
contains its network and `native_check` rows, and `original_file` contains its
read/write/sync/check rows. Do not add nested rows together. Missing, rewound or
overflowed measurements are `null`, never zero or success. Measurement overhead
spends the original deadline; no diagnostic value feeds an acquisition, issuer,
budget, retry or renewal. Later serving phases disable collection. The final
retention guard is deliberately not wrapped in an ending clock read: it remains
the last I/O before the infallible owner transfer.

## Storage-bootstrap timing

Each of the six bootstrap steps starts a separate diagnostic collector for its
actual storage-bootstrap attempt. Entering that step clears the cached
first-holder summary. A refusal there can carry `bootstrap` with the fixed
`scope: "storage_bootstrap"`, nominal `purpose_limit_us: 30000000`, `last_step`,
`returned`, `provider_rounds`, `elapsed_us`, `timing_format` and `timing`; it never reuses the earlier
preparation `timing` field. Shorter effective caps are not reported as a fresh
interval by this nominal value.

`last_step` and `returned` describe the last **measured operation**, not the
outcome of the whole storage-bootstrap attempt. `returned` is `true` or `false` for that
operation's native result, or `null` if it has not returned. The closed
`preparation.step` remains the reported native failure boundary.
No successful measurement establishes activation, serving or an accepted write.

`provider_rounds` is `[attempted, fully_validated]` for the fresh provider
observations in this attempt. A failed second or third round increments only
the attempted count. Overflow is `null`, not zero or a completed observation.
Each of the first three provider rounds has a separate inclusive duration; any
extra or overflowed round is recorded in the fixed `provider_round_other` bucket
and cannot count as the completed three-round control. Writer preparation also
records phase authentication checks, material checks and its final sample.
Counter/slot reobservations, execution preparation, announcement, acknowledgement,
peer release/finish and Firestore read/commit/rollback calls are timed separately.
The latter include the actual native transport guards, not merely network RTT.
No native check or request is removed or repeated. Final file guards remain the
last I/O before their infallible continuation transfer.

Bootstrap uses `timing_format: "operation_count_total_us_v1"`, with rows
`[operation_code, calls, total_us]`. This compact fixed vocabulary keeps maximal
diagnostics inside the existing 2,048-byte record ceiling. Missing, rewound or
overflowed clocks/counters are `null`, never zero or success. Preparation keeps
its separate named count/total/max format. Bootstrap codes are:

| Codes | Operations in the same order |
| --- | --- |
| 0, 1, 2 | role_stage, volume_acquisition, native_check |
| 17–21 | claim, volume, node, disk, instance |
| 28–34 | bootstrap_ready, bootstrap_authentication, bootstrap_file, bootstrap_projection, bootstrap_durability, bootstrap_peer, bootstrap_peer_check |
| 35–41 | bootstrap_writer, bootstrap_counter, bootstrap_slot, bootstrap_mutation, bootstrap_validation, bootstrap_release, authentication_check |
| 42–45 | provider_round_one, provider_round_two, provider_round_three, provider_round_other |
| 46–48 | bootstrap_writer_phase, bootstrap_writer_material, bootstrap_writer_sample |
| 49–52 | bootstrap_counter_after, bootstrap_slot_after, bootstrap_execution, bootstrap_announcement |
| 53–55 | bootstrap_acknowledgement, bootstrap_peer_release, bootstrap_peer_finish |
| 56–58 | bootstrap_firestore_read, bootstrap_firestore_commit, bootstrap_firestore_rollback |

Rows remain inclusive: provider and authentication timings nest inside outer
file/durability/writer phases, and Firestore calls nest inside counter/slot or
mutation phases. Do not add nested durations to their parents. `elapsed_us`
covers the whole caller action from immediately before role acquisition until
after final acknowledgement/release or refusal unwind. Its diagnostic clocks
cannot grant authority, replace a native failure or renew an original interval.
An unavailable elapsed time is inconclusive for margin.

The snapshot is retained only after the actual stage/file/port operation has
returned or unwound. Each completed action exports its own snapshot in the
existing `bootstrap_completed` record; refusal exports the attempted snapshot.
A completed timing snapshot must end at successful `bootstrap_release`, not a
read-only metadata control or an incomplete callback. It
changes no native call order, check, original deadline or retry rule. Sampling
or export failure cannot replace the first native error or its failed-request
tuple. The 2,048-byte and twelve-record ceilings remain unchanged.

## Earlier infrastructure measurements

On 2026-10-21, separate native Rust controls ran ten times on the selected
oauthcalendar node and retained disk, with its actual Controller KSA for metadata
reads. The complete eleven-request metadata sequence measured 600–1170 ms
(median 727 ms); the Firestore **database metadata GET** measured 39–237 ms.
Synthetic 946176-byte scratch-file writes measured 0.49–0.78 ms, file fsync
3.10–8.72 ms, directory fsync 0.002–0.003 ms, and readback/equality 0.36–1.04 ms.
Only a process-created sibling scratch directory/files were changed and removed;
the failed SQLite and native directory were not opened for contents or modified.
Both disposable probes were removed. Parent-root metadata changed from scratch
creation/removal. Pod creation to the CSI successful-attach event was eight
seconds, using coarse Kubernetes timestamps including scheduling/CSI overhead;
attachment preceded the timed file operations and is outside the original
Controller's five-second preparation interval.

These are infrastructure controls, not timings inside the failed Controller
invocation or evidence that its bound is reliable. The original observed failure
was 5.002 seconds from enrollment to refusal. Its role exchange, image preparation
and nested native validation costs still require the source-bound Controller
diagnostic; neither a passing scratch run nor original I/O batching proves a
cause, a complete latency budget, or successful native preparation.
