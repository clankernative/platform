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

A refusal at `preparation` additionally exports a closed `preparation` record:
`{"step":"claim_binding","category":"permission_denied"}` is an example.
The step is the innermost annotated actual boundary, including its existing
pre/post checks; it does not establish that a request was sent or a filesystem
operation completed. It distinguishes the role-stage acquisition, selected
profile/CA/credentials, fixed provider joins, block/mount checks, private-directory
creation, memory-image admission and original-file preparation/retention.
Desired instance/artifact admission runs before enrollment, so a preparation
refusal there can have no Controller incarnation or preceding `enrolled` event.
That admission is DATA only; no native acquisition, original seed or file owner
exists yet. Native image initialization and file retention still use the same
original bounded phase. The ordering does not assert a latency cause or a later
successful preparation.

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
