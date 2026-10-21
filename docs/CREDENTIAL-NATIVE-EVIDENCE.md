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
