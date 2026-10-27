# Private native Controller observations

The selected [connection/request contract](CREDENTIAL-NATIVE-ENROLLMENT.md#admitted-connections-and-fresh-requests)
is being ported and needs new cold-admission/warm-request evidence. Older full
revalidation profiles remain historical records bound to their source. A new
profile capture must identify actual admission separately from the first and
second requests; do not hide admission outside a request span and label it warm.
Warm requests target zero full scans, physical attachment rounds, repeated
provider authentication and issuer enrollment, with real authority/counter,
owned-handle, original-clock and refusal checks retained. This is a qualification
obligation, not a claim that current captures or their labels prove completion.

## Selected-contract implementation status

This source snapshot covers main including PRs 286, 287 and 291. PR 282 installed
the selected contract in the native documents; the shared proposals also reference that
contract. Specification changes did not implement or qualify it. The row names
below are from the workspace option-3 implementation plan. Open PRs and private
compositions are not counted as landed implementation.

| Owning plan row | Landed on this main snapshot | Still pending |
| --- | --- | --- |
| **Specify admitted connections and fresh requests** — Credential | PR 282 specifies admission, fresh requests, trusted ongoing content integrity and retained refusal/clock guarantees. | No runtime qualification follows from the specification. |
| **Separate full process admission from retained-handle checks** — Credential | PR 284 separates full `MessageProcess` executable admission from later retained-descriptor checks; PR 286 retains the role's self snapshot and connection-clock anchors across bounded stages. | Remaining packet/caller ports. Retained self checks do not remove main's per-stage issuer exchange or qualify the complete request port. |
| **Admit storage once and retain its actual physical owners** — G1 | PR 287 makes Current physical phases borrow the admitted volume and actual file/directory/device/mount/profile handles, removing repeated attachment rounds and the Current-only durability helper. Initial creation, first-holder/activation, real file owners and existing-file Runtime admission remain. | Bootstrap integration and the separate counter/request ports; this physical primitive does not qualify the complete warm path. Actual file/mount/writer and durability barriers remain required. |
| **Borrow fresh requests from the admitted enrolled connection** — Credential | Native channels, purpose-bound transcripts, actual sender handles and original refusal rules exist. | The owned request/lexical borrow, retained sender reuse and warm peer protocol. Main still exchanges with the issuer in `begin_stage`. |
| **Retain authenticated counter transport in the real storage connection** — G1 | Authenticated bounded coherent epoch reads and their actual owner checks exist. | Connection-retained authentication/expiry and the warm Current transport; existing Current acquisition still authenticates material. |
| **Port App/Shell consumers and SQL to the same request owner** — Product, with G1 owning serving | PR 285 binds SQL units and protected subject reads to actual consumer owners, with arming, close/postchecks and one-shot final settlement. | Porting the App/Shell callbacks and serving composition to the new single request original. |
| **Compose the independent connection/request failure campaign** — CI | PR 283 adds replayable independent reference histories; the production cold-handshake reducer and earlier campaigns remain. | Joining the new warm production transitions and consumer failures to those histories. The reference receipt explicitly reports no production-request or real-Linux-owner execution. |
| **Qualify the admitted-connection path on the real node** — Root | Earlier source-bound native evidence remains available. | Complete cold admission, two warm requests, refusal cases and browser lifecycle evidence for the composed implementation under the ordinary five-second bound. |

### Cumulative work currently available

PR 291 adds a process-wide diagnostic ledger for both actual executable-hash
loops, issuer-client exchanges and accepted issuer-service admissions, including
failed/partial work. Its nine-kind schema leaves the six storage/provider kinds
explicitly uncovered/null. A successful leaf count is not successful admission,
delivery or commit. SHA byte counts describe actual reads, including partial
failures; missing coverage, contention/loss, poison, abandonment and overflow
cannot be interpreted as zero work.

The issuer's `day2_native_issuer_cost_v2` records include a cumulative snapshot
within their 8 KiB bound. The detailed stream still stops after sixteen records;
the in-memory ledger continues but that capped export cannot prove later zero
work. Complete producer/owner/request joins, authenticated issuer cutpoints and
the six real storage hooks remain pending under the production, campaign and
qualification rows above. These are instrumentation results, not a completed
warm-request measurement or a new diagnostic authority endpoint.

The records below describe their actual implemented emitters or historical
source-bound measurements. They do not turn those pending rows into qualified
implementation, and a temporary measurement window is not the ordinary limit.

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
Each ordinary lifecycle record is at most 2,048 bytes including prefix and
newline; at most twelve such records (24 KiB) are written per process. Repeated
serving operations do not grow this lifecycle transcript. The separately bounded
timing DATA below can include later Current operations. A partial/failed export stops the executor and cannot
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
retained App responder select `storage_bootstrap`, with a temporary nominal 60-second
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
counter read. The user first approved thirty seconds per bootstrap action.
The later paired-read run completed reserve in 29.809998 seconds, but its next
dispatch refused at announcement after 30.001722 seconds. The user approved a
temporary sixty-second ceiling to measure all remaining steps, pending the
kernel-integrity/Firestore redesign intended to return to thirty seconds or less.
Neither this temporary ceiling nor successful DATA tests establishes margin;
the redesign's thirty-second target still requires repeated complete actions
within 24 seconds before claiming its six-second margin.

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

The subsequent same-source attempt completed all provider rounds but again
expired during the first counter read. Its ten full port samples totalled
19.995 seconds inclusive; no complete-action margin or causal speedup follows.
The transport now receives the caller's actual Budget in the one private post
API. It charges all full preguards immediately before the single HTTP request,
caps that request at the lesser of caller/parent remaining time and five seconds,
and charges the final full postguards before accepting a reply. Central response
checks and final clock observation also latch transport refusal. Ordinary read
ports keep their existing full pre/post behavior.

For pure full-port observations, authentication uses a closed leaf on the
actual provider-owned stage and exact shared read-state identity. It releases
that material borrow before the unchanged full file/provider/peer validation,
then samples the original clock again. No role/material getter or successful
check cache is introduced. HTTP still requires full physical admission BEFORE
and AFTER its effect. Every actual initial-image read retains its original
per-syscall identity, role, policy and clock guards and existing batch size.

## Preparation timing diagnosis

Ordinary Current App-serving has a distinct diagnostic root around its actual
Controller operation, including its role acquisition. App-side work before its
request becomes pending at the Controller is outside this sample. After the role/file/peer borrows unwind,
the Controller can emit `day2-native-controller-self-check` with format
`controller_current_app_serving_exclusive_ns_v3`, scope
`whole_current_app_serving_operation`, its own consecutive `sequence`, the count
of already emitted ordinary lifecycle records in `lifecycle_sequence`, selection
and Controller incarnation. `completed` reports only whether this actual Current
operation returned successfully; a later log or consumer can still fail.
It is historical DATA, not readiness,
permission, current validity or a sampled remaining budget. It has no bootstrap
action field and cannot be interpreted as a bootstrap full-check sample.

`profile.samples` counts whole Current operations, not full checks. The sixteen
fixed rows are `[span_attempts, exclusive_ns]`, in the following order:

| Row | Current work |
| --- | --- |
| 0 | Other, outside named spans |
| 1 | Peer executable bytes/SHA and chunk guards |
| 2 | Retained self-process identity |
| 3 | Self namespaces |
| 4 | Enrollment policy |
| 5 | Peer identity, excluding nested leaves |
| 6 | Storage profile |
| 7 | Initial-image byte loop; not the active writable-file guard |
| 8 | Volume, excluding nested leaves |
| 9 | Self-acquisition executable SHA and chunk guards |
| 10 | Issuer send/receive transport, including synchronous waits and bounded decode |
| 11 | Other packet polls; issuer transport is excluded |
| 12 | Provider HTTP and metadata-token exchange, including bounded response reads |
| 13 | Local role-acquisition composition, excluding nested leaves |
| 14 | Local physical composition, excluding nested leaves |
| 15 | Local remaining serving composition, excluding nested leaves |

These exclusive rows partition the attempted Current operation; sum them once.
Local rows are residual host composition, including local descriptor/byte work,
not a claim of CPU-only time. Issuer transport measures the caller's synchronous
wait and local packet work; it does not profile the remote issuer's execution.
Span attempts are not RPC counts. The intended next native capture attributes
at least 90% to named rows, but coverage and cost remain unmeasured until that
actual run. Inspect Other and the local residual rows before claiming a dominant
leaf, a net verity saving or complete request latency. Bootstrap retains its
separate nine-row full-check scope; these extra marks are disabled in that scope.
Optional `physical` DATA identifies the last attempted composite-check subcall,
whether that call succeeded, and the first failed subcall. An enclosing call's
later failure does not overwrite a nested call's successful outcome. Rows are fixed in order
durability, current/retained peer, final file, ProviderAcquire stage argument;
each is `[count, inclusive_us]`. The fourth row identifies a full physical check
at the ProviderAcquire stage argument; the fixed initial handoff below does not
enter it, unlike the preceding diagnostic baseline.
These rows overlap the exclusive profile and must not be added to it. A subcall
can contain several guards; the marker does not establish a failed statement or
cause. If role acquisition fails first, no physical row is fabricated.

The Current record is capped separately at 1536 bytes and at 256 records per
Controller. Each available sample is consumed once, including later successful
Current operations and a terminal refusal; startup does not consume the entire
capture. Ordinary lifecycle records still contain only the first release per
role. Reaching the diagnostic cap neither starts another native operation nor
changes its result. A capture reaching 256 records is potentially truncated;
missing samples, records or null timings are not zero exchanges or zero cost.
The existing 1024-byte
bootstrap profile and 2048-byte authority-record bounds stay unchanged. Missing,
rewound, nested-root or overflowed metric samples are inconclusive, never zero
cost. The collector does not replace native clocks, reset an original, cache a
check, suppress an error, skip I/O or change any five-second guard. Leaf spans
still finish before terminal native checks. Diagnostic clocks and output can
perturb elapsed time; no measured saving or complete serving margin follows
from enabling them. Bootstrap counts/costs do not transfer to Current.

For one isolated browser query, first retain private Controller and App stderr
with their actual process incarnations and note the last Current sequence after
startup and sign-in. In the authenticated same-origin browser, GET
`/api/oauthcalendar.inspect` once with no input or query string. The admitted
canary's `InspectIntent` handler has no provider effects and returns only its
declared connection and purpose. Do not reload `/docs`, fetch the schema, poll
health, or run other product actions inside that observation interval. Retain
the browser status/body and wall elapsed time privately, then collect the
subsequent Controller records from the same original. Count these whole Current
records and sum their sixteen exclusive ns rows once per record; inclusive
physical rows overlap and are never added. Report any refusal or missing/capped
interval rather than inferring a complete count. This is an observed isolated
interval, not an invocation-ID join: unrelated concurrent native work would
invalidate per-query attribution. Caller issuer spans are not remote RPC counts.

When the finite App response driver is included, join the App's private
`day2-native-response-delivery` record from that same isolated interval. Its own
sequence, attempts/entries, actual socket/Pending polls, written/postchecked
bytes and elapsed DATA cover delivery only, not handler scopes. Browser wall
latency, whole Current totals and response-driver elapsed time are different
measurements and must not be added. Completion is local transport completion,
not human exposure, Calendar qualification or a connected product account.

### Initial Current authentication: immediate checked-stage handoff

`begin_current_app` performs its full physical check and immediately passes the
same borrowed Controller stage to `AuthenticatedReads::acquire`. It returns the
physical owner and retained reader together. The private one-use handoff gives
authentication only the lexical stage borrow; neither the borrow nor a checked
token can escape to a caller or be saved across intervening I/O. No clock is
constructed or reset by this handoff. Authentication keeps its own fresh stage,
identity, purpose, original-clock and refusal checks around real provider I/O.

Previously, `serve_app_current` read/cloned binding DATA and used
`physical.controller_stage()` as the ProviderAcquire argument immediately after
`begin_current_app` completed the same full check. With no intervening work I/O,
wait, effect or ownership transfer, that second full composite check was a pure
duplicate, not another S1 boundary. The fixed handoff removes only that repeat.
The general stage getter and every later read, peer, acknowledgement and release
boundary retain their checks. Binding DATA is now read after authentication;
it remains historical request selection, not current permission.

The Current v2 profile keeps its fourth inclusive physical row, ProviderStage,
to compare against the prior diagnostic baseline. This closed acquisition no
longer enters that row. Authentication now runs inside the initial physical
composition, so its residual local work is in row 14; nested SHA, HTTP and other
named leaves retain their own exclusive attribution. A zero ProviderStage count
is not proof that the required checks or the complete serving operation passed.
The controlled handoff regressions cover one full check, the same stage and
original interval, later-boundary refusal, and error/unwind ownership. Actual
Linux/provider qualification and measured canary savings remain separate.

### Current prefix duplicate audit

The native25 whole-Current capture started eighteen App executable scans,
totalling 1.681 seconds (93.4 ms per scan on average). The source path through
the first composite check accounts for those eighteen: three in peer preparation,
thirteen in peer acceptance, and two in the final composite peer check. Role
acquisition scans the Controller itself; its cost is separate. Within acceptance,
two scans capture newly received Hello/Ack senders and the others reobserve the
retained/current sender sets. This is a source attribution of that prefix, not
evidence that every future request has the same counts or per-scan cost.

| Call site / repeat | S1 boundary decision | Expected gross saving |
| --- | --- | --- |
| `owner::begin_stage`: self capture, issuer exchange, final stage check | Keep: nonce/grant receive and role-bind signing intervene; self identity, namespaces and the final original clock stay fresh. | None from deleting a repeat. |
| `RetainedPeer::start_phase` / `prepare_current`: three retained-App checks | Keep: idle packet receive, Ready signing, send and their postchecks intervene. | None. |
| `PendingPhysicalFilePhase::acquire_durable` (formerly `acquire`) / `check_current_durability`'s first file check | Clear duplicate in both fixed Controller callers. Fuse acquisition and durability before publishing the physical phase; retain durability's pre/post checks around real provider/block reads. | One file check: roughly 6 ms as a proxy from native25's 5.9 ms FinalFile span; not an isolated measurement here. |
| `CurrentPhysicalFilePhase::check_current_durability`: surrounding file checks | Keep: authenticated provider reads, sysfs/proc reads and block preads intervene. | None. |
| `receive_storage` / `Peer::authenticate`: capture and publication observation | Keep: the kernel sender is received, bound to a signed grant and published as a new peer. Removing that scan requires a different closed constructor, not deleting a check. | None claimed. |
| `Peer::accept_message`: full sender check, `Message::verify`, full sender check | Clear duplicate: verification is bounded public-key/DATA work, with no signing, I/O, wait, effect or outgoing owner publication. Retain the incoming handles first, valid/original-budget gates, signature validation and one final full check of every sender handle. | One App scan for the Controller's prefix Ack: about 93 ms using native25's average. Further accepted App messages can save one each; count them in a matched capture. |
| `RetainedPeer::check_resources` followed by `Peer::check` in a current phase | Keep: these validate different old/current native handle sets and different grant/interval obligations. A joint observation could be a later separately qualified optimization; one set cannot simply be omitted. | None from deletion. |
| `accept_current`'s final peer check followed by the composite peer check | Keep: the intervening composite durability operation performs provider and block/profile I/O. The post-durability peer must be current again. | None. |
| Composite durability's final file check followed by the composite's last file check | Keep: peer executable/proc/namespace and pidfd observation I/O intervenes. The final file/path/clock observation must follow that peer work. | None. |
| `MessageProcess::check_same_actor`: byte scan followed by namespace/final-path/pidfd guards | Keep: one scan already joins every held/current/final descriptor. The later guards detect replacement, namespace change, death and expiry; they are not another byte scan. | None. |

The message-acceptance fix verifies the signed DATA before its one full native
observation; it never reuses a prior successful observation. Invalid signatures
and native refusal remain terminal. Its regression uses the production ordering
helper with signed DATA and controlled observations; a separate AST guard binds
that ordering to the actual native caller and rejects restoring the earlier
full check. Neither test supplies a native owner or claims kernel qualification.
The physical-factory repeat is removed by `acquire_durable`: the unexposed new
phase goes through the same precheck/durability/postcheck sequence used by later
durability checks, then returns to its fixed Controller caller. The first check
serves acquisition and pre-I/O admission once; provider/block reads retain their
postcheck, and errors refuse before owner drop. Regressions require two file
checks and one observation, with no publication on precheck, I/O or postcheck
failure. A separate AST regression inspects the native factory and both fixed
Controller callers, and rejects reintroducing either an earlier acquisition
check or an immediate caller durability check. These source controls supplement
the controlled sequencing tests; neither substitutes for Linux conformance.
Neither path creates a clock or returns a checked token.
Native26 on the diagnostic baseline confirms eighteen App scans: 1.629099 s,
or 90.5 ms per scan. Its whole Current attempt took 5.001639 s: issuer transport
was 1.332492 s, provider HTTP 1.316678 s, other packet waiting 0.416010 s and
self-acquisition SHA 0.057897 s. Other was only 2.417 microseconds: over 99.99%
was attributed to named leaves. App scans were the largest single leaf, about
32.6% of elapsed time, while issuer and provider work were also substantial.

The profile joins the following same-selection/incarnation App-serving refusal.
Its repeated ProviderStage entry lasted 79.545 ms and failed in durability;
the initial authentication body was not reached. The FinalFile sample was
5.828 ms. These update the provisional removed-work proxies to roughly 90.5 ms
per redundant Ack scan and roughly 5.8 ms for the file check. The source split
of scans by prefix step remains an inference: native26 exported no separate
peer-accept timing envelope. It completed no App Runtime/consumer or Shell
serving result. Neither removal was in that measured binary, so no saving or
five-second fit is established. Native27 and later evidence must likewise be
joined to its actual source, operation scope and outcome; later serving work
can add scans beyond this prefix.

#### Provider requests and round multiplicity

The native26 ProviderHttp leaf counts entered HTTP scopes, including the metadata
token call; it does not establish that every request reached the server or
completed. Its 25 entries are **not five storage rounds**. Before the first
storage round, `ProviderReader::acquire` performs six profiled calls: metadata
source token, project, cluster, Controller service account, token mint and epoch
database. The Kubernetes credential projection is a local file read. These are
provider-reader authentication, separate from the issuer transport bucket and
from the later serving caller's `AuthenticatedReads::acquire`.

Each `ProviderReader::observe_provider_inner` storage round requests exactly
claim, volume, node, disk and instance, in that order. `ProviderReader::check`,
`NativeVolumeResources::check_current` and a plain physical-file `check` retain
local role/profile/FD/path/mount/clock observations; they do not start this HTTP
round. The failed native26 prefix has the following source ordering:

| Round and call site | Entered storage HTTP scopes in native26 | Boundary decision |
| --- | --- | --- |
| Fresh physical volume: `NativeVolumeContinuity::finish_begin` -> `observe_provider` | 5 | Keep: join the selected current attachment under the new actual Controller stage before returning the current volume owner. |
| Initial file durability: `begin_current_app` -> file `check_current_durability` -> `NativeVolumeResources::check_durability_profile` | 5 | Keep: mount/block/directory/file acquisition and observation I/O followed the first round. Rejoin the provider before accepting the live ext4/journal contract and entering the peer exchange. In #270 this operation is inside `acquire_durable`, before physical publication. |
| First composite: `begin_current_app` -> phase `check` -> durability | 5 | Keep: Hello/Ack receive, Offer/Ready signing and send, and new-peer acceptance intervene. The provider attachment must be fresh again after that handshake. |
| Immediate ProviderAcquire argument: `serve_app_current` -> `physical.controller_stage` -> phase `check` -> durability | 4 of an intended 5 | Remove in #268: the preceding full composite just completed; only bounded binding DATA selection/clone intervened. This repeated durability attempt failed before the peer and final-file steps. |

The three earlier rounds returned successfully before the first composite's
peer/final-file checks completed. Their fifteen HTTP scopes plus the six setup
calls account for 21 entries. The remaining four of the measured 25 therefore
belong to the failed repeated round. This allocation is a source/control-flow
inference joined to the aggregate profile, not a per-route trace or evidence
that all four requests completed. It does not identify the exact failing guard.
The two **marked** durability entries omit the earlier initial file-durability
call: there are three durability invocations here (two returned, one failed),
plus the separate initial volume round.

#268 removes one attempted storage round from this prefix: four observed HTTP
scope entries in native26, or five reads if that round completes. It leaves
three complete storage rounds (15 reads) and the six setup calls before the
serving caller's authentication begins. It does not remove five rounds or the
whole 1.316678-second HTTP bucket. The failed repeated composite was only
79.545 ms inclusive; that is the baseline duplicate's envelope, not measured net
saving. Newly reachable authentication/serving I/O can increase a later whole
Current request count. No round duration can be obtained by dividing the HTTP
bucket by five, and inclusive durability time must not be added to its nested
exclusive HTTP time.

The same native26 prefix accounts for all eighteen App scans: three preparation,
thirteen peer acceptance and two first-composite scans. The failed repeated
round reached no peer check, so #268 removes no *observed* App scan from that
failed capture; a completed duplicate composite would also rescan both retained
and current peer sets. #269 removes one prefix Ack scan (eighteen to seventeen
at the same frontier); #270 removes a local file check and no provider round
or App scan. These counts describe that prefix, not a complete later serving
operation. Original intervals, permanent refusal and every real boundary remain.

Native27 used #268's runtime change, without #269 or #270. Its independently
joined ordinary App-serving refusal took 5.001278 seconds, versus native26's
5.001639 seconds. It entered 21 provider HTTP scopes (1.214255 s), matching
six setup calls and three completed storage rounds before the composite peer
check. It started seventeen App scans (1.619518 s), with namespaces 0.151016 s,
issuer transport 1.301037 s across four transport spans (two sends and two
receives in one issuer exchange), and packet waiting 0.582002 s.
App scans remained the largest named exclusive leaf, about 32.4% of elapsed time.

The marked physical rows were one completed durability check (325.382 ms),
one failed peer check (80.593 ms), and zero FinalFile/ProviderStage entries.
This failure was in the **first** composite, before the removed ProviderAcquire
argument check and before authentication's stage handoff ran. The 17 versus 18
scan count reflects that different failure frontier, not #269, which was absent.
Likewise, 21 versus 25 HTTP entries must not be presented as measured request
savings from #268: a run failing at this earlier frontier never reaches the old
duplicate either. The profile gives no exact inner failure cause. All six
bootstrap operations and activation completed, but neither failed Current prefix
establishes serving completion, net saving or five-second fitness. Root captured
the original records and closed its node window before this audit update; no
new probe, timeout change or issuer work is part of the update.

#### Later serving observation and settlement boundaries

Native26/27 refused before the first Controller epoch read. The following are
source findings for a later successful frontier, not measured request savings.
One browser operation can cause several Current operations; these counts are
per fixed native Controller operation, not per browser invocation.

After the first epoch read, both `serve_app_current` and `serve_shell_current`
called `physical.check()` immediately before
`reads.check_observation(physical.controller_stage()?, ...)`. The stage getter
itself performs the same complete physical check. No work I/O, wait, signing,
effect or owner transfer intervened. Remove the separate first call, keeping
the getter's full check immediately before observation consumption. This saves
one composite: five storage metadata reads and two App scan attempts in the App
path, or five reads and one retained-App scan in the Shell path. Each actual
read and subsequent observation validation keeps its own original-clock and
native guards. The caller regressions inspect both native methods, reject a
restored duplicate and require each observation's full checked getter.

The earlier native26 completed composite cost about 543 ms inclusive
(durability 330.405 ms, peer 206.899 ms, final file 5.828 ms). That is only a
proxy for the removed operation shape, not a measured later-read duration or
net saving. The roughly 90.5-ms App scan mean is likewise not a guarantee.

| Later call site | Audit decision | Removed work if consolidated |
| --- | --- | --- |
| First post-read `physical.check` then observation argument's full stage getter, App and Shell | Removed in this child; keep the getter's whole check before native observation validation. | One composite per fixed native operation, as counted above. |
| Observation validation followed by physical admission | Keep a full check after validation: `RetainedEpochReads::check_observation` samples through real self-process/FD and stage observations. A preceding physical check cannot cover that intervening I/O. | No deletion of the required post-I/O boundary. |
| App's last explicit `physical.check`, pure `snapshot_digest`, then `finish_app_known`'s entry check | Removed in the settlement child. The digest is bounded public DATA and the closed finisher keeps its full entry check before release work. | One composite. |
| `announce_app_known` postcheck then immediately `await_app_consumed` entry check | Removed by the closed `announce_and_await_app_consumed` operation. One middle full check serves post-send and pre-wait; pre-announcement and post-wait full checks remain. | One composite. |
| Acknowledgement postcheck then next epoch-read stage getter | Removed in the fixed acknowledgement/read child. The closed phase operation performs the post-wait full check once and directly calls the same retained reader through its checked file stage. Reader checks and later physical post-read validation remain. | One composite. |
| Terminal composite's last file check then explicit durability's first file check | Local file-check fusion candidate. Keep the later provider round: peer executable/proc/namespace observations separated it from the prior durability round. | One local file check; no provider round or App scan. |
| App scope physical checks around `reads.check_observation` in `CurrentAppServingPhase::check` | Keep: real self-process/FD/stage I/O intervenes. The physical App file/peer must be observed again afterward. | None from deleting a repeat. |

The settlement child replaces the two announcement/acknowledgement methods in
place; no old entry point or checked token remains. Its native operation is
full check, signed announcement/send, full check, acknowledgement wait, full
check. The middle check covers both adjacent boundaries without returning a
permission to a caller. Final observation validation still performs actual
native I/O; the App's terminal admission now happens once at the closed
finisher's first statement after bounded snapshot-DATA hashing. Its release,
peer completion and file completion checks are unchanged. Native-source
regressions require the operation order, reject an extra or missing check,
require the finisher's first check, and bind the actual Controller caller.
The observation-caller controls are updated for that consumed terminal owner.

Together these two settlement removals eliminate two complete composites per
completed App Current operation: ten metadata reads and four App scans. The
preceding first-observation fix removes one more composite in that App path.
Those are structural counts at a later frontier not reached by native26/27;
no measured net saving, action completion or five-second fit is claimed.

The acknowledgement/read child extends the same closed operation through the
fixed next epoch read. Its full post-acknowledgement check now serves the
immediate pre-read boundary, with no intervening work or stage publication.
The actual retained reader still checks exact selection and names, original
clock, process and owner before and after transport. Its failure also refuses
the physical phase; the caller's later full observation-admission checks remain.
This saves one additional composite per completed App Current operation: five
metadata reads and two App scan groups. These later-frontier counts remain
structural, with no native26/27 net saving or successful completion claim.

No later candidate changes the frozen #268/#269 sources selected for native28.
A temporary canary measurement ceiling, authentication limits and issuer work
are owned separately; no such limit or purpose changes are part of these fixes.

Bootstrap reads its counter and control slot in one bounded Controller-owned
read-write transaction, consumed by the slot commit. The post-commit and App
paired reads request a token-free strong snapshot. Both decoded observations
retain the same spent original budget. Complete requested-document, token and
global nondecreasing read-time checks precede the existing strict codecs;
discovery discards both values and rereads the whole pair. Every actual batch,
commit and attempted cleanup retains its native transport guards. Durable known
May still precedes the separate counter send. Normal reserve/settle require
three RPCs and dispatch four, excluding discovery/reconciliation. These are
protocol counts, not native timings. No deadline or byte ceiling increases,
ambiguous write retry or positive authority cache is introduced. The separate
provider lock deadline still applies; fewer exchanges do not establish a
complete native action or timing margin.

The Controller's first App-serving release or refusal can include a `serving`
diagnostic for the actual `current_app_serving` call. It covers role acquisition
and the unchanged physical, peer and provider calls. Current serving and
authentication remain capped at five seconds. No record is written while the
operation's role/physical/provider borrows remain live.

`caller_elapsed_us` measures the complete caller with an independent diagnostic
continuous clock, starting before role acquisition. `original_last_checked_us`
copies the SAME original acquisition's last successful shared sample, including
samples made by narrowed views. It survives unwind as read-only DATA. It is not
the failed guard's timestamp, current validity or remaining budget; it is absent
when role acquisition never returned its actual stage. Missing, rewound or
overflowed metric clocks are inconclusive and cannot change the native result.
The closed `failure.step` identifies the innermost annotated call and
`failure.category` uses the existing allowlist, without private error text or
provider payloads. A labelled call may contain several unchanged inner checks;
its label alone does not identify an internal statement or establish a cause.

Rows use `[operation_code, count, inclusive_total_us]`. Nested rows must not be
added together. The fixed serving codes are:

| Code | Call |
| --- | --- |
| 0 | Current role acquisition |
| 1 | Physical/peer phase construction |
| 2 | Pending physical phase |
| 3 | App peer preparation |
| 4 | Actual physical acquisition |
| 5 | Durability check |
| 6 | Accept current App peer |
| 7 | Constructed physical phase check |
| 8 | App request binding |
| 9 | Provider authentication and retention |
| 10 | Exact counter selectors |
| 11 | Counter read before announcement |
| 12 | Validate initial counter snapshot |
| 13 | Physical check before announcement |
| 14 | Provider observation check before announcement |
| 15 | Announce known |
| 16 | Await App acknowledgement |
| 17 | Counter read after acknowledgement |
| 18 | Validate final counter snapshot |
| 19 | Final provider observation check |
| 20 | Final physical check |
| 21 | Historical snapshot digest |
| 22 | Release and complete actual physical/peer phase |
| 23 | Whole serving operation, excluding role acquisition |

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
`scope: "storage_bootstrap"`, nominal `purpose_limit_us: 60000000`, `last_step`,
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
| 59 | bootstrap_writer_exchange |
| 60, 61 | bootstrap_snapshot, bootstrap_snapshot_after |

Codes 60 and 61 time the complete paired counter/slot observations. Earlier
single-observation code meanings remain unchanged; this source emits paired
timings instead of codes 36, 37, 49 and 50. The failure boundaries are
`bootstrap_snapshot_before` and `bootstrap_snapshot_after`.

Rows remain inclusive: provider and authentication timings nest inside outer
file/durability/writer phases, and Firestore calls nest inside counter/slot or
mutation phases. Do not add nested durations to their parents.
The `bootstrap_writer_sample` row counts calls to the full port observation,
including acquisition; it excludes decoding-only clock observations. The
`bootstrap_writer_exchange` row measures each complete budgeted HTTP envelope,
including its full pre/postguards, one attempted request and budget checks.
These are different observation boundaries; changing their call counts alone
does not establish a native performance improvement.
`elapsed_us` covers the whole caller action from immediately before role acquisition until
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

## Finite App response delivery measurements

A fully prepared App response with an exact body length at most 64 KiB uses one
actual App serving scope for all socket writes, flushes, shutdown and final
local HTTP completion. The same enrolled stage, signed grant, original clocks,
peer and authenticated reads remain owned across Pending and partial progress.
Each actual socket poll still performs fresh counter/physical/original checks
before and afterwards. Pending never marks the scope Known or releases its
peer. Only actual connection completion can request the independent final
strong post-read, native postchecks and peer acknowledgement/release.

Body preparation preserves headers and trailers and retains at most 64 frames,
64 KiB of body bytes and 64 KiB of trailer names/values. These checks bound what
this layer retains, not allocations already performed by a body producer.
Unknown-length/live, larger and Shell responses keep their existing scope composition;
this App-only change does not silently remove their guards or extend a stage
into the thirty-second HTTP connection lifetime. A retained response that
exhausts its original five-second or any shorter deadline refuses permanently.
A deferred producer with a bounded exact length completes before the actual
owner is leased. During delivery the same App's native registry entry is busy;
other consumers fail closed rather than borrow that response's grant. This can
affect concurrent requests and background work and needs native qualification.

The private `day2-native-response-delivery ` prefix carries
`finite_app_response_delivery_v1` DATA: one process-local sequence, completed or
refused outcome, scope attempts/entries, actual socket and Pending polls, raw
written bytes and postchecked written bytes. Actual successful byte counts are
charged even when the following guard refuses; a lost or malformed completion
publication cannot mark the Sink complete or restore a usable original.

`elapsed_us` is a checked `controlled_monotonic_data` stopwatch covering the inline
driver, including readiness/acquisition, Pending waits and final checks. It is
NOT admission's original native clock and cannot demonstrate a five-second fit.
It uses OAuth's existing clock port: the OS monotonic clock in production and
the selected scripted clock in simulation; a changed clock domain yields null.
Headers, body contents, URLs, tokens, certificates and process handles are not
exported. Records are at most 768 bytes and capped at 4,096 per process. Missing
records or null/overflowed counts are missing evidence, not zero work.

Collect the original App process's private stderr around an isolated user action.
For a completed eligible response, attempts and entries should both be one;
compare its actual poll count and elapsed time against the prior per-poll scope
composition. Handler/credential/read scopes outside delivery and Shell scopes
remain separate. A list query's two handler scopes are not folded into its one
delivery scope. Local protocol-model counts do not qualify native exchange cost;
that requires the joined native run. These records prove neither browser receipt
nor human acknowledgement, continued readiness, or a durable product connection.
