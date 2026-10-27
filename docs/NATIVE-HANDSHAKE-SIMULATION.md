# Native enrollment and peer handshake simulation

The private `native_enrollment::handshake::Transcript` is the shared production
decision reducer for enrollment and the App/Controller storage and
Shell/Controller serving channels. Production adapters feed it historical clock
observations after their actual native checks. The reducer chooses poll versus
syscall retry, enforces packet direction/order and sequence, and permanently
refuses invalid, replaced, rewound or expired observations. Unavailability and
interruption spend the same original interval; they do not advance a packet.

Enrollment remains capped at five seconds, including authentication for an
initial first-holder stage. The initial storage exchange remains capped at ten
seconds. The subsequent storage wire conversation records its explicit checked
stage purpose: `StorageBootstrap` has a temporary sixty-second ceiling per action,
pending the kernel-integrity/Firestore redesign, and ordinary
`CurrentRole` remains capped at five. Serving remains capped at five seconds.
Deadline equality refuses. No request deadline, signature, actual sender,
namespace, socket, file or final consumer boundary is removed. The selected
[connection/request contract](CREDENTIAL-NATIVE-ENROLLMENT.md#admitted-connections-and-fresh-requests)
replaces repeated full executable/physical/provider admission with retained-handle
checks after genuine admission; current authority, counters, clocks and refusal
remain mandatory. Its production port and composed qualification are in progress.

The storage adapter selects this class only after matching the actual signed
stage to the trusted request purpose and checking its purpose-specific native
acquisition. It never selects a class from a scalar duration. Authentication
remains at most five seconds of its own work inside the same admission parent
and all shorter caps; admission does not renew a request.
Metadata observation and initial-first-holder purposes cannot start a subsequent
storage transcript; bootstrap cannot start a serving transcript. Shorter signed
or configured ceilings remain unchanged, including equal one-second ceilings
that retain distinct purpose labels. Read-only metadata retains its separate
ten-second native ceiling.

The native adapters check actual owners before and after I/O as before. A full
send advances only the local transcript. The remote endpoint advances only after
its own receive and postchecks. Initial storage includes the final `Accepted`
message; current storage and serving include `Known`, `Consumed` and `Released`.
Starting another current transcript requires the complete previous transcript
and the exact next sequence. The existing native disposition and operation final
checks still independently control whether that next phase can actually start.

Transcript state is ordinary DATA. A successful simulated transcript cannot
construct an enrolled role, authenticated peer, original clock, prepared file,
holder, writer or OAuth consumer. Issuer birth continues to use its distinct
private startup channel and root/KMS checks.

## Campaign and independent model

The library campaign runs in the existing fast and full verification recipes.
It needs no sockets, cloud resources, secrets or enrolled-owner fixtures:

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::handshake::simulation::
```

Thirty-two seeds for each enrollment/serving family and each ordinary/bootstrap
storage purpose
exercise successful exchanges with interrupted calls, unavailable transport and
delayed readiness. Storage and serving histories continue through two current
exchanges and their acknowledgement/release messages. Bootstrap histories spend
eleven seconds before the first current packet under their original sixty-second
ceiling. A further thirty-two seeds per family/purpose generate adversarial
schedules from reachable prefixes.

Every syscall return in the successful histories is also a fault cut before its
final postcheck. Cuts explore local/peer death, expiry, rewind, native refusal,
clock replacement and premature phase restart. Actual queued sends additionally
exercise loss, duplicate packets and message substitution. Directed controls
cover partial packets, buffered replies after peer death, deadline equality and
the last instant strictly before the deadline. Clock controls also call the
shared reducer directly so simulated native guards cannot mask its decisions.
All forty family/purpose/fault combinations must reach executed refusal. Expiry
cuts must refuse at the immediate postcheck, and waits exceed even the bootstrap
ceiling. Direct controls independently check short purpose ceilings, the last
instant before each deadline, deadline equality, metadata rejection and rejection
of bootstrap for serving. Bootstrap accepts eleven-, thirty-, thirty-one- and
sixty-second ceilings only strictly before expiry and rejects sixty-one- and
120-second ceilings;
ordinary Current and serving keep their five-second limit. These are controlled
DATA observations, not evidence of native completion or the required live margin.

The independent oracle records the accepted prefix of a separately specified
wire conversation and the outstanding call/poll. It does not call the production
message catalog, cursor, deadline helper or transition methods to predict a
decision. Each event compares the result and complete bounded state of both
endpoints, including explicit purpose, pending syscall returns, clocks, liveness/refusal and every
queued packet. Histories replay twice and must match exactly. Limits are 512
events, 64 queued packets per direction and eight MiB per failure bundle;
overflow refuses instead of truncating the compared state.

## Failure evidence and replay

Model or replay divergence writes typed, redacted evidence under
`artifacts/native-handshake-simulation/`. It contains the seed, original and
reduced event history, full observations through divergence and a compiled source
identity covering the reducer, adapter mappings, phase hooks, native clock and
campaign/model sources. Reduction preserves the failure category within a
128-attempt budget. No raw native errors, certificates, process identities,
credentials, response bodies or tokens enter the bundle.

```console
DAY2_NATIVE_HANDSHAKE_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::handshake::simulation::replay_saved_native_handshake_history --exact
```

Replay rejects unsupported versions, oversized histories and a different
compiled source identity. Preserve the original bundle when fixing a failure;
add its reduced semantic history as a fixed regression on the corrected source.

## Composition and limits

The selected connection/request port must additionally compose full admission
with two fresh requests borrowing the same actual owner. Its independent model
must preserve current authority/counters, actual-handle observations, original
request/human clocks and permanent refusal across loss, duplicates, death,
replacement, expiry/rewind, uncertain SQL/provider completion and restore/writer
fencing. Full content/physical revalidation after admission is deliberately no
longer an obligation. The reference histories below do not qualify production
request wiring or real native owners. Wrong full-admission inputs still require
actual refusal tests.

### Admitted-connection reference histories

The test-only `handshake::simulation::connection_request` module specifies the
approved admission-once/fresh-request contract independently of the production
owner implementation. It starts with controlled cold-admission observations,
then exercises two independently bounded requests on the same selected
connection. Request identity, role, purpose, sequence, original clock, fresh
authority/counters, retained-handle observations, SQL arm/open/commit/close and
postcheck ordering, unknown sends and terminal refusal are ordinary model DATA.
They cannot construct a native owner, request, writer or provider permit.

The existing production DATA handshake reducer and its independent wire oracle
still exercise a successful and a refused cold enrollment. Warm request ports
are **not yet connected** to these new histories. The reference cases alone
qualify neither production warm checks nor any Linux handle/provider behavior.
They explicitly accept the new trusted-service assumption about unobserved
post-admission content drift, while retaining observed path/FD/namespace,
peer/issuer death, restart, counter, original-clock and refusal obligations.

The campaign runs automatically in the existing day2 library harness, fast
verification and workspace-day2 shard; no new runner, recipe or target is added.
Its generated receipt lists executed reference case families and seeds and sets
`production_request_wiring_executed` and `real_linux_owner_executed` to false.
Zero full-work attempts in those synthetic histories are not measured production
counter deltas. The actual production owner/counter hooks and composed
consumer comparison are still required after the production ports land.

This join is pending CI's **Compose the independent connection/request failure
campaign** plan row, using Credential's **Borrow fresh requests from the admitted
enrolled connection**, G1's retained storage/transport rows and Product's consumer
row. Root's **Qualify the admitted-connection path on the real node** is separate.
PR 284's retained-process primitives and PR 291's partial work ledger do not
turn these reference histories into production-request or native qualification.
See the [implementation status](CREDENTIAL-NATIVE-EVIDENCE.md#selected-contract-implementation-status).

Histories replay twice with complete bounded reference states. Unexpected
decisions retain the original and deletion-reduced history, both observations
through divergence, source identity and failure category. The limits are 512
events, four MiB per bundle and 128 reduction attempts. Replay rejects another
source, incomplete observations, changed seeds, non-deletion reductions,
unknown/duplicate fields and positional descriptors. Existing evidence is never
overwritten. The workspace-day2 shard retains receipts and failures as
`day2-connection-request-reference-<run>-<attempt>`.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::handshake::simulation::connection_request::
DAY2_CONNECTION_REQUEST_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::handshake::simulation::connection_request::tests::replay_saved_connection_request_history --exact
```

The standalone replay entry does no corpus work when its environment variable
is absent. Separate controls exercise saved-file replay, bounds and malformed
descriptors without relying on that optional entry as coverage.

The [storage lifecycle campaign](STORAGE-LIFECYCLE-SIMULATION.md) composes at the DATA transcript boundary:
actor and original clock domain/interval, protocol purpose, sequence, accepted
message prefix, pending transport observation and permanent refusal. Current
wire messages retain their existing request/transcript digests and semantic
checks; none of those values are native permission. Storage authority, first
holder decisions, files, durability, fencing and final consumer settlement still
belong to their own production owners and models.

These schedules qualify protocol decisions under controlled observations. They
do not simulate SCM_PIDFD, kernel identity, AppArmor, real hashing, KMS, network
performance, provider fidelity or storage durability. Loss/duplication are
adversarial transport observations, not claims that a healthy Unix sequence
packet socket spontaneously drops or duplicates messages. Existing actual Linux
socket/process/exec/confinement conformance tests remain separate and unchanged
in their behavior. A passing portable campaign is not live native qualification
or evidence of timing margin for OAuth startup.

The campaign schedules closed packet classifications, not signed wire bodies.
Signature, nonce/request binding, issuer selection and enrollment rekey/table
checks retain their separate cryptographic DATA and native controls. The
[OAuth consumer campaign](NATIVE-OAUTH-CONSUMER-SIMULATION.md) now joins these
transcript decisions to the storage lifecycle and OAuth consumers under controlled
DATA observations. It does not join signed wire bodies or native owner acquisition
into that simulation; the transcript alone does not establish those guarantees.
