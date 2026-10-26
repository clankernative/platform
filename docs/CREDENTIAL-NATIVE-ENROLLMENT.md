# Native process enrollment

## Terminal refusal in the App and Controller entrypoints

The normal container commands stay `day2-serve INSTANCE APP --edge` and
`day2-epoch-controller INSTANCE APP`. After a native refusal the actual
executor/resources unwind before a fixed, ownerless wait of at most 300 seconds.
The App retains and joins its actual HTTP owner threads, including TLS cleanup,
and permanently closes further owner launches before entering the wait. An
HTTP result alone is not evidence of thread exit. Ordinary argument failures
and non-native App errors keep their immediate failure behavior.

The refusal remains a failure. The wait performs no enrollment, provider call,
storage open, original capture, retry or clock/grant renewal. Its stop listeners
survive teardown of the former Tokio readiness runtime; SIGTERM and SIGINT stop
the wait promptly. Refusal messages remain redacted. No wrapper process, new
native actor/workload profile, auth bound or probe timeout is introduced.

An operator must disable startup/liveness probes for this single-original
qualification and stop all roles on the first refusal, using a shutdown budget
strictly below the 300-second hold. Readiness probes may remain. A 1200-second
whole-run observation cap is not the post-refusal shutdown budget. Expiry of the
hold exits with failure and a Deployment can restart it; this is no hard OS
scheduling bound or once-across-restarts guarantee during control-plane outage
or reboot. Capture actual Pod/container histories and verify resource closure.

## Literal platform health is not Current authority

The App's fixed `/health/live` and `/health/ready` responses contain only an
empty body and the existing method/admission status. A private, immutable host
response classification identifies that literal producer before native scope
resolution. The HTTP owner does not acquire Current for those probes; readiness
reports admission only, not native permission, a current counter or OAuth success.

Application responses cannot obtain the classification from a URL, status,
header, body or extension. Converting a literal response to an ordinary response
discards the classification. All ordinary App responses still resolve their real
scope and retain native acquisition, original-clock, transport and finalization
guards. Shell/receiver behavior, probe timeouts, header/connection bounds and
authentication bounds are unchanged. A cancelled literal probe holds no native
response lease to renew or refuse.

`day2-native-enrollment` implements the operator provisioner and its private
issuer child. It supplies `AppHost`, `SecurityShell` and `EpochController` stages.
A role stage does not supply human authentication, storage, an epoch, a first
holder, a provider credential or writer permission.

## Selected profile

The user selected connection admission followed by fresh request checks on
26 October 2026. This is the sole target S1 contract. Its implementation and
native qualification are in progress; this specification is not a deployment
or readiness result. Replace the former per-boundary full revalidation in
place, without a flag, fallback or second serving profile.

The first profile is one exact authority scope on a trusted common Linux node.
The operator must select and qualify the node, boot, kernel, architecture,
initial PID/user/time namespaces, containerd/runc service, native executables,
images and trusted init/launcher/debug processes. All enrolled native hosts must
share the node PID/user/time domain. Container mount/cgroup namespaces can differ.
The implementation supports Linux amd64 and arm64 and probes `SO_PASSPIDFD` on
the actual socket. Unsupported kernels and profiles refuse.

This is a trusted native profile. Processes able to impersonate ancillary
credentials, inspect another native process's private memory, replace its code
or control the runtime belong to the operator's TCB. Measuring an executable and
retaining a pidfd do not establish hostile-code containment or hardware attestation.
The source change does not approve a deployment, install a key, change hostPID,
create infrastructure or qualify the live canary.

### Admitted connections and fresh requests

A native connection is admitted once using the actual enrolled processes,
issuer/root and role bindings, selected executable bytes and runtime/node
identity, namespaces, original clocks, channel and received process handles.
Storage admission additionally establishes the actual file/mount/device,
selected provider attachment/durability profile, first holder, activated
lineage and permitted writer. No usable owner escapes before every required
admission operation and its postchecks complete.

Successful admission installs a private, nonserializable connection owner
retaining the actual resources on its owning process and thread. The admitted
connection is the real enrollment/peer channel and process/role incarnation,
including the App–Controller or Shell–Controller channel. An HTTP socket, SQL
connection, response identity or Runtime lookup cannot manufacture that owner.
Each newly created native peer channel requires full admission.

The trusted enrolled services and node maintain executable and physical-storage
integrity for the connection's lifetime. S1 no longer promises a complete
executable scan, cloud attachment round or physical/durability-profile proof at
every later boundary. Admission transcripts and selected digests are historical
DATA, not later request permission or constructors of a native owner.

Each request borrows the same live connection owner, with its own closed
purpose, operation binding and interval captured before entropy or I/O. Check
current user/app/operation authority and fresh coherent external counters bound
to the exact activated lineage, writer, request and provider version. A saved
snapshot is not another read. Protected writes, signing and transfer retain
fresh applicable authority/counter checks and the required postchecks.

At I/O, SQL, signing, acceptance, transfer and completion boundaries, the
request still checks its actual owned resources:

- The same enrolled/executor owner, role, scope, app/artifact, policy/store
  selection, connection incarnation, process and OS thread remain bound.
- Every relevant retained pidfd is live; the original channel has not closed.
  Actual authenticated packet senders are joined to the admitted process and
  retained proc/task and namespace anchors. Socket inheritance/transfer does
  not permit substituting a connection PID for a packet's SCM_PIDFD.
- Required fixed named file, directory, proc and namespace entries still join
  their retained descriptors by device/inode, mount identity, required modes
  and ownership. The executable handle/path identity is checked without
  reading its contents. Observable exec, namespace, remount or named-file
  replacement refuses. Metadata is not a claim of unchanged contents.
- BOOTTIME samples use the original domain and shared latest-observation
  state. Enforce the earliest request, human-original, credential and other
  applicable ceilings. Rewind, expiry, changed binding and refusal remain
  terminal; no wall clock or maximum of stale independent samples substitutes.
- Callback arming, single-writer/restore fencing, known/excluded/unknown
  settlement and commit/rollback/close/postcheck barriers remain mandatory.
  Actual database durability, byte bounds and provider errors still apply.

Checks borrow resources; they do not return a reusable positive witness. Scalar
IDs, certificates, database/path lookups and serialized receipts cannot create,
replace or retarget that borrow. Full admission still rejects wrong executable
bytes, runtime, role, sender, namespace, file, attachment, writer or clock.

A failed required check, uncertain protected effect, drop or cancellation
permanently refuses the affected request/original and the actual connection or
continuation owners holding that uncertainty. Catching an error, time passing,
a new stage or historical success cannot clear refusal. Pure known exclusions
before arming retain their existing narrower settlement semantics. No reconnect,
old-file adoption or second first-holder attempt repairs an abandoned owner.

The accepted reduction is detection of content or physical drift that retained
handle/identity checks cannot observe, including transient drift restored
between checks. Such drift could expose credentials or admit wrong writes.
Node/runtime administrators were already trusted; ongoing integrity enforcement
also rests with the admitted services. This is not hostile-code containment,
hardware attestation or instantaneous IAM/configuration revocation.

Admission consumes its own bounded work; its signed acquisition does not become
a connection-long permission. Only the actual live owner can lend a fresh
request interval. No existing request, grant, human original or effect is
renewed. Ordinary serving stays bounded to five seconds. Authentication spends
at most five seconds of its own work inside the same admission parent and all
shorter caps. This decision enlarges no bootstrap or measurement parent.

Retained provider material belongs to the admitted connection, exact recipient,
selection and actual expiry. New authentication, if required, is a separately
bounded admission operation; it cannot revive a refused owner or extend an
active request. Close/fail closed if it cannot complete within existing bounds.
A historical admission cannot substitute for current authority or a counter.

## Operator inputs and boot

The root-owned regular `/etc/day2/native-enrollment.json` contains an
`EnrollmentPolicy`: the shared `InitialBootstrapPolicy`, its exact selected
`EpochStore`, `root: { version, public_key }`, provisioner/issuer executable digests and
the explicit runtime/node selections. Shared `native_role` selections are the
single source of role, workload, container, image, native code and profile.
Unknown fields refuse. Configuration must not be writable by group or others.
These inputs are DATA; validating them grants no enrollment.

The root is a software-protected Ed25519 key generated inside Cloud KMS.
`root.version` is the complete numeric CryptoKeyVersion resource name;
`root.public_key` pins its canonical base64url public key. There is no private
root file, secret-loader fallback, endpoint override or configurable algorithm.
The provisioner authenticates through the fixed GCP metadata credential source.
Its selected workload identity should receive only version metadata, public-key
read and signing permissions on this dedicated key. App and Shell identities
receive no root-signing grant. The issuer child shares the provisioner's Pod
identity and privileged native trust boundary: KMS IAM does not isolate those
processes or prevent a compromised authorized process from requesting a
signature. KMS IAM alone proves no native role.

After joining its actual retained child, nonce and key possession, the private
birth path calls only the fixed KMS issuer-birth operation. The request signs the
original domain-separated PureEdDSA frame, never a precomputed digest or arbitrary
CSR. The client checks the exact enabled version, SOFTWARE protection, Ed25519
algorithm and public key, both request/response CRCs, and the returned signature.
Metadata authentication, three KMS requests, body reads and final native owner
checks share the original five-second acquisition. Proxies, redirects and
automatic retries are disabled. A failure permanently refuses that acquisition;
it cannot select a local key or extend the deadline. The child/process/namespace
checks surround the signing call and final channel publication.

KMS keeps the root private key; the issuer/client process keys remain local.
Privileged process inspection and compromised authorized provisioners are still
part of the native trust boundary. The separate operator root at
`deploy/gke/stacks/native-enrollment-root` creates the key and exact version;
it grants only the selected provisioner KSA the fixed key-scoped metadata,
public-key and signing permissions.
The software Ed25519 profile still needs actual deployment qualification.
See [KMS signing](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
and [algorithm support](https://docs.cloud.google.com/kms/docs/algorithms).

App and Shell remain unprivileged with all capabilities dropped. Their issuer receipt
retains the real per-message pidfd and requires a fresh signed request/challenge
from the root-enrolled child key. Executable/namespace measurement of the root
issuer belongs to the privileged provisioner and issuer's own current native
checks; clients do not need ptrace access to the issuer. An authenticated birth
certificate alone cannot reconstruct a receipt or current role owner.


The provisioner starts `/usr/local/bin/day2-native-enrollment issuer` itself,
retains its actual `Child`, and passes freshly created private sequence-packet
startup and listener sockets through stdin/stdout. The child generates its own
private key. The original parent nonce, child identity, native code, boot,
namespace joins, key possession and root signature bind one issuer generation.
There is no arbitrary CSR, caller PID or preexisting-socket birth constructor.
The provisioner supervises the retained child; the issuer checks its retained
parent before grants. Restart requires a new birth. Disposable installations
with abandoned socket state must be recreated.

## Current stages and original clocks

Native hosts admit their connection through `/run/day2-native-enrollment/issuer.sock`.
Each admission exchange
uses one original acquisition of at most five seconds, captured before entropy
and I/O. The issuer challenge and signed bind establish key possession. Each
message retains the actual received `SCM_PIDFD`; malformed, truncated, extra-FD
or unsupported ancillary data refuse. `SO_PEERPIDFD` alone cannot identify a
sender after socket inheritance or transfer.

The workspace pins the reviewed sender-pidfd implementation in the
[clankernative/rustix fork](https://github.com/clankernative/rustix/tree/6f3845cfc5b1ac7f490e6fe9641eed720c99f6d0).
It owns and closes all kernel-installed process and rights descriptors even
when ancillary framing or selection validation refuses a packet. Platform host
code uses its safe API; no local dependency override is required.

The provisioner retains the root-owned `0755` parent directory and creates or
checks its fixed `storage` child, owned by UID/GID 10001 with mode `0700`. It
never repairs an existing wrong owner or mode. Descriptor-relative opens refuse
symlinks and mount crossings; the supervisor rechecks the retained child and
named entry. The controller mounts only that child read/write for
`/run/day2-native-enrollment/storage/peer.sock`; App and Shell mount the parent
read-only. The provisioner needs `CAP_CHOWN` for the initial ownership transfer;
it sets the mode before transferring ownership. These directory checks grant no
storage or first-holder permission.

The issuer joins the retained process to one running container task init using
the fixed containerd socket and read-only version, Tasks.List/Get,
Containers.Get and CRI Version/ContainerStatus calls. Lists over 128 tasks or
messages over one MiB refuse. Authenticated Google cluster and Kubernetes reads
then join exact namespace, KSA, Pod, owner lineage, image/restart and node/boot
selections. Labels alone do not enroll a process. Connection-level peer pidfd is
used only for the fixed trusted, non-forwarding containerd endpoint, with its
actual selected executable and common-node checks. No existing epoch is read.
The revision field is required even when a reviewed containerd build reports
an empty string; that explicit value is still compared exactly, together with
the selected version and executable.

`EnrolledProcessRoleOwner` is installed on the final owning OS thread. A fresh
borrowing `EnrolledRoleStage` is a request from that admitted live owner,
retaining its exact identity, selected role and runtime incarnation. Its checks
follow the retained-handle contract above; it does not reacquire executable,
runtime or physical admission. Failed acquisition, required recheck or expiry
permanently refuses the actual affected owner. Lost initial replies cannot
rekey the same process; a full enrollment table refuses rather than evicting.

`EnrolledOriginalClock` captures its first BOOTTIME sample at the actual creator
entry before entropy/I/O and retains original self-task/namespace anchors.
Sampling requires a fresh stage from the same enrollment, role, process and
thread. Its origin is DATA. The consumer must enforce its original human
lifetime and operation binding. Owners, stages and clocks are neither Send,
Sync, Clone nor serializable; certificates cannot recreate them.

`SameEnrolledOwner` captures only continuity from a checked current stage. It
retains a weak reference to that exact native owner and checks a later current
stage against it. Dropping or replacing the owner permanently refuses the
handle. It grants no role, preparation, storage or human permission and never
extends an earlier phase's deadline.

## Verification limits

Focused tests cover signatures/selections, bounded task joins, real inherited
sockets, process exit and packet truncation. The explicit Linux root fixture
also launches a user-10001 client with zero effective capabilities: direct
issuer executable access is denied while root-enrolled pidfd reception succeeds.
Dependency tests exercise ancillary
ownership on both Linux backends. These tests do not qualify the selected live
GKE/runtime profile or turn the existing human/storage refusals into success.
The immutable dependency pin and real operator boot/profile qualification must
be in place before publishing or deploying the supplier.

## Fixed operations and deployment

The provisioner's lifecycle is selected by `ops/NativeEnrollment.roc`: create
the owned child once, check that actual child and storage directory, then wait
250 milliseconds before another current check. Rust retains native ownership
throughout. The checked fixed workflow runner cannot supply a PID, key, CSR or
saved native owner, and a stopped recipe drops the child. The issuer's private
startup path still bypasses no birth, code or current-parent check.

The [native-enrollment deployment root](../deploy/gke/stacks/native-enrollment/README.md)
mounts immutable public policy, uses the selected Localhost AppArmor profile,
and grants only the selected metadata reads. KMS and Google observer IAM are
separate instance-owned grants. Process readiness alone is not native enrollment.

The finite `day2-native-enrollment-qualify` client exercises the actual supplier
with explicitly selected disposable native executable/workload identities. Its
Roc campaign checks current stages, original-clock continuity and permanent
wrong-role refusal. Its receipt is historical test DATA, never a native owner or
production App/Shell lifecycle, human, storage, writer or OAuth permission.

## Controller socket mount reference

The Controller mounts the enrollment parent read-only and its `storage` child
writable. It also requires a second, unoverlaid read-only mount of that SAME
parent at `/run/day2-native-enrollment-reference`. The directory guard uses
`NO_XDEV` through the reference to select the actual original child, then joins
the canonical writable child by native device/inode and exact UID/GID/mode.
Both parents must be read-only; the actual child must be writable. All held and
named identities are rechecked. A missing/foreign reference or different
same-filesystem child refuses; there is no fallback or arbitrary mount exception.
The privileged provisioner retains its separate direct-child `NO_XDEV` path.
These are observed descriptor joins under the existing trusted node/mount TCB,
not atomic mount-table snapshots or containment from that TCB.

### Isolated Linux mount controls

The seven `mounted_controller_*` tests in `storage_socket_directory.rs` are
explicitly ignored unless run with their real Linux mount fixtures. They are
currently operator-only; an existing checked-in verification recipe does not
select them. Ordinary workspace CI must not be reported as their execution.
These controls exercise the filesystem guard, not enrollment, first-holder,
P3, a live Controller or a historical failure's exact inner cause.

Build the actual library test executable from the selected source on Linux:

```sh
bazel run //crates/xtask:xtask -- build-rust-test //crates/day2:unit_lib
```

Set `DAY2_SOCKET_LIB_TEST` to the exact executable path printed by that command, `DAY2_SOCKET_TEST_IMAGE` to
its matching pinned Linux runtime image, and retain their identities and the
current source/manifest-root provenance. Use two fresh local named volumes,
`DAY2_SOCKET_FIXTURE` and `DAY2_SOCKET_FOREIGN`, exclusively for these controls.
For each volume, initialize a root-owned 0755 parent and two distinct private
0700 UID/GID10001 child directories using these explicit fixture commands:

```sh
docker volume create "$DAY2_SOCKET_FIXTURE"
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --mount type=volume,src="$DAY2_SOCKET_FIXTURE",dst=/fixture --entrypoint /usr/bin/install "$DAY2_SOCKET_TEST_IMAGE" -d -m 0755 -o 0 -g 0 /fixture
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --mount type=volume,src="$DAY2_SOCKET_FIXTURE",dst=/fixture --entrypoint /usr/bin/install "$DAY2_SOCKET_TEST_IMAGE" -d -m 0700 -o 10001 -g 10001 /fixture/storage /fixture/foreign
```

Repeat those same setup commands for `DAY2_SOCKET_FOREIGN`. For each row below,
select the named test and apply the listed mount changes to this exact-case
command. The default is the positive layout:

```sh
docker run --rm --network none --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=volume,src="$DAY2_SOCKET_FIXTURE",dst=/run/day2-native-enrollment,readonly \
  --mount type=volume,src="$DAY2_SOCKET_FIXTURE",volume-subpath=storage,dst=/run/day2-native-enrollment/storage \
  --mount type=volume,src="$DAY2_SOCKET_FIXTURE",dst=/run/day2-native-enrollment-reference,readonly \
  --mount type=bind,src="$DAY2_SOCKET_LIB_TEST",dst=/socket-tests,readonly \
  --entrypoint /socket-tests "$DAY2_SOCKET_TEST_IMAGE" \
  --exact "security_epoch::native_enrollment::storage_socket_directory::tests::$DAY2_SOCKET_TEST" --ignored --nocapture
```

Each invocation must report exactly one passed test, zero failures and zero
ignored tests. Preserve each command, fixture mount layout and result separately.

| Layout change | `DAY2_SOCKET_TEST` |
| --- | --- |
| None: exact child RW; both views of parent RO | `mounted_controller_child_joins_strict_read_only_reference` |
| Canonical child `volume-subpath=foreign`, same filesystem and private mode | `mounted_controller_refuses_another_same_filesystem_private_child` |
| Reference source is `DAY2_SOCKET_FOREIGN` | `mounted_controller_refuses_another_reference_parent` |
| Canonical parent lacks `readonly` | `mounted_controller_refuses_a_writable_parent_or_reference` |
| Reference parent lacks `readonly` | `mounted_controller_refuses_a_writable_parent_or_reference` |
| Canonical child also has `readonly` | `mounted_controller_refuses_a_read_only_child_mount` |
| Extra RO bind of `volume-subpath=foreign` at `/run/day2-native-enrollment-reference/storage` | `mounted_controller_keeps_no_xdev_on_the_reference_child` |
| Reference mount omitted and reference path absent in the image | `mounted_controller_has_no_missing_reference_fallback` |

Run the three existing provisioner controls separately with no fixture volumes;
they create their own private temporary directories. Use the same exact-case
command's executable mount, `--user 0:0` and `--cap-drop ALL`. For
`chown_only_provisioner_checks_existing_private_child_without_read_access`, add
only `--cap-add CHOWN`. For
`root_creates_and_retains_exact_controller_socket_directory` and
`root_refuses_unsafe_parent_symlink_and_existing_child_owner`, additionally add
`FOWNER` and `DAC_OVERRIDE` for the tests' deliberate negative owner/mode
mutations. Those mutation-fixture capabilities are separate from the actual
CHOWN-only provisioner control. Remove only these local fixture volumes after
all test containers have closed; retain source/executable/image and log records.

## Historical bounded issuer cost observations

The following measurements describe their captured source before the selected
connection/request port. Their repeated full checks and fresh issuer stages
are historical implementation facts, not requirements of the new contract.

Initial-holder transport setup and authenticated file admission are separate
bounded operations. During App installation, its actual stage closes the
once-only attempt before connecting, checks successful transport completion and
returns only a same-owner socket. That old stage is not retained. The App
consumes the connector before any readiness wait or later acquisition; there is
no reconnect, Unstarted fallback or adoption from a descriptor or metadata.

The Controller closes file continuity with a pending token before readiness
entropy or I/O. Its fresh actual stage accepts the connection and sends a signed
`initial_ready` statement before acquiring provider/file authority. Queued
readiness is only DATA: it prompts the App to acquire a fresh stage whose
original clock starts before its issuer RPC. The App then authenticates the
actual readiness sender, signature, issuer, role and current original deadlines
before sending Hello. Controller provider/file acquisition can run while that
App RPC completes; issuer requests themselves still run serially.

The Controller keeps the same actual stage and narrowed acquisition through
readiness, file acquisition and the whole exchange. Hello echoes its readiness
nonce; Offer must use exactly its readiness statement, original clock and nonce.
The App retains the actual readiness sender handle with the later Offer and
Complete handles. Dropped/failed pending file work remains refused; only the
known successful full phase completion may reopen continuity. Neither the
connector, queued packet nor signed readiness grants file opening, a holder,
P3, a writer or final-consumer authority. The five-second bounds are unchanged.
This rearranges avoidable serialization; actual node latency, reliability and
the earlier live refusal still require measured native qualification.

The Controller's private lifecycle records also include inclusive original
preparation timings. `holder_role` is the later listener stage's actual role
acquisition; `holder_listener` covers its fresh same-owner file phase and socket
bind through the original final check. Both completed and failed outcomes are
cached as DATA after the measured operation returns; no record is emitted while
the file phase is live. Earlier preparation rows do not measure this later
stage. Diagnostic clocks do not supply, reset or extend a native interval, and
missing/rewound/overflowed timings remain null. These rows do not separate each
internal check or prove which individual call consumed the interval.

Every retained initial-image check rereads and compares the complete image. It
uses the same bounded 1 MiB requests as original initialization, with unchanged
native identity/original-clock checks before and after every actual pread and
one last check after the byte comparison. Short reads cause another guarded
read; zero progress or any changed byte refuses continuity. This applies only
to the retained initial image, including its durability and pre-physical
transition checks. App/current physical serving operations keep their separate
64 KiB batch. With a 946176-byte image and full read returns, listener setup's
nine full-image checks make nine preads instead of 135, rereading the same
bytes. That is a source count, not a measured latency or reliability result.

The subsequent first-holder operation also caches separate inclusive
rows: `first_role` acquires its actual fresh Controller stage, `first_file`
begins its current same-owner file phase, `first_ready` covers accept and signed
readiness before file/provider acquisition, and `first_exchange` includes listener
start, the unchanged exchange, durability checks and retained completion.
Successful return or failure unwind precedes each ending measurement; rows are
historical DATA, not renewed permission. A `first_holder` refusal now exports
the fixed innermost annotated `preparation.step` and closed category. Steps
distinguish role/file/start, repeated local checks/projection,
accept/Hello/peer/Offer/confirm/complete/acceptance, durability and retained
completion. Each annotated exchange expression includes its stage-argument
checks. Other unannotated DATA checks within the exchange remain
`first_exchange`; a label does not identify every underlying syscall.
`socket_poll_timeout` identifies a zero-result poll;
`socket_unexpected_events` identifies an unexpected count or event mask without
claiming every such event means a closed peer. `process_exited` identifies only
the existing exact native liveness refusal; `remote_stage_expired` identifies
the existing failed remote signed-stage deadline comparison. Unknown causes are never formatted or emitted. The same
2048-byte record bound, original five-second intervals, call order, protocol,
guards and failure behavior remain; this diagnostic addition fixes no timeout.

The issuer emits private stderr records prefixed with "day2-native-issuer-cost "
for its first sixteen accepted connections through the provisioner's inherited
stderr. Its startup channel and listener remain separate on stdin and stdout;
records never enter either protocol. Each day2_native_issuer_cost_v1
record has a sequence, the fixed limit, an outcome and fixed operation rows.
Later connections disable diagnostic sampling and logging; the normal admission
protocol and enrollment table continue unchanged. A partial/export failure is
terminal and never retries a record or a native operation. A preexisting fatal
native error retains its original cause.

Every row is [operation, [attempts, read_bytes, inclusive_total_us, max_us]].
Only hash rows report bytes: these are counts actually returned by hash reads,
including partial failed attempts, rather than selected length multiplied by
an inferred pass count. Other rows use null for bytes. Missing, rewound or
overflowing measurements remain null, never a synthetic zero. Hash subjects
distinguish issuer self, requester, containerd, and parent checks before and
after serving the request. Counts describe actual complete or partial reads,
including the fresh single-pass peer checks described below. There is no digest
cache, changed clock origin or extended deadline.

Hash timings include the original read/checksum/bounds and clock-check work,
not just checksum CPU time. Identity-body rows include their nested hashes and
end before the existing final pidfd liveness/original-clock guard. Earlier
failures record the failed body and preserve that error. The containerd RPC
group includes the fixed connection and RPC sequence; the Kubernetes group
includes the existing metadata, cluster and Kubernetes joins. Their attempt
counts describe group invocations, not HTTP requests or RPC messages.
Runtime, serve, parent and snapshot scopes are inclusive too: nested rows must
not be added together.

The original connection remains open through the existing post-request parent
check, which still uses its own fresh bounded acquisition. Its parent-after
and hash rows are separate from the grant-producing interval. All temporary
request observations, the channel and both acquisitions unwind before emission.
Long-lived issuer owners stay idle during logging. Parent failures still stop
the issuer generation; a failed client request alone still consumes only its
own connection. Diagnostics never publish error text, URLs, paths, process IDs,
credentials, keys, request nonces or provider payloads.

Elapsed values come from separate diagnostic boot-clock reads and never feed a
native acquisition, signed grant, permission or retry. Their overhead still
spends the original interval. Records do not measure caller work, queue time
before accept or their own log-write delay; logging can perturb the next queued
client. An outcome describes the return of existing calls, not readiness,
reliable completion or proof that an ambiguous send had no effect. Actual issuer
and Controller measurements require source/image/profile-bound deployment by
the operator. The existing read-only one-observation/ownerless-hold procedure and
retained failed originals remain separate evidence.

## Current-operation rendezvous

App bootstrap and App/Shell serving use a bounded untrusted wakeup on their
already retained socket before beginning the client's next request. The wakeup
contains only the channel kind, original exchange digest and next sequence. It
has a closed 256-byte JSON schema and a single nonblocking send; a failed or
partial notification cannot be retried. The Controller also waits for actual
pending DATA before each of its six bootstrap operations.

The Controller closes its original file continuation before readiness I/O. Its
actual admitted role signs a fresh begin-ready request statement. The exact
request stage, narrowed acquisition and nonce remain fixed through the later
exchange; a request does not perform another issuer enrollment. The client's
freshly signed Hello echoes the readiness nonce, and Offer must preserve the
entire readiness statement and request
transcript. A queued wakeup is never a signer, role, file, P3 or consumer proof.
Its strict kernel receive is deliberately discarded as untrusted DATA; the
authenticated Ready, Hello and later messages retain their own actual sender
handles.

App file continuity has separate Ready, Queued, Busy and Refused states. Queued
notification DATA cannot restore an abandoned phase or substitute for the
actual retained peer and fresh request. Only known completion after the required
handle, counter, original and consumer postchecks returns continuity to
Ready. Each current client receives exactly five authenticated messages
(begin-ready, offer, ready, result/known, release); all five actual sender
handles remain checked until final completion.

Initial Shell transport setup also completes separately on its owning
executor. It retains only same-owner connection DATA, and the authenticated
connection must complete full admission before requests can borrow it. Each
request after actual readiness has a distinct bound transcript and original
interval, rather than another full issuer grant.
Neither this setup nor the current-operation wakeup renews an old acquisition,
human original, failed operation or permission. The original five-second stage
limits and all provider/consumer checks remain in force. These are source and
protocol properties; real-node timing and the complete OAuth lifecycle still
require live qualification.

## Executable admission and retained peer handles

The actual issuer baseline on 21 October measured 16 requester hash reads
(334,095,744 bytes, 1,204,417 microseconds) and seven containerd hash reads
(306,038,040 bytes, 1,163,431 microseconds) in the Controller exchange.
The containerd RPC group took 16,695 microseconds and the Kubernetes group
294,956 microseconds; those groups and runtime totals are inclusive and must
not be added to their nested hash rows. This is a particular observed exchange,
not a latency or availability bound.

Full executable admission reads the selected bytes under its original bounded
acquisition before returning an owner. A wrong digest refuses. Bounded reads
and final process, path, descriptor, namespace, liveness and clock joins still
apply to that admission; no configured digest alone proves the observed bytes.

A later identity check can join one to five retained message-process
owners of the same actual process together. Each owner still comes from its
actual received kernel handle; signed process DATA cannot construct one. The
observation requires equal sealed process DATA and joins every held proc root,
process directory, executable and namespace descriptor to fresh native reads.
Every actual pidfd must be live before the reads and at the final guard.
Different actors refuse even when their selected executable bytes match.

An authenticated packet received on an admitted connection retains its actual
kernel process handle and joins it to the admitted actor without another full
executable read. A caller cannot construct a new admitted actor from the packet's
signed DATA or numeric PID. Every retained handle and named executable/proc/
namespace identity is checked again at the required request boundaries. No
hash result is treated as a permission; no positive check token escapes.

Empty, oversized, mixed-actor, replaced-descriptor, dead-peer or clock failures
latch every affected actual owner and acquisition. A later clock or stage cannot
revive them. Diagnostic hash counters report actual admission read attempts,
including partial failures; a warm request must not hide admission work outside
its measured scope.

These joins operate under the selected trusted executable/node contract.
Metadata is not an atomic content version: unchanged metadata cannot prove
unchanged bytes, and transient drift may escape detection after admission.
No lifetime, signed ceiling or native deadline is extended or reset. A source-bound
issuer/Controller rebuild and another real-node observation must establish any
actual performance gain; portable tests alone do not qualify preparation.
Metadata equality and observer access alone cannot install an admitted runtime
owner. Full hashing belongs to genuine runtime/process connection admission;
later checks retain the actual selected handles and binding rather than running
another full scan around each runtime or Kubernetes operation.

The issuer's owner and selected-container projections come from one bounded,
validated Pod body. `runtime_profile::container` returns both DATA values after
the existing Pod lifecycle, namespace, subject, service-account, controlling-owner,
container, image, state and restart checks. The caller no longer repeats the same
Pod validation immediately before invoking that helper. Missing or ambiguous
owners and foreign Pod identity still refuse without a result. This shares only
pure processing of the same captured bytes: Kubernetes requests, actual process
owners, fresh hash/check boundaries and original intervals are unchanged. It is
not a cached workload observation or native permission; no node-latency saving
is established by this parsing-only change.

## Issuer work inside one Current exchange

The Current profile's four issuer-transport spans are two sends and two
receives on one role-enrollment connection: Hello, Nonce, Bind and Grant.
They are not four server acquisitions or four equal-duration RPCs. The Nonce
wait includes policy/self/parent admission and the Hello sender capture. The
Grant wait includes Bind sender capture and signature verification, current
runtime/workload joins, final sender/parent checks, signing and publication.
Caller-side packet work and serial-issuer queueing can also contribute; the
aggregate does not measure remote CPU or each span separately. The issuer's
bounded first-sixteen-connection records may already be exhausted by startup.

Within a successful runtime join, the three containerd executable observations
protect different boundaries: capture of the newly connected fixed socket peer,
after the containerd RPC group, and after authenticated Kubernetes/provider I/O.
All three full reads remain. Requester and parent observations separated by
packet I/O, runtime/provider reads, signatures or publication remain fresh too.
No issuer-lifetime or cross-exchange digest, workload or permission cache is
introduced.

The fixed containerd group reads Version, CRI Version, Tasks.List,
Containers.Get, ContainerStatus and a final Tasks.Get. Tasks.List supplies the
actual unique PID-matched task, already checked for its exact live-init PID,
lowercase 64-byte container ID, running status and empty exec/container-ID field.
An immediate additional initial Tasks.Get checked precisely those same fields
before any use or effect. The selected list row now serves as that initial
observation. The final Get still compares the complete task after container/CRI
reads, refusing missing, dead, replaced or changed tasks. The actual process,
socket, original clock and surrounding kernel/workload guards are unchanged.

This removes one read-only RPC per exchange, seven to six. Loopback protocol
tests check the fixed order, namespace/request bindings, ambiguous/malformed
lists, all final task-field changes and expired originals. They establish
adapter behavior, not a current GKE role or measured node latency. The earlier
16.695ms RPC-group observation is a different source-bound exchange; no share
of the Current profile's issuer wait or historical hash cost is credited as a
saving. A fresh native measurement must establish the actual effect.
