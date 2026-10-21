# Native process enrollment

`day2-native-enrollment` implements the operator provisioner and its private
issuer child. It supplies `AppHost`, `SecurityShell` and `EpochController` stages.
A role stage does not supply human authentication, storage, an epoch, a first
holder, a provider credential or writer permission.

## Selected profile

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

Native hosts connect to `/run/day2-native-enrollment/issuer.sock`. Each exchange
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
borrowing `EnrolledRoleStage` rechecks the original issuer, current self/native
observations, operator selections and runtime incarnation. Failed acquisition,
recheck or expiry permanently refuses that owner. Lost initial replies cannot
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
cargo test --locked -p day2 --lib --no-run --message-format=json > socket-test-build.jsonl
jq -r 'select(.reason=="compiler-artifact" and .target.name=="day2" and .profile.test and .executable!=null) | .executable' socket-test-build.jsonl
```

Set `DAY2_SOCKET_LIB_TEST` to that exact executable, `DAY2_SOCKET_TEST_IMAGE` to
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

## Bounded issuer cost observations

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

## Fresh executable joins in current peer checks

The actual issuer baseline on 21 October measured 16 requester hash reads
(334,095,744 bytes, 1,204,417 microseconds) and seven containerd hash reads
(306,038,040 bytes, 1,163,431 microseconds) in the Controller exchange.
The containerd RPC group took 16,695 microseconds and the Kubernetes group
294,956 microseconds; those groups and runtime totals are inclusive and must
not be added to their nested hash rows. This is a particular observed exchange,
not a latency or availability bound.

Each retained peer check now hashes all freshly opened selected executable
bytes once instead of hashing two joined descriptors of the same file. The
initial observation still hashes the selected executable independently. Every
later check also performs a new complete read; there is no digest, path, inode
or cross-stage authorization cache. Diagnostic hash counters still report the
actual read attempts and bytes, including a failing partial read.

Before and after that read, held and current descriptors must agree on device,
inode, regular-file size, modification time and change time. The existing
512 MiB ceiling, 64 KiB bounded reads and original-clock checks remain. After
the remaining process/namespace checks, the caller reopens the actual procfs
executable path and joins all three descriptors to the earlier stamp. The
original pidfd liveness/original-clock check remains the final native guard;
diagnostic sampling finishes before it. Any refusal still latches the peer and
the same acquisition. No role lifetime, signed ceiling or native deadline is
extended or reset.

These joins operate under the existing trusted executable/node profile.
Metadata fields are observations, not an atomic snapshot or immutable content
version. In particular, ctime adds mutation detection without proving that every
arbitrarily timed write has a distinct timestamp. This does not claim strict
behavioral equivalence for hostile concurrent mutation of executable files or
containment from actors that can replace the trusted native code. A source-bound
issuer/Controller rebuild and another real-node observation must establish any
actual performance gain; portable tests alone do not qualify preparation.
