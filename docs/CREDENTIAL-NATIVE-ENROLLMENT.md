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
