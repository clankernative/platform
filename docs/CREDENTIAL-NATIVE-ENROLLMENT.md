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
`EpochStore`, root public key/version, provisioner/issuer executable digests and
the explicit runtime/node selections. Shared `native_role` selections are the
single source of role, workload, container, image, native code and profile.
Unknown fields refuse. Configuration must not be writable by group or others.
These inputs are DATA; validating them grants no enrollment.

The provisioner loads the matching Ed25519 PKCS#8 operator root from the
root-owned regular `/run/secrets/day2-native-enrollment-root.pk8`, with no group
or other permissions. Root and issuer are trusted privileged native processes;
this arrangement does not claim OS isolation of the root secret from a hostile
privileged issuer. The Rust key owner exposes signatures and a public key only.
The issuer never receives the root private key through the protocol. App and
Shell remain unprivileged with all capabilities dropped. Their issuer receipt
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

The issuer joins the retained process to one running container task init using
the fixed containerd socket and read-only version, Tasks.List/Get,
Containers.Get and CRI Version/ContainerStatus calls. Lists over 128 tasks or
messages over one MiB refuse. Authenticated Google cluster and Kubernetes reads
then join exact namespace, KSA, Pod, owner lineage, image/restart and node/boot
selections. Labels alone do not enroll a process. Connection-level peer pidfd is
used only for the fixed trusted, non-forwarding containerd endpoint, with its
actual selected executable and common-node checks. No existing epoch is read.

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
