# Native enrollment AppArmor loader

This separate root loads the provisioner/issuer profile on the dedicated Ubuntu
x86 GKE Standard pool. The instance supplies its namespace, exact pool and
protected enrollment label, exact selected client executable paths, immutable
loader image and Kubernetes connection.
It creates only a namespace, immutable policy ConfigMap and pool-scoped
DaemonSet. Keep its independent backend and values outside automatic apply.

The profile source is
[`day2-native-enrollment`](../native-enrollment-pool/apparmor/day2-native-enrollment.tftpl).
Use this required container selection on both provisioner and issuer:

```yaml
securityContext:
  appArmorProfile:
    type: Localhost
    localhostProfile: day2-native-enrollment
  capabilities:
    drop: [ALL]
    add: [SYS_PTRACE, CHOWN]
  allowPrivilegeEscalation: false
```

Those processes also need the dedicated placement, hostPID and the separately
reviewed issuer/runtime/projection mounts. App and Shell retain RuntimeDefault,
non-root users and dropped capabilities. The profile does not enroll a process.
Check every enrolled binary's complete lifecycle under the selected profile
before production use.

## Policy boundary

The instance supplies one to three exact selected native client paths under
`/usr/local/bin`, validated without wildcards, whitespace or policy syntax.
The profile allows read observations of those executable paths and proc
task/namespace/start/clock metadata. `ptrace (read)` is limited to the trusted
host, default container and same-role peer labels. It denies trace/control,
process memory/environment and unrelated files. It grants no blanket file rule,
mount or administration capability. The required issuer binary can execute
itself for its private child; containerd and client code are read-only.
Fixed configuration, issuer/storage directories, public TLS roots, projected
Kubernetes identity and network socket classes support the existing S1 adapters.
Provider endpoints and current authority remain enforced by those adapters.

AppArmor cannot express the native policy's dynamic selected-process membership.
These path/peer-class permissions also cover observation metadata in those
classes before S1's retained pidfd/code/container checks refuse an unselected
process. They are not a role grant or hostile-code containment.

On the qualified GKE `6.8.0-1055-gke` kernel, namespace-object opens are mediated
as the exact path `/`; the exact root read rule is required for them. It also
permits listing root-directory metadata, with no descendant file permission.
This behavior was diagnosed from the actual audit records. Qualification must
be repeated after a kernel/runtime/profile change.

## Loader and lifecycle

The loader uses the selected node's parser and matching x86 dynamic libraries
from a read-only `/usr` mount. It installs no packages and writes no node file
or parser cache. The single init process has only MAC_ADMIN and a writable
AppArmor securityfs mount. It is an explicit policy administrator in the node's
trusted boundary and runs RuntimeDefault; no Unconfined workload is needed. It has no
hostPID, host networking, runtime socket, workload token or IAM grant.
The effective Pod scheduling request is 10m CPU and 32 MiB memory (the larger
of init and steady requests). Include this in the already tight pool budget.

The persistent readiness process is UID0, RuntimeDefault, capability-free,
and mounts the AppArmor filesystem read-only. The kernel policy-list interface
requires root visibility even though its file mode is world-readable; a
capability-free root reader was tested independently. It requires the exact profile to
be loaded in enforce mode. ConfigMap content changes update the Pod template
and reload the policy on every selected node. A reboot/replacement starts a new
loader Pod. Require one desired/Ready loader on this single-node pool before
starting the native participants; a missing Localhost profile refuses startup.
The parser emits a cache-interface warning on the qualified node even with
cache use disabled. Successful loading, enforce-mode readback, actual required
observations and forbidden-path denial were checked separately.

Deleting this stack does not unload an active kernel profile. Stop its consumers
before an explicit removal or node retirement. Loading a different profile
requires fresh qualification and enrollment of the disposable canary.

Official references: [Kubernetes Localhost profiles and node loading](https://kubernetes.io/docs/tutorials/security/apparmor/),
[AppArmor proc/ptrace mediation](https://gitlab.com/apparmor/apparmor/-/wikis/TechnicalDoc_Proc_and_ptrace).
