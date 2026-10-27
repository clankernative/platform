# Native runtime identity observations

The credential bootstrap path needs a current native runtime identity before it can authorize an initial epoch write. Kubernetes response data does not establish which Pod contains the calling process.

These primitives and bounded response codecs are used by the implemented native
enrollment/runtime producer. They cannot independently construct a role or a
bootstrap execution owner.

## Retained native observation

Full executable/runtime admission and later handle checks have distinct roles
under the selected [S1 connection/request contract](CREDENTIAL-NATIVE-ENROLLMENT.md#admitted-connections-and-fresh-requests).
This contract is being ported; it is not a new native qualification result.
Main separates full `MessageProcess` capture from later retained-descriptor
checks (PR 284). PR 286 also retains the role's self snapshot and actual
connection-clock anchors across bounded stages; `begin_stage` still exchanges
with the issuer. The remaining packet/caller work under **Separate full process
admission from retained-handle checks** and **Borrow fresh requests from the
admitted enrolled connection** is Credential's pending plan work.
Provider/transport reuse remains G1's pending counter row;
see the [implementation status](CREDENTIAL-NATIVE-EVIDENCE.md#selected-contract-implementation-status).
Executable bytes and selected runtime/provider joins are admitted before an
owner escapes. Later request checks retain the actual process/task/proc and
namespace identity observations below without another executable scan or cloud
identity/attachment round. The trusted services maintain content/physical
integrity while current authority, counters, clock and refusal remain checked.

`NativeNamespaceObservation` retains the actual proc root, kernel self-process and self-task directories, task stat/status files, time namespace offsets file, and six namespace descriptors. Acquisition starts under the existing original Linux BOOTTIME deadline. Every fixed open is bracketed by checks against that same acquisition.

Linux exposes `timens_offsets` in the process (TGID) directory, not the per-thread directory. The observation reads it through the retained fixed `/proc/self` directory. Before and after each offsets read, the process time and time-for-children namespace descriptors must both match the current thread's retained time namespace. This equality does not prove membership in the node's initial namespace.

Revalidation checks the actual process and Rust thread, original acquisition domain, freshly opened fixed `/proc/self` and `/proc/thread-self` paths, exact proc device/inode/mount ID, full task identity, retained and freshly opened namespace identities, the process/thread time namespace join, and complete unchanged zero time offsets. Missing procfs/nsfs support, mount ID, namespace, bounds or current facts refuses the observation and acquisition permanently.

The owning handle cannot clone, serialize, send between threads or be reconstructed from its serializable data. Consuming it into `NamespaceFacts` discards the descriptors and produces historical data.

Mappings are read completely within explicit byte, entry and path bounds. Mapping addresses, file identity and permissions are data; they do not certify image membership or immutable executed memory.

## Selected container data

The shared selection contract is
`day2_capabilities::security_epoch::bootstrap`. `InitialBootstrapPolicy` requires
separate `app`, `shell` and `controller` workloads. Every `GkeRoleSelection`
requires `container: ContainerSelection { name, image }`; the image is an
immutable digest. No separate caller-supplied container can replace it at the
response codec. All three roles require distinct workload, KSA and GSA identities.
The names may repeat across different namespaces; immutable UIDs must differ.

`BootstrapRuntimeProfile` separately requires these executable and artifact pins:

| Selection | Exact selected bytes |
| --- | --- |
| `app_host_code` | Native AppHost executable, observed through its retained executable descriptor |
| `security_shell_code` | Native SecurityShell executable, observed through its retained executable descriptor |
| `controller_code` | Native epoch-controller executable, observed through its retained executable descriptor |
| `app_artifact` | Roc application artifact admitted by the AppHost |

An artifact digest or image digest cannot substitute for a native executable
digest. AppHost and SecurityShell may use the same native executable bytes, but
still have separate selected workloads, containers and enrolled roles. Matching
code alone cannot identify which role the process currently owns.

`InitialBootstrapPolicy::native_role(NativeRole)` returns a borrowed
`NativeRoleSelection { role, workload, code, profile }`. The only supported role
labels are `AppHost` / `app_host`, `SecurityShell` / `security_shell` and
`EpochController` / `epoch_controller`. `profile` is the exact
`runtime_profile.manifest` digest under `gke_linux_trusted_native_v1`.
Enrollment must join that profile and role to the selected workload/container
and executable; it must not retain independent caller overrides for those
selections. The enrollment root, issuer birth, runtime and node selections are
additional required inputs of the native enrollment producer.

All these selections and the borrowed view are DATA. They do not prove
executable admission, enrollment, namespace/clock identity or a current role.
The implemented AppHost and SecurityShell producers require their actual native
owners and refuse when those suppliers cannot complete. Selections alone cannot
replace them. Disposable installations are regenerated and redeployed.

The response codec joins the selected container to the exact TokenReview Pod UID and existing role/lifecycle checks. It requires the supported containerd identifier and both configured image and current image status to match the selected immutable SHA256 image digest. A running container may be unready because readiness can depend on bootstrap completion.

These joins remain response data. They cannot mint a role capability or reconstruct a native observation.

## Required runtime join

The fixed native enrollment producer implements the issuer/runtime join to the
actual process incarnation, container/sandbox/Pod, image and node initial time
namespace. Projected Pod UID, cgroup text, Kubernetes status, zero offsets,
historical receipts or a peer PID alone do not establish that join. Each selected
deployment still needs its real kernel/issuer/runtime qualification. Qualifying
the new composed connection/request path remains Root's pending **Qualify the
admitted-connection path on the real node** row; existing producers are not absent
factories, and earlier qualification does not qualify the new port.

## Connection creator PID visibility

Connection-time credential data records numeric PID visibility explicitly. A positive kernel PID becomes `Visible` with a checked nonzero value; zero becomes `NotVisible`. Negative PIDs and unavailable user/group values refuse. A peer outside the receiver's PID namespace may have no visible numeric PID.

The observation still requires the actual socket, successfully acquired original `SO_PEERPIDFD`, live retained process handle, unchanged original acquisition, current process/thread and sticky refusal checks. It never reopens or substitutes a numeric PID. Serialized visibility data cannot recreate that observation.

This data shape does not qualify a node-to-Pod endpoint, per-message sender, image, runtime, role or storage authority. The safe per-message receiver, two-sided issuer/requester joins and actual cross-namespace deployment qualification remain separate requirements.
