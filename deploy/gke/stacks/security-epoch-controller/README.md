# Native initial-only epoch Controller

This optional root creates one dormant-or-active Deployment and, only upon activation, its public
metadata ConfigMap. Use the existing enrollment namespace, Controller KSA/GSA,
Calendar disk and dedicated native node. It creates no IAM, identity, secret,
database, disk or node. The privileged Controller and selected node/provider are
accepted TCB; this is not hostile-code containment.

The image must be the qualified artifact-bearing Calendar child image containing
`day2-epoch-controller`. The command is fixed to that binary, instance and app.
It enrolls on its final OS thread, exclusively prepares the original image,
performs authenticated first-holder/P3 and six-step create/activate, and retains
all original owners while serving fresh App or Shell scopes. Health appears only
after activation and listener creation; health is lifecycle DATA, not a current
role/provider/serving proof. The Shell receives no App database identity.

Keep `activate=false` until Root has registered/read the actual Deployment UID
and selected that UID, exact images/native code, public enrollment profile,
original clock/runtime, and immutable volume/node metadata. This registration
starts no placeholder executor or native-input ConfigMap. It needs no invented
workload UID, native-node CSI mount path or fabricated bootstrap profile. Supply
only `app`, `namespace` and the qualified digest-pinned `image` (plus Kubernetes
connection settings) for registration. Leave `bootstrap_alias`, `instance_json`,
`enrollment_json`, `storage_json`, `host_state_path` and `node_profile` omitted.
The dormant Pod template has no native-input annotation, native node selection,
toleration, volume, volume mount or projected credentials. Only after registration can the
operator bind the actual workload UID into the complete native inputs. Native admission still independently refuses a
foreign UID or incomplete profile. Metadata equality and mock plans do not
qualify any native ownership. Final activation/apply is separately approved.

Activation requires every native input above. `host_state_path` must then be the
operator-observed existing CSI global mount of the
SAME App disk on the selected node. The App must see that same volume at `/state`
in addition to any prerequisite-only installation mount. Never infer a native
mount witness from the PVC name or copy an ordinary `.state` database into the
initial file. The provisioner must already own `/run/day2-native-enrollment` and
its private storage child; hostPath uses Directory, never DirectoryOrCreate.

The Controller observes `/etc/day2/native-enrollment.json` and
`/etc/day2-native/storage.json` through regular read-only subPath mounts. Standard
Kubernetes API/CA and explicit selected TokenReview-audience tokens are projected
read-only. Private keys are never ConfigMap inputs. App and Shell remain separate
unprivileged workloads. Current S1 requires hostPID=true for their initial PID
namespace identity as well: UID/GID10001, RuntimeDefault, dropALL, immutable
subPath policy and read-only enrollment socket mounts. They receive no
Controller GSA, device, containerd, KMS or ptrace grant. The prerequisite-only
profile remains separate and gains no native attachments.

No reset/adoption/recovery path exists. An uncertain operation stops the process;
a Kubernetes restart encounters existing originals and refuses. Do not clear the
permanent slots, unlink sockets, delete originals, change profile deadlines or
refresh role permits to make a restart succeed. Disposable qualification state
must be replaced as an explicitly owned fresh installation. Earlier failures
and their evidence remain historical. Resource requests are unmeasured starting
bounds, not a capacity qualification.

The activation apply returns the desired workload change without waiting for
rollout: actual first-holder activation needs the separately deployed App. Once
the actual fixed listener exists, its idle readiness is DATA only. The
Controller holds no live role stage while waiting for App startup; it consumes
the original listener into a fresh same-owner initial-file phase only after a
pending connection. No offer, P3 or activation is inferred from that readiness.
The original five-second exchange budget is unchanged.

Activation requires `disk_device_group_id`, the operator-observed owning group
of the selected block device on the actual native node (integer 1..2147483647).
Record this selection and the default `Merge` group policy in the retained
operator static runtime/TCB profile. The current Calendar node was observed with
root:disk, mode0660, GID6; this is an instance selection, not a GKE-wide default.
The activated Controller declares only this supplemental group; registration
must omit the input and declares no supplemental group. Primary UID/GID10001
remain. No `fsGroup`, init-container, device chmod/chown or volume
ownership repair is introduced; App and Shell roots receive no change.
[Supplemental groups](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
apply to processes, unlike volume ownership handling through `fsGroup`.

The pinned Kubernetes provider's typed Deployment cannot express
`supplementalGroupsPolicy`. This stack retains the same Deployment resource and
uses Kubernetes' default `Merge` policy, which can add group memberships from the
image. Before activation, inspect `/etc/passwd` and `/etc/group` in the exact
pinned image, and retain the running Pod's actual process groups. The current
Calendar selection expects GID6 and primary GID10001; any additional image group
must be explicitly accepted in the operator's trusted Controller profile.
Registration's empty declaration is not proof of an empty process group set.

Disk-group DAC is not a read-only device permission: mode0660 allows group writes
as well, potentially to other exposed devices with that group. The accepted
privileged Controller remains trusted; its fixed storage adapter opens the
selected block device read-only. No hostile-Controller containment is claimed.
S1's process/code/birth/namespace/workload checks do not compare supplemental
groups, and this deployment change weakens no native check. Qualify actual
process groups and device access on the selected node; mock plans verify only
the declaration. Final apply and native/P3 qualification remain operator-owned.

The activated Controller also mounts a pod-local memory `emptyDir`, limited to
64Mi, at `/tmp`. Artifact admission copies its verified worker executable into a
private temporary file before starting the worker, as App and Shell admission do.
The root filesystem remains read-only; scratch is neither the selected state
volume nor a host directory, and dormant registration declares no volume or
mount. Its memory use counts against the Controller's existing memory limit.
The operator must qualify writing and executing the admitted worker in the real
Pod; a mock plan is not that evidence. This supplies the missing scratch path;
it does not establish the exact errno of an earlier `image_admission/io` refusal
or authorize retrying, adopting or resetting a refused original storage owner.
