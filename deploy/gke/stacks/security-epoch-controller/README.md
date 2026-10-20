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
workload UID or fabricated bootstrap profile. Only after registration can the
operator bind the actual workload UID into the complete native inputs. Native admission still independently refuses a
foreign UID or incomplete profile. Metadata equality and mock plans do not
qualify any native ownership. Final activation/apply is separately approved.

`host_state_path` must be the operator-observed existing CSI global mount of the
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
