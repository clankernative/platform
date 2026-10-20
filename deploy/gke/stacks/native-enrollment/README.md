# Native enrollment issuer

Deploys the fixed `day2-native-enrollment` provisioner and its owned issuer child
on one explicitly selected node of the native pool. It uses the already loaded
`day2-native-enrollment` AppArmor profile, root UID, dropped capabilities except
`SYS_PTRACE` and `CHOWN`, and a read-only root filesystem. App and Shell receive
neither capability, the runtime socket nor the KMS root grant.

Inputs are one immutable runtime image, the bounded public `EnrollmentPolicy`,
pool/profile and exact operator Kubernetes context. The policy ConfigMap is
immutable and mounted read-only at `/etc/day2/native-enrollment.json`. The native
entrypoint validates its complete typed policy and actual retained process/code
observations; Terraform's input checks do not grant enrollment. Select all
actual workload, namespace and KSA UIDs before starting clients.

The fixed KSA is `day2-native-enrollment/provisioner`, matching the separately
approved KMS root principal. Instance-owned IAM must grant the selected KMS
version's metadata/public-key/signing operations, and separately the selected
project/cluster/GSA metadata reads. This root creates no Google IAM or resource.
Kubernetes RBAC grants `get` only, bounded to the selected namespace, account,
workload and node metadata. Pod/ReplicaSet names are dynamic; the issuer checks
their exact retained task, Pod UID and controlling workload lineage.

`ops/NativeEnrollment.roc` orders start, current-child/storage checks and bounded
waits. The Rust birth capability retains the actual child, pidfds, directories
and original acquisition; the workflow receives none of them. The fixed runner
and its source/toolchain/executable digest metadata must match the image. An
issuer death, recipe failure or unexpected completion terminates that generation.
Abandoned socket state refuses. Recreate a disposable installation's state after
stopping its actual owner; never adopt an old issuer or relax native checks.

Build the runtime target of `deploy/gke/images/native-enrollment/Dockerfile` on native Linux
amd64, retaining the exact source and published image digest. The image includes
`day2-native-enrollment-qualify ROLE` for finite source-bound qualification.
Only `app_host`, `security_shell` and `epoch_controller` are accepted; no caller
PID, policy path, certificate, endpoint or key can be supplied. Select this
disposable executable's actual digest, image and dedicated workload/KSA UIDs in
the qualification policy. It must be the container task init, with hostPID,
UID/GID 10001, RuntimeDefault and all capabilities dropped. Mount the policy and
issuer parent directory read-only. It checks real enrollment, current stages,
original-clock continuity, and permanent refusal after a wrong-role check.

Its receipt is historical supplier test evidence. It establishes neither the
real App/Shell executor lifecycle nor human authentication, a first holder,
storage/P3, writer permission or OAuth success. Production role binaries and
their exact policy still require their own qualification before activation.

Use an instance-owned backend and reviewed values. Keep this root separate from
the root-key and AppArmor loader state; those remain owned by their infra worker.
