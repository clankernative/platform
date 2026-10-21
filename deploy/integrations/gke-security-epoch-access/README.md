# GKE security-epoch adapter access

An optional, instance-selected IAM/RBAC root for the native storage controller
and the App's read-only epoch adapter. It reuses existing project and GSA
identities. It creates no database, GSA, key, disk, node, namespace or workload.
The Firestore authority root continues to own its separate database roles.

Inputs are explicit scope, immutable project/GSA identities, existing App
KSA/StatefulSet names, a separate controller namespace and the selected disk,
instance, PVC/PV and node names. Names and provider readback are DATA. Nothing
here constructs an enrollment, first holder, P3, active epoch or current writer.

## Grants

| Grant | Recipient and scope |
| --- | --- |
| Project metadata and GKE cluster GET | App/Controller GSAs in the selected project; no list/connect or Viewer role |
| GSA metadata and access-token mint | Each GSA on itself only; no App-to-Controller mint, signing or delegation chain |
| Compute disk/instance GET | Controller GSA on the exact named disk and instance; no project storage role |
| Workload Identity | New controller KSA to the existing controller GSA; existing App binding stays in app-edge |
| KSA/workload/Pod lineage GET | Each KSA in its own namespace; App's exact single-replica Pod, controller's dynamic Pod/ReplicaSet names |
| Namespace GET and TokenReview create | Only App/Controller KSAs; namespace names are explicit |
| PVC/PV/Node GET | Controller KSA only, on the exact selected names |

Project/cluster metadata uses a project binding and can read metadata of other
clusters in that project. Compute access uses resource-level additive members.
Controller Pod/ReplicaSet GETs are namespace-wide because their names are assigned
at rollout; there is no list/watch. TokenReview create cannot be restricted by
resource name. It reads no credential and mints no Kubernetes token; native code
still validates the exact selected audience, identity and current process.

The custom token role includes only
`iam.serviceAccounts.get` and `iam.serviceAccounts.getAccessToken`.
[Google's service-account permission documentation](https://docs.cloud.google.com/iam/docs/service-account-permissions)
explains that access-token minting differs from signing or delegated chains.
The selected Compute bindings use the provider's
[disk IAM member](https://registry.terraform.io/providers/hashicorp/google/6.50.0/docs/resources/compute_disk_iam)
and [instance IAM member](https://registry.terraform.io/providers/hashicorp/google/6.50.0/docs/resources/compute_instance_iam)
resources. These are additive; other grants remain visible for effective-IAM
review. No exclusivity or atomic name/UID-binding guarantee follows from a plan.

## Workload prerequisites

The provisioner stack owns the controller namespace. The App namespace, KSA,
GSA, disk, PVC/PV and node must already exist. The root creates only the fixed
controller KSA, named from the app scope with an `-epoch-controller` suffix.
It does not edit the existing App KSA or its Workload Identity binding.

The controller is a separate trusted native executor. If it is outside the App
namespace, it cannot mount that App PVC by a cross-namespace PVC reference.
Its separately reviewed workload must provide the selected volume's actual
same-node CSI mount at the fixed `/state` path. The native adapter must verify
the provider attachment and retained block/directory/file descriptors; a host
path string is insufficient.

Actual App/Controller workloads must explicitly mount their Kubernetes API token
and CA at the standard paths and a projected subject token at
`/var/run/secrets/day2-native/subject-token`, with the selected TokenReview
audience. Token automount remains false. No default token, credential Secret,
privileged workload or broad namespace exception is installed by this root.

Issuer/provisioner runtime-discovery permissions are separate S1/T1 inputs.
This module does not infer those grants from its KMS role or give the controller
the issuer's containerd/launcher operations.

## Validation and use

The tests mock both providers. Run OpenTofu 1.11.5 with backend disabled for local
format/init/validate/test. The instance supplies its own state prefix and values
before an operator saves a real plan; this root is not automatically added to an
instance's apply workflow.

```sh
tofu fmt -check -recursive deploy/integrations/gke-security-epoch-access
tofu -chdir=deploy/integrations/gke-security-epoch-access init -backend=false -lockfile=readonly
tofu -chdir=deploy/integrations/gke-security-epoch-access validate
tofu -chdir=deploy/integrations/gke-security-epoch-access test
```

Keep the actual controller workload, artifact/config admission, authenticated
creator offer, original-file preparation, first-holder/P3 transition, current
serving and final consumers separate from this resource plan. Applying IAM/RBAC
does not initialize an epoch, recover an abandoned file/socket, qualify the
selected GKE/kernel profile or complete live OAuth.
