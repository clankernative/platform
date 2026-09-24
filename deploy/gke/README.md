# Company internal tools on GKE

These public OpenTofu roots create a dedicated Standard GKE cluster, then one
IAP-protected edge and single-replica SQLite workload per app. All company inputs
come from a separate private instance repository; start with the
[synthetic template](../../examples/instance/README.md).

| Root | Ownership |
| --- | --- |
| [cluster](stacks/cluster/main.tf) | Dedicated VPC, private nodes, NAT, GKE Dataplane V2, node identity, Artifact Registry |
| [app-edge](stacks/app-edge/main.tf) | Namespace, service account, retained disk, quotas, Service, IAP BackendConfig, certificate, DNS, Ingress, network policy and contract |
| [day2-app](stacks/day2-app/main.tf) | Instance ConfigMap and one-replica StatefulSet |
| [qualification-runner](stacks/qualification-runner/main.tf) | Optional x86_64 native Docker VM, off by default, private IP and IAP SSH |

The cluster example is zonal and uses fixed non-overlapping private ranges in a
new dedicated VPC. It is a reference deployment, not a multi-zone HA service.
Review cost, ranges, node sizing and organizational policies before applying.
Provider schemas and mocked plans are tested; **this reference stack has not yet
been exercised end to end in a fresh cloud project**. Qualification below is a
required deployment step, not a claim supplied by the source tests.

## Prepare the private project and identity

1. Use a dedicated Google Cloud project with billing enabled, in the company's
   organization, and a Google Workspace domain. An organization administrator
   creates the project and grants the provisioning operator scoped permissions
   for Service Usage, Compute networking, GKE, Artifact Registry, DNS, service
   accounts, project IAM and IAP policy. Do not give these roles to app pods.
2. Install OpenTofu 1.11.5, gcloud, kubectl and the GKE gcloud authentication plugin.
   Run `gcloud auth login` and `gcloud auth application-default login` as the
   provisioning operator. CI should use workload identity federation with a
   dedicated provisioning identity. Do not create or commit service-account keys.
3. Create a private GCS bucket for OpenTofu state in that project, enable uniform
   bucket-level access, public-access prevention and object versioning. Grant only
   the provisioning identity bucket-scoped object access. State contains private
   configuration. Keep backend configuration and all tfvars in the private repo.
4. Create a public Cloud DNS managed zone for the app subdomain and delegate it
   at the parent zone. Put its name and real app domain in private edge tfvars.
5. Configure Google Auth Platform branding/audience for the organization's IAP
   use. This stack uses the Google-managed OAuth client available with GKE
   1.29.4-gke.1043000 and later. It requires no OAuth client secret in Terraform.
   Review [Google's IAP setup](https://docs.cloud.google.com/iap/docs/enabling-kubernetes-howto)
   and [BackendConfig options](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/ingress-configuration).
   Grant explicit user/group IAP access; day2 separately checks the hosted domain
   and its own authority policy. An IAP group grant does not grant app operations.

## Apply order

Run from the platform root. The examples use absolute private paths because
`-chdir` changes OpenTofu's path base. Use a different backend prefix for each
cluster, each app edge and each app workload. Never reuse a saved plan across roots.

```console
tofu -chdir=deploy/gke/stacks/cluster init -lockfile=readonly -backend-config=/private/instance/backend/cluster.hcl
tofu -chdir=deploy/gke/stacks/cluster plan -var-file=/private/instance/cluster.tfvars -out=/private/instance/cluster.tfplan
tofu -chdir=deploy/gke/stacks/cluster apply /private/instance/cluster.tfplan
gcloud container clusters get-credentials CLUSTER --zone ZONE --project PROJECT
```

The Kubernetes API permits only `admin_cidrs`. Use your actual operator egress
address; the template's TEST-NET address intentionally cannot work. Nodes have
no public addresses and use NAT for external HTTPS. The node pool uses Ubuntu,
cgroup v2 and an explicit `pod_pids_limit` (1024 by default). Verify the actual
kernel with the probe before deploying. Do not substitute COS or Autopilot and
assume containment is equivalent.

Initialize, plan and apply `app-edge` using the same three commands with that
root's own backend and tfvars. The live GKE API must exist before planning its
BackendConfig and ManagedCertificate resources. Initially leave
`backend_service_name` empty. This creates the edge but writes an empty audience;
`day2-app` rejects it until bootstrap is complete.

```console
kubectl -n APP_NAMESPACE get ingress app -o jsonpath='{.metadata.annotations.ingress\.kubernetes\.io/backends}'
gcloud compute backend-services describe BACKEND_NAME --global --project PROJECT
```

Select the backend corresponding to this app's Service/port (never the controller's
default backend). Confirm IAP is enabled. Set `backend_service_name` privately and
plan/apply `app-edge` again. It reads the backend's numeric ID, grants IAP access
and publishes the exact `/projects/NUMBER/global/backendServices/ID` audience.
Wait for the managed certificate to become Active and DNS to resolve. Initial
provisioning may take tens of minutes; inspect Ingress events for controller errors.
The reference disables HTTP immediately; if a GKE version requires a staged TLS
bootstrap, resolve certificate provisioning before deploying an app, and leave
HTTP disabled in the final plan.

The network policy allows only GFE health/proxy ranges to port 8080, kube-dns, and
public IPv4 HTTPS egress (including IAP's public signing keys). It excludes private
and metadata ranges. Kubernetes NetworkPolicy cannot express an FQDN allowlist;
companies needing narrower external egress must supply a controlled proxy. No
pod service account token or cloud IAM role is granted to the runtime.

## Build, qualify and deploy

Follow [native Linux qualification](../linux-sqlite/README.md) on a real engine of
the target architecture. `xtask qualify-linux` uses public Reports and row-authority
fixtures; those receipts qualify those artifacts and the platform, **not a private
app**. Build and verify each private app with the pinned Linux tooling, retain its
artifact-bound acceptance evidence privately, and exercise its operations and
backup/restore on the deployment kernel before admitting it.

Push the exact qualified runtime image to the private Artifact Registry and record
its digest. Use [the app Dockerfile](images/app/Dockerfile) to bake a write-protected
artifact into that runtime digest, then push and record the app image digest.
Never publish company app artifacts as platform release assets. Platform and native
library notices are retained in the runtime image at `/usr/share/doc/`.

Before deploying, render [the probe Job](k8s/landlock-probe-job.yaml) in the private
instance repo. Substitute only its documented `${DAY2_PROBE_*}` placeholders,
including the exact runtime image, namespace, resources and process bounds.
Run it on the target node pool with `kubectl apply -f PRIVATE_PROBE_FILE`, inspect
its logs and require both sandbox qualification and cgroup preflight to pass.
Landlock ABI 3, seccomp, cgroup v2 and private cgroup namespaces are mandatory.
The reference cannot promise every current GKE kernel supplies them.

Fill workload tfvars with the image digest, artifact ID, hosted domain, initial
principals and the **complete authority policy for that artifact**. The template
intentionally has an empty policy and is refused until filled. Match the node
pool's actual PID bound; a declared value is not a substitute for checking it.
Initialize, plan and apply `day2-app` with its separate backend. Confirm rollout,
readiness, authenticated access, denial for an unauthorized account, app operation
authority and rejection of unsigned direct requests. Retain this evidence privately.

## Updates, rollback and data recovery

Keep platform, app source, artifacts, provider locks and image digests versioned
in private deployment records. Review plans before apply; a changed image or
instance configuration rolls the pod. App authority is seeded only once, so
policy changes require explicit activation rather than a ConfigMap edit alone.

Before schema changes, quiesce writes and scheduled/external work and use day2's
backup procedure from [the Linux guide](../linux-sqlite/README.md). Export backups
to restricted storage outside the cluster; exercise restore in a separate private
environment and verify properties before declaring the backup usable. A disk
snapshot alone does not prove cross-provider consistency.

For tooling against the PVC, scale the StatefulSet to zero and wait for termination
before attaching a trusted maintenance pod with the tooling image. Never run two
servers or maintenance writers against the same state. Remove maintenance pods
before restoring the one-replica workload. The runtime image intentionally lacks
operator tools. Backup/restore Jobs are operator-owned, not automatically scheduled
by this reference stack.

To roll back code, plan the prior qualified image and configuration. After a schema
migration, first prove backward compatibility or restore the matching backup;
never point an old artifact at incompatible state. Node upgrades require rerunning
the probe and a representative application acceptance campaign. Namespace/PVC
`prevent_destroy`, Retain storage and cluster deletion protection guard accidents;
removing them is an explicit decommissioning change after verified backups.

## The rendered instance.json

The JSON matches `crates/day2/src/artifact.rs` (`Instance`, `AppBinding`,
`Edge`, `IdentityProvider`) and `crates/day2-capabilities/src/runtime.rs`.
Every struct denies unknown fields.

```json
{
  "installation": "<installation>", "environment": "<environment>",
  "identity": { "scheme": "google_iap", "hosted_domain": "<hosted_domain>" },
  "apps": { "<app_id>": {
    "artifact": "artifacts/<artifact_id>",
    "readers": [...], "writers": [...], "authority": {...},
    "runtime": { "kind": "linux_sqlite_single_v1", "resources": {
      "memory_mib": M, "cpu_millis": C, "process_limit": P,
      "process_limit_enforced_by": "pod", "http_concurrency": H, "shutdown_seconds": S } },
    "edge": { "origin": "<edge_origin>", "iap_audience": "<contract IAP_JWT_AUDIENCE>" } } }
}
```

Several fields are fixed or seeded once:

- `installation`, `environment` and the app key are fixed after the first
  start.
- Readers, writers and authority are copied into the app's database
  on the first start only. Later changes need explicit activation (`day2
  activate`).
- Platform audit pages and APIs are available only to the enabled authority
  policy's `admins` (app owners). There is no separate audit-access variable.
- The root refuses an authority with no operations.

## How the pod satisfies day2-serve

`day2-serve` checks its own environment before it serves (`deployment.rs`
`kernel_guards`). The pod is shaped to pass each check:

| day2-serve requires | The pod |
| --- | --- |
| `/proc/self/cgroup` is exactly `0::/` | Private cgroup namespace. This is containerd's default with cgroup v2 on GKE. |
| `memory.max` ≤ `memory_mib` MiB | `limits.memory = <memory_mib>Mi`. Requests equal limits. |
| `cpu.max` quota/period ≤ `cpu_millis` | `limits.cpu = <cpu_millis>m`. The default 100 ms CFS period gives `<cpu_millis*100> 100000`. |
| `pids.max` ≤ `process_limit`, **or** any value when the profile says `process_limit_enforced_by: "pod"` | Kubernetes cannot bound a container's processes, only a pod's (kubelet `podPidsLimit`, on the pod cgroup the container cannot see). The container's own value is `max` or whatever the runtime wrote (containerd 2 on COS writes a node-derived one, such as `629145`), and is not the bound. The root renders `"pod"`. It requires the declared `pod_pids_limit` to be **≤ `process_limit`**, so the real bound is at least as tight as the admitted profile. The node pool must be configured with that `podPidsLimit`; the root cannot observe it. |
| Instance file is a regular file on a read-only mount | ConfigMap mounted with `subPath`, read-only. The pod template carries its sha256, so an edit rolls the pod. |
| `artifacts/` read-only, with nothing writable under it | Baked into the image (`images/app`). The read-only root filesystem covers it. |
| `.state` writable, owned by the server | PVC at `/srv/day2/.state`. A root init container with only `CAP_CHOWN` sets `10001:10001` on every start. `day2-serve` runs `chmod 0700` on it, so it must own it; there is no `fsGroup`. |
| `/tmp` writable and executable | 64Mi memory `emptyDir`. The supervisor copies worker executables there. |
| One server per state | `replicas = 1` in a StatefulSet, which never overlaps pods, plus day2's lock on `.state/<app>.serve.lock`. |
| Sandbox qualifies at start (Landlock ABI 3 + seccomp) | Seccomp `RuntimeDefault`. Whether the node kernel qualifies is what `k8s/landlock-probe-job.yaml` finds out. |

Pod and container settings:

- non-root 10001:10001;
- `readOnlyRootFilesystem`;
- drop ALL capabilities;
- `allowPrivilegeEscalation: false`;
- no service account token;
- readiness `/health/ready` and liveness `/health/live` on port 8080. Neither
  needs an IAP assertion.

`day2-serve` prints `{"mode":"edge",...}` once it is serving. It exits with
`day2-serve refused or stopped: …` when a guard fails.


## Infrastructure checks

From each root run `tofu init -backend=false -lockfile=readonly`, `tofu validate`
and `tofu test`. Tests use mocked providers and never provision cloud resources.
The qualification VM's existing `startup.sh` installs native host prerequisites;
platform operational recipes remain in Roc. There is no claim that cloud bootstrap
is shell-free. Public CI does not hold cloud credentials or deploy infrastructure.
