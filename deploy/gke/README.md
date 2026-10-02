# Company internal tools on GKE

These public OpenTofu roots create a dedicated project foundation and Standard
GKE cluster, then one IAP-protected edge and single-replica SQLite workload per
app. They are the whole control plane of an instance: nothing is shared with
another platform's infrastructure code. All company inputs
come from a separate private instance repository; start with the
[synthetic template](../../examples/instance/README.md).

| Root | Ownership |
| --- | --- |
| [project](stacks/project/main.tf) | APIs, the OpenTofu state bucket and its per-prefix IAM, storage audit logs, the DNS provider token's secret |
| [cluster](stacks/cluster/main.tf) | Dedicated VPC, zonal Standard cluster with Workload Identity and Calico network policy, one Ubuntu node pool with a pod PID limit, node identity |
| [tenancy](stacks/tenancy/main.tf) | Retained SQLite storage and snapshot classes, admission policies for app namespaces (including the backup Job service account exception) |
| [app-edge](stacks/app-edge/main.tf) | Per app: namespace, runtime service account, retained disk, quotas, Service, IAP BackendConfig, HTTPS redirect, managed certificate, static IP, Cloudflare DNS, Ingress, network policy, image repository, workload state bucket, GKE backup plan, off-cluster backup bucket with its object-create-only Workload Identity uploader, and the platform contract |
| [security-shell-edge](stacks/security-shell-edge/main.tf) | Per installation: dedicated security namespace, shell service account, named secret access, IAP Service/backend, certificate, DNS, routing, network policy and a shell contract consumed by app deployments |
| [security-shell](stacks/security-shell/main.tf) | Separate stateless shell Deployment and read-only instance ConfigMap, consuming the resolved installation edge and exact selected secret-container contract |
| [day2-app](stacks/day2-app/main.tf) | Instance ConfigMap, one-replica StatefulSet and the hourly off-cluster backup CronJob |
| [qualification-runner](stacks/qualification-runner/main.tf) | Optional x86_64 native Docker VM, off by default, private IP and IAP SSH |
| [gitea-instance-ci](stacks/gitea-instance-ci/main.tf) | Optional plan-on-PR / apply-on-main CI for an instance repository on Gitea |

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
4. The app domain's zone is on Cloudflare. Create an API token scoped to DNS
   edit on that zone, store it in the project's Secret Manager secret the
   project stack creates, and put the zone id and app domain in the private
   edge tfvars. Applies read the token into the process environment only.
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

Apply `project` first, then `cluster`, then `tenancy`, each with its own
backend prefix. The cluster's control-plane endpoint is public and its nodes
have external addresses (no Cloud NAT); making both private is a separate,
planned change. The node pool uses Ubuntu, cgroup v2 and an explicit
`pod_pids_limit` (1024 or more; GKE's minimum). Verify the actual
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
A FrontendConfig redirects HTTP to HTTPS.

The network policy denies everything by default and allows only GFE health/proxy
ranges to port 8080, kube-dns, the GKE metadata server (Workload Identity), and
public IPv4 egress (including IAP's public signing keys); cluster ranges are
excluded. Kubernetes NetworkPolicy cannot express an FQDN allowlist;
companies needing narrower external egress must supply a controlled proxy. No
pod service account token or cloud IAM role is granted to the runtime.

## Installation security origin

The private instance repo selects the shell hostname once, in values for
`security-shell-edge` (for example `config/security-shell.tfvars`). Its required
`domain` input drives DNS, the dedicated GKE certificate, the Ingress host,
`SECURITY_SHELL_ORIGIN` and the reauthentication callback URL. There is no
platform hostname default. A company can use `security.tools.example.com` or
another dedicated hostname under its own domain. DNS stays unproxied so TLS uses
the certificate for that exact hostname.

Initialize and plan this root with its own backend prefix and instance values.
Bootstrap `backend_service_name` empty, then select the backend of
`<security namespace>/security-shell` from the `security-shell` Ingress. A second
apply verifies the Service identity and enabled IAP before publishing its
numeric audience. Until then, the contract's audience is empty and app
deployments refuse to consume it.

After the backend is resolved, an OAuth-enabled app's workload values refer to
the published ConfigMap:

```hcl
security_shell_contract = {
  namespace = "day2-security"
  name      = "security-shell-contract"
}
```

`day2-app` reads this reference during planning and generates the installation's
`security_shell.origin`, `security_shell.iap_audience` and
`oauth_shell_transport.service_account` in `instance.json`.
It rejects an app contract, a malformed or unresolved edge, and reuse of the
app's origin or IAP audience. The hostname is never copied into app source or
per-app tfvars. Use a qualified runtime that supports these instance fields
before enabling this reference on an existing workload.

The root supplies edge infrastructure, a dedicated Google service account,
Kubernetes workload identity binding, and named-secret IAM. Its custom signing
role contains only `iam.serviceAccounts.signJwt` and is bound on that service
account to itself. No service-account key or project-wide signing grant is
created. The Kubernetes service account has token automount disabled and uses
the explicit GKE metadata interface. Egress includes the documented metadata
ports for both standard networking and Dataplane V2; see [Google's network
policy requirements](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy#network_policy_and_workload_identity_federation_for_gke).
A separately
qualified shell workload, selected approval authority, pinned key provider and
Google web OAuth client are still required to serve approvals. Register the
root's `reauth_callback_url` output with that client. Changing the hostname also
requires a new registration qualification before admitting the replacement
instance; successful DNS/TLS provisioning alone does not qualify OAuth.

The shared `apps[app].oauth_connections` contract selects app-owned requirements,
reviewed profiles and version-pinned key providers. See
[selected outbound OAuth connections](../../docs/OAUTH-INSTANCE.md) for the
instance fields, callback namespace and current readiness checks. This contract
does not yet add OAuth selection variables or a shell workload to `day2-app`.

Private approval transport also selects `oauth_shell_transport.service_account`
from the published shell contract. Pass the same `security_shell_contract`
reference to each selected `app-edge` root to add precisely that service account
to its app backend's IAP access binding. The shell contract must have a resolved
IAP audience distinct from the app's audience. Its locations reuse ordinary
selected app edges; no receiver hostname list is authored separately.

`security-shell-edge.runtime_secret_ids` must include only selected attestation
and reauthentication client-secret containers. App custody verifier and encryption
containers belong in each selected `app-edge.runtime_secret_ids`, together with
its attestation verification container. The shell secret IAM member changes from
the direct Kubernetes federation principal to its dedicated Google service
account when applying this update; review that policy migration before rollout.
No secret value is read by OpenTofu. Applying these plans still does not qualify
live workload identity, secret custody, provider readiness or OAuth registration.

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

## Deploy the dedicated OAuth shell

After resolving `security-shell-edge`, create the separate Google Web clients
and store their credentials in exact Secret Manager versions. Keep the selected
client IDs, provider references, company origin, resource selectors and
`oauth_runtime.shell_resources` in the private instance repository; see
[OAuth instance setup](../../docs/OAUTH-INSTANCE.md#dedicated-shell-launcher).
Use `day2 oauth-setup INSTANCE` to derive the dependent bindings and exact Google
callback URLs. Desired setup metadata cannot enable provider readiness.

The shell edge's `runtime_secret_ids` must contain exactly the selected
reauthentication and registration client-secret containers and shell attestation
containers. It must exclude all app custody containers, even if selecting another
version. Apply the updated edge contract before planning the workload; the new
workload refuses an unresolved contract or a different declared secret set.

Build `images/security-shell/Dockerfile` using the reviewed digest-pinned
platform runtime image and a context containing only the selected admitted Linux
`artifacts/` tree. Preserve its reviewed read-only file modes. The platform runtime
now includes `day2-security-shell` and its pinned Roc workflow distribution.
It has no shell script, package installation or application build hook.

Initialize and plan `stacks/security-shell` with its own private GCS backend
prefix, the dedicated edge namespace, digest-pinned shell image and
`instance_json = file(...)` input from that same instance repository. The root
consumes the existing edge's service account and selector; it creates no app PVC,
credential mount, identity or alternative URL catalog. Use the actual qualified
metadata-enabled node pool. The selected pod PID limit is a declaration until
verified against that pool; native startup separately checks memory/CPU bounds.

Before claiming live readiness, retain evidence for the exact deployed image,
instance digest, admitted artifact set, node/cgroup bounds, service-account
mapping, effective IAM and namespace/network isolation. Confirm readiness/drain,
unsigned direct-request denial and authenticated routing. Process probes alone
do not qualify a Google client; perform the signed live registration campaign
from the selected canary account and observe the owning app's acknowledgement.
No live shell deployment or Google qualification has been performed by these
source and mocked-plan tests.

## Instance CI on Gitea

`stacks/gitea-instance-ci` gives an instance configuration repository on Gitea
plan-on-pull-request, apply-on-main CI with no key:

- a dedicated runner VM (no external IP; SSH through IAP), registered to that
  one repository. Its controller is act_runner's Docker-in-Docker build, run
  privileged as in the fleet runner profile; jobs run in its inner daemon in a
  pinned slim image, with no Docker socket, privileges or host volumes;
- a workload identity provider for workflow tokens from `git-oidc`, which
  trusts only the repository's native Gitea ids and maps a pull-request run of
  the plan workflow to a read-only plan identity it creates, and a
  `push`/`workflow_dispatch` run of the apply workflow on `refs/heads/main` to
  the instance's apply identity. Anything else maps to no role.

Before the first apply, create the runner registration secret (the root reads
it once) and enable Actions on the repository. `git-oidc` issues tokens for
pull-request runs only for an explicitly trusted audience and workflow path, so
the provider's canonical audience and the plan workflow must also be listed in
its `trustedPullRequestPolicies`; main-branch runs need no entry. Workflows use
the auth action's default audience, which is the provider's canonical URL.

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
operator tools other than the read-only `day2-inspect` and the online
`day2-backup`. Online backups are scheduled (below); restore is an operator
procedure.

### Maintenance: `day2 platform maintain`

`day2 platform maintain OPERATION REQUEST_JSON` runs day2's own operations
against a stopped app. `ops/Maintain.roc` orders the steps; the Rust session
behind its `maintenance-*` capabilities (`crates/day2-ops/src/maintenance.rs`)
does every native action with `kubectl` and the registry API. Operations:

| Operation | What it does | App afterwards |
| --- | --- | --- |
| `inspect` | Reads the active authority stamp and policy | restored |
| `backup` | Verified backup, copied to `~/day2-backups/<namespace>/<stamp>/` | restored |
| `authority-apply` | Backup, then applies the policy in the current ConfigMap, after a typed `apply` | restored |
| `activate` | Backup, migration plan, typed `activate`, migration, fresh activation of the target artifact | stopped: apply day2-app for the new image next |

The request file names the target exactly:

```json
{
  "namespace": "app-go", "statefulset": "day2-go", "configmap": "day2-go-instance",
  "app": "go", "pvc": "data",
  "app_image": "REGISTRY/go/golinks@sha256:...", "artifact_id": "64 hex",
  "tooling_image": "REGISTRY/go/day2-tooling@sha256:...",
  "operator": "you@example.com",
  "pod_label": {"key": "internal-tools.wonderly.io/service", "value": "background"},
  "request_id": "release-2026-09-26",
  "target": {"instance": "desired-instance.json", "app_image": "REGISTRY/go/golinks@sha256:...", "artifact_id": "64 hex"}
}
```

`request_id` is for `authority-apply` and `activate`; `target` (the desired
instance, e.g. rendered from the day2-app plan) is for `activate` only;
`backup_dir` and `"yes": true` (skip the typed confirmation, recorded) are
optional. The tooling image must come from the same platform build as the app's
artifact.

What the session guarantees, whatever the recipe does:

- The maintenance pod ([k8s/maintenance-pod.yaml](k8s/maintenance-pod.yaml),
  rendered from a fixed placeholder set) is removed on every exit, including
  Ctrl-C; its one-hour deadline is the backstop.
- Before the migration fence, any failure restores the StatefulSet's replicas on
  its original image. After the fence the old image is never restarted on the
  migrated volume; the session prints the two ways forward instead.
- The fence needs a verified local backup, a migration plan and a confirmation
  from the same session, and `migration apply` refuses to run without it.
- Artifacts come from the digest-pinned app images: manifest, layer, artifact
  identity and worker digests are checked, and links or devices are refused.
- The local backup copy must match a SHA-256 manifest computed in the pod; a
  mismatching copy is renamed `<stamp>.INCOMPLETE` and refused.
- One session per namespace; the running image must equal `app_image`.
- Every step is journalled to `~/day2-backups/<namespace>/<stamp>.session.json`
  before it runs, for recovery after the operator's machine dies mid-session.

`deploy/gke/scripts/day2-maintain.sh` remains until this command has run a
production activation; it will then be removed.

To roll back code, plan the prior qualified image and configuration. After a schema
migration, first prove backward compatibility or restore the matching backup;
never point an old artifact at incompatible state. Node upgrades require rerunning
the probe and a representative application acceptance campaign. Namespace/PVC
`prevent_destroy`, Retain storage and cluster deletion protection guard accidents;
removing them is an explicit decommissioning change after verified backups.

## Scheduled off-cluster backups

`day2-app` creates the CronJob `day2-<app>-backup` (schedule `backup_schedule`,
default `17 * * * *`, UTC; `concurrencyPolicy: Forbid`, a 10-minute start
deadline, a 30-minute run deadline, one retry, three successful and three failed
Jobs kept). Each run:

1. is scheduled only onto the app pod's node (required pod affinity on
   `app.kubernetes.io/name=day2-<app>`), because the state disk is
   ReadWriteOnce. While the app is stopped, for example during maintenance, the
   run stays Pending and fails at its deadline instead of taking the volume;
2. runs one container of the StatefulSet's exact app image:
   `/usr/local/bin/day2-backup /srv/day2/instance.json <app_id> /backup/snapshot
   --upload-gcs <project>-<app>-backups --object-prefix <app_id>`, with the same
   instance ConfigMap (`subPath`), state volume and baked artifact. It takes an
   online SQLite snapshot beside the serving pod without its lock and verifies
   the bundle ([Linux guide](../linux-sqlite/README.md#online-backup-in-the-runtime-image));
3. in the same process, takes the pod's access token from the GKE metadata
   server and uploads every file of the verified bundle as its own object
   `<app_id>/<UTC yyyymmddThhmmssZ>/<relative path>` (the binary appends the
   timestamp), streaming each file as a JSON API media upload with
   `ifGenerationMatch=0`, so an existing object is never replaced. Each
   response must name the object with the file's exact size. Only then is
   `<app_id>/<stamp>/COMPLETE` written, listing every object, its size and the
   manifest's sha256. Nothing is retried; any failure fails the Job and leaves
   a prefix without `COMPLETE`, which is never a backup.

The container runs as 10001 with a read-only root, no capabilities,
`RuntimeDefault` seccomp and no mounted token; there is no shell and no second
image in the pod. The pod runs as the Kubernetes
service account `backup` (labels `internal-tools.wonderly.io/service=backup`
plus the app's o11y label), which the tenancy policy admits only for such Jobs
with token automount off. `app-edge` binds it through Workload Identity to the
Google service account `<app>-backup`, whose only grant is
`roles/storage.objectCreator` on the backup bucket: it cannot list, read,
overwrite or delete backups. The bucket has uniform access, enforced public
access prevention, an **unlocked** retention policy of
`offsite_backup_retention_days` (default 30; nobody can delete or replace an
object earlier, and the policy can still be shortened or removed by an
administrator) and a lifecycle rule deleting objects one day later. The bucket
has `prevent_destroy`. Principals in `offsite_backup_readers` get
`roles/storage.objectViewer` to download backups.

Watch for failed `day2-<app>-backup` Jobs (`kubectl -n app-<app> get jobs`) and
for the age of the newest `COMPLETE` object; a missed schedule creates no Job.
Each hourly prefix holds the full, uncompressed bundle (databases and
artifact), so storage is about 24 × 30 bundles at the default settings.

Wire it by applying `app-edge` first and passing its `backup_bucket` output to
`day2-app`'s required `backup_bucket` variable. Both the CronJob and the
`backup` service account are platform-owned objects in the app namespace
(`forbid-platform-resource-mutation`, `forbid-app-service-account-mutation`),
so the identities in the tenancy stack's `platform_automation_usernames` apply
them.

### Restore from an off-cluster backup

A downloaded backup is verified and restored only by the tooling image of the
same platform build (`day2 platform restore` verifies the bundle, then writes a
new directory). Restore never activates historical grants: it disables them,
rotates browser sessions and signing secrets, and requires a fresh authority
activation.

Pick a backup whose prefix has `COMPLETE`, download the whole prefix, and
check it against the marker before trusting it (an x86_64 Docker host; the
restore itself runs with no network):

```console
gcloud storage ls gs://PROJECT-APP-backups/APP_ID/          # one prefix per run
gcloud storage cat gs://PROJECT-APP-backups/APP_ID/STAMP/COMPLETE
mkdir restore && gcloud storage cp -r gs://PROJECT-APP-backups/APP_ID/STAMP restore/
mv restore/STAMP restore/snapshot
```

`COMPLETE` lists every object name and byte count, and the sha256 of
`backup.json`. Require that the downloaded tree has exactly those files and
sizes (plus `COMPLETE` itself) and that `sha256sum restore/snapshot/backup.json`
matches (the marker's value is `sha256:<hex>`). A prefix without `COMPLETE` is
an interrupted upload: do not use it. Then verify and restore with the tooling
image:

```console
rm restore/snapshot/COMPLETE
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD/restore:/work" \
  --entrypoint /workspace/platform/cli/day2 TOOLING_IMAGE@sha256:... \
  platform restore /work/snapshot /work/restored
```

`restored/` then holds `instance.json` (grants cleared), `artifacts/<id>/` and
`.state/` with the app database and provider stores. Exercise it in a separate
private environment before relying on it.

Restoring into the app's own volume replaces its current data, so take a fresh
backup first (`day2 platform maintain backup REQUEST_JSON`, which also copies
it off-cluster). Then, with the app stopped
(`kubectl -n NS scale statefulset day2-APP --replicas=0`, wait for the pod to
terminate; backup runs cannot start without it), attach the maintenance pod
from [k8s/maintenance-pod.yaml](k8s/maintenance-pod.yaml) rendered exactly as
`day2-maintain.sh` renders it, and in it:

1. `kubectl cp` the downloaded, checked `snapshot/` to `/srv/day2/restore-in`, the current
   desired `instance.json` (ConfigMap `day2-APP-instance`) to
   `/srv/day2/instance.json`, and the running artifact (as `day2-maintain.sh`
   fetches it) to `/srv/day2/artifacts/ARTIFACT_ID`;
2. `/workspace/platform/cli/day2 platform restore /srv/day2/restore-in /srv/day2/restored`;
3. remove the app's current `.state/APP.sqlite`, `.state/APP.sqlite-wal` and
   `.state/APP.sqlite-shm` (and the same three files of every provider store in
   `restored/.state/`), then copy `restored/.state/*` into `/srv/day2/.state/`.
   A stale `-wal` left beside a restored database would be replayed into it;
4. activate current authority on the restored database with the `day2-host`
   workflow `authority activate /srv/day2/instance.json APP
   /srv/day2/artifacts/ARTIFACT_ID OPERATOR EXPECTED_STAMP REQUEST_ID`, where
   `EXPECTED_STAMP` is the restored database's stamp from `authority inspect`
   (both as `day2-maintain.sh` invokes them; always check `.ok`);
5. delete the maintenance pod and scale the StatefulSet back to one replica.

Linux qualification exercises this restore-then-fresh-activation sequence
(`linux-runtime-restore`); `day2-maintain.sh` has no `restore` operation yet,
and this in-cluster procedure has not been exercised on GKE.

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
- Readers, writers and operation actors are lowercase e-mail addresses, or
  `domain:<hosted_domain>` for everyone at the domain IAP verifies. The root
  refuses any other `domain:` entry, as day2 does.
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

## Apps with providers and signed webhooks

`day2-app` accepts an operator-owned `resource_catalog`, `resource_policies`,
`schedules` and `ingress`. They use the same contracts as a native Day2 instance;
no credential bytes belong in these inputs. A declared schedule runs only when
bound to an actor. Keep bindings disabled until the fresh app's source coverage
has been initialized. Startup refuses an enabled signed endpoint whose signing
secret is not registered.

Provider credentials come from Secret Manager through the cluster's Secret
Manager CSI add-on; no secret value passes through OpenTofu. For each secret:

1. Store it in Secret Manager in the app's project and note its version number.
2. List the secret id in `app-edge.runtime_secret_ids`. That grants only the
   app's `runtime` Kubernetes service account's Workload Identity principal
   `roles/secretmanager.secretAccessor` on that secret.
3. In `day2-app.provider_credentials`, pair the day2 credential reference that a
   catalog connection declares (`credential_ref` or `signing_secret_ref`) with
   the exact version (`projects/P/secrets/S/versions/N`, never `latest`) and its
   fingerprint: `sha256:` and the hex SHA-256 of the value without trailing
   newlines. Set `credential_operator` to the installation administrator
   recorded as the registrant.

Before `day2-serve` starts, the pod copies each version into memory as a
10001-owned 0400 file and runs the runtime image's `day2-provision-credentials`
against the reviewed plan, exactly as `day2 platform provision-credentials`
does for a Compose package. It refuses a missing, extra or changed secret. To
rotate, add a new version, advance the credential's revision in the catalog,
and update the version and fingerprint together.

Size the state volume for the app's invocation rate. A completed invocation keeps
its full trace, which includes the authority it ran under, for 72 hours unless
`journal_trace_hours` is set; an app with frequent schedules should set a few
hours. Backups copy the database online within a fixed deadline, so a database
that outgrows it stops the hourly backup before the disk fills.

`app-edge.signed_webhook_paths` optionally routes exact `/ingress/<endpoint>`
paths through a separate backend without IAP. This is for provider deliveries:
Day2 still requires the configured signature before admission. The ordinary
backend and every other path retain IAP. Prefixes, wildcards, queries and paths
outside `/ingress/` are refused. With no paths configured, no additional Service
or BackendConfig exists. The separate backend is never the default backend.
