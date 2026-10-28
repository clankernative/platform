# Optional Gitea Actions host runner

The qualification VM remains an operator-managed x86_64 Linux/Docker host by
default. Leave `ci_runner = null` (the default) to preserve its current startup,
IAM and plan. When selected, the VM additionally registers as one repository's
Gitea Actions host runner; SSH through IAP and the existing host report remain
unchanged.

The runner is installed as a pinned `act_runner` Linux binary and runs under the
`day2-qualification` system account. Its `host` executor is intentional: the
qualification procedure checks the actual VM kernel, cgroups and Docker engine,
which a Docker-in-Docker job would mask. The account is in the `docker` group,
which is effectively root access to the VM. The runner service restarts on boot;
its persisted registration file avoids duplicate registration on ordinary
reboots. Registration is performed only when that file is absent.

## Private configuration example

Create a repository-scoped Gitea runner registration token out of band, store it
as a Secret Manager secret in `project_id`, and grant no other principal access
unless separately needed. Put only the secret **id** in the private instance
configuration. The token value is fetched by the VM service account at first
registration; it is not an OpenTofu input, metadata value, or state value. The
example pins `act_runner` 0.2.11 to the SHA-256 published in its Linux amd64
release asset's upstream [`checksums.txt`](https://gitea.com/gitea/runner/releases/download/v0.2.11/checksums.txt);
review and update both together when changing versions.

```hcl
project_id       = "example-project"
enabled          = true
desired_status   = "RUNNING"
operator_members = ["user:operator@example.com"]

# Existing app image-push selection. Empty means no Artifact Registry writer grant.
image_push_repository_id = "app-go"

ci_runner = {
  gitea_url              = "https://git.example.com"
  repository             = "example-org/app-go"
  registration_secret_id = "app-go-qualification-runner-token"
  labels                 = ["qualify-x86"]
  runner_version         = "0.2.11"
  runner_sha256          = "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c"
}
```

`registration_secret_id` names an existing Secret Manager secret in `project_id`;
this stack does not create it or read its value during planning. `labels` are
Gitea `host` labels selected by workflows with `runs-on`. The registration
secret must be generated for exactly `repository` at that repository's Actions
runner settings; an organization- or instance-scoped token would violate this
stack's trust boundary. There is no runner registration for multiple repos.

The VM service account receives `roles/secretmanager.secretAccessor` on exactly
the selected secret and no new project role. Existing
`image_push_repository_id` remains the only optional image-write grant; CI does
not add any other Artifact Registry repository. Secret values are never
available to OpenTofu state.

## Workflow trust and availability

Every workflow in the registered repository that targets one of these labels
runs directly on the VM as `day2-qualification`, with access to its Docker
daemon. GCE's attached service account is also reachable from guest processes:
matching workflows therefore have its existing image-push rights and the
selected secret's read permission, including the ability to retrieve the
registration token. A compromised or untrusted workflow can take over the VM,
use those credentials, and persist across jobs. Do not register a repository
that runs untrusted workflow code on these labels. Protect its main branch and
review workflow-file changes; remember that pull-request workflows can target
runner labels too. Restrict qualification jobs to reviewed workflow definitions
(for example, a dedicated label used only by a protected-main or manually
dispatched workflow) and do not treat branch protection alone as a sandbox.

Wonderly's private instance configuration currently keeps this VM
`TERMINATED` by default. It must be `RUNNING` while a release job is queued or
executing; a stopped VM cannot accept queued work. Starting/stopping it on demand
from CI is a separate follow-up, not part of this stack.

## Offline mocked tests

From the platform repository root:

```console
tofu fmt -check -recursive deploy/gke/stacks/qualification-runner
tofu -chdir=deploy/gke/stacks/qualification-runner init -backend=false -lockfile=readonly
tofu -chdir=deploy/gke/stacks/qualification-runner validate
tofu -chdir=deploy/gke/stacks/qualification-runner test
```

The mocked tests do not contact Gitea or Secret Manager and do not apply cloud
infrastructure. They cover the unchanged null path, exact-secret IAM, rendered
repository/labels without a token value, validation boundaries and two runner
labels.
