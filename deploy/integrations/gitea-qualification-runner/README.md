# Optional Gitea host-executor qualification runner

This provider-specific deployment example creates a dedicated GCE VM for one
Gitea repository's qualification jobs. It is an opt-in integration under
[`deploy/integrations/`](../README.md), not a prerequisite or change to the core
[`qualification-runner` VM](../../gke/stacks/qualification-runner/README.md).
The core qualification-runner remains a plain operator VM.

The runner uses an x86_64 C3 Sapphire Rapids machine (`c3-standard-8` by
default), Debian 13 and the exact host prerequisites from the core
`deploy/gke/stacks/qualification-runner/startup.sh`. The integration composes
that script by file reference, so Docker, build tooling and the qualification
host report have one source of truth. It then installs digest-pinned
`act_runner` 0.2.11 in host mode and starts it as the dedicated
`day2-qualification` account. That account is unprivileged except for its
membership in the `docker` group; access to the Docker socket is effectively
root authority on this VM.

The VM has no external IP. SSH is allowed only from the IAP TCP forwarding
range and requires OS Login. Its dedicated service account receives
`roles/secretmanager.secretAccessor` on only `registration_secret_id`; it has no
image-push permission unless `image_push_repository_ids` names repositories,
which receive individual `roles/artifactregistry.writer` grants.

## Private configuration example

Create a repository-scoped Gitea Actions runner registration token for exactly
`repository`, store it in an existing Secret Manager secret, and explicitly
select this root from the private instance's root mapping. Keep the backend,
workflow triggers and approvals in that private instance repository. The
integration does not create or read the secret value at plan time.

```hcl
project_id      = "example-project"
region          = "us-central1"
zone            = "us-central1-a"
operator_members = [
  "user:operator@example.com",
  "user:reviewer@example.com",
]

gitea_url             = "https://git.example.com"
repository            = "wonderly/platform"
registration_secret_id = "platform-qualification-runner-token"
runner_labels          = ["qualify-x86", "release-x86"]

# Optional. Empty by default, granting no Artifact Registry writer role.
image_push_repository_ids = [
  "qualification-images",
  "release-images",
]

# Defaults are c3-standard-8 and Debian 13. The host CPU family is fixed to C3.
```

The secret must contain only the repository-scoped runner registration token;
organization- or instance-scoped tokens violate the trust boundary. The
registration token is fetched at boot using the VM service account. In pinned
`act_runner` v0.2.11, `register` exposes its token input only through the
`--token` command-line flag (the flag has no environment-variable binding). The
startup script therefore uses act_runner's interactive registration input,
feeding a temporary root-only mode-0600 file on `/run` (tmpfs) through stdin;
the file is removed immediately after registration. The registration token is
not included in argv, instance metadata, Terraform inputs/state, or persistent
disk. The generated `.runner` file contains the separate runner credential
needed by the daemon and is owned mode 0600 by the runner account.

## Host-executor trust model

Every job from the registered repository that targets one of these labels runs
directly on the VM as `day2-qualification`. It can use Docker and therefore
obtain host-level authority. The attached VM service account is also available
to guest processes: such jobs inherit its permission to read the named
registration secret and any configured Artifact Registry writer grants. A
malicious workflow can read those credentials, take over the VM and persist.
This is deliberate for qualification that must observe the build host's real
kernel, cgroups, Docker engine and Sapphire Rapids CPU; it is not a sandbox.

Protect `main`, require review for workflow-file changes, and do not run
untrusted pull-request or fork code on these labels. Prefer a protected-main,
dispatch-only release workflow that checks out the reviewed commit and is the
only workflow authorized to target the qualification label. Branch protection
alone does not prevent another workflow in the repository from targeting a
host label.

## Offline mocked tests

From the platform repository root:

```console
tofu fmt -check -recursive deploy/integrations/gitea-qualification-runner
tofu -chdir=deploy/integrations/gitea-qualification-runner init -backend=false -lockfile=readonly
tofu -chdir=deploy/integrations/gitea-qualification-runner validate
tofu -chdir=deploy/integrations/gitea-qualification-runner test
```

The tests mock Google providers and only plan. They cover the defaults, exact
secret IAM, two independent Artifact Registry repository grants, two host
labels, token-free startup metadata and stdin registration, IAP-only access,
and invalid repository, label, machine-type, secret-id and repository-id
inputs. They do not contact Gitea or Secret Manager, apply cloud resources, or
qualify a live runner.
