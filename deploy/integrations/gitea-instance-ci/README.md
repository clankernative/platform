# Optional Gitea instance CI on GCE

This is an opt-in provider deployment example for a **private instance
configuration repository hosted on Gitea**. It is not part of the
[core GKE runtime stacks](../../gke/README.md) or their apply order, and it does
not require app source repositories to use Gitea. GitHub- and GitLab-backed
instances can use their own CI without deploying this example. See
[instance ownership and provider scope](../README.md).

## What this root creates

The [OpenTofu root](main.tf) creates:

- a dedicated runner VM with no external IP and operator SSH through IAP,
  registered to exactly one private repository;
- a digest-pinned act_runner Docker-in-Docker controller, running privileged,
  whose jobs run in the inner daemon with no Docker socket, privileges or host
  volumes declared for the jobs;
- a workload identity provider for workflow tokens from an operator-selected
  `git-oidc` issuer, bound to the repository's native Gitea IDs and exact
  plan/apply workflow paths;
- a read-only plan identity for pull-request plans and a binding to the
  instance's existing apply identity for `push`/`workflow_dispatch` runs of the
  apply workflow on `refs/heads/main`. Other event/ref/path combinations are
  refused.

The runner VM's identity reads its registration secret and writes logs. Job
provisioning authority comes from the separately selected federated identities,
not a committed service-account key. The controller remains privileged; these
settings and the mocked tests are not a hostile-code containment qualification.
Do not admit public or untrusted fork jobs to this company runner.

## Private inputs and prerequisites

Select `deploy/integrations/gitea-instance-ci` explicitly in the private
instance's root mapping. Keep its backend configuration, values, workflows and
approval policy there; do not include it in an automatic runtime-root sweep.
The example does not create the CI workflow files or choose the stacks those
workflows plan and apply.

Required private inputs include the GCP project ID and number, operator members,
repository name and native IDs, existing workload identity pool, apply identity,
state bucket, Gitea server URL and OIDC issuer URL. Set `gitea_url` and
`oidc_issuer_uri` explicitly, for example `https://git.example.com` and
`https://git-oidc.example.com`; neither has a platform default. Keep a separate
backend prefix for this root.

Before applying, enable Compute, IAP, IAM, IAM Credentials, STS and Secret
Manager in the selected project. Create the workload identity pool and the
repository-scoped runner registration secret, and enable Actions on the
repository. Registration reads the token once at first boot; the root does not
place its value in OpenTofu inputs or state.

This example assumes a `git-oidc` issuer with the reviewed GitHub-shaped Gitea
workflow claims; it does not provision that issuer or claim support for an
arbitrary OIDC server. For pull-request runs, the provider's canonical audience
and the plan workflow must be explicitly admitted in the issuer's
`trustedPullRequestPolicies`. Main-branch runs need no such entry. The provider
accepts its canonical URL as the sole audience, matching the auth action's
default. Use the root's `workload_identity_provider`, `oidc_audience` and
`runner_label` outputs in the instance-owned workflow configuration.

For a private compiled job image, set `job_image` to its reviewed digest and
`job_image_repository_id` to its Artifact Registry repository in the selected
project and region. The VM gains `artifactregistry.reader` on that repository
only. Startup stops the prior controller, then opens the persistent inner Docker
data directory in a temporary daemon using the same pinned controller image.
An already cached digest needs no token or pull. A cold cache uses the VM's
short-lived metadata token and a RAM-backed Docker configuration, then verifies
`linux/amd64` and stops the temporary daemon before starting the configured
runner. Prewarm failure leaves the configured runner stopped. Neither registry
credentials nor a Docker socket are mounted in job containers.

Select the image in workflows only after verifying this path on the actual
runner. Apply the repository-reader/startup inputs first, then run startup while
the runner has no active job and record cold/warm inner-daemon pulls before the
workflow image change. Updating instance metadata alone does not run startup
on an already running VM. Keep the persistent Docker data directory across
reboots; a host-daemon image pull does not populate the job daemon's cache.
The root's source-only tests do not establish this live qualification.

App compilation and release still execute the platform's pinned
[operations recipes](../../../ops/README.md), under their existing guards.
This runner is for infrastructure plans/applies, not an alternative app builder
or operational SDK.

## Source-only checks

From the platform repository root:

```console
tofu fmt -check -recursive deploy/integrations/gitea-instance-ci
tofu -chdir=deploy/integrations/gitea-instance-ci init -backend=false -lockfile=readonly
tofu -chdir=deploy/integrations/gitea-instance-ci validate
tofu -chdir=deploy/integrations/gitea-instance-ci test
```

The tests mock Google providers and plan only. They check explicit endpoint
rendering, repository/workflow identity restrictions, read-only plan roles,
private networking, job settings and pinned images. They do not contact a
company Gitea server, read company state, apply infrastructure, or establish
live CI qualification.
