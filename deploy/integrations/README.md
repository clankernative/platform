# Optional provider deployment examples

These examples are opt-in provider integrations, not core runtime stacks or an
installation catalog. The [GKE deployment guide](../gke/README.md) defines the
runtime apply order without selecting a Git host or infrastructure CI provider.

## Instance ownership

A company chooses the Git host for its instance configuration, the hosts for
its app repositories, and its infrastructure CI independently. One app source
binding does not select the host for every other repository. Keep actual
repository identities, workflow triggers, runner configuration, federated
identities, approvals, backend inputs and credentials in the private instance
repository.

GitHub Actions, GitLab CI, Gitea Actions and manual operator provisioning can
all drive an instance's infrastructure. There is no mandatory platform CI
provider or app job SDK. Platform-owned build, admission, verification and
release decisions remain in the pinned [operations recipes](../../ops/README.md);
CI does not replace their guards or let app repositories choose arbitrary tasks.

The control plane's [remote Git source binding](../../docs/CONTROL-PLANE.md#where-an-apps-source-lives)
reads exact commits over HTTPS from GitHub, GitLab or Gitea. That source support
does not imply equivalent webhook, check-publication, hosted runner or
deployment-CI integrations. Provider adapters retain their actual semantics and
qualification requirements; no generalized CI interface is introduced here.

## Included example

| Example | Provider-specific implementation |
| --- | --- |
| [Gitea instance CI](gitea-instance-ci/README.md) | Optional GCE runner and workload identity provider for infrastructure plans/applies from one private Gitea repository |

The Gitea example is reusable because every company endpoint and repository
identity is an explicit input. It is not required for GitHub- or GitLab-backed
instances. Turnkey GitHub Actions and GitLab CI provisioning examples are not
included; those instances supply their own provider identity and CI wiring.

Opt in by selecting the example's root explicitly in the private instance's
root mapping. Do not discover or apply every directory under `deploy/` or
`deploy/integrations/`. Provider-specific examples carry their own provider
locks, mocked tests and prerequisites, separate from the runtime stack list.

Mocked tests validate rendering and contracts, not live provider authentication
or hostile-code containment. Do not run public or untrusted fork workflows on
company runners or give them deployment credentials. Qualify the exact selected
provider, runner, identities and workflows before using an example for real
infrastructure.
