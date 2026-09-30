# Private instance template

Copy this directory **outside** the platform checkout into a private repository.
Replace reserved example values there. Keep app source in separate private repos.
Never put real credentials, state, grants, domains or app images in this example.

Suggested private layout:

```text
my-instance/
  backend/cluster.hcl
  backend/security-shell.hcl
  backend/apps/reports-edge.hcl
  backend/apps/reports-workload.hcl
  cluster.tfvars
  security-shell.tfvars
  reports-edge.tfvars
  reports-workload.tfvars
  backups/                 # ignored, protected storage elsewhere
```

Rename the `.example` configuration files after copying them. Each OpenTofu root
has its own backend prefix. Backends, tfvars and kubeconfig belong privately;
use application-default credentials or workload identity, never committed keys.
The [deployment runbook](../../deploy/gke/README.md) explains apply order and IAM.

The optional `security-shell.tfvars.example` selects one security hostname for
the installation. OAuth-enabled workload values refer to the resulting contract
by namespace and ConfigMap name, as the runbook describes.

For a runnable local instance, from the platform root use:

```console
./cli/day2 platform local-dev examples/reports --directory ../my-private-instance
```

The workflow creates a checked `instance.json` with the example's authority,
resources and local identity. Generated artifact paths are machine-specific.
Production configuration is rendered by the workload stack using that artifact's
complete operation authority; do not copy local development identity into GKE.
