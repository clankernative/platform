# Native enrollment Google metadata access

This separate, manually selected root grants the provisioner's exact direct
Workload Identity principal only the reads used by native enrollment:

- `resourcemanager.projects.get` on the selected project.
- `container.clusters.get` conditioned on the exact selected GKE cluster.
- `iam.serviceAccounts.get` bound separately on the three selected App, Shell
  and controller Google accounts.

Three single-permission custom roles and five additive member bindings are
created. No complete IAM policy is replaced. There are no list, impersonation,
token, signing, secret, runtime mutation or Kubernetes permissions. This root
does not broaden the separate KMS signer role or deploy a workload. IAM access
does not enroll or grant a native role; exact UID/code/node/clock joins remain
the supplier's responsibility.

Select an explicit zonal or regional cluster scope. For IAM Conditions, zonal
clusters use `projects/PROJECT/zones/ZONE/clusters/NAME`; regional clusters use
`projects/PROJECT/locations/REGION/clusters/NAME`. These are not full-resource
names and must not be guessed from the REST endpoint spelling. Resource Manager
project reads use their separate project-scoped role. IAM account reads are
bound on the exact account resource rather than on the project.

Keep the instance backend and variables outside automatic apply. Initialize
this root, run the mocked plans, then retain a saved real plan. Require explicit
approval for these new IAM resources before apply. Qualification must exercise
the selected API reads under the real provisioner identity; a plan is not an
access result. A replaced account is still refused by the supplier's selected
unique-ID checks; these grants do not migrate enrollment.

References: [IAM condition resource formats](https://docs.cloud.google.com/iam/docs/conditions-resource-attributes),
[condition attribute support](https://docs.cloud.google.com/iam/docs/conditions-attribute-reference),
[service account get authorization](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/get).
