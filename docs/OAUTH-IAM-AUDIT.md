# Installation OAuth IAM audit

Audit the dedicated shell and each selected app runtime GSA against its reviewed
deployment. Keep evidence in protected operator storage, bound to the instance
commit, workload images, resource identities and observation time. This is an
operator procedure; its results cannot populate native live-readiness leases.

## Enable the query project

Select `enable_cloud_asset_api = true` in the private `project` root values,
review its plan and apply it through the normal instance workflow. This enables
`cloudasset.googleapis.com` without granting roles. Removing the selection stops
managing the API; `disable_on_destroy = false` keeps it enabled.

The query project and analysis scope are distinct. Analyze from the containing
organization to include inherited bindings and sibling resources. The auditor
needs `cloudasset.assets.analyzeIamPolicy`, `cloudasset.assets.searchAllResources`,
`cloudasset.assets.searchAllIamPolicies` and `iam.roles.get` at that scope, plus
`serviceusage.services.use` in the query project. Group expansion needs Workspace
`groups.read`. Keep this read authority on the operator, outside workload IAM.
See [Google's audit prerequisites](https://docs.cloud.google.com/policy-intelligence/docs/analyze-iam-policies).

## Collect both directions

Replace uppercase selections from the private instance and live resource
inventory. Use an existing private output directory. The environment assignment
selects the query project for this invocation without changing gcloud's global
configuration; `--organization` selects the analysis scope.

```console
CLOUDSDK_CORE_PROJECT=QUERY_PROJECT gcloud asset analyze-iam-policy \
  --organization=ORGANIZATION_NUMBER --identity=serviceAccount:GSA_EMAIL \
  --expand-roles --expand-resources --output-resource-edges \
  --execution-timeout=30s --show-response --quiet --format=json \
  > /private/audit/gsa-access.json
```

Review every returned resource and permission, including conditional grants.
Compare the five Compute reads and exact secret containers to the deployment;
for the shell, also compare its self-only `signJwt` and selected app-backend IAP
access. Any other permission needs resolution. Follow every outgoing service
account impersonation path and audit the reachable account's authority too.

Collect incoming access to each shell/app GSA separately:

```console
CLOUDSDK_CORE_PROJECT=QUERY_PROJECT gcloud asset analyze-iam-policy \
  --organization=ORGANIZATION_NUMBER \
  --full-resource-name=//iam.googleapis.com/projects/GSA_PROJECT/serviceAccounts/GSA_EMAIL \
  --permissions=iam.serviceAccounts.actAs,iam.serviceAccounts.getAccessToken,iam.serviceAccounts.getOpenIdToken,iam.serviceAccounts.implicitDelegation,iam.serviceAccounts.signBlob,iam.serviceAccounts.signJwt \
  --expand-groups --analyze-service-account-impersonation \
  --execution-timeout=30s --show-response --quiet --format=json \
  > /private/audit/gsa-impersonators.json
```

Review the selected KSA and signer, administrative principals and every additional
impersonator. Group expansion is effective only without an identity selector.
The impersonation option finds principals able to become accounts in the query
results; it does not replace following outgoing paths from the workload.
See [Google's query options](https://docs.cloud.google.com/policy-intelligence/docs/analyze-iam-policies#enable-options).

## Finish the evidence

Require `fullyExplored = true` for the response, its analyses and results. Resolve
all noncritical errors, unknown conditions, unsupported resources and expansion
limits. A denied, partial or empty truncated response is inconclusive. Use the
long-running API with a separately reviewed private output sink if necessary.
See the [response contract](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/analyzeIamPolicy).

Independently reread live IAM policies, custom role definitions, user-managed
service-account key metadata, all KSA annotations, RBAC, pod identities and
namespace network policies. Compare against the reviewed deployment and account
for bindings outside the analyzed organization. Rerun after changes and reconcile
inventory lag. Policy Analyzer covers allow policies and best-effort metadata;
it excludes deny policies, principal access boundaries and Kubernetes RBAC.
See [coverage and freshness](https://docs.cloud.google.com/policy-intelligence/docs/policy-analyzer-overview).

Only a resolved, current audit plus the independent workload and protocol
campaigns can support installation qualification. Desired JSON, mocked plans,
frontend TLS, secret availability and this document establish none of those results.
