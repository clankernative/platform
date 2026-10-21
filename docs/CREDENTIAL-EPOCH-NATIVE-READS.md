# Private credential epoch read acquisition

The native read adapter is a private AppHost/controller implementation beneath
`security_epoch`. It does not register an app capability or bootstrap command.
`CurrentBootstrapExecution` still has no production factory. A read observation
cannot authorize Create, Activate, restore or takeover.

## Acquisition and support

An acquisition begins with actual Linux `CLOCK_BOOTTIME`, before entropy,
executable, projection, authentication or database I/O. Identity requests and
coherent Firestore reads retain that original interval: at most five seconds,
or the selected shorter lease. Each HTTP timeout also respects the caller's
smaller ceiling. A failed request, clock rewind, process change or selected
resource mismatch refuses the owning acquisition. There is no renewal.

The process observer retains `/proc/self/exe`, hashes its actual bytes and
checks the original descriptor and current executable identity. The selected
`controller_code` is that executable's SHA-256, not a container image hash.
These observations do not establish immutable executable memory, time namespace
qualification, dependency/image admission or hostile code containment. Other
platforms refuse; neither `Instant` nor wall time substitutes for BOOTTIME.

The staged profile uses these fixed projected paths:

| Purpose | Path |
| --- | --- |
| Kubernetes API authentication | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| Separately reviewed subject token | `/var/run/secrets/day2-native/subject-token` |
| Selected cluster CA | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` |

Descriptors must be regular files and reads are bounded. Projection symlinks
may resolve Kubernetes' atomic writer; their path alone does not authenticate
the caller or prove that its process belongs to the token's Pod. An actual
deployment must supply and qualify these projections, executable/profile
admission and process-to-Pod binding before a serving bootstrap factory exists.
Acquisition now requires a borrowing real enrolled AppHost or EpochController
stage matching the complete bootstrap/store selection. AppHost selects its
native host executable independently of its Roc artifact. SecurityShell is not
an epoch reader. The original stage remains borrowed through every request and
local use, and its narrower I/O clock preserves the original domain, origin and
earlier deadline. Code selections or parsed certificates cannot create that
borrow. See
[runtime identity selections](CREDENTIAL-RUNTIME-IDENTITY.md#selected-container-data).

## Authenticated response checks

TokenReview must return authentication, the exact selected audience and KSA
name/UID, and one bound Pod name/UID. Current namespace, KSA, Pod and controlling
workload objects must match the selected UIDs; deletion timestamps refuse.
Deployment lineage includes its current ReplicaSet. StatefulSet lineage is
direct. TokenReview node extras are not used as evidence. Its deletion grace
period does not establish instantaneous liveness.

The authenticated GKE reply must match cluster ID, location, running state,
selected direct IP endpoint and CA bytes. DNS endpoints are unsupported by this
profile. The fixed authenticated Google GET and project check precede reading
or sending either Kubernetes projection. Kubernetes dispatch itself refuses
until the checked recipient is bound to the same live acquisition domain.
Configured origin and CA equality cannot unlock it. Project number, immutable
GSA UID and physical Firestore database UID
are checked separately. Metadata equality and a decoded token are not a current
role proof. The UID-target mint request is retained by the owning adapter; its
expiry string is historical data, not qualified UTC.

HTTP clients disable proxies, redirects and automatic retries. Response bodies
are bounded while reading. Routes are fixed provider/Kubernetes selections,
including only Firestore `batchGet` and `rollback`; no counter commit route is
installed. Credentials cannot be cloned, serialized, formatted or moved to a
different thread. Owned token buffers and parsed token fields are zeroized on
drop. Header/request/parser copies are not a complete plaintext erasure claim.

## Permissions for deployment review

This matrix describes requests made by the staged adapter. It adds no grants.
Company IAM, Kubernetes RBAC, instance values and live qualification remain
operator owned. Authorization for metadata reads and minting must be reviewed
separately from the epoch data reader; no project-wide writer role is implied.

| Credential | Exact operation | Required permission / scope |
| --- | --- | --- |
| Kubernetes API projection | POST `authentication.k8s.io/v1/tokenreviews` | `create` on `tokenreviews`; authenticated subject token is supplied separately |
| Kubernetes API projection | GET selected namespace | `get` on `namespaces`, selected name |
| Kubernetes API projection | GET current KSA, bound Pod, ReplicaSet and selected Deployment/StatefulSet | `get` on those resources in the selected namespace; use exact names where known; no list, watch or writes |
| GKE metadata source | GET selected project | `resourcemanager.projects.get` on that project |
| GKE metadata source | GET selected cluster | `container.clusters.get` on that cluster |
| GKE metadata source | GET selected GSA by immutable UID | `iam.serviceAccounts.get` on that account |
| GKE metadata source | POST UID-target `generateAccessToken` | `iam.serviceAccounts.getAccessToken` on that exact target; no delegates; datastore scope, 300 seconds |
| Minted target credential | GET selected database metadata | `datastore.databases.getMetadata` on that database |
| Minted target credential | `batchGet` epoch documents | `datastore.entities.get` on that database |
| Minted target credential | Read-only transaction and `rollback` | `datastore.databases.get` on that database |

The source credential must have the OAuth scopes required by these metadata
and IAM APIs, typically `cloud-platform`; the minted credential requests only
`https://www.googleapis.com/auth/datastore`. Scope does not grant IAM authority.
The read-only transaction is initiated by `batchGet`'s `newTransaction` field.

Primary API references: [TokenReview and bound tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/),
[GKE cluster get](https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters/get),
[GKE cluster identity and CA](https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters),
[project get](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/get),
[GSA get](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/get),
[UID-target mint](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken),
[Firestore permissions](https://docs.cloud.google.com/firestore/native/docs/security/iam).
