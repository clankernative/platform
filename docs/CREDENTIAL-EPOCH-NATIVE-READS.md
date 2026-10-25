# Private credential epoch read acquisition

The native read adapter is a private AppHost/controller implementation beneath
`security_epoch`. It does not register an app capability or bootstrap command.
A read observation cannot authorize Create, Activate, restore or takeover.
The selected [connection/request contract](CREDENTIAL-NATIVE-ENROLLMENT.md#admitted-connections-and-fresh-requests)
is being implemented and requires separate native qualification.

## Acquisition and support

Full connection authentication begins with actual Linux `CLOCK_BOOTTIME`,
before entropy, executable, projection, authentication or database I/O. Its
authentication work spends at most five seconds inside the same admission
parent and any shorter cap. Successful material is retained only by the actual
admitted connection, exact recipient, policy/store binding and credential expiry.
It cannot authorize a later operation on its own or reconstruct its owner.

Each later coherent Firestore read borrows a fresh bounded request from that
same live owner. It does not repeat metadata/TokenReview/workload/GSA/database
authentication. Its original interval, every HTTP timeout and response-body
read respect the ordinary five-second request limit and all shorter ceilings.
Current authority, counters and actual owned-handle checks remain fresh. A
failed request, rewind, process/binding change or expired credential refuses the
actual owning phase. A new authentication operation cannot revive refusal or
renew an existing request, human original or signed grant.

App-serving reads require the separate signed `AppServing` purpose and its
same-origin thirty-second ceiling: **temporary, user decision 2026-10-25, revert
after 3 measurement runs**. Generic Current and Shell retain their five-second
bounds.
Role authentication still finishes within the first five seconds of that
original. Each distinct App provider-authentication operation captures one
opaque, at-most-five-second work window immediately before its first native
check. Its deadline is also bounded by the original App parent, signed purpose
and selected lease; it retains that parent's origin, domain, process and sticky
refusal. An expired or dropped work owner cannot be reopened or replaced, and
only the same actual enrolled owner can consume it before deriving the retained
I/O view from the original parent.
This does not renew the App grant. Generic Current, Shell, storage-bootstrap and
metadata-observation authentication keep their existing first-prefix bounds.
Shorter leases, signed ceilings and individual HTTP timeouts still narrow the
caller's original interval. See the
[scope and rollback rules](NATIVE-HANDSHAKE-SIMULATION.md). A failed request, clock rewind, process change or selected
resource mismatch refuses the owning acquisition. There is no renewal.

The process observer retains `/proc/self/exe`, hashes its actual bytes and
checks the original descriptor and current executable identity at full admission.
The selected
`controller_code` is that executable's SHA-256, not a container image hash.
Later request checks join retained/named executable and namespace handles without
scanning the bytes. These observations do not establish immutable executable
memory, time namespace
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
admission and process-to-Pod binding before its native owner can serve requests.
Connection admission requires a borrowing real enrolled AppHost or EpochController
stage matching the complete bootstrap/store selection. AppHost selects its
native host executable independently of its Roc artifact. SecurityShell is not
an epoch reader. Each later request borrows the same admitted actual owner through
its operation and local use; its narrower I/O clock preserves that request's
original domain, origin and earlier deadline. Code selections or parsed
certificates cannot create that
borrow. See
[runtime identity selections](CREDENTIAL-RUNTIME-IDENTITY.md#selected-container-data).

## Full admission response checks

These are genuine connection-admission checks, not requests to repeat at every
serving boundary. Selection/recipient, current authority, credential expiry,
actual handles and fresh coherent counters still constrain each later use.

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
