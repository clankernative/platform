# Typed app queries on normal hosts

Apps call their generated `ImportedContracts` functions. Input/result types and
operation digests come from the caller's exact build imports. There is no app API
for selecting a peer URL, signing a request or choosing an actor. The host resolves
one current resource grant; the receiver separately authorizes the inherited actor.
Nominal root records are generated once per type ID. Unsupported nested nominal
codec dependencies fail the build rather than being erased to structural types.

The container entrypoint accepts `day2-serve INSTANCE APP --edge --app-calls HOST_JSON`.
Private POST endpoints `/_platform/app-issue` and `/_platform/app-query` require
exactly one IAP workload assertion. Human/browser capacity is separate from the
bounded eight-call private pool, so a query can obtain its issuer proof from its
own host without taking its own browser permit. Bodies, proof lifetimes, response
bytes, deadlines and peer/key counts are bounded. Unsupported paths, redirecting
transports, unknown fields and unauthenticated claims are refused.

`day2-control::app_host::Configuration` is infrastructure bootstrap, not company
business policy. It fixes one installation/environment/app, workload identity,
managed signing-key files, public peer trust keys, gate audiences, peer URLs and
GKE serving bindings. Grants remain in activated instance authority. The issuer
reopens the durable invocation, checks its current authority and exact imported
grant, verifies the root IAP account binding and only then signs the request.
The receiver checks IAP, both signatures, the current selected serving generation,
its loaded artifact and its own current operation/row policy.

The first query flow supports human-rooted calls in one installation/environment.
Other origin families require their admitted ingress. App reentry and chains
deeper than four hops are refused. Durable remote command sends are the next
implementation batch; query admission never accepts a command as a read.

## GKE deployment

The `app-edge` root's optional `app_calls` creates two distinct protected backends,
routes only the exact private paths to them and publishes their resolved audiences.
The issuer backend grants only its own workload; the receiver grants explicitly
selected incoming workloads. Neither uses the human backend's domain membership.
The runtime KSA impersonates its bound GSA using Workload Identity. That GSA can
sign JWTs only as itself and discover clusters; namespace RBAC permits `get` of
only the exact StatefulSet, ordinal-zero pod and runtime service account. An explicit
network policy permits HTTPS to the selected Kubernetes serving API CIDR.

The `day2-app` root's optional `app_calls` renders the bootstrap file and mounts
two exact Secret Manager versions through CSI. A fixed file-install init container
copies keys into a memory volume as UID 10001, mode 0400. The serving container
mounts it read-only. Include these secret IDs in `app-edge.runtime_secret_ids`.
Private key bytes never enter OpenTofu state. Independent issuer/workload keys
and public trust sets permit explicit rotation; a missing key fails startup.

Both the StatefulSet and pod declare installation/environment/app/artifact.
`DAY2_EXPECTED_ARTIFACT` fences actual host loading. The authenticated GKE probe
checks cluster CA, controller UID/generation, ready revision, pod ownership,
running pinned image, artifact environment and KSA-to-GSA binding before and
after the call. Request claims are never substituted for provider observations.

The release host exports active selectors atomically using
`day2-serving-snapshot JOURNAL TARGETS_JSON OUTPUT`. Targets are an exact bounded
JSON array of release targets in one installation/environment. The exported file
contains only checked active serving selections, never the control journal.
Publish those bytes as `serving.json` in the configured serving-snapshot ConfigMap
when releases activate or change. Its directory mount follows atomic ConfigMap
updates without rolling the app workload. The mount may initially be absent so
the workload can become ready before activation; calls fail until a matching
selector exists. The host rereads selection and fresh provider evidence around
every call. Publication is part of deployment integration, not an app-maintained
operation/type catalog.

The local HTTP/provider fixtures establish protocol and host wiring. They do not
establish real cluster authentication or production readiness; the fresh two-app
cluster canary belongs to the integrated qualification batch.
