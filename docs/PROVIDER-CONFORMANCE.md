# Provider Conformance Probes

This increment captures narrowly scoped GCP Secret Manager and optional GKE
observations to challenge assumptions in the deterministic lab. It is not a
qualified production retirement adapter, a deployment workflow, or a new app SDK.
The receipt deliberately reports `status: "observed_not_qualified"` and
`provider_qualified: false`, including when every probe completes.

A live run requires an operator-designated sandbox project, credentials,
precreated disposable secret versions and, optionally, a GKE target. No live
execution is implied by local fixture tests or by the existence of this command.

## Safety Scope

The only remote mutations are conditional disable requests for the two exact
numeric secret versions named in the admitted profile. They must be disposable
and unused by any workload. The ownership label is an admission check, not proof
that no external system consumes those versions; the operator must establish
that before running the probes.

The runner does not create projects, secrets, versions, aliases, clusters or
deployments. It does not enable APIs, grant IAM, fetch secret payloads, destroy or
re-enable versions, stop workloads, or perform automatic cleanup. The optional
GKE probe is read-only and independent of the two secret-disable probes. It does
not authorize disabling a secret used by the observed deployment.

An explicit token file is the only credential input. There is no ADC, metadata
server, ambient `gcloud` configuration, kubeconfig or credential-command fallback.
Native clients bound response sizes and request deadlines, reject redirects,
disable automatic request retries, and retain uncertainty after a lost response.

## Prerequisites

Before the first invocation, an operator must supply:

1. A designated sandbox project number and an existing Secret Manager secret
   whose name begins with `day2-conformance-`.
2. The secret label `day2-conformance-run` with exactly the profile's
   `run_marker`, and two distinct, existing numeric versions initially `ENABLED`.
3. Two distinct, existing version aliases that both map to `lost_ack_version`.
   The probe reads their map and verifies the numeric version metadata; it does
   not create aliases or use `latest`. See Google's
   [version-alias documentation](https://docs.cloud.google.com/secret-manager/docs/assign-alias-to-secret-version).
4. An operator-owned JSON profile with `environment: "sandbox"` and an absolute
   Unix-seconds expiration later than now but no more than one hour away.
5. A regular token file with owner-only permissions, normally mode `0600`,
   containing a valid OAuth access token. Provision a principal restricted to the
   intended metadata reads and version disables, plus the optional GKE read
   permissions. Secret payload access is neither needed nor exercised.
6. An existing parent directory for a fresh, private evidence directory. A new
   run refuses an already-existing evidence directory.

Resource provisioning, API enablement, IAM and token issuance remain explicit
operator prerequisites. The CLI does not perform hidden setup.

## Profile

The contract is [`Profile`](../crates/day2-control/src/provider_conformance.rs).
Unknown fields, mismatched scope, invalid identifiers, nonnumeric versions and
expired authorization are rejected. This example is intentionally inadmissible:
the project and resource names are illustrative, and `expires_at_unix: 0` must
not be treated as an authorization.

```json
{
  "format": 1,
  "installation": "exampleco",
  "environment": "sandbox",
  "project_number": 123456789012,
  "secret": "day2-conformance-example",
  "run_marker": "example-run",
  "aliases": ["app_a", "app_b"],
  "lost_ack_version": 1,
  "late_version": 2,
  "expires_at_unix": 0,
  "gke": null
}
```

An optional `gke` object has this shape:

```json
{
  "project_number": 123456789012,
  "location": "us-central1",
  "cluster": "designated-sandbox",
  "namespace": "day2-conformance-example",
  "deployment": "designated-deployment",
  "deployment_uid": "operator-observed-deployment-uid",
  "revision": "1"
}
```

The project must match the secret project. The namespace must start with
`day2-conformance-`; deployment UID and revision must identify the intended
existing deployment. The adapter discovers the designated cluster's endpoint
and CA through GKE, then performs scoped Kubernetes reads. The token needs
cluster discovery and the required Deployment, ReplicaSet, Pod and Node read
access; the cluster endpoint must be reachable from the operator's machine.
No endpoint, credential command or arbitrary provider URL is accepted in the
profile. `gke: null` leaves the quiescence obligation unfulfilled; it is not a
passing quiescence result.

## Run And Resume

Run inside `platform/`, replacing the arguments with the operator-designated
profile, private token file and evidence directory:

```text
cargo run --locked -p xtask -- provider-conformance PROFILE TOKEN_FILE NEW_DIRECTORY
cargo run --locked -p xtask -- provider-conformance-resume PROFILE TOKEN_FILE DIRECTORY
```

The first command validates local inputs, binds a new evidence session, builds
the pinned private Roc runner and executes its fixed probe sequence. Profile
data stays in the Rust supervisor; Roc requests only closed capabilities with
empty inputs. It cannot choose a project, version, endpoint or credentials.

Before compilation or provider I/O, the CLI also creates a private, create-only
reservation under `artifacts/provider-conformance-runs`. Its identity includes
the project number, secret, ownership marker and sorted pair of numeric versions,
not the profile's expiration or the versions' probe roles. The reservation binds
the fixture to its canonical evidence directory. A second fresh run cannot
automatically admit the same fixture in another directory, even after expiration
or a compilation failure. Resume must match the original reservation. Failed
admission leaves existing files untouched; do not delete the reservation to
work around a refusal.

This registry prevents accidental fixture reuse within this workspace; it is
not a distributed provider lock and does not grant authority by itself. Using a
new fixture marker requires an explicit operator decision and matching resource
ownership label. Session expiration and implementation checks still apply.

Resume requires the same profile identity, implementation pin and observation
origin, plus authorization that has not expired. A refreshed token may be
supplied explicitly. Editing the profile's expiration or changing code does not
authorize continuing an old session. An expired or incompatible session requires
operator review, not deletion of its evidence and a blind restart.

Completed observations are reused from the checkpoint. A dispatch intent is
committed before provider I/O; if the process stops without recording its result,
resume records uncertainty rather than dispatching again. The original version,
creation time and ETag are retained. The adapter does not refresh an ETag to make
a previously rejected or ambiguous mutation succeed. This conservative policy
can leave a version unchanged when a crash occurred before network dispatch.
That is an unresolved observation, not permission for an automatic retry.

## Probe Sequence

[`ProviderConformance.roc`](../ops/ProviderConformance.roc) owns the order; the
native session independently enforces it and stops on errors.

| Boundary | Observation and limitation |
| --- | --- |
| `provider-open` | Validate ownership and capture the two enabled versions' identities and ETags. |
| `provider-aliases` | Check that both configured aliases resolve to the same exact numeric version. |
| `provider-lost-ack-dispatch` | Dispatch at most one conditional disable for the first version, deliberately withholding its response from the session's outcome. |
| `provider-lost-ack-observe` | Read that version's metadata. A disabled postcondition is not proof that this exact native effect caused it. |
| `provider-late-hold` | Persist the second version's intended request without sending it. |
| `provider-late-observe` | Read metadata while the original request is still held locally. An enabled observation cannot authorize another disable. |
| `provider-late-deliver` | Deliver the originally held request once, with its original ETag. |
| `provider-late-reconcile` | Capture subsequent metadata without retrying the mutation. |
| `provider-quiescence` | Capture optional GKE controller, Pod and Node observations, or record the missing target. Never create a native drain receipt. |
| `provider-receipt` | Persist the completed observation report, limitations and retained cleanup obligations. |

The late-delivery experiment controls a request **before it reaches GCP**. It
does not demonstrate that GCP queued a request, nor does it establish the absence
of provider-side late application. It demonstrates why an early read is
insufficient to justify retrying an outstanding mutation. A rejected request or
inconclusive metadata read remains recorded as such; completing the sequence is
not equivalent to observing both versions become disabled.

## Why Qualification Remains False

Secret Manager documents strong consistency for adding and accessing an exact
numeric version, but not for aliases or the other operations used here. Metadata
observations must therefore not be promoted to authoritative absence or ordering
proofs. See [resource consistency](https://docs.cloud.google.com/secret-manager/docs/reference/consistency).

The [disable API](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/disable)
accepts an ETag precondition. This probe preserves that token as opaque equality
evidence; it does not invent an ordered `provider_revision` from it or manufacture
an exact-effect receipt from a disabled readback. See also Google's
[ETag guidance](https://docs.cloud.google.com/secret-manager/docs/etags).

Kubernetes controllers can create replacement Pods, and deletion from the API
does not by itself prove that a process has stopped. The adapter therefore
reports physical quiescence as unproven even if the API lists no remaining Pods.
It does not prove controller fencing, node shutdown, or cessation of traffic and
external work. See [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
and [Pod termination semantics](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#forced-pod-termination).

These limitations prevent this adapter from supplying the stronger receipts
required by the [runtime-secret lifecycle](RUNTIME-SECRET-LIFECYCLE.md#provider-qualification).
The native hosts now enforce that distinction with the typed contracts in
[`provider_evidence.rs`](../crates/day2-control/src/provider_evidence.rs) and the
runtime-secret incarnation/qualification registry. These probes still cannot
issue qualified read barriers or terminated-and-fenced drain proofs. Their
observations do not bypass those requirements; no live provider gained authority
as a result of the synthetic simulation hardening.

## Evidence And Cleanup

The private evidence directory contains `identity.json`, `profile.json`,
`observations.sqlite3`, `session.lock` and, after completion, `receipt.json`.
The append-only SQLite transcript binds ordered intent/result pairs through
digests to the profile and implementation. A process lock excludes concurrent
use of the same session. The transcript has explicit event and byte budgets.

Evidence contains metadata, not OAuth tokens or secret payloads. Metadata still
includes enterprise resource identities and should remain protected. Local
digests detect inconsistent evidence; they are not a signature from Google or a
tamper-proof store against an administrator who controls the entire directory.

Receipt `origin` distinguishes `live_gcp` from `transport_fixture`.
`live_provider_calls_replayed: false` is intentional: checkpoint validation and
reuse are not deterministic replay of cloud services. Fixture tests exercise
the protocol and guards without cloud credentials and cannot count as live
provider qualification. Ordinary verification must not require live secrets.

There is no cleanup automation. Retain the evidence, review every dispatched
intent and observed result, and leave the disposable versions disabled if they
were disabled. Unknown outcomes require operator reconciliation. Do not re-enable
or destroy a version merely to restore the fixture. Cleanup, new fixtures and
any later live probe require explicit operator decisions.

## Main Files

- [`ops/ProviderConformance.roc`](../ops/ProviderConformance.roc): fixed private probe sequence.
- [`provider_conformance.rs`](../crates/day2-control/src/provider_conformance.rs): profile, token input, checkpoint and receipt guards.
- [`gcp_secret_conformance.rs`](../crates/day2-control/src/gcp_secret_conformance.rs): bounded metadata and conditional-disable adapter.
- [`kubernetes_conformance.rs`](../crates/day2-control/src/kubernetes_conformance.rs): conservative, read-only GKE observations.
- [`xtask/provider_conformance.rs`](../crates/xtask/src/provider_conformance.rs): explicit operator command adapter.
- [`workflow_tests.rs`](../crates/day2-ops/src/workflow_tests.rs): compiled Roc ordering, stop-on-error and invalid-command tests.
- [`gcp_secret_conformance` tests](../crates/day2-control/tests/gcp_secret_conformance.rs): local HTTP protocol fixtures.
