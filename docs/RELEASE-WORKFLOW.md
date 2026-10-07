# Secret-dependent release workflow

This is a private control-plane workflow. The bounded contract prepares an exact
secret dependency and deployment candidate, then commits the approved active
pointer. `day2-gke-release` executes it for installed single-replica GKE app-call
workloads and publishes serving selections from verified deployment readback.
The independent lab providers still exercise fault schedules without cloud access.

## Start with these files

- `ops/Release.roc`: pure step selection from persisted phase and logical occurrence.
- `ops/GkeRelease.roc`: bounded native build-adoption/release drivers and selector publication.
- `crates/day2-control/src/gke_release.rs`: exact Secret Manager access, conditional
  StatefulSet updates, deployment readback and ConfigMap publication.
- `crates/day2-control/src/release_recipe.rs`: runs the checked compiled Roc recipe.
- `crates/day2-control/src/release_execution.rs`: typed effects, durable steps,
  leases, provider validation, outbox, and the Temporal activity backend.
- `crates/day2-control/src/release.rs`: exact Git/build approval, secret readiness,
  desired generation, cancellation/revocation, and atomic activation guards.
- `crates/day2-control/src/simulation/`: independent provider state, fault
  schedules, per-step assertions, and replay.

## Decisions and authority

### Native GKE entrypoint

Install infrastructure with the normal `deploy/gke/stacks/day2-app` root first.
For this profile, use app calls with exactly two CSI keys (workload and issuer),
an immutable image, the installed `runtime` Kubernetes service account and one
SQLite StatefulSet replica. Provider credentials (`provider_credentials`) are
part of the profile; OAuth runtime is a separate profile. Enable
`release_managed = true` on the installed workload; the adapter refuses
workloads without that ownership annotation. Infrastructure plans then read the
current image, artifact guard, release annotations and immutable instance
ConfigMap from the installed controller. They continue to manage pod guardrails,
storage, identity and edge configuration.

`tofu output -json release_deployment` renders public candidate metadata from
the selected stack inputs: the static serving binding, image, instance, CSI
projection, numeric key versions, serving ConfigMap and, for an app with provider
credentials, `credentials` (null otherwise). Key versions are ordered
`[workload, issuer]` and must match those exact CSI paths. `credentials` names the
credential SecretProviderClass and registrant, each pinned entry, and the exact
registration metadata the stack renders from the same instance. The static
deployment binding stays stable across software releases; the complete candidate
input has a separate digest in the durable release plan.

The operator-owned JSON configuration has `version: 1`, `journal`,
`artifact_store`, `instance`, `owner`, `durability`, `authority` and `candidates`.
Each candidate contains the existing typed `ReleaseApproval` and `deployment`
metadata. All candidates belong to one installation/environment. Put callees
before callers for initial deployment. The catalog instance selects the same
app bindings and resource catalog as the per-app deployment renderings. The
artifact store must contain admitted native workers executable on the release
host; use the qualified Linux architecture for Linux deployment. Install
`day2-sandbox` alongside the release executable for native worker admission.

```text
day2-gke-release approve CONFIG
day2-gke-release run CONFIG TOKEN_FILE
```

Approval consumes actual successful build-journal records and the configured
source/policy authority. This CLI makes an explicit local operator assertion;
it does not authenticate a forge merge or infer authority from GitHub CI.
`TOKEN_FILE` is a bounded private regular file containing a short-lived Google
Cloud access token. There is no ambient credential or arbitrary endpoint fallback.

Already qualified native app artifacts can be adopted into the build journal:

```text
day2-gke-release prepare CONFIG ORIGINAL_SOURCE TOOLCHAINS QUALIFIED_DIRECTORY
```

This prints a configuration with the actual build execution/evidence IDs, ready
for `approve`. It requires the preserved native qualification's passed profile,
all 24 required checks, matching native architecture, complete original source
and toolchain pins, every preserved evidence log, and exact admitted artifact
and worker bytes. It runs the existing build state machine to record that actual
evidence; it never replaces a failed or missing qualification with a passing
result. Source/commit and review authority remain explicit operator assertions,
not proof supplied by the qualification receipt. The immutable deployment image
is an explicit operator selection; this adoption checks app build evidence, not
registry provenance of that image. Ordinary builds can supply their existing
successful build IDs without this adoption step.

The command advances the existing release recipe up to 60 times per candidate.
Pending deployment or unknown writes produce an error and retain the durable
execution. Rerun the same configuration to continue. A conditional patch tests
controller UID and resourceVersion before replacing the template. A lost
acknowledgment reconciles the exact release/effect markers and template; missing
markers after an unknown write never authorize a blind second mutation.

Fresh readback requires the prepared controller incarnation, ready current pod,
actual immutable running image, artifact guard, scope and workload identity.
It checks the numeric Secret Manager key accesses and CSI projection again
immediately before journal activation. Secret payload bytes are CRC-checked,
discarded and never journaled. Numeric version accesses are strongly consistent;
IAM and other Secret Manager changes can be eventually consistent, so a
successful access is evidence of that observed access, not an instantaneous
revocation guarantee. See [the provider contract](https://docs.cloud.google.com/secret-manager/docs/access-secret-version).

Activation atomically queues a publication revision with its receipt. After the
selected candidates are active, the driver publishes their coherent serving
snapshot to each selected app's named ConfigMap with conditional writes and exact
readback. Only then does it acknowledge the journal intent. A crash after partial
publication retries safely; an old acknowledgment cannot erase a newer activation
and an older publisher cannot overwrite a newer ConfigMap revision. Calls still
probe physical serving bindings. A single-replica rollout can interrupt calls;
neither deployment nor publication is an atomic cloud traffic switch. There is
no cleanup of old immutable instance or credential ConfigMaps in this increment.

The normal path is:

```text
approved candidate
  -> prepare dependency
  -> observe exact secret version (wait until usable)
  -> prepare deployment
  -> observe that deployment (wait until ready)
  -> activate under current authority
```

Roc selects one operation per advance. It receives only the phase and logical
step number. Rust independently checks the allowed predecessor, company, pinned
recipe and provider bindings, current approval, and exact provider receipt. A
recipe cannot skip preparation by returning `activate` early.

The approved candidate identifies an exact successful build, source commit,
policy and immutable secret version. Approval evidence comes from a trusted host
adapter; a digest is an identity, not authentication of a forge. The qualified
production forge adapter must verify protected merge and exact-candidate checks.
No apply-first/merge-later path is authorized by this workflow. Secret material
is never included in source, the Roc decision input, or simulation traces.
Release admission also requires an explicit runtime-secret binding and atomically
reserves a protected consumer. A retirement barrier blocks new reservations and
pending activation, including through another app alias of the same version.

### Provider credentials

Registration (`day2-provision-credentials` in the `credential-registration`
init container) checks a plan pinned to an operator-only copy of the serving
instance and loads the artifact that instance names from the image. Both belong
to the release: each release creates an immutable
`day2-release-<id>-credentials` ConfigMap from the candidate's
`credentials.metadata`, points the `credential-metadata` volume at it, runs
registration from the released image, rewrites the `credential-files` copy list
for the pinned keys and stamps `day2.dev/credentials-sha256` with the plan's
SHA-256, as the stack does. Infrastructure plans keep those live fields.

The stack keeps the credential SecretProviderClass and the Secret Manager IAM;
the release never writes them. The candidate's `credentials.entries` pin each
reference key, exact numeric version and reviewed fingerprint, and the deployment
input digest pins them all. Before preparing and again before activation the
adapter requires that the SecretProviderClass projects exactly those versions at
those keys, and accesses every version: its checksum must hold and the SHA-256
of the value without trailing newlines must equal the reviewed fingerprint, the
same fingerprint registration enforces. Payloads are discarded after the check
and never journaled. Admission also refuses metadata whose operator instance is
not the candidate instance plus a control section naming only the registrant,
whose plan digests do not match its files, or whose inputs differ from the
pinned entries. A candidate without credentials is refused on a workload that
still has credential machinery, and the reverse.

While `release_managed` is enabled the credential set is fixed: the day2-app
root refuses a plan whose `provider_credentials` keys differ from the live
`credential-files` list, whose registrant differs, whose registration image is
not the released image, or whose versions do not name the project by number.
Adding, removing or rotating a provider credential (a new reference revision
changes its key) is not yet a release-managed change. Until it is, disable
`release_managed`, apply the change with the candidate image and artifact
through OpenTofu, and enable it again.

Approval still registers only the workload key as the release's runtime secret.
Like the issuer key, provider credentials are pinned and verified by the
deployment input, not reserved as protected consumers, so they have no
retirement barrier: disabling a credential version that a release depends on is
not blocked by this workflow.

## Persistence and recovery

`provider_evidence.rs` separates equality-only opaque tokens, ordered revisions
within one identified stream, effect acknowledgments, and qualified read barriers.
A barrier binds the trusted adapter authority, exact resource and (for deployment
readiness) the original preparation effect. A receipt digest is not proof of
provider consistency. An adapter must qualify its protocol before issuing barriers.

Weak secret reads are recorded in workflow evidence but cannot advance the
qualified frontier or grant readiness. A qualified incomparable revision or
contradictory same-revision state records durable uncertainty and invalidates old
ready handles without inventing an ordering. Clearing a same-stream contradiction
requires qualified evidence newer than both the prior state and the conflict.
Incomparable streams and opaque revision changes remain blocked pending an
explicit reviewed resynchronization capability, which this increment does not
implement. Repeated same-state reads may have new receipts
without inventing a new state revision.

Deployment preparation records its physical controller incarnation. Qualified
readback must follow that exact preparation; incarnation drift blocks activation.
These contracts do not turn an empty Kubernetes inventory into a drain proof.
Nonempty legacy journals with untyped evidence fail closed and require an explicit
reviewed migration. Verification never rewrites user journals to bypass this check.

Release execution admission records its dispatch intent in the same SQLite
transaction. The existing Temporal adapter delivers only the execution identity;
the activity reloads persisted state and runs the pinned recipe. Polls and
retries do not depend on an in-memory Roc process or a retained readiness handle.

The release-step journal is additive. The existing build workflow keeps its
three single-use effect kinds. Release steps instead identify a logical name and
occurrence within a pinned execution. Retries reuse that identity; a new completed
observation advances the occurrence. Lease epochs fence journal completions, not
remote requests already sent by another worker.

Provider I/O happens outside SQLite transactions. After an ambiguous mutation,
the next attempt reconciles its exact identity. Mere absence from an eventually
consistent list is not proof that a mutation was never applied. An unresolved
outcome must remain explicit instead of permitting a blind second mutation.

Activation rechecks current desired generation and readiness. The active pointer,
activation receipt, workflow completion, consumer protections and audit are committed together.
Superseded or revoked candidates cannot take over, and replaying an old receipt
does not restore an old active pointer.

These deployment-proof and workflow-completion guarantees apply to releases
enrolled in this workflow. The older native `Journal::activate_release` primitive
remains for unenrolled secret-readiness guard fixtures; it refuses enrolled
releases. It is not an app SDK or an alternative production deployment entrypoint.

## Qualification boundary

The lab must demonstrate both safety and progress: no unauthorized or stale
activation at any boundary, and actual activation of the newest eligible release
after finite recoverable faults stop. Missing prerequisites and genuinely unknown
mutation outcomes require explicit durable waiting/intervention states, not a
successful-looking runner exit.

Provider facts are observations, not omniscience. A secret revocation that has
not yet been observed cannot be made atomic with SQLite activation. Real adapters
need qualified readback and, where available, provider-side conditional writes.
The simulator separates external secret availability from a watcher delivering
that metadata into the journal. Delivered changes must invalidate stale readiness;
unacknowledged provider reads are not treated as delivered evidence.
The current active pointer is not an atomic cloud traffic switch, nor a guarantee
that an externally disabled incumbent secret remains usable. Destructive shared
resource transitions now have a separate [protected-retirement contract](RUNTIME-SECRET-LIFECYCLE.md).
Routing activation, general cleanup/compensation, irreversible destruction and
broader secret-manager semantics still need contracts and conformance tests.

See [the lab guide](DETERMINISTIC-LAB.md) for campaign/replay commands and
[verification coverage](VERIFICATION-COVERAGE.md) for the remaining suite
porting obligation. HTTP fixtures validate provider protocols separately from
native runtime qualification and actual GKE deployment evidence.
