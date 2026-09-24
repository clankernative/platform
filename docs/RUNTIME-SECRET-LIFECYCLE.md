# Runtime secret rollover and protected retirement

This increment models application runtime-secret versions, not the credentials
the control plane uses to call GitHub or a secret provider. Secret material is
supplied through an authorized channel and assumed valid for its upstream
service. Creating or revoking that upstream password/key is a separate capability.
Neither the journal nor the simulation accepts secret material.

## Main files

- `crates/day2-control/src/runtime_secret.rs`: canonical resource identities,
  app binding admission, consumer protections, retirement barriers and audit.
- `crates/day2-control/src/release.rs`: release approval reserves a consumer;
  activation updates consumer protections in the same SQLite transaction.
- `crates/day2-control/src/release_execution.rs`: the existing durable deployment
  host rechecks version availability at claim, dispatch and activation boundaries.
- `ops/Release.roc`: the existing pure replacement-deployment recipe.
- `ops/SecretRetirement.roc`: the pure protected-disable recipe.
- `crates/day2-control/src/secret_retirement.rs`: retirement leases, provider
  dispatch, exact receipts, reconciliation and Temporal outbox.
- `crates/day2-control/src/simulation/retirements.rs`: the shared-consumer oracle
  and integration into the existing generated world.

## Identity and authority

`ProviderResource` identifies the physical provider/account/secret. A
`SecretVersionKey` adds the immutable numeric version. App aliases and mutable
binding revisions do not partition the physical resource's retirement accounting.
Two authorized app bindings can point at the same key; a different company or
environment cannot claim that resource as its own.

Every release approval requires an explicitly registered target/reference pair.
Registration is a trusted installation-adapter action, not an app capability.
The resource's retirement authority is separate from an app's Git approval and
pins its own policy and revision. Neither a digest nor an operator-name string
is production authentication: live adapters must establish their provenance.

The `Available` lifecycle state means new consumer reservations are permitted.
It does not establish physical existence, enabled state, access, projection or
credential validity. The release recipe still requires exact readiness and
deployment readback before activation.

## Rollover

```text
register supplied V2 and its authorized app bindings
  -> approve an exact successor build using V2
  -> prepare and observe V2 readiness
  -> prepare and observe the exact successor deployment
  -> activate that successor
  -> separately observe the old deployment drained
  -> explicitly release policy-retained rollback protection
```

The existing release recipe handles deployment preparation and activation. A
failed, cancelled or superseded successor does not disable V1. Activating V2
does not infer that the old V1 deployment has disappeared: its consumer becomes
`Draining`, with rollback protection retained. Other apps using V1 keep their
own independent protections.

A drain observation binds the old release, successor, canonical version, exact
deployment fact and prepared physical controller/generation. The prepare
acknowledgment records that incarnation before a later drain may refer to it.
It comes from a trusted adapter, separately from the active-pointer update.
Outstanding dispatched or
ambiguous deployment work prevents releasing the consumer. Unstarted abandoned
candidates have a narrower explicit cleanup path; clearing a current deployment
pointer is not proof that an earlier provider mutation never happened.
The simulator schedules physical deployment quiescence separately from fetching
and accepting its drain readback. Requesting a readback cannot stop old work or
invent a quiescence fact.
A stopped deployment cannot satisfy the provider's readiness readback. Stopping
work without fencing its controller does not establish that it cannot restart.

### Physical quiescence evidence

`ConsumerQuiescenceProof` separates `ObservationOnly` from
`TerminatedAndFenced`. API deletion, zero visible pods, an idle process or a
digest describing those observations cannot release a consumer. The only
admitted positive proof in this increment declares complete termination of the
prepared incarnation, all descendants and delegated work, and a retained fence
preventing future recreation. Logical fences alone are unsupported: they would
also need to cover already cached credentials and delegated work.

The trusted host must first record an explicit qualification review for that
exact prepared deployment, adapter binding revision and physical incarnation.
A proof references the resulting private-construction authority handle and
binds its own exact release/version/successor/deployment subject. This is a
trusted-adapter attestation boundary, not a cryptographic proof that a provider
really stopped work. No live provider is granted this authority automatically.
The synthetic provider's closed-world qualification is not cloud qualification.

Qualification revocation and observed controller/generation changes invalidate
the proof for subsequent drain, rollback-release and disable guards. Historical
receipts remain immutable and readable. `ConsumerCounts.unproven` includes
previously freed consumers whose evidence is no longer current; these count as
protected even though their historical stage is still `Drained`. Incarnation
history prevents a stale observation from restoring an earlier identity.
Replaying an old qualification request likewise cannot undo a later revocation.

This increment has no replacement-proof recovery operation. A new review does
not silently replace the immutable accepted drain receipt or free its consumer
again. Such a consumer remains protected until a future explicit, reviewed
recovery contract is implemented.

Cancelled candidates that prepared a deployment but never activated remain
protected in this increment. They need a future qualified pending-deployment
discard capability; the never-deployed abandonment path cannot release them.

## Retirement

```text
Available -> Retiring -> Disabled
                |
                +-- wait for every protected consumer
                +-- disable the exact provider version
                +-- observe the exact disabled state
                +-- commit the physical receipt and terminal outcome
```

Retirement atomically installs a durable barrier and its workflow/outbox record.
New bindings, new release reservations and pending activations cannot use that
version afterward. Existing active consumers remain protected while replacements
move through their own release workflows.

The barrier closes the race between checking references and dispatching disable.
Pending, active, draining, policy-retained rollback and no-longer-proven freed
consumers all block that dispatch. Multiple retirement requests cannot create independent destructive
executions for the same physical version.

Provider I/O remains outside SQLite transactions. The host records dispatch
before calling the provider, fences expired completions, and reconciles uncertain
mutations. A lost response is not permission to disable again. A retry after an
uncertain dispatch requires qualified evidence of nonapplication. Revocation
blocks new writes but does not erase receipts for work already dispatched.
The durable dispatch marker is the authorization boundary. A provider request
authorized before revocation can arrive afterward. Evidence of nonapplication
must establish that the old request cannot still apply; a missing or delayed
receipt alone is insufficient.

Revocation leaves the barrier in place. This increment has no operator recovery
contract for resuming a stopped retirement or withdrawing its barrier; restoring
authority does not automatically resume it. That is an explicit recovery limit,
not permission to edit journal rows or re-enable the version.

If consumer quiescence becomes unproven after a disable was already dispatched,
the exact qualified physical disabled readback is still recorded. The terminal
outcome is stopped for lost authority, not successful protected retirement.
Re-protection cannot undo a provider mutation or justify concealing its result;
it prevents new dispatch and prevents claiming that the safety obligation held
through completion.

This workflow performs protected **disable**, not irreversible destruction.
External re-enablement, secret-container deletion and upstream credential
revocation are not silently folded into this contract.

## Journal compatibility

Runtime-secret schema version 2 stores incarnation history and explicit
quiescence qualification receipts. All version-1 runtime-secret journals,
including empty ones, fail closed rather than upgrading weaker evidence.
Fresh journals initialize version 2. No accepted drain is promoted to a stronger
proof by renaming fields or synthesizing a qualification.

An older control journal containing release approvals without canonical consumer
records fails closed on open. Release history alone does not establish physical
secret identity or prove that old deployments stopped. Those journals require an
explicit, reviewed migration with trusted resource bindings and conservative
consumer protections; this increment does not implement that migration.
Journals that have neither runtime-secret schema metadata nor existing release
approvals can initialize normally. Existing user journals are not reset or deleted.

## Generated acceptance

The shared world contains six candidate builds: competing revisions of one app,
two revisions of a second app sharing V1/V2 through another alias, and an
independent company's app. The same real release/retirement hosts and SQLite
journal run under generated admission, worker scheduling, faults and restarts.

The independent oracle derives expected protections from admitted approvals,
validated activations and separately accepted drain/rollback observations. It
does not trust the lifecycle table's consumer count as its expected answer.
Coverage must witness actual shared consumers, blocked retirement, rollover,
cleanup, disable and reconciliation during generated scheduling. Recovery-pass
progress cannot substitute for that evidence.

See [STATEFUL-SIMULATION.md](STATEFUL-SIMULATION.md) for campaign, replay and
semantic shrinking commands. The provider remains synthetic. Qualification of
canonical provider identity, quiescence observations and ambiguous disable
semantics against small real-provider sandboxes is still required before a
production deployment claim.

## Provider Qualification

A real secret/deployment adapter must pass adversarial conformance tests against
its actual provider before the synthetic lab's results transfer to that adapter:

- **Canonical identity:** Different app aliases resolve to the same physical
  provider/account/secret/version key. Binding changes cannot split consumer
  accounting, substitute `latest`, or cross company/environment ownership.
- **Qualified absence:** Reconciliation identifies the exact dispatched effect.
  Permission to retry requires evidence that it neither applied nor can apply
  later, including queued requests and delayed acknowledgments. An empty lookup,
  timeout or expired host lease is not sufficient. Where the provider cannot
  establish this, the result must remain ambiguous and require intervention.
- **Exact quiescence:** Drain readback establishes that the exact old deployment,
  descendants and delegated work have terminated, with a retained fence against
  recreation. It binds the deployment effect, readiness, prepared incarnation
  and current qualification revision; a successor's active pointer is not
  evidence. A replacement incarnation invalidates the old proof. API absence,
  physical stopping, fencing and readback visibility must be tested separately.
- **State and revision:** Enabled/disabled and deployment-readiness observations
  refer to the exact immutable version and deployment. Provider revisions must
  support the contract's ordering checks across stale reads, retries and restarts;
  adapters cannot invent increasing revisions to conceal contradictory results.
- **Crash and authority boundaries:** Exercise crashes before dispatch, after
  provider application and before journal settlement, lost acknowledgments,
  duplicate delivery, and revocation during reconciliation. Prove stable effect
  identity, no blind repeat mutation, and exact receipt recovery without putting
  credentials or secret material into plans, history or audit evidence.

These adapters are not qualified yet. The lab uses an authoritative synthetic
receipt ledger and explicit synthetic quiescence; native and Temporal tests exercise
host behavior against those contracts, not real-provider consistency, IAM or
workload lifecycle behavior. Small provider sandboxes, late-application probes
and deployment-controller conformance remain necessary. Protected disable also
does not prove upstream credential validity or implement credential revocation,
version destruction, or recovery of a stopped retirement barrier.

## Focused verification

Build the pinned private Roc runner before invoking the native test suites:

```text
cargo run --locked -p xtask -- workflows
cargo test --locked -p day2-control --test runtime_secret --test secret_retirement
cargo test --locked -p day2-control --test durable_secret_retirement
cargo test --locked -p day2-control --test simulation_retirement --test simulation_generation
```

The durable test starts a disposable local Temporal server with persisted state,
restarts it after a lost provider acknowledgment, and replays its history. Its
provider receipts live in a separate SQLite database. The simulation test
requires a complete two-app rollover, one shared disable, bounded JSON evidence,
and exact replay; the generation suite tests typed histories and shrinking.
