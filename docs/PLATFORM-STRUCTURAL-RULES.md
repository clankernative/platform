# Platform structural rules rollout

The platform must enforce the same explicit authority, bounded execution and
deterministic decision boundaries that it supplies to applications. This plan
turns the principles behind RADICAL into executable restrictions and evidence.
Roc remains the product and operational composition language; Rust owns native
kernels, admission, enforcement and adapters as required by [AGENTS](../AGENTS.md).

Each pull request must identify the illegal program, durable state or execution
schedule it rejects, include a valid positive control, and record the exact
locally verified head. A checklist or type name alone establishes no guarantee.

## Pull request sequence

| Slice | Change and ownership | Required evidence and dependency |
| --- | --- | --- |
| 1 | Generic platform architecture ratchet, strict source/dependency inventory and reviewed ambient-effect allowances; this rollout owns xtask and configuration. | Reject new, moved, increased and stale allowances, aliases, test-scope escapes and malformed policy. Run in existing fast/full lint gates; pin policy bytes in verification and build identities. No production behavior changes. |
| 2 | Strict dependency and effect boundaries for shared contracts and extracted platform decision kernels; this rollout owns the control-plane extraction. | Explicit normal/build dependency allowlists, no runtime dependencies or ambient calls in strict sources, unknown crates rejected, real production kernel moved behind the boundary with compatibility reexports. |
| 3 | Enforced sealed proof APIs for readiness, authorization and consuming dispatch; this rollout owns control-plane proofs, domain owners retain OAuth/credential APIs. | Negative compiler fixtures for construction, deserialization, cloning consuming permits and wrong-stage calls. AST checks guard configured proof shapes; mutable wire records cannot become authority by decoding. |
| 4 | OAuth effects ports, complete deterministic lifecycle coverage and durable schema invariants; existing OAuth DST owner retains its source lease. | Shared production/simulation clock, entropy, transport and custody boundaries; exact replay, independent oracle, schema upgrade negatives, SQLite races and process kill/reopen. Integrate after a frozen verified-head handoff. |
| 5 | OAuth prepared settlement and custody proofs, plus credential boundary follow-up under an explicit lease. | Commit metadata and encrypted material together; bind responses to exact slot/account/profile/generation/epoch. Consume secret-reveal permits only at protected sinks. Revalidate authority at use. Remove migrated generic exceptions. |
| 6 | Mandatory provider pack evidence and canonical operation authority. | Register production and simulation adapters together; require protocol conformance and exact readiness evidence. Derive channels and permission summaries from one operation graph; old consent cannot widen. |
| 7 | Bounded execution, isolation and typed uncertainty across runtime and control plane. | Enforced row/byte/execution/retry/queue limits; fairness and cancellation schedules; unavailable authorization fails closed; ambiguous writes reconcile before qualified retry. Preserve exact bindings and one mutation authority. |
| 8 | Release, resource and observability evidence closure. | Desired/prepared state cannot activate without readiness; ordered transitions cannot be superseded; exact artifact/contract/binding identities survive recovery. Missing telemetry is explicit. Restore and adapter conformance remain real-world qualification obligations. |

Slices are ordered by dependency, not by permission to edit another owner's
files. Independent slices may proceed in separate worktrees. Domain behavior
already being implemented by another session is integrated once, after handoff.
Every completed slice removes its obsolete exceptions rather than refreshing
them into a larger baseline.

## File leases and merge order

An owner declares exact files, worktree, base/head and resource use before editing.
Shared verification files have one owner at a time. Changes to the same lockfile
preserve independently added package dependency edges; changes to dependency
versions or features need explicit coordination. A waiting owner may continue
work that does not depend on the contested source or validation resource.

Full native gates run against frozen sources and have a shared local resource
lease. Scoped compilations use bounded build parallelism. A merge handoff names
the verified head, commands and receipts, failures and remaining scope. Merge
one exact head, rebase its dependents, and rerun checks affected by integration.
An earlier receipt never qualifies a changed source snapshot.

The user permits public rollout PRs to merge after local validation when hosted
Actions cannot start because organization funding is unavailable. Record that
condition explicitly; actual test failures must be fixed or clearly established
as unrelated with independent evidence. Preserve branch protection settings.
This authorization covers public code integration, not private deployments,
cloud mutation, secret access or qualification VM ownership.

## Architecture ratchet

`cargo run --locked -p xtask -- architecture-check` checks the reviewed
`architecture-rules.json`. `architecture-inventory` reports facts to stdout; it
does not modify policy or approve new allowances. Every native verification
recipe checks these boundaries before execution; `verify-lint` checks them again
before Clippy in both fast and full verification.

The source catalog is explicit and exact. The checker parses authored production
Rust, follows test-only module scopes and visits other conditional code
conservatively. It records calls to ambient time, entropy, environment, scheduler,
process, filesystem and network primitives, plus prohibited SQLite ambient
functions and relevant lint suppressions. Call fingerprints use normalized syntax
and context, not line numbers. Changed context, additional calls and removed
calls require review; comments and formatting cannot grant an allowance.

`architecture-boundaries.json` classifies every workspace package and pins its
declared dependency kinds, production target sources, aliases and feature selections. Unknown
packages or dependencies fail, including optional and alternate-target entries.
Contract and kernel packages cannot depend on runtime/adapter/tool packages in
normal or build dependencies, and cannot contain ambient-effect allowances.
Kernel source uses `no_std`; dependencies may still use std transitively, so this
is a source/API boundary rather than proof of transitive purity. Dependency
versions and actual resolved transitive packages remain pinned by Cargo.lock.

The production build decision engine and `BuildPlan` now live in `day2-kernel`.
The existing `day2-control::{kernel,contracts}` paths reexport these same types;
the control adapter retains I/O and `Instance` planning. Kernel dependencies are
explicitly limited to `anyhow`, `serde`, and shared `day2-capabilities`, with
`serde_json` available only in tests. Historical wire behavior is preserved:
unknown discriminators and malformed data-bearing variants reject, while serde
unit variants such as `Accepted` still accept extra fields pending a separate
codec admission change.

After verifying Cargo's exact target sources and dependencies, the boundary
checker requires unconditional crate-level `forbid` attributes for unsafe code
and Clippy's disallowed methods, types and macros. It checks strict production
libraries with the pinned `architecture/clippy.toml`, including resolved aliases,
and replaces inherited lint-cap flags so they cannot weaken this host check.
Strict packages have one production library target; adding a binary or build
script needs a reviewed enforcement boundary. Kernel sources additionally
require unconditional `no_std` and reject explicit function-pointer, callback,
async and Future interfaces. Pure closures and serialization bounds remain
valid. This syntax check does not prove purity through arbitrary serialization
implementations, macro expansion or transitive dependencies.

The compiler check uses the native process supervisor with two build jobs, a
ten-minute deadline, process-group cleanup and bounded diagnostic logs. Invalid
configured standard-library paths fail admission even when Clippy emits only a
warning; absent optional third-party paths are explicitly marked in the policy.

The shared Clippy configuration is included in native and isolated build input
identities. Tampering changes the identity and prevents materializing previously
captured inputs. Kernel state and compatibility tests run in required control
and workspace runtime suites.

An allowance documents why an existing call remains, its owning boundary and
the condition for removing it. It is technical debt, not a new general-purpose
capability. New sources default to no ambient effects. Strict contract/kernel
boundaries have no effect allowances. Production adapters may retain narrowly
reviewed effect access; every adapter call is still individually catalogued.

Merged OAuth PR111 supplies its production/simulation effects port and lifecycle
campaigns. Its integration catalogs five source files and three dev dependency
entries, retires 65 legacy effect groups (73 occurrences), and retains seven
individually reviewed raw calls inside `oauth/effects.rs`. This grants no file
exemption or additional ambient effects to its callers. The existing sealed
OAuth and credential proof APIs are unchanged. OAuth's schema admission scans
remain a separate bounded-work obligation; the build journal's budget does not
cover them.

The syntax checker is an accidental-drift guard. It does not perform full rustc
name resolution, expand arbitrary dependency macros or prove purity through
unknown helpers. Dependency boundaries, restricted APIs and Clippy restrictions
provide complementary enforcement. It is not hostile-code containment.

## Proof and durable state rules

Authority-bearing values have private constructors and fields. Dispatch/reveal
permits are consuming, non-Clone, non-Copy, non-Default and non-Deserialize.
Readiness handles may be cloneable when their use revalidates durable current
authority. Wire and storage records are separate from verified values.

Proofs bind the exact installation, app, operation, artifact, binding, account,
generation and epoch required for their action. Persisted facts do not become
current authority merely by decoding. The responsible boundary establishes
eligibility; protected use repeats freshness, revocation and version checks.

Persistent sum states carry only their applicable fields. The database enforces
the corresponding presence/absence, uniqueness and relationship constraints,
including direct malformed writes and supported upgrades. Network operations
never occur inside business transactions. Durable dispatch fencing precedes
provider sends; response loss remains uncertain until qualified observation.

## Principle enforcement map

This map names obligations, not completed coverage. Slice 1 delivers the source
and dependency ratchet. The kernel, proof, durable-state and bounded-admission
changes follow in separate PRs. Existing application behavior remains useful
evidence, but it does not establish the corresponding platform guarantee.
Record a completed slice's exact PR, locally checked head and counterexamples
before treating its row as enforced. Live provider and restore obligations
remain separate from native source and compiler checks.

| Principle | Mechanisms and required evidence |
| --- | --- |
| One canonical operation and transient generation | Checked registration and generated channel contracts; no manually duplicated schemas or provider scope maps. |
| Pure decisions and mediated nondeterminism | Strict kernel dependencies, architecture/Clippy guards, explicit facts and shared engine ports; reproducible schedules. |
| Impossible states and protected actions | State-specific types, sealed proof APIs, transactional constraints, CAS and negative fixtures. |
| Bounded queries and durable commands | Distinct phases, materialization and database execution budgets, atomic acceptance/completion and bounded effect work. |
| Independent failure domains and explicit overload | Scoped identities/data, quotas, bounded admission, fairness and cancellation campaigns. |
| Multiple providers and one write authority | Captured immutable affinity, exact adapter versions, fenced mutation and explicit cutover. |
| Unknown states and remote uncertainty | Exhaustive outcomes and fail-closed admission; qualified reconciliation before retry or reported success. |
| Desired is not active | Sealed ready bindings and atomic activation; incumbent-preservation campaigns. |
| Secrets and canonical identity | Private custody/sinks, redacted projections, leak canaries and current target-scoped authority at every protected hop. |
| Provider knowledge shared by all consumers | Paired simulator/production registration, protocol/provider conformance, versioned evidence and impacted consumer campaigns. |
| Exact release and recovery identity | Pinned artifacts/storage/contracts, ordered compatibility barriers, fenced restore and retained executions. |
| Operational truth and support profiles | Standard bounded telemetry, explicit missing/stale evidence, documented reliability/support profiles and real restore qualification. |

Simulation executes the production engine and transitions. Independent models
compute expected behavior without calling those transitions. Replay artifacts
retain bounded schedules, seeds and exact identities, with synthetic secret
references. Cryptographic entropy remains distinct from replayable ID entropy.
Real SQLite/process recovery and real-provider qualification supplement the lab.

Marketplace investment and reliability profile selection remain explicit product
and instance policy choices. Code-only checks cannot prove live provider delivery,
current revocation, cryptographic correctness or production availability.
