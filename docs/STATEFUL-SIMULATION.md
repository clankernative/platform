# Stateful operation generation

The control-plane lab generates operation attempts and their execution schedule
separately. It runs the real SQLite journal and native hosts, including the same
compiled Roc release and retirement recipes used by Temporal. It does not replace those hosts
with the generator's predictions.

## Main files

- `crates/day2-control/src/simulation/generation.rs`: typed intents, scheduler
  choices, bounded generation guidance, and compilation to concrete actions.
- `crates/day2-control/src/simulation/mod.rs`: real host execution, per-event
  safety checks, durable restart, bounded recovery, and exact replay.
- `crates/day2-control/src/simulation/coverage.rs`: observed transitions and
  campaign qualification, separate from requested or attempted behavior.
- `crates/day2-control/src/simulation/weak_provider.rs`: weak metadata reads,
  delayed physical application, external changes and controller recreation.
- `crates/day2-control/src/simulation/shrink.rs`: bounded semantic reduction and
  private counterexample bundles.
- `crates/day2-control/tests/simulation_generation.rs`: property tests over typed
  histories and schedules, plus reducer tests.
- `crates/day2-control/src/simulation_campaign.rs`: evidence binding and mandatory
  generated-coverage gate for the private Roc campaign recipe.

## Inputs and scheduling

A `Program` contains an intent stream and an independently seeded scheduler
stream. Intents include submissions, approvals, release starts, secret metadata,
cancellation, revocation, shared-version retirement, consumer drain, rollback
protection release, and explicit invalid attempts. Scheduler choices select
admission, worker advancement, contention, duplicate delivery, physical deployment
quiescence, time, and restart;
provider faults belong to the scheduled effect attempt.

Generation guidance tracks attempted progress to favor meaningful requests and
populated workers. It is deliberately separate from the safety oracle and never
calls the production reducer to manufacture an expected answer. Its optimistic
predictions can be wrong under faults: the host may refuse or wait, and the
actual observations determine the test result. The explicit invalid lane retains
unauthorized and premature attempts rather than filtering them all away.

There is no successful workflow bootstrap. Scenario formats 2, 3 and 4 start with no
admitted builds; submissions become real journal events. Format 1 remains an
explicit compatibility mode for existing regression fixtures that preadmit the
three candidate builds. Format 3 adds the six-candidate shared-secret catalog and
retirement actions; formats 1 and 2 retain their three-candidate input bounds.
Format 4 adds bounded weak-provider actions. Traces use format 5 and pin the implementation and Roc
recipe; old traces are not silently reinterpreted under new semantics.

## What constitutes coverage

The trace records the exact end of the generated input schedule. Everything
after that belongs to the fault-free, bounded fair recovery pass. Recovery can
test convergence, but cannot satisfy generated-schedule coverage requirements.

Coverage counts attempts, meaningful admissions, refusals, inert events, and
observed transitions. A label saying "accepted" is insufficient: relevant
native state changes, acquired leases, provider facts, and activation receipts
must support the transition. The oracle checks unrequested durable admissions
and effects after every event, not only at restart.

CI and normal verification require at least eight generated cases, progress in
multiple cases, and scheduled witnesses for submission, successful build,
approval, release start, provider mutation, activation, isolation refusal,
cross-execution interleaving, and restart with work pending. The shared-version
campaign additionally requires two-app protection and rollover, blocked retirement,
independent quiescence and drain, explicit rollback release, disabled-state
confirmation, and ambiguous-disable reconciliation. Weak-provider schedules also
exercise stale/opaque observations, held requests and later application, external
state changes, and observation-only stopping versus fenced controller recreation.
These are scheduled environment events, not extra production workflows. Generated and
regression coverage are separate. An inert generated campaign cannot borrow
qualification from the handwritten regressions.

Receipt format 2 pins each program, concrete scenario, trace, and computed
coverage. Verification regenerates the required program and recomputes coverage
from its trace before accepting the aggregate receipt.

## Counterexamples

The CLI and CI campaigns use a seeded SplitMix64 generator. A separate Proptest
test generates typed histories directly. Both use the same program compiler,
host runner, safety oracle, and semantic reducer. On a reproducible failure the
reducer removes intent groups and scheduling decisions, then simplifies typed
parameters. Removing a submission or approval prunes its positive dependants;
remaining intents are recompiled against the reduced generation guidance.
Stable entity identities and intentional invalid attempts are not renumbered
into different requests.

A reduction must preserve the failure fingerprint, including the failing action
kind when available. Unclassified host failures and replay divergence are
reported separately. Reduction has an explicit evaluation budget; its output is
not claimed to be globally minimal. When reduction is possible, original and
reduced evidence are retained in a new private counterexample directory, and
the reduced trace is replayed.
Reviewed reduced scenarios can join the committed regression corpus; generated
failures never automatically become approved source changes.

## Running the lab

```text
cargo run --locked -p xtask -- simulate-control
cargo run --locked -p xtask -- simulate-control 42 8
cargo run --locked -p xtask -- replay-control PATH/TO/TRACE.json
```

Runs with one to seven generated cases are exploratory and explicitly marked
`coverage_qualified: false`; they cannot substitute for the eight-case CI gate.
Evidence is written under `artifacts/control-simulation/`. Compiler/toolchain
failures remain failures, not successful simulation results.

## Deliberate bounds

This increment varies admission population/order and operation histories within
six candidate identities, two companies, three app targets and four worker slots.
Two apps in one company share secret versions through distinct aliases. It does
not generate arbitrary company/resource graphs or owner-transfer operations.
External secret mutations are currently bounded to retiring, unprotected versions,
not arbitrary sabotage of an active application's credentials. A held original
request or an externally disabled version without an exact platform-effect
acknowledgment may finish the lab in an explicitly witnessed reconciliation state.
That is unresolved intervention, not successful retirement. Fair recovery does
not manufacture a provider receipt or silently deliver a held external request.
Future capabilities should add typed intents, independent invariants, shrink
rules and observed coverage obligations to this same lab.

The [runtime-secret lifecycle](RUNTIME-SECRET-LIFECYCLE.md) adds canonical shared
versions, consumer drain and rollback protections, a durable retirement barrier,
and protected disable. Upstream credential rotation and irreversible secret
destruction remain separate capabilities.

The scheduler interleaves explicit host boundaries, not arbitrary CPU
instructions. Finite campaigns are evidence, not exhaustive proof over all
orders. Liveness requires eventual prerequisites and fair scheduling after
finite faults; permanent outages can remain explicitly waiting or unresolved.
Synthetic provider behavior still requires real-provider conformance checks.
