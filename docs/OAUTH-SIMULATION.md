# OAuth simulation and durable invariants

The existing OAuth implementation uses one native effect boundary in
`crates/day2/src/oauth/effects.rs`: wall time, monotonic leases, cryptographic
entropy, bounded provider HTTP, and blocking worker dispatch. Production uses
the OS clock, OS entropy, and the real HTTP adapter. Simulation hooks are compiled
only into test binaries. A simulated monotonic deadline cannot be compared with
a live deadline or a different simulation's deadline, so a test receipt cannot
become live readiness.

Request-body deadlines run on Tokio's clock. The HTTP-handler campaign pauses
that clock, supplies an in-memory stalled body, and advances the timer without
sleeping or opening a listener. Async simulation scopes restore the selected
environment around each future poll; blocking dispatch inherits it explicitly.
Real socket, concurrency, and subprocess kill/reopen tests remain separate native
adapter qualification. Simulation does not qualify a live deployment or client.

## Required campaigns

`xtask verify-fast` and `xtask verify` execute these library tests through the
existing `ops/Verify.roc` policy. No app task API or separate CI recipe is needed.

The composed campaign runs the production callback parser, encrypted verifier
and code custody, dispatch fence, token-response validation, external-account
quarantine, fresh shell attestation, and activation against real on-disk SQLite.
An independent symbolic oracle predicts acceptance and lifecycle state. Seeded
histories include rejected sessions/accounts, ambiguous exchange, expiry,
cancellation, repeated operations, and database reopen. Each history must replay
to exactly the same complete bounded reserved-table snapshots. Snapshots include
every row and column; binary values have length and content fingerprints, and a
row-budget overflow fails rather than truncating the state.

Additional seeded campaigns cover both Google registration policies and GitLab,
native Secret Manager/token/userinfo/refresh parsing, workload metadata identity,
OIDC key and token reads, one-use reauthentication callbacks, IAM receiver
credentials, private transport substitution/response loss, cloud routing checks,
readiness lease invalidation, signed publication with its original expiry, and
request-body deadlines. Provider responses and failure positions are scripted;
unselected or unscripted requests fail without falling back to the network.
Successful paths and each relevant fault boundary run twice for exact replay.
Inbound code redemption, refresh narrowing/replay, grant revocation, channel
removal, access expiry, custody rollback, and reopen also run against an independent
seeded oracle with complete snapshots and reduced counterexamples. The refresh
kernel retains its independent proptest model; native connect/inbound concurrency
and refresh subprocess crash qualification remain required as well.

The registration coverage test compares the complete reviewed host catalog with
the profile/adapter/simulator/conformance tuples exercised by its runnable
drivers. Adding a catalog entry without adding a driver fails the normal gate.
The compiled source catalog includes all OAuth modules, shared custody crypto,
IAP authentication/signing, the shared instance contract, and the verification
recipe. An AST maintenance guard rejects known direct ambient time, entropy,
HTTP, thread-sleep and Tokio timer paths outside the effect boundary, ignoring
`cfg(test)` adapter fixtures. Adding a module also requires source coverage.
This guard complements review; it is not a Rust sandbox or a proof about
effects hidden in a dependency or macro.

## Counterexample evidence and replay

Composed oracle or exact-replay failures write an implementation-bound bundle
under ignored `artifacts/oauth-simulation/failure-SEED.json`. The bundle contains
the seed, original and reduced semantic history, failure category, and complete
observations through the divergent step. Reduction deletes steps while retaining
the same failure category, within a fixed attempt budget. A replay mismatch
includes both traces. No callback code, PKCE verifier, access token, client
credential, provider response body, or authorization header enters the bundle.
The source identity binds replay to the compiled OAuth source catalog and its
recorded build inputs; it is not whole-executable binary attestation. Reduction
retains actual observed failures even if subsequent attempts pass, so an
intermittent replay mismatch does not lose its evidence. Evidence belongs in
protected storage, like other raw replay artifacts.

```text
DAY2_OAUTH_REPLAY=<bundle-path> cargo test --locked -p day2 --lib oauth::simulation::replay_saved_oauth_history -- --exact
```

The replay command succeeds only when the saved reduced history passes; a
persisting counterexample reproduces its failure. Reduction does not silently
update or approve a regression corpus. Runtime/setup errors retain the bounded
semantic history but may occur before a divergent database observation exists.

## Current schema admission

Refresh, connect, callback/exchange bindings, and inbound state use schema version 2;
managed credentials also use version 2, and custody uses version 3.
An entirely absent owned schema unit can be created inside the caller's
transaction. An existing unit must already have the exact current version,
column types/nullability/keys, foreign keys, indexes and guard definitions.
Admission also checks bounded existing row storage types, state predicates and
relationships. Earlier versions, partial units, missing guards, orphaned
references and substituted schemas fail closed without repair. Admission does
not migrate tables, restamp versions or disable foreign-key enforcement.

There is one exception, kept only for GoLinks' persisted links (AGENTS.md).
Builds before the version-2 credential unit installed a version-1 unit in every
store, whether or not the app declares managed credentials. When
`Runtime::initialize` opens a store whose credential unit is version 1, holds
only objects a version-1 installer created and has no row in any credential
table, it drops that unit, and the ordinary fresh installation then creates the
current unit in the same transaction
(`managed_credentials::store::replace_empty_version_1_unit`). A version-1 unit
holding any credential row or any other object is refused, and every other
version is refused as before. Nothing else is migrated.

Current databases reject inserts and updates containing partial
refresh receipts, partial account/scope evidence, empty required identities,
fractional counters, invalid initial/replacement generation relationships,
receipt versions that skip the base version, self-linked refresh successors, or
incorrect ciphertext/nonce types and bounds. Paired fields have separate
equivalence checks: a noncommitted row cannot carry either half of a receipt,
and an unapproved row cannot carry either half of its account evidence.
Native SQLite cases require fresh creation and exact current reopen, refusal of
earlier or partial schemas without mutation, malformed new-write rejection,
schema substitution refusal and transaction rollback. Qualifying a changed
source requires running those cases and the normal full gate.

These are durable structural invariants. Semantic account identity, authority,
current epochs, authenticated freshness, and custody authentication remain
enforced by the qualified nominal APIs and transaction fences. SQL shape checks
do not replace those checks or prove every possible safety property. The future
nominal outbound Use API remains separate work; these campaigns cover the code
that currently exists.

## Provider extension coverage

The published registry is `oauth/catalog.rs`. Its Google mapped-human, Google
external-account and GitLab external-account profiles must exactly equal the
set of runnable adapter/profile/simulator/conformance tuples. A negative gate
test removes the GitLab driver and proves the catalog cannot pass coverage.
Future extensions must update the explicit source inventory and provide a
driver; another profile label or a simulator digest alone is insufficient.

Registration drivers execute the actual native wire adapter through the shared
controlled clock/entropy/transport boundary. Google has nine HTTP boundaries;
GitLab has twelve, including token-info evidence after every exchange/refresh.
The independent order model owns these counts and exact public method/host/path
sequences. Eight seeds cover loss at every HTTP boundary and pre-step expiry
across those schedules. Every step must match the expected request prefix;
wrong endpoints, retries or I/O after failure/expiry fail the oracle even when
the session returns an error. Histories repeat exactly, failed sessions cannot
issue receipts, and expired receipts lose readiness.
GitLab's real HTTP fixtures additionally reject broader scopes, wrong clients,
wrong numeric subjects, locked accounts and non-rotating refresh responses.

Registration divergences persist redacted step/request observations with the
seed, provider driver, fault boundary, expiry schedule and complete compiled
source identity under `artifacts/oauth-simulation/registration-*.json`. Use the
existing `DAY2_OAUTH_REPLAY` entry point to replay them; bodies, tokens and
headers do not enter those observations. Each registration history has a fixed
nine-step campaign; outbound/inbound state histories retain their bounded
semantic reduction and complete real-SQLite snapshots.

The full gate also builds `oauth-gitlab-canary` and admits its real nominal SDK
declaration. The setup integration test runs that same artifact for two companies
with different clients and account ceilings, derives distinct callback and
registration pins, and rejects a provider substitution. Desired metadata and
simulated/native fixture receipts cannot establish live GitLab readiness.
