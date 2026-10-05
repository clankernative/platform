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

Additional seeded campaigns cover both reviewed Google registration policies,
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

## Schema upgrades

Refresh, connect, callback/exchange bindings, and inbound state use schema version 2;
custody uses version 3.
Known legacy versions upgrade additively inside a transaction. Before stamping
the version, admission checks the reviewed column types/nullability/keys, foreign
keys, unique indexes, installed guard definitions, existing row storage types,
and state predicates. Invalid legacy rows, orphaned references, substituted
schemas or guards, and unknown versions fail closed. Tables are not rebuilt and
foreign-key enforcement is not disabled.

Both new and upgraded databases reject inserts and updates containing partial
refresh receipts, partial account/scope evidence, empty required identities,
fractional counters, invalid initial/replacement generation relationships,
receipt versions that skip the base version, self-linked refresh successors, or
incorrect ciphertext/nonce types and bounds. Paired fields have separate
equivalence checks: a noncommitted row cannot carry either half of a receipt,
and an unapproved row cannot carry either half of its account evidence.
Reopen, rejected legacy upgrades, malformed new writes, schema substitution,
and transaction rollback have native SQLite regression coverage.

These are durable structural invariants. Semantic account identity, authority,
current epochs, authenticated freshness, and custody authentication remain
enforced by the qualified nominal APIs and transaction fences. SQL shape checks
do not replace those checks or prove every possible safety property. The future
nominal outbound Use API and provider/client extensibility remain separate work;
these campaigns cover the code that currently exists.
