# Verification actor conformance

This complete, synthetic app proves operation-bound verification principals for
both commands and queries. It is a platform regression fixture, not Freetool or
a production authentication design. It has no provider operations or credentials.

The toy domain permits only the disposable fixture operator (`developer`) to
create or count notes. Rejection is a normal business rule; handlers do not
recognize synthetic test names or weaken permissions to obtain witnesses.
Command and query error definitions use distinct `Api.verification_principal`
values, while their ordinary generated cases use the operator.

Full `xtask verify` admits this fixture and pins its artifact in the receipt.
`app_contract::admitted_failure_principals_are_atomic_replayable_and_simulation_only`
checks real generated contracts, four selected-actor rejection traces, unchanged
business state, no provider dispatch, duplicate delivery, cross-target and
narrowed policy refusal, artifact/actor replay counterexamples, and nonsimulated
denial with authorized command/query positive controls.

From the platform root:

```sh
bazel run //crates/xtask:xtask -- build fixtures/verification-actor-conformance
DAY2_TEST_VERIFICATION_ACTORS_ARTIFACT=/absolute/path/to/admitted/artifact \
  cargo test --locked -p day2 --test day2_integration \
  app_contract::admitted_failure_principals_are_atomic_replayable_and_simulation_only -- --exact --nocapture
```

The test retains histories under unique `artifacts/verification-actors-*`
directories and prints the one-command saved-file replay beside each trace:

```sh
bazel run //crates/day2:day2 -- replay ARTIFACT TRACE_FILE
```

Replay validates the stored request and deterministic decisions; it does not
repeat provider writes or overwrite the supplied file. Generated artifacts and
raw evidence stay under ignored `artifacts/`, never in this fixture directory.
