# Exact verifier key and current epoch adapter

`managed_credentials::authority::SelectedAuthority` now requires an explicit
`VerificationSource` as well as the installation's exact-version key provider.
It has no production snapshot-only fallback. No live source is installed by this
change, and native credential authentication remains unsupported. The existing
selection fixtures name their test-only local source explicitly.

The source is a private, trusted installation port. It must return fresh local
evidence authenticated by the actual admitted owner, with the real namespace,
family, epoch-store origin, binding and management commitments. It must not
perform network/provider I/O or acquire a new owner: epoch checks also run
inside the caller's guarded SQL. An observation record is DATA, not a native
proof. A future native supplier and its qualification remain separate work.

Verification loads only the selected `CustodyVerifier` key and checks its actual
binding, exact version and purpose. It never borrows custody encryption or human
delivery authority. Selection and observation locks are released before key
provider work. Afterwards the adapter rechecks the current source, fixed
readiness window and local selection revision before constructing a verifier
lease. Even an identical replacement or remove/readd invalidates pending key
work. Both the provider Result and postcheck are evaluated; the provider error
remains primary if both refuse. Temporary key buffers are zeroized on every
success and error path, including wrong-identity material.

The source must advance its revision when its epoch, verifier, enablement,
binding, policy or fixed readiness window changes. Process-local bounded history
remembers accepted source revisions, clock samples and epoch floors, including
newer evidence which cannot match a stale local selection. Wrong-world evidence
cannot poison the rightful world's history. Removing a family does not evict its
history; a full history refuses new domains rather than forgetting a floor.
These are process-local protections, not a durable external restore witness.
A dishonest source before any contrary observation is outside this adapter's
proof; a real supplier must authenticate and fence its evidence independently.

The post-key clock must not rewind or change domains. Elapsed monotonic provider
work supplies an additional lower bound for the source's integer-second wall
sample, with checked addition; it never renews the readiness window or replaces
a native original, deadline or permanent refusal. Every later epoch lookup gets
a fresh local observation and does not fetch key material inside SQL.

## Local coverage

Focused tests independently vary source origin, verifier purpose/version,
retirement, epoch/revision rollback, local replacement/ABA, unavailable sources,
provider errors and key-I/O clock faults. The existing real SQLite bearer/reopen
case now uses a separately controlled epoch source. Advancing it fences both a
stale local selection and the old stored bearer without changing the token row.

Thirty-two generated histories replay twice against an independent event-only
reference model. Every event compares the complete selected set, local revision
and all local/source floor maps; full scoped DATA is committed by digest rather
than exported. Outcomes also compare acceptance, exact key-load count and source
observation count. A deliberately false oracle is retained and replayed through
the same source-bound decoder. Evidence contains only closed fixture events and
boolean/count outcomes from both runs, including a second-run-only disagreement;
it never serializes key material or downstream errors.
Failures are saved under `artifacts/credential-verifier-adapter/failure-*.json`.
Replay limits are 64 events and 128 KiB; unknown fields, changed source and a
non-reproducing or successful counterexample are refused.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::authority::tests::
DAY2_CREDENTIAL_VERIFIER_ADAPTER_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::authority::tests::replay_saved_exact_adapter_history --exact
```

These are controlled-source and ordinary SQLite checks. They do not establish
native producer admission, a durable external epoch service, live key-provider
behavior, production management/delivery, reveal/ack or deployed qualification.
