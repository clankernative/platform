# Credential issuance process-loss coverage

The fixed client and personal profiles run their actual compiled conformance
commands through Runtime, confirmed invocation authority and the ordinary SQL
transaction coordinator. Each creates its public product registration and
private credential state together. Custody keys/readiness are explicit disposable
fixtures; this does not qualify a live supplier, native enrollment or browser
transport.

Two test-only checkpoints exercise real process death:

- After the successful product/private writes and invocation completion are
  staged on the original transaction, immediately before COMMIT.
- After the coordinator reports successful COMMIT, before Runtime returns the
  public result to its caller.

Unarmed checkpoints do no I/O, clock or authority work. An armed checkpoint pins
the child process, thread, invocation, database and artifact. It verifies the
staged/committed rows, emits a fixed marker without data, then blocks on its
control pipe. The parent requests SIGKILL and requires the actual wait status
and pipe EOF before reopening the real SQLite database. Finite parent deadlines
and cleanup refuse unknown completion; this is not an arbitrary descendant or
hard operating-system deadline guarantee. Fault selection uses the marker,
never sleeps or timing guesses. Ordinary successful execution is a positive
baseline; actual missing-checkpoint and normal-exit controls must be refused.

An independent lifecycle oracle expects rollback before COMMIT and one durable
issuance after COMMIT. Reopen compares product rows, lineage/version/material,
delivery and the public receipt. Same-intent recovery and repeated receipt
lookup must preserve the exact opaque private/product rows. The latter must
request no new private entropy. A changed duplicate input must be refused.
A passing real fixture baseline is followed by a rollback mutation to a
different encoded product revision; the same reader must refuse it.
Identifiers use a replayable port; material entropy is a separate OS port, so a
rewound synthetic stream cannot conceal replacement of an existing secret.

Both profiles, both cuts and three fixed seeds form twelve declared histories.
Every history runs twice. CI requires the current success receipt and retains
redacted failing cases under `credential-crash-reopen`; the output contains
only closed profile/cut/seed, source/artifact identity, numeric child status and
safe counts/booleans. It contains no tokens, keys, verifier/ciphertext values,
private snapshots, process arguments, environments or downstream error text.

```console
DAY2_CREDENTIAL_CRASH_REPLAY=<failure.json> bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::simulation::crash_reopen::replay_saved_credential_process_loss --exact
```

Replay also needs the current conformance fixture through
`DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT`. Use the CI revision and matching
artifact. Unknown fields, oversized inputs and mismatched source/artifact are
refused before a child starts. Source binding is not an independent complete
compiler/action closure. Native tests are explicitly excluded from gates that
have not prepared this fixture; the full workspace-day2 gate runs them.

Reveal-authorization and acknowledgement process-loss cuts are a separate next
slice. This harness never reconstructs a response permit or adds a public secret
getter, compatibility path, migration or alternate issuance implementation.
